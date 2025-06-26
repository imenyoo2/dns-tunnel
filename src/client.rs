use tokio::net::UdpSocket;
use trust_dns_proto::op::{Message, MessageType, OpCode, Query};
use trust_dns_proto::rr::{Name, RecordType};
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable, BinDecoder};
use base64::{engine::general_purpose, Engine as _};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::io::AsyncReadExt;
mod tunnel;


use std::env;
fn debug(msg: &str) {
    if env::var("DEBUG").ok().as_deref() == Some("1") {
        println!("[DEBUG] {}", msg);
    }
}

async fn dns_receive(socket: &UdpSocket) -> Result<(std::net::SocketAddr, Message, Vec<u8>), ()> {
    let mut buf = [0u8; 64 * 1024];

    let (amt, src) = socket.recv_from(&mut buf).await.or_else(|_| Err(()))?;

    // Convert the bytes to a string and print it
    let mut msg = Message::from_bytes(&buf[..amt]).or_else(|_| Err(()))?;

    let data = msg
        .take_answers()
        .first()
        .and_then(|record| record.data())
        .and_then(|data| data.as_txt())
        .and_then(|txt| txt.txt_data().first())
        .and_then(|txt_1| Some(std::str::from_utf8(txt_1).expect("invalid utf-8").to_string()))
        .ok_or(())?;

    let decoded_data = general_purpose::STANDARD.decode(data).or_else(|_| Err(()))?;

    return Ok((src, msg, decoded_data));
}


fn name_format_array(arr: &[u8]) -> Vec<u8> {
    let mut formated: Vec<u8> = vec![];
    let mut len = arr.len();
    let mut index = 0;
    while len > 60 {
        formated.extend_from_slice(&[60]);
        formated.extend_from_slice(arr.get(index..index+60).unwrap());
        index += 60;
        len = len - 60;
    }
    formated.extend_from_slice(&[(arr.len() - index) as u8]);
    formated.extend_from_slice(arr.get(index..arr.len()).unwrap());
    return formated;
}

// returns if succeeded or not
async fn dns_encapsulate(socket: &UdpSocket, address_to: String, data: &[u8]) -> Result<usize, ()> {

    //assert!(data.len() <= 200);

    let mut msg = Message::new();
    msg.set_id(1234);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    let defix = &[5, b'h', b'e', b'l', b'l', b'o', 4, b'n', b'y', b'l', b'y', 2, b'm', b'e'];
    let mut raw_data = name_format_array(data);
    raw_data.extend_from_slice(defix);
    raw_data.extend_from_slice(&[0]);
    debug(&format!("sending data: {:?}", raw_data));
    msg.add_query(Query::query(Name::from_bytes(&raw_data).or_else(|_| Err(()))?, RecordType::TXT));
    msg.set_recursion_desired(true); // important for the msg to reach the server

    // serialize data
    let mut req_buffer = Vec::with_capacity(64 * 1024);
    msg.emit(&mut trust_dns_proto::serialize::binary::BinEncoder::new(&mut req_buffer)).or_else(|_| Err(()))?;

    // Send query
    debug(&format!("sending DNS query to {}", &address_to));
    return socket.send_to(&req_buffer, &address_to).await.or_else(|_| Err(()));

}


async fn compute_mtu(socket: &UdpSocket, address_to: String) -> usize {
    for i in (10..0xff).step_by(10).rev() {
        let tmp_data = vec![0x41; i];
        if let Ok(sent_data) = dns_encapsulate(socket, address_to.clone(), &tmp_data).await {
            if let Ok((_, _, data)) =  dns_receive(socket).await {
                return i;
            }
        }
    }
    return 0;
}

async fn read_packets_and_send(dev: &mut File, packet: &mut [u8], socket: &UdpSocket, server_addr: String) {
    if let Ok(bytes_readed) = dev.read(packet).await {
        tunnel::hexdump(&packet[0..bytes_readed]);
        let _ = dns_encapsulate(&socket, String::from(server_addr), &packet[0..bytes_readed]).await;
    };
}

async fn receive_and_write_packets(dev: &mut File, socket: &UdpSocket) {
    let (_, _, data) = match dns_receive(&socket).await {
        Ok(res) => res,
        Err(_) => return,
    };
    println!("got data:");
    tunnel::hexdump(&data);
    let _ = dev.write_all(&data);
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Bind a local UDP socket for sending
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    //socket.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

    //let server_addr = "172.20.10.1:53";
    // let server_addr = "192.168.156.147:53";
    let server_addr = "10.0.2.3:53";
    

    // setup tunnel
    //println!("mtu = {}", compute_mtu(&socket, String::from(server_addr)));

    let mut dev: File = tunnel::open_tunnel(String::from("tun38"));
    let mut packet: [u8; 200] = [0; 200];


    println!("> run setup ip");
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf).unwrap();

    loop {
        read_packets_and_send(&mut dev, &mut packet, &socket, String::from(server_addr)).await;
        receive_and_write_packets(&mut dev, &socket).await;
    }
    
    /*
    let mtu = compute_mtu(&socket, String::from(server_addr));
    println!("got mtu = {}", mtu);

    let _ = dns_encapsulate(&socket, String::from(server_addr), &[0xff, 0xff, 0xff, 0xff]);
    */

    // Receive response
    /*
    let mut resp_buffer = [0u8; 3024];
    let (amt, _) = socket.recv_from(&mut resp_buffer)?;

    // Parse response
    let response = Message::from_bytes(&resp_buffer[..amt]).unwrap();

    debug(&format!("Received response:\n{:#?}", response));
    return Ok(())
    */

}

