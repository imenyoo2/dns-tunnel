
use tokio::net::UdpSocket;
use trust_dns_proto::op::{Message, MessageType, OpCode, Query};
use trust_dns_proto::rr::{Name, Record, RecordType, RData};
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable, BinEncoder};
use base64::{engine::general_purpose, Engine as _};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::io::{self, AsyncReadExt};
use tokio::task;
use std::sync::Arc;
use tokio::sync::Mutex;

mod tunnel;


async fn dns_encapsulate(socket: &UdpSocket, data: &[u8], msg: Message, src: std::net::SocketAddr) -> bool {
    // Prepare response message
    let mut resp = Message::new();
    resp.set_id(msg.id());
    resp.set_message_type(MessageType::Response);
    resp.set_op_code(OpCode::Query);
    resp.set_recursion_desired(msg.recursion_desired());
    resp.set_recursion_available(true);
    resp.set_authoritative(true);
    resp.set_response_code(trust_dns_proto::op::ResponseCode::NoError);

    if let Some(query) = msg.queries().first() {

        if true {

            let mut txt_record = Record::from_rdata(
                query.name().clone(),
                1000,
                RData::TXT(trust_dns_proto::rr::rdata::TXT::new(vec![general_purpose::STANDARD.encode(data)])), // base64 encoding
            );

            resp.add_query(query.clone());
            txt_record.set_ttl(0); // setting time to live to 0 to avoid caching
            resp.add_answer(txt_record);
        } else {
            resp.add_query(query.clone());
            resp.set_response_code(trust_dns_proto::op::ResponseCode::NXDomain);
        }
    }
    // Serialize response
    let mut resp_buffer = Vec::with_capacity(512);
    let mut encoder = BinEncoder::new(&mut resp_buffer);
    if let Err(e) = resp.emit(&mut encoder) {
        eprintln!("Failed to encode DNS response: {}", e);
        return false;
    }

    // Send response
    socket.send_to(&resp_buffer, src).await.unwrap();
    println!("Sent response to {}", src);

    return true;
}


async fn dns_receive(socket: &UdpSocket) -> Result<(std::net::SocketAddr, Message, Vec<u8>), ()> {
    let mut buf = [0u8; 64 * 1024];

    println!("[+] recieving from client");
    let (amt, src) = socket.recv_from(&mut buf).await.or_else(|_| Err(()))?;
    println!("[+] done recieving from client");

    // Convert the bytes to a string and print it
    let msg = Message::from_bytes(&buf[..amt]).or_else(|_| Err(()))?;

    let data = msg.query()
        .and_then(|query| Some(query.name().to_bytes().or_else(|_| Err(()))))
        .ok_or(())??;

    return Ok((src, msg, data[1..(data[0] + 1) as usize].to_vec()));

}

/*
async fn receive_and_write_packets(dev: &mut File, socket: &UdpSocket) -> Result<(std::net::SocketAddr, Message), ()> {
    if let Ok((src, msg, data)) = dns_receive(&socket).await {
        tunnel::hexdump(&data);
        println!("[+] writing data");
        let _ = dev.write_all(&data);
        println!("[+] done writing data");
        return Ok((src, msg));
    } else {
        return Err(());
    }
}

async fn read_packets_and_send(dev: &mut File, packet: &mut [u8], socket: &UdpSocket, server_addr: String, src) {
    if let Ok(bytes_readed) = dev.read(&mut packet) {
        dns_encapsulate(&socket, &packet[0..bytes_readed], msg, src).await;
    }
}
*/

async fn handle_dns_receive(data: Vec<u8>, msg: Message, src: std::net::SocketAddr, dev: Arc<Mutex<File>>, socket: Arc<UdpSocket>) {
    let mut packet: [u8; 200] = [0; 200];
    let mut file = dev.lock().await;

    tunnel::hexdump(&data);
    println!("[+] writing data");
    let _ = file.write_all(&data).await;
    println!("[+] done writing data");
    if let Ok(bytes_readed) = file.read(&mut packet).await {
        dns_encapsulate(&socket, &packet[0..bytes_readed], msg, src).await;
    }
}

#[tokio::main]
async fn main() -> Result<(),()> {
    // Bind the UDP socket to localhost:8080
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:53").await.or_else(|_| Err(()))?);
    println!("UDP server listening on 0.0.0.0:53");

    let dev: File = tunnel::open_tunnel(String::from("tun38"));
    let shared_file = Arc::new(Mutex::new(dev));
    //let mut packet: [u8; 200] = [0; 200];


    println!("> run setup ip");
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf).unwrap();


    let mut handles: Vec<task::JoinHandle<()>> = Vec::new();


    loop {
        // Receive a message from any client
        println!("tesssst");
        if let Ok((src, msg, data)) = dns_receive(&socket).await {
            let file_clone = Arc::clone(&shared_file);
            let socket_clone = Arc::clone(&socket);
            let handle = task::spawn(handle_dns_receive(data, msg, src, file_clone, socket_clone));
            handles.push(handle);
        }
    }

    /*
    loop {
        if let Ok(bytes_readed) = dev.read(&mut packet) {
            tunnel::hexdump(&packet[0..bytes_readed]);
            let _ = dns_encapsulate(&socket, String::from(server_addr), &packet[0..bytes_readed]);
            let (_, _, data) = match dns_receive(&socket) {
                Ok(res) => res,
                Err(_) => continue,
            };
            println!("got data:");
            tunnel::hexdump(&data);
            let _ = dev.write_all(&data);
        };
    }
    */
}

