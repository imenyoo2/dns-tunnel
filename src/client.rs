use std::net::UdpSocket;
use trust_dns_proto::op::{Message, MessageType, OpCode, Query};
use trust_dns_proto::rr::{Name, RecordType};
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable, BinDecoder};
use base64::{engine::general_purpose, Engine as _};

fn dns_receive(socket: &UdpSocket) -> Result<(std::net::SocketAddr, Message, Vec<u8>), ()> {
    let mut buf = [0u8; 64 * 1024];

    let (amt, src) = socket.recv_from(&mut buf).or_else(|_| Err(()))?;

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

// returns if succeeded or not
fn dns_encapsulate(socket: &UdpSocket, address_to: String, data: &[u8]) -> bool {

    assert!(data.len() <= 0xff);

    let mut msg = Message::new();
    msg.set_id(1234);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    let defix = &[5, b'h', b'e', b'l', b'l', b'o', 4, b'n', b'y', b'l', b'y', 2, b'm', b'e'];
    let mut raw_data = Vec::with_capacity(defix.len() + data.len());
    raw_data.extend_from_slice(&[data.len() as u8]);
    raw_data.extend_from_slice(data);
    raw_data.extend_from_slice(defix);
    raw_data.extend_from_slice(&[0]);
    println!("sending data: {}", String::from_utf8_lossy(&raw_data));
    msg.add_query(Query::query(Name::from_bytes(&raw_data).unwrap(), RecordType::TXT));
    msg.set_recursion_desired(true); // important for the msg to reach the server

    // serialize data
    let mut req_buffer = Vec::with_capacity(64 * 1024);
    msg.emit(&mut trust_dns_proto::serialize::binary::BinEncoder::new(&mut req_buffer)).unwrap();

    // Send query
    socket.send_to(&req_buffer, &address_to).unwrap();
    println!("Sent DNS query to {}", &address_to);

    return true;
}

fn main() -> std::io::Result<()> {
    // Bind a local UDP socket for sending
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

    let server_addr = "10.0.2.3:53";
    //let server_addr = "127.0.0.1:8080";

    dns_encapsulate(&socket, String::from(server_addr), "helloworld5".as_bytes());

    // Receive response
    let mut resp_buffer = [0u8; 3024];
    let (amt, _) = socket.recv_from(&mut resp_buffer)?;

    // Parse response
    let response = Message::from_bytes(&resp_buffer[..amt]).unwrap();

    println!("Received response:\n{:#?}", response);

    Ok(())
}

