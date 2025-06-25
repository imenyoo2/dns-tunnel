use std::net::UdpSocket;
use trust_dns_proto::op::{Message, MessageType, OpCode, Query};
use trust_dns_proto::rr::{Name, RecordType};
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable, BinDecoder};

fn main() -> std::io::Result<()> {
    // Bind a local UDP socket for sending
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

    let server_addr = "192.168.156.147:53";
    //let server_addr = "127.0.0.1:8080";

    // Build DNS query message
    let mut msg = Message::new();
    msg.set_id(1234);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.add_query(Query::query(Name::from_ascii("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.hello.nyly.me").unwrap(), RecordType::TXT));
    msg.set_recursion_desired(true); // important for the msg to reach the server

    // Serialize query
    let mut req_buffer = Vec::with_capacity(512);
    msg.emit(&mut trust_dns_proto::serialize::binary::BinEncoder::new(&mut req_buffer)).unwrap();

    // Send query
    socket.send_to(&req_buffer, server_addr)?;
    println!("Sent DNS query to {}", server_addr);

    // Receive response
    let mut resp_buffer = [0u8; 3024];
    let (amt, _) = socket.recv_from(&mut resp_buffer)?;

    // Parse response
    let response = Message::from_bytes(&resp_buffer[..amt]).unwrap();

    println!("Received response:\n{:#?}", response);

    Ok(())
}

