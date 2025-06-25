
use std::net::UdpSocket;
use trust_dns_proto::op::{Message, MessageType, OpCode, Query};
use trust_dns_proto::rr::{Name, Record, RecordType, RData};
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable, BinEncoder};



fn main() -> std::io::Result<()> {
    // Bind the UDP socket to localhost:8080
    let socket = UdpSocket::bind("0.0.0.0:53")?;
    println!("UDP server listening on 0.0.0.0:53");

    let mut buf = [0u8; 1024];

    loop {
        // Receive a message from any client
        let (amt, src) = socket.recv_from(&mut buf)?;

        // Convert the bytes to a string and print it
        let msg = match Message::from_bytes(&buf[..amt]) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("Failed to parse DNS message: {}", e);
                continue;
            }
        };

        if src.ip().to_string() != "127.0.0.1" {
            println!("Received DNS from {}: {:?}", src, msg);
        }

        // Prepare response message
        let mut resp = Message::new();
        resp.set_id(msg.id());
        resp.set_message_type(MessageType::Response);
        resp.set_op_code(OpCode::Query);
        resp.set_recursion_desired(msg.recursion_desired());
        resp.set_recursion_available(true);
        resp.set_authoritative(true);
        resp.set_response_code(trust_dns_proto::op::ResponseCode::NoError);

        // For simplicity, respond with A record for "example.com." if queried
        if let Some(query) = msg.queries().first() {
            let name = query.name().to_ascii();

            if true {
                println!("name = {}", name);
                /*
                let record = Record::from_rdata(
                    Name::from_ascii("hello.nyly.me.").unwrap(),
                    300, // TTL
                    RData::A("93.184.216.34".parse().unwrap()),
                );
                */

                let txt_record = Record::from_rdata(
                    Name::from_ascii("hello.nyly.me.").unwrap(),
                    1000,
                    RData::TXT(trust_dns_proto::rr::rdata::TXT::new(vec!["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()])),
                );
                let txt_record2 = Record::from_rdata(
                    Name::from_ascii("hello.nyly.me.").unwrap(),
                    1000,
                    RData::TXT(trust_dns_proto::rr::rdata::TXT::new(vec!["BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string()])),
                );

                resp.add_query(query.clone());
                //resp.add_answer(record);
                resp.add_answer(txt_record);
                resp.add_answer(txt_record2);
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
            continue;
        }

        // Send response
        socket.send_to(&resp_buffer, src)?;
        if src.ip().to_string() != "127.0.0.1" {
            println!("Sent response to {}", src);
        }

    }
}

