
use std::collections::VecDeque;
use std::os::fd::AsRawFd;
use mio::unix::SourceFd;
use mio::net::UdpSocket;
use mio::{Events, Interest, Poll, Token};
use trust_dns_proto::op::{Message, MessageType, OpCode, Query};
use trust_dns_proto::rr::{Name, Record, RecordType, RData};
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable, BinEncoder};
use base64::{engine::general_purpose, Engine as _};
use std::fs::File;
use std::io::prelude::*;
mod tunnel;
mod packet;


fn dns_encapsulate(socket: &UdpSocket, data: &[u8], msg: Message, src: std::net::SocketAddr) -> bool {
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
    socket.send_to(&resp_buffer, src).unwrap();
    println!("Sent response to {}", src);

    return true;
}

fn decapsulate_client_data(data: &[u8]) -> Vec<u8> {
    let mut res: Vec<u8> = vec![];
    let mut index = 0;
    while index < data.len() {
        res.extend_from_slice(data.get(((index + 1) as usize)..=index + (data[index] as usize)).unwrap_or(&[]));
        index = index + (data[index] as usize) + 1;
    }
    return res[..res.len() - "hellonylyme".len()].to_vec();
}

fn dns_receive(socket: &UdpSocket) -> Result<(std::net::SocketAddr, Message, Vec<u8>), ()> {
    let mut buf = [0u8; 64 * 1024];

    println!("[+] recieving from client");
    let (amt, src) = socket.recv_from(&mut buf).or_else(|_| Err(()))?;
    println!("[+] done recieving from client");

    // Convert the bytes to a string and print it
    let msg = Message::from_bytes(&buf[..amt]).or_else(|_| Err(()))?;

    let data = msg.query()
        .and_then(|query| Some(query.name().to_bytes().or_else(|_| Err(()))))
        .ok_or(())??;

    return Ok((src, msg, decapsulate_client_data(&data)));

}

const UDP_SOCKET: Token = Token(0);
const DEV_TUN: Token = Token(1);

fn main() -> Result<(),()> {
    // Bind the UDP socket to localhost:8080
    let mut socket = UdpSocket::bind("0.0.0.0:53".parse().unwrap()).map_err(|_| ())?;
    println!("UDP server listening on 0.0.0.0:53");

    let mut dev: File = tunnel::open_tunnel(String::from("tun38"));

    let mut poll = Poll::new().map_err(|_| ())?;

    let raw_fd = dev.as_raw_fd();
    let mut tun_source = SourceFd(&raw_fd);
    poll.registry().register(&mut tun_source, DEV_TUN, Interest::READABLE).map_err(|_| ())?;


    println!("> run setup ip");
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf).unwrap();


    let mut events = Events::with_capacity(128);
    poll.registry().register(&mut socket, UDP_SOCKET, Interest::READABLE).map_err(|_| ())?;

    // buffers
    let mut read_packets: VecDeque<packet::Packet> = vec![].into();
    let mut write_packets: VecDeque<packet::Packet> = vec![].into();

    loop {
        println!("read_packets = {}, write_packets = {}", read_packets.len(), write_packets.len());
        println!("writing data to tunnel:");
        loop {
            if let Some(packet) = write_packets.pop_front() {
                tunnel::hexdump(packet.data());
                let _ = dev.write_all(packet.data());
            } else {
                break;
            }
        }

        // wait for Events
        poll.poll(&mut events, None).map_err(|_| ())?;
        // Receive a message from any client
        for event in &events {
            match event.token() {
                UDP_SOCKET => {
                    if let Ok((src, msg, data)) = dns_receive(&socket) {
                        println!("got from client:");
                        tunnel::hexdump(&data);
                        if &data != "PING".as_bytes() {
                            write_packets.push_back(packet::Packet::from_slice(&data));
                        }
                        if let Some(packet) = read_packets.pop_front() {
                            dns_encapsulate(&socket, packet.data(), msg, src);
                        } else {
                            dns_encapsulate(&socket, "nodata".as_bytes(), msg, src);
                        }
                    }
                },
                DEV_TUN => {
                    let mut packet = [0; 200];
                    if let Ok(bytes_readed) = dev.read(&mut packet) {
                        println!("reading from tunnel:");
                        tunnel::hexdump(&packet);
                        read_packets.push_back(packet::Packet::from_slice(&packet[..bytes_readed]));
                    }
                }
                Token(_) => unreachable!()
            }
        }

        /*
        if let Ok((src, msg, data)) = dns_receive(&socket) {
            tunnel::hexdump(&data);
            println!("[+] writing data");
            let _ = dev.write_all(&data);
            println!("[+] done writing data");
            if let Ok(bytes_readed) = dev.read(&mut packet) {
                dns_encapsulate(&socket, &packet[0..bytes_readed], msg, src);
            }
        }
        */
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

