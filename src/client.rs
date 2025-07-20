use std::os::fd::AsRawFd;
use std::collections::VecDeque;
use mio::net::UdpSocket;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use trust_dns_proto::op::{Message, MessageType, OpCode, Query};
use trust_dns_proto::rr::{Name, RecordType};
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};
use base64::{engine::general_purpose, Engine as _};
use std::fs::File;
use std::io::prelude::*;
use std::time::Duration;
mod tunnel;
mod packet;


use std::env;
fn debug(msg: &str) {
    if env::var("DEBUG").ok().as_deref() == Some("1") {
        println!("[DEBUG] {}", msg);
    }
}

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
fn dns_encapsulate(socket: &UdpSocket, address_to: String, data: &[u8]) -> Result<usize, ()> {

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
    return socket.send_to(&req_buffer, address_to.parse().unwrap()).or_else(|_| Err(()));

}


fn compute_mtu(socket: &UdpSocket, address_to: String) -> usize {
    for i in (10..0xff).step_by(10).rev() {
        let tmp_data = vec![0x41; i];
        if let Ok(_) = dns_encapsulate(socket, address_to.clone(), &tmp_data) {
            if let Ok((_, _, _)) =  dns_receive(socket) {
                return i;
            }
        }
    }
    return 0;
}

fn send_ping(dev: &mut File, socket: &UdpSocket, server_addr: &str) {
    println!("sending ping msg");
    let _ = dns_encapsulate(&socket, String::from(server_addr), "PING".as_bytes());
    let (_, _, data) = match dns_receive(&socket) {
        Ok(res) => res, Err(_) => return,
    };
    println!("got data:");
    tunnel::hexdump(&data);
    if &data != "nodata".as_bytes() {
        let _ = dev.write_all(&data);
    }
}

fn send_packet(dev: &mut File, socket: &UdpSocket, server_addr: &str) {
    let mut packet: [u8; 200] = [0; 200];

    if let Ok(bytes_readed) = dev.read(&mut packet) {
        tunnel::hexdump(&packet[0..bytes_readed]);
        let _ = dns_encapsulate(&socket, String::from(server_addr), &packet[0..bytes_readed]);
        let (_, _, data) = match dns_receive(&socket) {
            Ok(res) => res,
            Err(_) => return,
        };
        println!("got data:");
        tunnel::hexdump(&data);
        if &data != "nodata".as_bytes() {
            let _ = dev.write_all(&data);
        }
    }
}

fn read_tunnel(dev: &mut File, read_packets: &mut VecDeque<packet::Packet>) {
    let mut packet: [u8; 200] = [0; 200];

    if let Ok(bytes_readed) = dev.read(&mut packet) {
        tunnel::hexdump(&packet[0..bytes_readed]);
        read_packets.push_back(packet::Packet::from_slice(&packet[..bytes_readed]));
    }
}

fn read_dns_socket(socket: &UdpSocket, write_packets: &mut VecDeque<packet::Packet>) {
    let (_, _, data) = match dns_receive(&socket) {
        Ok(res) => res, Err(_) => return,
    };
    println!("got from server");
    tunnel::hexdump(&data);
    if data != "nodata".as_bytes() {
        write_packets.push_back(packet::Packet::from_slice(&data));
    }
}


const UDP_SOCKET: Token = Token(0);
const DEV_TUN: Token = Token(1);
const BACKGROUND_INTERVAL: Duration = Duration::from_millis(500);

fn main() -> std::io::Result<()> {
    // Bind a local UDP socket for sending
    let mut socket = UdpSocket::bind("0.0.0.0:0".parse().unwrap())?;
    //socket.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

    //let server_addr = "172.20.10.1:53";
    //let server_addr = "10.0.2.3:53";
    let server_addr = "127.0.0.1:8080";
    

    // setup tunnel
    //println!("mtu = {}", compute_mtu(&socket, String::from(server_addr)));

    let mut dev: File = tunnel::open_tunnel(String::from("tun38"));

    // settuping epoll
    let mut poll = Poll::new()?;

    let raw_fd = dev.as_raw_fd();
    let mut tun_source = SourceFd(&raw_fd);
    poll.registry().register(&mut tun_source, DEV_TUN, Interest::READABLE)?;
    poll.registry().register(&mut socket, UDP_SOCKET, Interest::READABLE)?;

    let mut read_packets: VecDeque<packet::Packet> = vec![].into();
    let mut write_packets: VecDeque<packet::Packet> = vec![].into();

    let mut events = Events::with_capacity(128);


    println!("> run setup ip");
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf).unwrap();


    loop {

        if let Some(packet) = read_packets.pop_front() {
            println!("sending to server");
            let _ = dns_encapsulate(&socket, String::from(server_addr), packet.data());
        }
        if let Some(packet) = write_packets.pop_front() {
            let _ = dev.write_all(packet.data());
        }
        let _ = dns_encapsulate(&socket, String::from(server_addr), "PING".as_bytes());

        poll.poll(&mut events, Some(BACKGROUND_INTERVAL))?;

        for event in &events {
            match event.token() {
                DEV_TUN => {
                    read_tunnel(&mut dev, &mut read_packets);
                },
                UDP_SOCKET => {
                    read_dns_socket(&socket, &mut write_packets);
                },
                Token(_) => {
                    continue;
                }
            }
        }
        /*
        println!("> run setup ip");
        let mut buf = String::new();
        std::io::stdin().read_line(&mut buf).unwrap();
        */
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

