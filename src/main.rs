


use std::net::UdpSocket;

fn main() -> std::io::Result<()> {
    // Bind the UDP socket to localhost:8080
    let socket = UdpSocket::bind("127.0.0.1:8080")?;
    println!("UDP server listening on 127.0.0.1:8080");

    let mut buf = [0u8; 1024];

    loop {
        // Receive a message from any client
        let (amt, src) = socket.recv_from(&mut buf)?;

        // Convert the bytes to a string and print it
        let msg = String::from_utf8_lossy(&buf[..amt]);
        println!("Received from {}: {}", src, msg);

        // (Optional) Send a response back to the client
        // socket.send_to(b"Message received", &src)?;
    }
}

