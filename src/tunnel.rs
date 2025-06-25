
use std::os::unix::io::FromRawFd;
use std::fs::File;
use nix::libc;
use std::io::prelude::*;
use std::io::stdin;

fn open_tunnel(dev: String) -> File {
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let fd: i32;

    unsafe {fd = libc::open("/dev/net/tun\x00".as_ptr() as *const i8, libc::O_RDWR);}
    if fd < 0 {
        panic!("failed to open /dev/net/tun, fd = {fd}");
    }

    println!("opened /dev/net/tun: fd = {}", fd);

    ifr.ifr_ifru.ifru_flags = libc::IFF_TUN as i16;
    if dev.len() > 0 {
        let mut tmp: [i8; 16] = [0; 16];
        for (index, value) in dev.as_bytes().iter().enumerate() {
            tmp[index] = *value as i8;
        }
        ifr.ifr_name = tmp;
    }

    unsafe {
        if libc::ioctl(fd, libc::TUNSETIFF, &mut ifr) < 0 {
            panic!("ioctl fails");
        }

        return File::from_raw_fd(fd);
    };


}

fn hexdump(data: &[u8]) {
    const BYTES_PER_LINE: usize = 16;

    for (i, chunk) in data.chunks(BYTES_PER_LINE).enumerate() {
        // Print offset
        print!("{:08x}: ", i * BYTES_PER_LINE);

        // Print hex bytes
        for byte in chunk {
            print!("{:02x} ", byte);
        }

        // Pad spaces if last line is short
        for _ in 0..(BYTES_PER_LINE - chunk.len()) {
            print!("   ");
        }

        // Print ASCII representation
        print!("|");
        for &byte in chunk {
            let ch = if byte.is_ascii_graphic() || byte == b' ' {
                byte as char
            } else {
                '.'
            };
            print!("{}", ch);
        }
        println!("|");
    }
}

fn main() {
    let mut dev: File = open_tunnel(String::from("tun38"));

    let mut content: [u8; 1024] = [0; 1024];

    let mut bytes_readed: usize;
    loop {
        bytes_readed = dev.read(&mut content).unwrap();
        println!("bytes_readed = {}", bytes_readed);
        hexdump(&content[0..bytes_readed]);
        if bytes_readed != 56 {
            break;
        }
    }


    // write loop
    loop {
        print!(">");
        let mut tmp = String::new();
        stdin().read_line(&mut tmp).unwrap();

        dev.write_all(& content[0..bytes_readed]).unwrap();
    }

}
