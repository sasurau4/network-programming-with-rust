use std::env;
use std::net::IpAddr;

use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

#[macro_use]
extern crate log;

fn main() {
    env::set_var("RUST_LOG", "debug");
    env_logger::init();
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        error!("Please specify target interface name");
        std::process::exit(1);
    }
    let interface_name = &args[1];
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == *interface_name)
        .expect("Failed to get interface");

    let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to create datalink channel {}", e),
    };

    loop {
        match rx.next() {
            Ok(frame) => {
                let frame = EthernetPacket::new(frame).unwrap();
                match frame.get_ethertype() {
                    EtherTypes::Ipv4 => {
                        ipv4_handler(&frame);
                    }
                    EtherTypes::Ipv6 => {
                        ipv6_handler(&frame);
                    }
                    _ => {
                        info!("Not an IPv4 or IPv6 packet");
                    }
                }
            }

            Err(e) => {
                error!("Failed to read: {}", e);
            }
        }
    }
}

fn ipv4_handler(ethernet: &EthernetPacket) {
    if let Some(packet) = Ipv4Packet::new(ethernet.payload()) {
        match packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                tcp_handler(
                    IpAddr::V4(packet.get_source()),
                    IpAddr::V4(packet.get_destination()),
                    &packet.payload(),
                );
            }
            IpNextHeaderProtocols::Udp => {
                udp_handler(
                    IpAddr::V4(packet.get_source()),
                    IpAddr::V4(packet.get_destination()),
                    &packet.payload(),
                );
            }
            _ => {
                info!("Not a TCP or UDP packet");
            }
        }
    }
}

fn ipv6_handler(ethernet: &EthernetPacket) {
    if let Some(packet) = Ipv6Packet::new(ethernet.payload()) {
        match packet.get_next_header() {
            IpNextHeaderProtocols::Tcp => {
                tcp_handler(
                    IpAddr::V6(packet.get_source()),
                    IpAddr::V6(packet.get_destination()),
                    &packet.payload(),
                );
            }
            IpNextHeaderProtocols::Udp => {
                udp_handler(
                    IpAddr::V6(packet.get_source()),
                    IpAddr::V6(packet.get_destination()),
                    &packet.payload(),
                );
            }
            _ => {
                info!("Not a TCP or UDP packet");
            }
        }
    }
}

fn tcp_handler(source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        println!(
            "Captured a {} packet from {}|{} to {}|{}\n",
            "TCP",
            source,
            tcp.get_source(),
            destination,
            tcp.get_destination(),
        );
        print_packet_info(tcp);
    }
}

fn udp_handler(source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let udp = UdpPacket::new(packet);
    if let Some(udp) = udp {
        println!(
            "Captured a {} packet from {}|{} to {}|{}\n",
            "UDP",
            source,
            udp.get_source(),
            destination,
            udp.get_destination(),
        );
        print_packet_info(udp);
    }
}

fn print_packet_info(packet: impl Packet) {
    const WIDTH: usize = 64;
    let payload = packet.payload();
    let len = payload.len();

    for i in 0..len {
        print!("{:<02X}", payload[i]);

        if i % WIDTH == WIDTH - 1 || i == len - 1 {
            for _j in 0..WIDTH - 1 - (i % (WIDTH)) {
                print!(" ");
            }

            print!("|");
            for j in i - i % WIDTH..=i {
                if payload[j].is_ascii_alphabetic() {
                    print!("{}", payload[j] as char);
                } else {
                    print!(".");
                }
            }
            println!();
        }
    }
    println!("{}", "=".repeat(WIDTH * 3));
    println!();
}
