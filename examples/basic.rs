use etherparse::{SlicedPacket, TcpOptionElement, TcpOptionReadError};
use pack2::recv_all_socket;
use std::mem::MaybeUninit;

// IMPORTANT:
// This example needs to be run as administrator and to receive incoming packets
// you need to allow the firewall rule which pops up upon starting the example.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket = recv_all_socket()?;

    let mut buf = vec![0u8; 65535];
    loop {
        // This is safe as described in the documentation of socket2::Socket::recv_from
        let buf_maybe = unsafe { &mut *(&mut buf[..] as *mut [u8] as *mut [MaybeUninit<u8>]) };
        let (read, _) = socket.recv_from(buf_maybe)?;

        let packet = match SlicedPacket::from_ip(&buf[..read]) {
            Ok(p) => p,
            _ => {
                println!("received but unable to parse");
                continue;
            }
        };
        print_packet(&packet);
    }
}

fn print_packet(packet: &SlicedPacket) {
    use etherparse::{InternetSlice::*, LinkSlice::*, TransportSlice::*, VlanSlice::*};

    match &packet.link {
        Some(Ethernet2(value)) => println!(
            "  Ethernet2 {:?} => {:?}",
            value.source(),
            value.destination()
        ),
        None => {}
    }

    match &packet.vlan {
        Some(SingleVlan(value)) => println!("  SingleVlan {:?}", value.vlan_identifier()),
        Some(DoubleVlan(value)) => println!(
            "  DoubleVlan {:?}, {:?}",
            value.outer().vlan_identifier(),
            value.inner().vlan_identifier()
        ),
        None => {}
    }

    match &packet.ip {
        Some(Ipv4(value, extensions)) => {
            println!(
                "  Ipv4 {:?} => {:?}",
                value.source_addr(),
                value.destination_addr()
            );
            if false == extensions.is_empty() {
                println!("    {:?}", extensions);
            }
        }
        Some(Ipv6(value, extensions)) => {
            println!(
                "  Ipv6 {:?} => {:?}",
                value.source_addr(),
                value.destination_addr()
            );
            if false == extensions.is_empty() {
                println!("    {:?}", extensions);
            }
        }
        None => {}
    }

    match &packet.transport {
        Some(Udp(value)) => println!(
            "  UDP {:?} -> {:?}",
            value.source_port(),
            value.destination_port()
        ),
        Some(Tcp(value)) => {
            println!(
                "  TCP {:?} -> {:?}",
                value.source_port(),
                value.destination_port()
            );
            let options: Vec<Result<TcpOptionElement, TcpOptionReadError>> =
                value.options_iterator().collect();
            println!("    {:?}", options);
        }
        Some(Unknown(ip_protocol)) => {
            println!("  Unknwon Protocol (ip protocol number {:?}", ip_protocol)
        }
        None => {}
    }
}
