//! Provides a function [recv_all_socket] that creates a Socket that receives all incoming and outgoing ipv4 packets.
//!
//! ## Example
//! ```
//! use pack2::recv_all_socket;
//! use std::mem::MaybeUninit;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let socket = recv_all_socket()?;
//!
//! let mut buf = vec![0u8; 65535];
//! loop {
//!     // This is safe as described in the documentation of Socket::recv_from
//!     let buf_maybe = unsafe { &mut *(&mut buf[..] as *mut [u8] as *mut [MaybeUninit<u8>]) };
//!     let (read, addr) = socket.recv_from(buf_maybe)?;
//!     println!("received {} bytes from {:?}", read, addr);
//! }
//! # }
//! ```
//!
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    net::{Ipv4Addr, SocketAddr},
    os::windows::prelude::AsRawSocket,
    ptr,
};
use windows::{
    core::{PCSTR, PSTR},
    Win32::Networking::WinSock::{
        gethostbyname, gethostname, WSAData, WSAGetLastError, WSAIoctl, WSAStartup, IN_ADDR,
        RCVALL_ON, SIO_RCVALL, SOCKET, SOCKET_ERROR, WSA_ERROR,
    },
};

pub fn recv_all_socket() -> Result<Socket, SocketError> {
    type E = SocketError;

    const WINSOCK_VERSION: u16 = 2 << 8 | 2;
    let mut wsa_data = WSAData::default();
    unsafe { WSAStartup(WINSOCK_VERSION, &mut wsa_data as *mut _) };

    let mut hostname = [0u8; 100];
    if unsafe { gethostname(PSTR(hostname.as_mut_ptr()), hostname.len() as i32) } == SOCKET_ERROR {
        return Err(E::win_sock("failed to get hostname"));
    }

    let local = unsafe { gethostbyname(PCSTR(hostname.as_mut_ptr())) };
    if local.is_null() {
        return Err(E::win_sock("failed to get local address"));
    }

    let h_addr = unsafe { *((*local).h_addr_list) };
    if h_addr.is_null() {
        return Err(E::win_sock("failed to find host"));
    }
    let ip_addr = unsafe { (*(h_addr as *const IN_ADDR)).S_un.S_addr.to_be() };

    let addr = SocketAddr::new(Ipv4Addr::from(ip_addr).into(), 0);

    let socket = Socket::new(Domain::IPV4, Type::RAW, None)?;

    // This is only here to have windows request creation of inbound firewall rule for udp and tcp
    // for this application.
    {
        let socket0 = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP))?;
        socket0.bind(&addr.into())?;
    }

    socket.bind(&addr.into())?;

    let win_sock = SOCKET(socket.as_raw_socket() as usize);

    let mut in_ = 0u32;
    let res = unsafe {
        WSAIoctl(
            win_sock,
            SIO_RCVALL,
            &RCVALL_ON.0 as *const _ as *const _,
            4,
            ptr::null_mut(),
            0,
            &mut in_ as *mut _ as *mut _,
            ptr::null_mut(),
            None,
        )
    };
    if res == SOCKET_ERROR {
        return Err(E::win_sock("failed to set socket option SIO_RCVALL"));
    }

    Ok(socket)
}

#[derive(thiserror::Error, Debug)]
pub enum SocketError {
    #[error("Io Error {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}. {1:?}")]
    WinSock(&'static str, WSA_ERROR),
}

impl SocketError {
    fn win_sock(msg: &'static str) -> Self {
        Self::WinSock(msg, unsafe { WSAGetLastError() })
    }
}

// fn get_local_ipv6() {
//     let mut buf_len = 15000u32;
//     let mut addrs_bytes = Vec::with_capacity(buf_len as usize);

//     // Reallocating a maximum of 10 times
//     for _ in 0..10 {
//         match unsafe {
//             GetAdaptersAddresses(
//                 AF_INET6,
//                 GET_ADAPTERS_ADDRESSES_FLAGS(0),
//                 ptr::null_mut(),
//                 addrs_bytes.as_mut_ptr() as *mut _,
//                 &mut buf_len,
//             )
//         } {
//             // Success
//             0 => break,
//             // Overflow
//             111 => addrs_bytes.reserve(buf_len as usize),
//             e => {
//                 panic!("failed to get adapter addresses: {:?}", e);
//             }
//         }
//     }
//     unsafe {
//         addrs_bytes.set_len(buf_len as usize);
//     }

//     let mut addr = unsafe { &*(addrs_bytes.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH) };

//     loop {
//         println!("{:?}", unsafe { u16s_to_string(addr.FriendlyName.0) });
//         println!("{:?}", unsafe { addr.Dhcpv6Server.iSockaddrLength });
//         if addr.Next == ptr::null_mut() {
//             break;
//         }
//         addr = unsafe { &*(addr.Next as *const IP_ADAPTER_ADDRESSES_LH) };
//     }
// }
