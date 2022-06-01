//! Provides one function [recv_all_socket] which creates a [Socket](socket2::Socket) that receives all incoming and outgoing ipv4 packets.
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
//!     // This is safe as described in the documentation of socket2::Socket::recv_from
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
use windows::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR},
    NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    },
    Networking::WinSock::AF_INET,
};
use windows::{
    core::{PCSTR, PCWSTR, PSTR},
    Win32::{
        Foundation::HWND,
        Networking::WinSock::{
            gethostbyname, gethostname, WSAData, WSAGetLastError, WSAIoctl, WSAStartup, IN_ADDR,
            RCVALL_IPLEVEL, RCVALL_ON, SIO_RCVALL, SOCKET, SOCKET_ERROR, WSA_ERROR,
        },
        UI::WindowsAndMessaging::{FindWindowExW, FindWindowW, GetWindowThreadProcessId},
    },
};

pub trait SocketExt {
    fn new_recv_all(
        local_ip: Option<Ipv4Addr>,
        remote_ip: Option<Ipv4Addr>,
    ) -> Result<Socket, SocketError>;
}

impl SocketExt for Socket {
    /// Creates a new [Socket](socket2::Socket) that receives all incoming and outgoing ipv4 packets.
    /// If `local_ip` is `None` a local ip will be automatically chosen (which is fine for most purposes).
    /// If `remote_ip` is `Some` the socket will only receive the packets from the given remote ip address,
    /// otherwise packets from all ip addresses are received. Note that this disables receiving any outgoing packets.
    fn new_recv_all(
        local_ip: Option<Ipv4Addr>,
        remote_ip: Option<Ipv4Addr>,
    ) -> Result<Socket, SocketError> {
        type E = SocketError;

        // Starting WSA with version 2.2
        const WINSOCK_VERSION: u16 = 2 << 8 | 2;
        let mut wsa_data = WSAData::default();
        unsafe { WSAStartup(WINSOCK_VERSION, &mut wsa_data as *mut _) };

        let local_ip = match local_ip {
            Some(ip) => ip,
            None => {
                let mut hostname = [0u8; 100];
                if unsafe { gethostname(PSTR(hostname.as_mut_ptr()), hostname.len() as i32) }
                    == SOCKET_ERROR
                {
                    return Err(E::win_sock("failed to get hostname"));
                }

                let local = unsafe { gethostbyname(PCSTR(hostname.as_mut_ptr())) };
                if local.is_null() {
                    return Err(E::win_sock("failed to get local address"));
                }

                // Todo: We are just selecting the first host address we find. This should probably
                // be changed in the future.
                let h_addr = unsafe { *((*local).h_addr_list) };
                if h_addr.is_null() {
                    return Err(E::win_sock("failed to find host"));
                }
                let ip_addr = unsafe { (*(h_addr as *const IN_ADDR)).S_un.S_addr.to_be() };
                Ipv4Addr::from(ip_addr).into()
            }
        };

        let addr = SocketAddr::new(local_ip.into(), 0);

        let socket = Socket::new(Domain::IPV4, Type::RAW, None)?;

        // This is only here to have windows request creation of inbound firewall rule for udp and tcp
        // for this application.
        {
            let socket0 = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP))?;
            socket0.bind(&addr.into())?;
        }

        socket.bind(&addr.into())?;

        let win_sock = SOCKET(socket.as_raw_socket() as usize);

        let option = if remote_ip.is_some() {
            RCVALL_IPLEVEL
        } else {
            RCVALL_ON
        };
        let mut in_ = 0u32;
        let res = unsafe {
            WSAIoctl(
                win_sock,
                SIO_RCVALL,
                &option.0 as *const _ as *const _,
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

        if let Some(remote_addr) = remote_ip {
            socket.connect(&SocketAddr::new(remote_addr.into(), 0).into())?;
        }

        Ok(socket)
    }
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

#[test]
fn test_get_window_pid() {
    let now = std::time::Instant::now();

    let pids = get_window_pids("FINAL FANTASY XIV");
    println!("{:?}", pids.collect::<Vec<_>>());
}

pub type Pid = u32;

pub fn get_window_pids<S: AsRef<str>>(window_name: S) -> impl Iterator<Item = Pid> {
    let window_name = window_name
        .as_ref()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<u16>>();

    let mut pid = 0u32;
    let mut hwnd = None;

    std::iter::from_fn(move || {
        let window_name = PCWSTR(window_name.as_ptr());

        // hwnd is None the first time this closure is called afterwards it's Some
        let hwnd_ = match hwnd {
            None => unsafe { FindWindowExW(None, None, None, window_name) },
            Some(hwnd) => unsafe { FindWindowExW(None, hwnd, None, window_name) },
        };
        if hwnd_.0 == 0 {
            return None;
        } else {
            hwnd = Some(hwnd_);
        }

        unsafe { GetWindowThreadProcessId(hwnd, &mut pid as *mut _) };
        if pid == 0 {
            return None;
        }

        Some(pid)
    })
}

#[derive(Debug, Clone)]
struct TcpTable(Vec<TcpConnection>);

#[derive(Debug, Clone)]
pub struct TcpConnection {
    // Todo: Maybe add this state
    // state: TcpState,
    pub process: Pid,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
}

impl TcpTable {
    pub fn new() -> Result<Self, SocketError> {
        let mut connections = Vec::new();

        let mut tcp_table_bytes = Vec::new();
        let mut size = 0;
        // resizing a max of 10 times
        for _ in 0..10 {
            let res = unsafe {
                GetExtendedTcpTable(
                    tcp_table_bytes.as_mut_ptr() as *mut _,
                    &mut size,
                    false,
                    AF_INET.0,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            };

            if res == ERROR_INSUFFICIENT_BUFFER.0 {
                tcp_table_bytes.resize(size as usize, 0);
            } else if res == NO_ERROR.0 {
                break;
            } else {
                return Err(SocketError::win_sock("failed to get tcp table"));
            }
        }

        let tcp_table = unsafe { &*(tcp_table_bytes.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
        for i in 0..tcp_table.dwNumEntries {
            let tcp_row = unsafe {
                &*((tcp_table.table.as_ptr() as *const MIB_TCPROW_OWNER_PID).add(i as usize))
            };
            let local_addr = SocketAddr::new(
                Ipv4Addr::from(tcp_row.dwLocalAddr.to_be()).into(),
                (tcp_row.dwLocalPort as u16).to_be(),
            );
            let remote_addr = SocketAddr::new(
                Ipv4Addr::from(tcp_row.dwRemoteAddr.to_be()).into(),
                (tcp_row.dwRemotePort as u16).to_be(),
            );
            connections.push(TcpConnection {
                process: tcp_row.dwOwningPid,
                local_addr,
                remote_addr,
            });
        }
        Ok(TcpTable(connections))
    }

    pub fn connections_for_pid(&self, pid: Pid) -> impl Iterator<Item = &TcpConnection> {
        self.0.iter().filter(move |conn| conn.process == pid)
    }
}

#[test]
fn test_get_tcp_table() {
    let tcp_table = TcpTable::new().unwrap();
    println!("{:?}", tcp_table);
}

#[test]
fn test_pid_with_tcp_table() {
    let pid = get_window_pids("FINAL FANTASY XIV").next().unwrap();
    let tcp_table = TcpTable::new().unwrap();
    for connection in tcp_table.connections_for_pid(pid) {
        println!("{:?}", connection);
    }
}
