## packet sniffing for windows

[![API](https://docs.rs/pack2/badge.svg)](https://docs.rs/pack2)

This crate provides one function `recv_all_socket` which creates a `socket2::Socket`
that receives all incoming and outgoing ipv4 packets.

## Example

```rust
use pack2::recv_all_socket;
use std::mem::MaybeUninit;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket = recv_all_socket()?;

    let mut buf = vec![0u8; 65535];
    loop {
        // This is safe as described in the documentation of socket2::Socket::recv_from
        let buf_maybe = unsafe { &mut *(&mut buf[..] as *mut [u8] as *mut [MaybeUninit<u8>]) };
        let (read, addr) = socket.recv_from(buf_maybe)?;
        println!("received {} bytes from {:?}", read, addr);
    }
}
```
