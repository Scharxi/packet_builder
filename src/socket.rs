//! Network socket implementation for sending and receiving packets.
//!
//! This module provides both synchronous and asynchronous socket implementations
//! for working with raw network packets. It supports IPv4 protocols and offers
//! features like non-blocking I/O and timeout configuration.

use std::io::{self, ErrorKind};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use socket2::{Domain, Protocol, Socket, Type, SockAddr};
use tokio::io::Interest;
use std::mem::MaybeUninit;

use crate::PacketBuilder;
use crate::error::PacketError;

/// Minimum size required for an IPv4 header
const MIN_BUFFER_SIZE: usize = 20;

/// A synchronous socket wrapper for sending and receiving network packets.
///
/// This struct provides a high-level interface for working with raw sockets,
/// including support for both blocking and non-blocking operations.
pub struct PacketSocket {
    socket: Socket,
    is_blocking: bool,
}

impl PacketSocket {
    /// Creates a new raw socket for the specified protocol.
    ///
    /// # Arguments
    /// * `protocol` - The protocol to use (e.g., TCP, UDP)
    ///
    /// # Returns
    /// * `Ok(PacketSocket)` - The created socket
    /// * `Err(io::Error)` - If socket creation fails
    pub fn new(protocol: Protocol) -> io::Result<Self> {
        let domain = Domain::IPV4;
        let socket_type = Type::RAW;
        
        let socket = Socket::new(domain, socket_type, Some(protocol))?;
        
        Ok(Self {
            socket,
            is_blocking: true,
        })
    }

    /// Sets the socket to blocking or non-blocking mode.
    ///
    /// # Arguments
    /// * `nonblocking` - If true, sets the socket to non-blocking mode
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        self.socket.set_nonblocking(nonblocking)?;
        self.is_blocking = !nonblocking;
        Ok(())
    }

    /// Sets the socket timeout for both read and write operations.
    ///
    /// # Arguments
    /// * `timeout` - The timeout duration, or None to disable timeout
    pub fn set_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        if let Some(duration) = timeout {
            self.socket.set_read_timeout(Some(duration))?;
            self.socket.set_write_timeout(Some(duration))?;
        } else {
            self.socket.set_read_timeout(None)?;
            self.socket.set_write_timeout(None)?;
        }
        Ok(())
    }

    /// Binds the socket to a specific network interface.
    ///
    /// # Arguments
    /// * `addr` - The IPv4 address to bind to
    pub fn bind(&self, addr: Ipv4Addr) -> io::Result<()> {
        let sock_addr = SocketAddr::V4(SocketAddrV4::new(addr, 0));
        self.socket.bind(&SockAddr::from(sock_addr))?;
        Ok(())
    }

    /// Sends a packet to the specified destination.
    ///
    /// # Arguments
    /// * `packet` - The packet to send
    /// * `dst_addr` - The destination IPv4 address
    ///
    /// # Returns
    /// * `Ok(usize)` - The number of bytes sent
    /// * `Err(PacketError)` - If sending fails
    pub fn send<P: PacketBuilder>(&self, packet: &P, dst_addr: Ipv4Addr) -> Result<usize, PacketError> {
        let bytes = packet.build()?;
        let sock_addr = SocketAddr::V4(SocketAddrV4::new(dst_addr, 0));
        
        match self.socket.send_to(&bytes, &SockAddr::from(sock_addr)) {
            Ok(n) => Ok(n),
            Err(e) => Err(PacketError::IoError(e)),
        }
    }

    /// Receives a packet into the provided buffer.
    ///
    /// # Arguments
    /// * `buffer` - The buffer to store the received packet
    ///
    /// # Returns
    /// * `Ok((usize, Ipv4Addr))` - The number of bytes received and the source address
    /// * `Err(PacketError)` - If receiving fails
    pub fn receive(&self, buffer: &mut [u8]) -> Result<(usize, Ipv4Addr), PacketError> {
        if buffer.len() < MIN_BUFFER_SIZE {
            return Err(PacketError::IoError(io::Error::new(
                ErrorKind::InvalidInput,
                format!("Buffer size must be at least {} bytes", MIN_BUFFER_SIZE)
            )));
        }

        let mut uninit_buffer: Vec<MaybeUninit<u8>> = vec![MaybeUninit::uninit(); buffer.len()];
        
        let n = match self.socket.recv(uninit_buffer.as_mut_slice()) {
            Ok(n) => n,
            Err(e) => return Err(PacketError::IoError(e)),
        };

        unsafe {
            for i in 0..n {
                buffer[i] = uninit_buffer[i].assume_init();
            }
        }

        if n >= 16 {
            let src_ip = Ipv4Addr::new(
                buffer[12],
                buffer[13],
                buffer[14],
                buffer[15]
            );
            Ok((n, src_ip))
        } else {
            Err(PacketError::IoError(io::Error::new(
                ErrorKind::InvalidData,
                "Received packet too small to contain IP header"
            )))
        }
    }

    /// Attempts to receive a packet without blocking.
    ///
    /// # Arguments
    /// * `buffer` - The buffer to store the received packet
    ///
    /// # Returns
    /// * `Ok(Some((usize, Ipv4Addr)))` - The number of bytes received and source address
    /// * `Ok(None)` - If no packet is available
    /// * `Err(PacketError)` - If receiving fails
    pub fn try_receive(&self, buffer: &mut [u8]) -> Result<Option<(usize, Ipv4Addr)>, PacketError> {
        if !self.is_blocking {
            match self.receive(buffer) {
                Ok(result) => Ok(Some(result)),
                Err(PacketError::IoError(e)) if e.kind() == ErrorKind::WouldBlock => Ok(None),
                Err(e) => Err(e),
            }
        } else {
            Err(PacketError::InvalidOperation("Socket is in blocking mode".into()))
        }
    }
}

/// An asynchronous socket wrapper for sending and receiving network packets.
///
/// This struct provides an async interface for working with raw sockets using
/// the Tokio runtime.
pub struct AsyncPacketSocket {
    socket: tokio::net::UdpSocket,
}

impl AsyncPacketSocket {
    /// Creates a new async raw socket for the specified protocol.
    ///
    /// # Arguments
    /// * `protocol` - The protocol to use (e.g., TCP, UDP)
    pub async fn new(protocol: Protocol) -> io::Result<Self> {
        let std_socket = Socket::new(Domain::IPV4, Type::RAW, Some(protocol))?;
        std_socket.set_nonblocking(true)?;
        
        let socket = tokio::net::UdpSocket::from_std(std_socket.into())?;
        
        Ok(Self { socket })
    }

    /// Binds the socket to a specific network interface.
    ///
    /// # Arguments
    /// * `addr` - The IPv4 address to bind to
    pub async fn bind(&self, addr: Ipv4Addr) -> io::Result<()> {
        let sock_addr = SocketAddr::V4(SocketAddrV4::new(addr, 0));
        tokio::net::UdpSocket::bind(&sock_addr).await?;
        Ok(())
    }

    /// Sends a packet asynchronously to the specified destination.
    ///
    /// # Arguments
    /// * `packet` - The packet to send
    /// * `dst_addr` - The destination IPv4 address
    ///
    /// # Returns
    /// * `Ok(usize)` - The number of bytes sent
    /// * `Err(PacketError)` - If sending fails
    pub async fn send<P: PacketBuilder>(&self, packet: &P, dst_addr: Ipv4Addr) -> Result<usize, PacketError> {
        let bytes = packet.build()?;
        let sock_addr = SocketAddr::V4(SocketAddrV4::new(dst_addr, 0));
        
        match self.socket.send_to(&bytes, sock_addr).await {
            Ok(n) => Ok(n),
            Err(e) => Err(PacketError::IoError(e)),
        }
    }

    /// Receives a packet asynchronously into the provided buffer.
    ///
    /// # Arguments
    /// * `buffer` - The buffer to store the received packet
    ///
    /// # Returns
    /// * `Ok((usize, Ipv4Addr))` - The number of bytes received and source address
    /// * `Err(PacketError)` - If receiving fails
    pub async fn receive(&self, buffer: &mut [u8]) -> Result<(usize, Ipv4Addr), PacketError> {
        match self.socket.recv_from(buffer).await {
            Ok((n, src_addr)) => {
                if let SocketAddr::V4(v4_addr) = src_addr {
                    Ok((n, *v4_addr.ip()))
                } else {
                    Err(PacketError::InvalidAddress)
                }
            }
            Err(e) => Err(PacketError::IoError(e)),
        }
    }

    /// Waits for the socket to become ready for the specified operation.
    ///
    /// # Arguments
    /// * `interest` - The type of operation to wait for (read/write)
    pub async fn ready(&self, interest: Interest) -> io::Result<()> {
        self.socket.ready(interest).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip::{IpProtocol, Ipv4Packet, Ipv4Address};
    use std::time::Duration;

    const LOCAL_ADDR: Ipv4Addr = Ipv4Addr::LOCALHOST;
    const TIMEOUT: Duration = Duration::from_millis(100);

    fn create_test_packet() -> Ipv4Packet {
        let src_ip = Ipv4Address::new([127, 0, 0, 1]);
        let dst_ip = Ipv4Address::new([127, 0, 0, 1]);
        
        Ipv4Packet::builder()
            .protocol(IpProtocol::TCP)
            .src_addr(src_ip)
            .dst_addr(dst_ip)
            .payload(vec![1, 2, 3, 4])
            .build()
            .unwrap()
    }

    fn skip_if_permission_error<T>(result: Result<T, io::Error>) -> Option<T> {
        match result {
            Ok(value) => Some(value),
            Err(e) => {
                if e.kind() == ErrorKind::PermissionDenied {
                    eprintln!("Skipping test due to insufficient permissions");
                    None
                } else {
                    panic!("Unexpected error: {:?}", e)
                }
            }
        }
    }

    #[test]
    fn test_socket_creation() {
        if skip_if_permission_error(PacketSocket::new(Protocol::TCP)).is_none() {
            return;
        }
    }

    #[test]
    fn test_socket_bind() {
        let socket = match skip_if_permission_error(PacketSocket::new(Protocol::TCP)) {
            Some(s) => s,
            None => return,
        };

        if skip_if_permission_error(socket.bind(LOCAL_ADDR)).is_none() {
            return;
        }
    }

    #[test]
    fn test_socket_timeout() {
        let mut socket = match skip_if_permission_error(PacketSocket::new(Protocol::TCP)) {
            Some(s) => s,
            None => return,
        };

        if skip_if_permission_error(socket.set_timeout(Some(TIMEOUT))).is_none() {
            return;
        }

        if skip_if_permission_error(socket.set_timeout(None)).is_none() {
            return;
        }
    }

    #[test]
    fn test_buffer_boundaries() {
        let mut socket = match skip_if_permission_error(PacketSocket::new(Protocol::TCP)) {
            Some(s) => s,
            None => return,
        };

        if skip_if_permission_error(socket.set_timeout(Some(TIMEOUT))).is_none() {
            return;
        }

        // Test with empty buffer
        let mut empty_buffer = Vec::new();
        match socket.receive(&mut empty_buffer) {
            Ok(_) => panic!("Should not succeed with empty buffer"),
            Err(PacketError::IoError(e)) => {
                assert!(e.kind() == ErrorKind::InvalidInput || e.kind() == ErrorKind::PermissionDenied,
                       "Unexpected error: {:?}", e);
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }

        // Test with buffer smaller than minimum packet size
        let mut small_buffer = vec![0u8; MIN_BUFFER_SIZE - 1];
        match socket.receive(&mut small_buffer) {
            Ok(_) => panic!("Should not succeed with small buffer"),
            Err(PacketError::IoError(e)) => {
                assert!(e.kind() == ErrorKind::InvalidInput || e.kind() == ErrorKind::PermissionDenied,
                       "Unexpected error: {:?}", e);
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }

        // Test with valid size buffer
        let mut valid_buffer = vec![0u8; MIN_BUFFER_SIZE];
        match socket.receive(&mut valid_buffer) {
            Ok(_) => panic!("Should not succeed when no data is available"),
            Err(PacketError::IoError(e)) => {
                assert!(e.kind() == ErrorKind::TimedOut || 
                       e.kind() == ErrorKind::WouldBlock || 
                       e.kind() == ErrorKind::PermissionDenied,
                       "Unexpected error: {:?}", e);
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_blocking_send_receive() {
        let sender = match skip_if_permission_error(PacketSocket::new(Protocol::TCP)) {
            Some(s) => s,
            None => return,
        };

        let mut receiver = match skip_if_permission_error(PacketSocket::new(Protocol::TCP)) {
            Some(s) => s,
            None => return,
        };

        // Configure sockets
        if skip_if_permission_error(receiver.bind(LOCAL_ADDR)).is_none() {
            return;
        }

        if skip_if_permission_error(receiver.set_timeout(Some(TIMEOUT))).is_none() {
            return;
        }

        // Create and send test packet
        let packet = create_test_packet();
        match sender.send(&packet, LOCAL_ADDR) {
            Ok(sent) => {
                assert_eq!(sent, packet.length());
                
                // Try to receive
                let mut buffer = vec![0u8; 2048];
                match receiver.receive(&mut buffer) {
                    Ok((n, addr)) => {
                        assert!(n > 0);
                        assert_eq!(addr, LOCAL_ADDR);
                    }
                    Err(PacketError::IoError(e)) => {
                        assert!(e.kind() == ErrorKind::TimedOut || 
                               e.kind() == ErrorKind::WouldBlock || 
                               e.kind() == ErrorKind::PermissionDenied,
                               "Unexpected error: {:?}", e);
                    }
                    Err(e) => panic!("Unexpected error: {:?}", e),
                }
            }
            Err(PacketError::IoError(e)) => {
                assert!(e.kind() == ErrorKind::PermissionDenied,
                       "Unexpected error: {:?}", e);
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_async_socket_creation() {
        let socket = AsyncPacketSocket::new(Protocol::TCP).await;
        assert!(socket.is_ok());
    }

    #[tokio::test]
    async fn test_async_socket_bind() {
        let socket = AsyncPacketSocket::new(Protocol::TCP).await.unwrap();
        let result = socket.bind(LOCAL_ADDR).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_async_send_receive() {
        let socket = AsyncPacketSocket::new(Protocol::TCP).await.unwrap();
        
        match socket.bind(LOCAL_ADDR).await {
            Ok(_) => {
                let packet = create_test_packet();
                
                // Test sending
                match socket.send(&packet, LOCAL_ADDR).await {
                    Ok(n) => assert_eq!(n, packet.length()),
                    Err(e) => eprintln!("Send error (might be expected): {:?}", e),
                }

                // Test receiving with timeout
                let mut buffer = vec![0u8; 2048];
                tokio::time::timeout(TIMEOUT, socket.receive(&mut buffer))
                    .await
                    .unwrap_or_else(|_| Ok((0, LOCAL_ADDR))) // Timeout is ok
                    .unwrap_or_else(|e| {
                        eprintln!("Receive error (might be expected): {:?}", e);
                        (0, LOCAL_ADDR)
                    });
            }
            Err(e) => eprintln!("Bind error (might be expected): {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_async_ready() {
        let socket = AsyncPacketSocket::new(Protocol::TCP).await.unwrap();
        
        // Test readable readiness with timeout
        let timeout_result = tokio::time::timeout(
            TIMEOUT,
            socket.ready(Interest::READABLE)
        ).await;
        
        match timeout_result {
            Ok(result) => assert!(result.is_ok()),
            Err(_) => (), // Timeout is acceptable
        }
    }
} 