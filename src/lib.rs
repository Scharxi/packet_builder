//! A Rust library for building and manipulating network packets.
//! 
//! This library provides a flexible and type-safe way to construct various types of network packets,
//! including Ethernet frames, IPv4 packets, TCP segments, and UDP datagrams. It features:
//! 
//! - Builder pattern for packet construction
//! - Checksum calculation and validation
//! - Raw socket support for sending and receiving packets
//! - Async support via Tokio
//! - Serialization support via Serde


pub mod ethernet;
pub mod ip;
pub mod tcp;
pub mod udp;
pub mod icmp;
pub mod arp;
pub mod dhcp;
pub mod error;
pub mod socket;

pub use error::PacketError;

/// Core trait for all packet builders.
/// 
/// This trait defines the common interface that all packet types must implement
/// for building and validating network packets.
pub trait PacketBuilder {
    /// Build the packet and return it as a vector of bytes.
    /// 
    /// # Returns
    /// - `Ok(Vec<u8>)` - The serialized packet as a byte vector
    /// - `Err(PacketError)` - If packet construction fails
    fn build(&self) -> Result<Vec<u8>, PacketError>;
    
    /// Get the total length of the packet in bytes.
    fn length(&self) -> usize;
    
    /// Validate the packet fields and structure.
    /// 
    /// # Returns
    /// - `Ok(())` - If the packet is valid
    /// - `Err(PacketError)` - If validation fails
    fn validate(&self) -> Result<(), PacketError>;
}

/// Trait for packets that require checksum calculation.
/// 
/// This trait is implemented by packet types that include a checksum field
/// for data integrity verification.
pub trait Checksumable {
    /// Calculate the checksum for the packet.
    /// 
    /// # Returns
    /// The calculated checksum value as a 16-bit unsigned integer.
    fn calculate_checksum(&self) -> u16;
    
    /// Verify the checksum of the packet.
    /// 
    /// # Returns
    /// `true` if the checksum is valid, `false` otherwise.
    fn verify_checksum(&self) -> bool;
}

/// Common header trait for all packet types.
/// 
/// This trait defines the interface for accessing and manipulating
/// packet headers across different protocols.
pub trait PacketHeader {
    /// Get the header length in bytes.
    fn header_length(&self) -> usize;
    
    /// Get the header as a byte vector.
    /// 
    /// # Returns
    /// - `Ok(Vec<u8>)` - The serialized header as a byte vector
    /// - `Err(PacketError)` - If serialization fails
    fn as_bytes(&self) -> Result<Vec<u8>, PacketError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethernet::{EthernetPacket, MacAddress, EtherType};
    use crate::ip::{Ipv4Packet, Ipv4Address, IpProtocol};
    use crate::tcp::{TcpPacket, TcpFlags};
    use crate::udp::UdpPacket;
    use crate::icmp::{IcmpPacket, IcmpType};
    use crate::arp::{ArpPacket, Operation as ArpOperation};
    use crate::dhcp::DhcpPacket;

    #[test]
    fn test_ethernet_packet() {
        let src_mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let dst_mac = MacAddress::new([0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]);
        
        let packet = EthernetPacket::builder()
            .src_mac(src_mac)
            .dst_mac(dst_mac)
            .ether_type(EtherType::IPv4)
            .payload(vec![1, 2, 3, 4])
            .build()
            .unwrap();

        assert!(packet.validate().is_ok());
        let bytes = packet.build().unwrap();
        assert_eq!(bytes.len(), 60); // 14 (header) + 46 (minimum payload size with padding)
    }

    #[test]
    fn test_ipv4_packet() {
        let src_ip = Ipv4Address::new([192, 168, 1, 1]);
        let dst_ip = Ipv4Address::new([192, 168, 1, 2]);
        
        let packet = Ipv4Packet::builder()
            .protocol(IpProtocol::TCP)
            .src_addr(src_ip)
            .dst_addr(dst_ip)
            .payload(vec![1, 2, 3, 4])
            .build()
            .unwrap();

        assert!(packet.validate().is_ok());
        let bytes = packet.build().unwrap();
        assert_eq!(bytes.len(), 24); // 20 (header) + 4 (payload)
    }

    #[test]
    fn test_tcp_packet() {
        let mut flags = TcpFlags::new();
        flags.syn = true;
        
        let packet = TcpPacket::builder()
            .src_port(12345)
            .dst_port(80)
            .sequence(1000)
            .flags(flags)
            .payload(vec![1, 2, 3, 4])
            .build()
            .unwrap();

        assert!(packet.validate().is_ok());
        let bytes = packet.build().unwrap();
        assert_eq!(bytes.len(), 24); // 20 (header) + 4 (payload)
    }

    #[test]
    fn test_udp_packet() {
        let packet = UdpPacket::builder()
            .src_port(12345)
            .dst_port(53)
            .payload(vec![1, 2, 3, 4])
            .build()
            .unwrap();

        assert!(packet.validate().is_ok());
        let bytes = packet.build().unwrap();
        assert_eq!(bytes.len(), 12); // 8 (header) + 4 (payload)
    }

    #[test]
    fn test_icmp_packet() {
        let packet = IcmpPacket::echo_request(1, 1, b"Hello, World!".to_vec()).unwrap();

        assert!(packet.validate().is_ok());
        assert_eq!(packet.header.message_type as u8, IcmpType::EchoRequest as u8);
    }

    #[test]
    fn test_arp_packet() {
        let src_mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let src_ip = Ipv4Address::new([192, 168, 1, 1]);
        let target_ip = Ipv4Address::new([192, 168, 1, 2]);

        let packet = ArpPacket::request(src_mac, src_ip, target_ip).unwrap();

        assert!(packet.validate().is_ok());
        assert_eq!(packet.header.operation as u16, ArpOperation::Request as u16);
    }

    #[test]
    fn test_dhcp_packet() {
        let chaddr = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let xid = 0x12345678;

        let packet = DhcpPacket::discover(xid, chaddr).unwrap();

        assert!(packet.validate().is_ok());
        assert_eq!(packet.header.op, 1); // BOOTREQUEST
    }
}
