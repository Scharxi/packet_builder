use serde::{Deserialize, Serialize};

pub mod ethernet;
pub mod ip;
pub mod tcp;
pub mod udp;
pub mod error;
pub mod socket;

pub use error::PacketError;

/// Core trait for all packet builders
pub trait PacketBuilder {
    /// Build the packet and return it as a vector of bytes
    fn build(&self) -> Result<Vec<u8>, PacketError>;
    
    /// Get the total length of the packet
    fn length(&self) -> usize;
    
    /// Validate the packet fields
    fn validate(&self) -> Result<(), PacketError>;
}

/// Trait for packets that require checksum calculation
pub trait Checksumable {
    /// Calculate the checksum for the packet
    fn calculate_checksum(&self) -> u16;
    
    /// Verify the checksum of the packet
    fn verify_checksum(&self) -> bool;
}

/// Common header trait for all packet types
pub trait PacketHeader {
    /// Get the header length in bytes
    fn header_length(&self) -> usize;
    
    /// Get the header as bytes
    fn as_bytes(&self) -> Result<Vec<u8>, PacketError>;
}

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethernet::{EthernetPacket, MacAddress, EtherType};
    use crate::ip::{Ipv4Packet, Ipv4Address, IpProtocol};
    use crate::tcp::{TcpPacket, TcpFlags};
    use crate::udp::UdpPacket;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }

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
}
