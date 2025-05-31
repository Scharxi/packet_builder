//! ARP (Address Resolution Protocol) implementation.
//!
//! This module provides types and functionality for working with ARP packets,
//! including hardware and protocol address resolution.

use serde::{Deserialize, Serialize};
use crate::{PacketBuilder, PacketError, PacketHeader};
use crate::ethernet::MacAddress;
use crate::ip::Ipv4Address;

/// ARP hardware types.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[repr(u16)]
pub enum HardwareType {
    /// Ethernet (10Mb)
    Ethernet = 1,
    /// Experimental Ethernet
    ExperimentalEthernet = 2,
    /// AX.25 Level 2
    AX25 = 3,
    /// ProNET Token Ring
    ProNetTokenRing = 4,
    /// Chaos
    Chaos = 5,
    /// IEEE 802 Networks
    IEEE802 = 6,
    /// ARCNET
    ARCNET = 7,
}

/// ARP operation codes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u16)]
pub enum Operation {
    /// ARP Request
    Request = 1,
    /// ARP Reply
    Reply = 2,
    /// RARP Request
    ReverseRequest = 3,
    /// RARP Reply
    ReverseReply = 4,
}

/// ARP header structure.
///
/// Contains the fields defined in the ARP packet format:
/// - Hardware Type: Type of hardware address
/// - Protocol Type: Type of protocol address
/// - Hardware Address Length: Length of hardware addresses
/// - Protocol Address Length: Length of protocol addresses
/// - Operation: Type of ARP operation
/// - Sender Hardware Address: Source hardware address
/// - Sender Protocol Address: Source protocol address
/// - Target Hardware Address: Destination hardware address
/// - Target Protocol Address: Destination protocol address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpHeader {
    pub hardware_type: HardwareType,
    pub protocol_type: u16,
    pub hardware_addr_len: u8,
    pub protocol_addr_len: u8,
    pub operation: Operation,
    pub sender_hardware_addr: MacAddress,
    pub sender_protocol_addr: Ipv4Address,
    pub target_hardware_addr: MacAddress,
    pub target_protocol_addr: Ipv4Address,
}

impl ArpHeader {
    /// Creates a new ARP header with the specified parameters.
    fn new(
        operation: Operation,
        sender_hardware_addr: MacAddress,
        sender_protocol_addr: Ipv4Address,
        target_hardware_addr: MacAddress,
        target_protocol_addr: Ipv4Address,
    ) -> Self {
        Self {
            hardware_type: HardwareType::Ethernet,
            protocol_type: 0x0800, // IPv4
            hardware_addr_len: 6,   // MAC address length
            protocol_addr_len: 4,   // IPv4 address length
            operation,
            sender_hardware_addr,
            sender_protocol_addr,
            target_hardware_addr,
            target_protocol_addr,
        }
    }
}

/// Complete ARP packet structure.
///
/// Contains the ARP header. Note that ARP packets do not have a payload section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpPacket {
    pub header: ArpHeader,
}

/// Builder for constructing ARP packets.
///
/// Provides a fluent interface for creating ARP packets with proper
/// validation and error handling.
#[derive(Debug, Default)]
pub struct ArpBuilder {
    operation: Option<Operation>,
    sender_hardware_addr: Option<MacAddress>,
    sender_protocol_addr: Option<Ipv4Address>,
    target_hardware_addr: Option<MacAddress>,
    target_protocol_addr: Option<Ipv4Address>,
}

impl ArpBuilder {
    /// Creates a new ARP packet builder with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the ARP operation.
    pub fn operation(mut self, operation: Operation) -> Self {
        self.operation = Some(operation);
        self
    }

    /// Sets the sender hardware address.
    pub fn sender_hardware_addr(mut self, addr: MacAddress) -> Self {
        self.sender_hardware_addr = Some(addr);
        self
    }

    /// Sets the sender protocol address.
    pub fn sender_protocol_addr(mut self, addr: Ipv4Address) -> Self {
        self.sender_protocol_addr = Some(addr);
        self
    }

    /// Sets the target hardware address.
    pub fn target_hardware_addr(mut self, addr: MacAddress) -> Self {
        self.target_hardware_addr = Some(addr);
        self
    }

    /// Sets the target protocol address.
    pub fn target_protocol_addr(mut self, addr: Ipv4Address) -> Self {
        self.target_protocol_addr = Some(addr);
        self
    }

    /// Builds the ARP packet.
    ///
    /// # Returns
    /// - `Ok(ArpPacket)` - The constructed ARP packet
    /// - `Err(PacketError)` - If any required fields are missing
    pub fn build(self) -> Result<ArpPacket, PacketError> {
        let operation = self.operation.ok_or_else(|| 
            PacketError::InvalidFieldValue("ARP operation not set".to_string()))?;
        let sender_hardware_addr = self.sender_hardware_addr.ok_or_else(|| 
            PacketError::InvalidFieldValue("Sender hardware address not set".to_string()))?;
        let sender_protocol_addr = self.sender_protocol_addr.ok_or_else(|| 
            PacketError::InvalidFieldValue("Sender protocol address not set".to_string()))?;
        let target_hardware_addr = self.target_hardware_addr.ok_or_else(|| 
            PacketError::InvalidFieldValue("Target hardware address not set".to_string()))?;
        let target_protocol_addr = self.target_protocol_addr.ok_or_else(|| 
            PacketError::InvalidFieldValue("Target protocol address not set".to_string()))?;

        let packet = ArpPacket {
            header: ArpHeader::new(
                operation,
                sender_hardware_addr,
                sender_protocol_addr,
                target_hardware_addr,
                target_protocol_addr,
            ),
        };

        packet.validate()?;
        Ok(packet)
    }
}

impl ArpPacket {
    /// Creates a new ARP packet builder.
    pub fn builder() -> ArpBuilder {
        ArpBuilder::new()
    }

    /// Creates a new ARP request packet.
    ///
    /// # Arguments
    /// * `sender_hardware_addr` - Source MAC address
    /// * `sender_protocol_addr` - Source IP address
    /// * `target_protocol_addr` - Target IP address to resolve
    pub fn request(
        sender_hardware_addr: MacAddress,
        sender_protocol_addr: Ipv4Address,
        target_protocol_addr: Ipv4Address,
    ) -> Result<Self, PacketError> {
        ArpBuilder::new()
            .operation(Operation::Request)
            .sender_hardware_addr(sender_hardware_addr)
            .sender_protocol_addr(sender_protocol_addr)
            .target_hardware_addr(MacAddress::new([0; 6])) // Empty target MAC for request
            .target_protocol_addr(target_protocol_addr)
            .build()
    }

    /// Creates a new ARP reply packet.
    ///
    /// # Arguments
    /// * `sender_hardware_addr` - Source MAC address
    /// * `sender_protocol_addr` - Source IP address
    /// * `target_hardware_addr` - Target MAC address
    /// * `target_protocol_addr` - Target IP address
    pub fn reply(
        sender_hardware_addr: MacAddress,
        sender_protocol_addr: Ipv4Address,
        target_hardware_addr: MacAddress,
        target_protocol_addr: Ipv4Address,
    ) -> Result<Self, PacketError> {
        ArpBuilder::new()
            .operation(Operation::Reply)
            .sender_hardware_addr(sender_hardware_addr)
            .sender_protocol_addr(sender_protocol_addr)
            .target_hardware_addr(target_hardware_addr)
            .target_protocol_addr(target_protocol_addr)
            .build()
    }
}

impl PacketHeader for ArpHeader {
    fn header_length(&self) -> usize {
        28 // Fixed size for Ethernet/IPv4 ARP
    }

    fn as_bytes(&self) -> Result<Vec<u8>, PacketError> {
        let mut bytes = Vec::with_capacity(self.header_length());
        
        // Hardware Type
        bytes.extend_from_slice(&(self.hardware_type as u16).to_be_bytes());
        
        // Protocol Type
        bytes.extend_from_slice(&self.protocol_type.to_be_bytes());
        
        // Hardware Address Length
        bytes.push(self.hardware_addr_len);
        
        // Protocol Address Length
        bytes.push(self.protocol_addr_len);
        
        // Operation
        bytes.extend_from_slice(&(self.operation as u16).to_be_bytes());
        
        // Sender Hardware Address
        bytes.extend_from_slice(self.sender_hardware_addr.as_bytes());
        
        // Sender Protocol Address
        bytes.extend_from_slice(self.sender_protocol_addr.as_bytes());
        
        // Target Hardware Address
        bytes.extend_from_slice(self.target_hardware_addr.as_bytes());
        
        // Target Protocol Address
        bytes.extend_from_slice(self.target_protocol_addr.as_bytes());
        
        Ok(bytes)
    }
}

impl PacketBuilder for ArpPacket {
    fn build(&self) -> Result<Vec<u8>, PacketError> {
        self.header.as_bytes()
    }

    fn length(&self) -> usize {
        self.header.header_length()
    }

    fn validate(&self) -> Result<(), PacketError> {
        // Validate hardware and protocol types
        if self.header.hardware_type != HardwareType::Ethernet {
            return Err(PacketError::UnsupportedProtocol(
                "Only Ethernet hardware type is supported".to_string()
            ));
        }
        if self.header.protocol_type != 0x0800 {
            return Err(PacketError::UnsupportedProtocol(
                "Only IPv4 protocol type is supported".to_string()
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_addresses() -> (MacAddress, MacAddress, Ipv4Address, Ipv4Address) {
        let sender_mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let target_mac = MacAddress::new([0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]);
        let sender_ip = Ipv4Address::new([192, 168, 1, 1]);
        let target_ip = Ipv4Address::new([192, 168, 1, 2]);
        (sender_mac, target_mac, sender_ip, target_ip)
    }

    #[test]
    fn test_arp_request() {
        let (sender_mac, _, sender_ip, target_ip) = create_test_addresses();
        
        let packet = ArpPacket::request(sender_mac, sender_ip, target_ip).unwrap();
        
        assert_eq!(packet.header.operation as u16, Operation::Request as u16);
        assert_eq!(packet.header.sender_hardware_addr, sender_mac);
        assert_eq!(packet.header.sender_protocol_addr, sender_ip);
        assert_eq!(packet.header.target_protocol_addr, target_ip);
        assert!(packet.validate().is_ok());
    }

    #[test]
    fn test_arp_reply() {
        let (sender_mac, target_mac, sender_ip, target_ip) = create_test_addresses();
        
        let packet = ArpPacket::reply(sender_mac, sender_ip, target_mac, target_ip).unwrap();
        
        assert_eq!(packet.header.operation as u16, Operation::Reply as u16);
        assert_eq!(packet.header.sender_hardware_addr, sender_mac);
        assert_eq!(packet.header.sender_protocol_addr, sender_ip);
        assert_eq!(packet.header.target_hardware_addr, target_mac);
        assert_eq!(packet.header.target_protocol_addr, target_ip);
        assert!(packet.validate().is_ok());
    }

    #[test]
    fn test_arp_builder() {
        let (sender_mac, target_mac, sender_ip, target_ip) = create_test_addresses();
        
        let packet = ArpPacket::builder()
            .operation(Operation::Request)
            .sender_hardware_addr(sender_mac)
            .sender_protocol_addr(sender_ip)
            .target_hardware_addr(target_mac)
            .target_protocol_addr(target_ip)
            .build()
            .unwrap();

        assert_eq!(packet.header.operation as u16, Operation::Request as u16);
        assert_eq!(packet.header.sender_hardware_addr, sender_mac);
        assert_eq!(packet.header.sender_protocol_addr, sender_ip);
        assert_eq!(packet.header.target_hardware_addr, target_mac);
        assert_eq!(packet.header.target_protocol_addr, target_ip);
        assert!(packet.validate().is_ok());
    }
} 