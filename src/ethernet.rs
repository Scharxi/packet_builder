//! Ethernet frame implementation.
//!
//! This module provides types and functionality for working with Ethernet frames,
//! including MAC addresses, EtherTypes, and frame construction.

use serde::{Deserialize, Serialize};
use crate::{PacketBuilder, PacketError, PacketHeader};

/// Represents a MAC (Media Access Control) address.
///
/// A MAC address is a unique identifier assigned to network interfaces
/// for communications at the data link layer.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    /// Creates a new MAC address from a 6-byte array.
    ///
    /// # Arguments
    /// * `addr` - A 6-byte array containing the MAC address
    pub fn new(addr: [u8; 6]) -> Self {
        Self(addr)
    }

    /// Returns a reference to the underlying bytes of the MAC address.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Ethernet frame type identifiers.
///
/// These values identify the protocol encapsulated in the frame's payload.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u16)]
pub enum EtherType {
    /// Internet Protocol version 4 (0x0800)
    IPv4 = 0x0800,
    /// Internet Protocol version 6 (0x86DD)
    IPv6 = 0x86DD,
    /// Address Resolution Protocol (0x0806)
    ARP = 0x0806,
}

/// Represents an Ethernet frame header.
///
/// The header contains source and destination MAC addresses and the EtherType
/// field identifying the encapsulated protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthernetHeader {
    dst_mac: MacAddress,
    src_mac: MacAddress,
    ether_type: EtherType,
}

impl EthernetHeader {
    /// Creates a new Ethernet header.
    ///
    /// # Arguments
    /// * `dst_mac` - Destination MAC address
    /// * `src_mac` - Source MAC address
    /// * `ether_type` - Type of the encapsulated protocol
    pub fn new(dst_mac: MacAddress, src_mac: MacAddress, ether_type: EtherType) -> Self {
        Self {
            dst_mac,
            src_mac,
            ether_type,
        }
    }
}

/// Represents a complete Ethernet frame.
///
/// An Ethernet frame consists of a header and payload data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthernetPacket {
    header: EthernetHeader,
    payload: Vec<u8>,
}

/// Builder for constructing Ethernet frames.
///
/// This struct provides a fluent interface for creating Ethernet frames
/// with proper validation and error handling.
#[derive(Debug, Default)]
pub struct EthernetBuilder {
    src_mac: Option<MacAddress>,
    dst_mac: Option<MacAddress>,
    ether_type: Option<EtherType>,
    payload: Vec<u8>,
}

impl EthernetBuilder {
    /// Creates a new Ethernet frame builder with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the source MAC address.
    pub fn src_mac(mut self, mac: MacAddress) -> Self {
        self.src_mac = Some(mac);
        self
    }

    /// Sets the destination MAC address.
    pub fn dst_mac(mut self, mac: MacAddress) -> Self {
        self.dst_mac = Some(mac);
        self
    }

    /// Sets the EtherType value.
    pub fn ether_type(mut self, ether_type: EtherType) -> Self {
        self.ether_type = Some(ether_type);
        self
    }

    /// Sets the payload data.
    pub fn payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }

    /// Builds the Ethernet frame.
    ///
    /// # Returns
    /// - `Ok(EthernetPacket)` - The constructed Ethernet frame
    /// - `Err(PacketError)` - If any required fields are missing
    pub fn build(self) -> Result<EthernetPacket, PacketError> {
        let src_mac = self.src_mac.ok_or_else(|| 
            PacketError::InvalidFieldValue("Source MAC address not set".to_string()))?;
        let dst_mac = self.dst_mac.ok_or_else(|| 
            PacketError::InvalidFieldValue("Destination MAC address not set".to_string()))?;
        let ether_type = self.ether_type.ok_or_else(|| 
            PacketError::InvalidFieldValue("EtherType not set".to_string()))?;

        let packet = EthernetPacket {
            header: EthernetHeader::new(dst_mac, src_mac, ether_type),
            payload: self.payload,
        };

        packet.validate()?;
        Ok(packet)
    }
}

impl EthernetPacket {
    /// Creates a new Ethernet frame builder.
    pub fn builder() -> EthernetBuilder {
        EthernetBuilder::new()
    }

    /// Calculates the required padding length to meet minimum frame size.
    ///
    /// Ethernet frames must be at least 64 bytes long (including header and FCS).
    /// This method calculates how much padding is needed to meet this requirement.
    fn get_padding_length(&self) -> usize {
        let min_payload_size = 46; // Minimum Ethernet payload size
        let current_payload_size = self.payload.len();
        if current_payload_size < min_payload_size {
            min_payload_size - current_payload_size
        } else {
            0
        }
    }
}

impl PacketHeader for EthernetHeader {
    fn header_length(&self) -> usize {
        14 // 6 (dst_mac) + 6 (src_mac) + 2 (ether_type)
    }

    fn as_bytes(&self) -> Result<Vec<u8>, PacketError> {
        let mut bytes = Vec::with_capacity(self.header_length());
        bytes.extend_from_slice(self.dst_mac.as_bytes());
        bytes.extend_from_slice(self.src_mac.as_bytes());
        bytes.extend_from_slice(&(self.ether_type as u16).to_be_bytes());
        Ok(bytes)
    }
}

impl PacketBuilder for EthernetPacket {
    fn build(&self) -> Result<Vec<u8>, PacketError> {
        self.validate()?;
        let mut packet = self.header.as_bytes()?;
        packet.extend_from_slice(&self.payload);
        
        // Add padding if necessary
        let padding_length = self.get_padding_length();
        if padding_length > 0 {
            packet.extend(std::iter::repeat(0).take(padding_length));
        }
        
        Ok(packet)
    }

    fn length(&self) -> usize {
        self.header.header_length() + self.payload.len() + self.get_padding_length()
    }

    fn validate(&self) -> Result<(), PacketError> {
        if self.payload.len() > 1500 {
            return Err(PacketError::InvalidLength);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethernet_builder() {
        let src_mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let dst_mac = MacAddress::new([0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]);
        
        let packet = EthernetPacket::builder()
            .src_mac(src_mac)
            .dst_mac(dst_mac)
            .ether_type(EtherType::IPv4)
            .payload(vec![1, 2, 3, 4])
            .build()
            .unwrap();

        assert_eq!(packet.length(), 60); // 14 (header) + 46 (minimum payload with padding)
        
        // Test missing fields
        let result = EthernetPacket::builder()
            .src_mac(src_mac)
            .ether_type(EtherType::IPv4)
            .build();
        assert!(result.is_err());
    }
} 