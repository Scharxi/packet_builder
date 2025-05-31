//! UDP (User Datagram Protocol) implementation.
//!
//! This module provides types and functionality for working with UDP packets,
//! including header construction and packet building.

use serde::{Deserialize, Serialize};
use crate::{PacketBuilder, PacketError, PacketHeader, Checksumable};

/// UDP header structure.
///
/// Contains the basic fields of a UDP header:
/// - Source port
/// - Destination port
/// - Length (header + payload)
/// - Checksum
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpHeader {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
}

impl UdpHeader {
    /// Creates a new UDP header with the specified parameters.
    ///
    /// # Arguments
    /// * `src_port` - Source port number
    /// * `dst_port` - Destination port number
    /// * `length` - Total length of the UDP packet (header + payload)
    fn new(src_port: u16, dst_port: u16, length: u16) -> Self {
        Self {
            src_port,
            dst_port,
            length,
            checksum: 0,
        }
    }
}

/// Complete UDP packet structure.
///
/// Contains both the UDP header and payload data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpPacket {
    header: UdpHeader,
    payload: Vec<u8>,
}

/// Builder for constructing UDP packets.
///
/// Provides a fluent interface for creating UDP packets with proper
/// validation and error handling.
#[derive(Debug, Default)]
pub struct UdpBuilder {
    src_port: Option<u16>,
    dst_port: Option<u16>,
    payload: Vec<u8>,
}

impl UdpBuilder {
    /// Creates a new UDP packet builder with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the source port.
    pub fn src_port(mut self, port: u16) -> Self {
        self.src_port = Some(port);
        self
    }

    /// Sets the destination port.
    pub fn dst_port(mut self, port: u16) -> Self {
        self.dst_port = Some(port);
        self
    }

    /// Sets the payload data.
    pub fn payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }

    /// Builds the UDP packet.
    ///
    /// # Returns
    /// - `Ok(UdpPacket)` - The constructed UDP packet
    /// - `Err(PacketError)` - If any required fields are missing
    pub fn build(self) -> Result<UdpPacket, PacketError> {
        let src_port = self.src_port.ok_or_else(|| 
            PacketError::InvalidFieldValue("Source port not set".to_string()))?;
        let dst_port = self.dst_port.ok_or_else(|| 
            PacketError::InvalidFieldValue("Destination port not set".to_string()))?;

        let length = (8 + self.payload.len()) as u16; // 8 bytes header + payload
        let packet = UdpPacket {
            header: UdpHeader::new(src_port, dst_port, length),
            payload: self.payload,
        };

        packet.validate()?;
        Ok(packet)
    }
}

impl UdpPacket {
    /// Creates a new UDP packet builder.
    pub fn builder() -> UdpBuilder {
        UdpBuilder::new()
    }
}

impl PacketHeader for UdpHeader {
    /// Returns the length of the UDP header in bytes.
    ///
    /// The UDP header is always 8 bytes long.
    fn header_length(&self) -> usize {
        8 // UDP header is always 8 bytes
    }

    /// Converts the header to its byte representation.
    ///
    /// # Returns
    /// - `Ok(Vec<u8>)` - The serialized header as a byte vector
    /// - `Err(PacketError)` - If serialization fails
    fn as_bytes(&self) -> Result<Vec<u8>, PacketError> {
        let mut bytes = Vec::with_capacity(self.header_length());
        
        // Source Port
        bytes.extend_from_slice(&self.src_port.to_be_bytes());
        
        // Destination Port
        bytes.extend_from_slice(&self.dst_port.to_be_bytes());
        
        // Length
        bytes.extend_from_slice(&self.length.to_be_bytes());
        
        // Checksum
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        
        Ok(bytes)
    }
}

impl Checksumable for UdpHeader {
    /// Calculates the UDP checksum.
    ///
    /// Note: This is a simplified checksum calculation.
    /// In practice, UDP checksum includes a pseudo-header with IP addresses.
    fn calculate_checksum(&self) -> u16 {
        let mut sum = 0u32;
        let bytes = self.as_bytes().unwrap();
        
        for i in (0..bytes.len()).step_by(2) {
            let word = if i + 1 < bytes.len() {
                ((bytes[i] as u32) << 8) | (bytes[i + 1] as u32)
            } else {
                (bytes[i] as u32) << 8
            };
            sum += word;
        }
        
        while (sum >> 16) > 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        
        !sum as u16
    }

    /// Verifies the UDP checksum.
    ///
    /// # Returns
    /// `true` if the checksum is valid, `false` otherwise.
    fn verify_checksum(&self) -> bool {
        self.calculate_checksum() == 0
    }
}

impl PacketBuilder for UdpPacket {
    /// Builds the complete UDP packet.
    ///
    /// # Returns
    /// - `Ok(Vec<u8>)` - The serialized packet as a byte vector
    /// - `Err(PacketError)` - If packet construction fails
    fn build(&self) -> Result<Vec<u8>, PacketError> {
        let mut packet = self.header.as_bytes()?;
        packet.extend_from_slice(&self.payload);
        Ok(packet)
    }

    /// Returns the total length of the UDP packet in bytes.
    fn length(&self) -> usize {
        self.header.header_length() + self.payload.len()
    }

    /// Validates the UDP packet.
    ///
    /// Ensures that the total packet length does not exceed the maximum
    /// allowed size for a UDP packet (65,535 bytes).
    ///
    /// # Returns
    /// - `Ok(())` - If the packet is valid
    /// - `Err(PacketError)` - If validation fails
    fn validate(&self) -> Result<(), PacketError> {
        if self.length() > 65535 {
            return Err(PacketError::InvalidLength);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_builder() {
        let packet = UdpPacket::builder()
            .src_port(12345)
            .dst_port(53)
            .payload(vec![1, 2, 3, 4])
            .build()
            .unwrap();

        assert!(packet.validate().is_ok());
        assert_eq!(packet.length(), 12); // 8 (header) + 4 (payload)
        
        // Test missing fields
        let result = UdpPacket::builder()
            .src_port(12345)
            .build();
        assert!(result.is_err());
    }
} 