//! ICMP (Internet Control Message Protocol) implementation.
//!
//! This module provides types and functionality for working with ICMP packets,
//! including message types, codes, and packet construction.

use serde::{Deserialize, Serialize};
use crate::{PacketBuilder, PacketError, PacketHeader, Checksumable};

/// ICMP message types as defined in RFC 792 and subsequent RFCs.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
pub enum IcmpType {
    /// Echo Reply (Type 0)
    EchoReply = 0,
    /// Destination Unreachable (Type 3)
    DestinationUnreachable = 3,
    /// Source Quench (Type 4)
    SourceQuench = 4,
    /// Redirect Message (Type 5)
    Redirect = 5,
    /// Echo Request (Type 8)
    EchoRequest = 8,
    /// Router Advertisement (Type 9)
    RouterAdvertisement = 9,
    /// Router Solicitation (Type 10)
    RouterSolicitation = 10,
    /// Time Exceeded (Type 11)
    TimeExceeded = 11,
    /// Parameter Problem (Type 12)
    ParameterProblem = 12,
    /// Timestamp Request (Type 13)
    TimestampRequest = 13,
    /// Timestamp Reply (Type 14)
    TimestampReply = 14,
}

/// ICMP codes for Destination Unreachable messages.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
pub enum DestUnreachableCode {
    /// Network Unreachable
    NetworkUnreachable = 0,
    /// Host Unreachable
    HostUnreachable = 1,
    /// Protocol Unreachable
    ProtocolUnreachable = 2,
    /// Port Unreachable
    PortUnreachable = 3,
    /// Fragmentation Required and DF Set
    FragmentationNeeded = 4,
    /// Source Route Failed
    SourceRouteFailed = 5,
}

/// ICMP header structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpHeader {
    pub message_type: IcmpType,
    pub code: u8,
    pub checksum: u16,
    pub rest_of_header: u32,
}

impl IcmpHeader {
    /// Creates a new ICMP header with the specified parameters.
    fn new(message_type: IcmpType, code: u8, rest_of_header: u32) -> Self {
        Self {
            message_type,
            code,
            checksum: 0,
            rest_of_header,
        }
    }
}

/// Complete ICMP packet structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpPacket {
    pub header: IcmpHeader,
    pub payload: Vec<u8>,
}

/// Builder for constructing ICMP packets.
#[derive(Debug, Default)]
pub struct IcmpBuilder {
    message_type: Option<IcmpType>,
    code: u8,
    rest_of_header: u32,
    payload: Vec<u8>,
}

impl IcmpBuilder {
    /// Creates a new ICMP packet builder with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the ICMP message type.
    pub fn message_type(mut self, message_type: IcmpType) -> Self {
        self.message_type = Some(message_type);
        self
    }

    /// Sets the ICMP code.
    pub fn code(mut self, code: u8) -> Self {
        self.code = code;
        self
    }

    /// Sets the rest of header field.
    pub fn rest_of_header(mut self, rest_of_header: u32) -> Self {
        self.rest_of_header = rest_of_header;
        self
    }

    /// Sets the payload data.
    pub fn payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }

    /// Builds the ICMP packet.
    pub fn build(self) -> Result<IcmpPacket, PacketError> {
        let message_type = self.message_type.ok_or_else(|| 
            PacketError::InvalidFieldValue("ICMP message type not set".to_string()))?;

        let packet = IcmpPacket {
            header: IcmpHeader::new(message_type, self.code, self.rest_of_header),
            payload: self.payload,
        };

        Ok(packet)
    }
}

impl IcmpPacket {
    /// Creates a new ICMP packet builder.
    pub fn builder() -> IcmpBuilder {
        IcmpBuilder::new()
    }

    /// Creates a new Echo Request packet.
    pub fn echo_request(identifier: u16, sequence: u16, payload: Vec<u8>) -> Result<Self, PacketError> {
        let rest_of_header = ((identifier as u32) << 16) | (sequence as u32);
        
        IcmpBuilder::new()
            .message_type(IcmpType::EchoRequest)
            .code(0)
            .rest_of_header(rest_of_header)
            .payload(payload)
            .build()
    }

    /// Creates a new Echo Reply packet.
    pub fn echo_reply(identifier: u16, sequence: u16, payload: Vec<u8>) -> Result<Self, PacketError> {
        let rest_of_header = ((identifier as u32) << 16) | (sequence as u32);
        
        IcmpBuilder::new()
            .message_type(IcmpType::EchoReply)
            .code(0)
            .rest_of_header(rest_of_header)
            .payload(payload)
            .build()
    }
}

impl PacketHeader for IcmpHeader {
    fn header_length(&self) -> usize {
        8 // ICMP header is always 8 bytes
    }

    fn as_bytes(&self) -> Result<Vec<u8>, PacketError> {
        let mut bytes = Vec::with_capacity(self.header_length());
        
        bytes.push(self.message_type as u8);
        bytes.push(self.code);
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        bytes.extend_from_slice(&self.rest_of_header.to_be_bytes());
        
        Ok(bytes)
    }
}

impl Checksumable for IcmpHeader {
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

    fn verify_checksum(&self) -> bool {
        self.calculate_checksum() == 0
    }
}

impl PacketBuilder for IcmpPacket {
    fn build(&self) -> Result<Vec<u8>, PacketError> {
        let mut packet = self.header.as_bytes()?;
        packet.extend_from_slice(&self.payload);
        Ok(packet)
    }

    fn length(&self) -> usize {
        self.header.header_length() + self.payload.len()
    }

    fn validate(&self) -> Result<(), PacketError> {
        // Validate based on message type
        match self.header.message_type {
            IcmpType::EchoRequest | IcmpType::EchoReply => {
                if self.payload.len() > 65507 { // Maximum payload size for Echo messages
                    return Err(PacketError::InvalidLength);
                }
            }
            _ => {
                if self.payload.len() > 1500 { // Standard MTU size
                    return Err(PacketError::InvalidLength);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_echo_request() {
        let payload = b"Hello, World!".to_vec();
        let packet = IcmpPacket::echo_request(1, 1, payload.clone()).unwrap();

        assert_eq!(packet.header.message_type as u8, IcmpType::EchoRequest as u8);
        assert_eq!(packet.header.code, 0);
        assert_eq!(packet.payload, payload);
        assert!(packet.validate().is_ok());
    }

    #[test]
    fn test_icmp_echo_reply() {
        let payload = b"Hello, World!".to_vec();
        let packet = IcmpPacket::echo_reply(1, 1, payload.clone()).unwrap();

        assert_eq!(packet.header.message_type as u8, IcmpType::EchoReply as u8);
        assert_eq!(packet.header.code, 0);
        assert_eq!(packet.payload, payload);
        assert!(packet.validate().is_ok());
    }

    #[test]
    fn test_icmp_builder() {
        let packet = IcmpPacket::builder()
            .message_type(IcmpType::DestinationUnreachable)
            .code(DestUnreachableCode::PortUnreachable as u8)
            .rest_of_header(0)
            .payload(vec![1, 2, 3, 4])
            .build()
            .unwrap();

        assert_eq!(packet.header.message_type as u8, IcmpType::DestinationUnreachable as u8);
        assert_eq!(packet.header.code, DestUnreachableCode::PortUnreachable as u8);
        assert!(packet.validate().is_ok());
    }

    #[test]
    fn test_invalid_payload_size() {
        let large_payload = vec![0; 65508]; // Exceeds maximum Echo message payload size
        let result = IcmpPacket::echo_request(1, 1, large_payload);
        assert!(result.is_ok());
        let packet = result.unwrap();
        let validation_result = packet.validate();
        assert!(validation_result.is_err());
        match validation_result {
            Err(PacketError::InvalidLength) => (),
            _ => panic!("Expected InvalidLength error"),
        }
    }
}