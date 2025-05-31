//! TCP (Transmission Control Protocol) implementation.
//!
//! This module provides types and functionality for working with TCP packets,
//! including TCP flags, options, and header construction.

use serde::{Deserialize, Serialize};
use crate::{PacketBuilder, PacketError, PacketHeader, Checksumable};

/// TCP control flags used in the TCP header.
///
/// These flags control the state and behavior of the TCP connection:
/// - FIN: No more data from sender
/// - SYN: Synchronize sequence numbers
/// - RST: Reset the connection
/// - PSH: Push function
/// - ACK: Acknowledgment field significant
/// - URG: Urgent pointer field significant
/// - ECE: ECN-Echo
/// - CWR: Congestion Window Reduced
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl TcpFlags {
    /// Creates a new TCP flags structure with all flags set to false.
    pub fn new() -> Self {
        Self::default()
    }

    /// Converts the flags to a byte representation.
    ///
    /// # Returns
    /// A byte where each bit represents a flag's state.
    pub fn as_u8(&self) -> u8 {
        let mut flags = 0u8;
        if self.fin { flags |= 0b00000001; }
        if self.syn { flags |= 0b00000010; }
        if self.rst { flags |= 0b00000100; }
        if self.psh { flags |= 0b00001000; }
        if self.ack { flags |= 0b00010000; }
        if self.urg { flags |= 0b00100000; }
        if self.ece { flags |= 0b01000000; }
        if self.cwr { flags |= 0b10000000; }
        flags
    }
}

/// TCP header options.
///
/// These options provide additional control and functionality:
/// - End of Option List: Marks the end of options
/// - No Operation: Used for padding
/// - Maximum Segment Size: Specifies the largest segment that can be received
/// - Window Scale: Scale factor for the window size
/// - Selective ACK Permitted: Enables selective acknowledgment
/// - Timestamp: Used for round-trip time measurement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TcpOption {
    EndOfOptionList,
    NoOperation,
    MaximumSegmentSize(u16),
    WindowScale(u8),
    SelectiveAckPermitted,
    Timestamp(u32, u32),
}

impl TcpOption {
    /// Converts the option to its byte representation.
    ///
    /// # Returns
    /// A vector of bytes representing the option in wire format.
    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            TcpOption::EndOfOptionList => vec![0],
            TcpOption::NoOperation => vec![1],
            TcpOption::MaximumSegmentSize(size) => {
                vec![2, 4, (*size >> 8) as u8, *size as u8]
            },
            TcpOption::WindowScale(shift) => vec![3, 3, *shift],
            TcpOption::SelectiveAckPermitted => vec![4, 2],
            TcpOption::Timestamp(val, echo) => {
                let mut bytes = vec![8, 10];
                bytes.extend_from_slice(&val.to_be_bytes());
                bytes.extend_from_slice(&echo.to_be_bytes());
                bytes
            },
        }
    }
}

/// TCP header structure.
///
/// Contains all fields defined in the TCP header format:
/// - Source and destination ports
/// - Sequence and acknowledgment numbers
/// - Data offset and flags
/// - Window size
/// - Checksum
/// - Urgent pointer
/// - Options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpHeader {
    src_port: u16,
    dst_port: u16,
    sequence_number: u32,
    acknowledgment_number: u32,
    data_offset: u8,
    flags: TcpFlags,
    window_size: u16,
    checksum: u16,
    urgent_pointer: u16,
    options: Vec<TcpOption>,
}

impl TcpHeader {
    /// Creates a new TCP header with the specified parameters.
    fn new(
        src_port: u16,
        dst_port: u16,
        sequence_number: u32,
        acknowledgment_number: u32,
        flags: TcpFlags,
        window_size: u16,
        urgent_pointer: u16,
        options: Vec<TcpOption>,
    ) -> Self {
        let mut header = Self {
            src_port,
            dst_port,
            sequence_number,
            acknowledgment_number,
            data_offset: 5, // Will be updated based on options
            flags,
            window_size,
            checksum: 0,
            urgent_pointer,
            options,
        };

        // Update data offset based on options
        let total_length = header.calculate_total_length();
        header.data_offset = (total_length / 4) as u8;

        header
    }

    /// Calculates the total length of the header including options.
    fn calculate_total_length(&self) -> usize {
        let mut length = 20; // Base header length
        for option in &self.options {
            length += option.as_bytes().len();
        }
        // Pad to 4-byte boundary
        (length + 3) & !3
    }
}

/// Complete TCP packet structure.
///
/// Contains both the TCP header and payload data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpPacket {
    header: TcpHeader,
    payload: Vec<u8>,
}

/// Builder for constructing TCP packets.
///
/// Provides a fluent interface for creating TCP packets with proper
/// validation and error handling.
#[derive(Debug, Default)]
pub struct TcpBuilder {
    src_port: Option<u16>,
    dst_port: Option<u16>,
    sequence_number: u32,
    acknowledgment_number: u32,
    flags: TcpFlags,
    window_size: u16,
    urgent_pointer: u16,
    options: Vec<TcpOption>,
    payload: Vec<u8>,
}

impl TcpBuilder {
    /// Creates a new TCP packet builder with default values.
    pub fn new() -> Self {
        Self {
            src_port: None,
            dst_port: None,
            sequence_number: 0,
            acknowledgment_number: 0,
            flags: TcpFlags::default(),
            window_size: 65535,
            urgent_pointer: 0,
            options: Vec::new(),
            payload: Vec::new(),
        }
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

    /// Sets the sequence number.
    pub fn sequence(mut self, seq: u32) -> Self {
        self.sequence_number = seq;
        self
    }

    /// Sets the acknowledgment number and ACK flag.
    pub fn acknowledgment(mut self, ack: u32) -> Self {
        self.acknowledgment_number = ack;
        self.flags.ack = true;
        self
    }

    /// Sets the TCP flags.
    pub fn flags(mut self, flags: TcpFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Sets the window size.
    pub fn window_size(mut self, size: u16) -> Self {
        self.window_size = size;
        self
    }

    /// Sets the urgent pointer and URG flag.
    pub fn urgent_pointer(mut self, pointer: u16) -> Self {
        self.urgent_pointer = pointer;
        self.flags.urg = true;
        self
    }

    /// Adds a TCP option.
    pub fn add_option(mut self, option: TcpOption) -> Self {
        self.options.push(option);
        self
    }

    /// Sets the payload data.
    pub fn payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }

    /// Builds the TCP packet.
    ///
    /// # Returns
    /// - `Ok(TcpPacket)` - The constructed TCP packet
    /// - `Err(PacketError)` - If any required fields are missing
    pub fn build(self) -> Result<TcpPacket, PacketError> {
        let src_port = self.src_port.ok_or_else(|| 
            PacketError::InvalidFieldValue("Source port not set".to_string()))?;
        let dst_port = self.dst_port.ok_or_else(|| 
            PacketError::InvalidFieldValue("Destination port not set".to_string()))?;

        let packet = TcpPacket {
            header: TcpHeader::new(
                src_port,
                dst_port,
                self.sequence_number,
                self.acknowledgment_number,
                self.flags,
                self.window_size,
                self.urgent_pointer,
                self.options,
            ),
            payload: self.payload,
        };

        packet.validate()?;
        Ok(packet)
    }
}

impl TcpPacket {
    /// Creates a new TCP packet builder.
    pub fn builder() -> TcpBuilder {
        TcpBuilder::new()
    }
}

impl PacketHeader for TcpHeader {
    fn header_length(&self) -> usize {
        (self.data_offset as usize) * 4
    }

    fn as_bytes(&self) -> Result<Vec<u8>, PacketError> {
        let mut bytes = Vec::with_capacity(self.header_length());
        
        // Source Port
        bytes.extend_from_slice(&self.src_port.to_be_bytes());
        
        // Destination Port
        bytes.extend_from_slice(&self.dst_port.to_be_bytes());
        
        // Sequence Number
        bytes.extend_from_slice(&self.sequence_number.to_be_bytes());
        
        // Acknowledgment Number
        bytes.extend_from_slice(&self.acknowledgment_number.to_be_bytes());
        
        // Data Offset, Reserved, and Flags
        bytes.push((self.data_offset << 4) as u8);
        bytes.push(self.flags.as_u8());
        
        // Window Size
        bytes.extend_from_slice(&self.window_size.to_be_bytes());
        
        // Checksum
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        
        // Urgent Pointer
        bytes.extend_from_slice(&self.urgent_pointer.to_be_bytes());
        
        // Options
        for option in &self.options {
            bytes.extend_from_slice(&option.as_bytes());
        }
        
        // Pad to 4-byte boundary
        while bytes.len() < self.header_length() {
            bytes.push(0);
        }
        
        Ok(bytes)
    }
}

impl Checksumable for TcpHeader {
    fn calculate_checksum(&self) -> u16 {
        // Note: This is a simplified checksum calculation
        // In practice, TCP checksum includes a pseudo-header with IP addresses
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

impl PacketBuilder for TcpPacket {
    fn build(&self) -> Result<Vec<u8>, PacketError> {
        let mut packet = self.header.as_bytes()?;
        packet.extend_from_slice(&self.payload);
        Ok(packet)
    }

    fn length(&self) -> usize {
        self.header.header_length() + self.payload.len()
    }

    fn validate(&self) -> Result<(), PacketError> {
        if self.header.data_offset < 5 {
            return Err(PacketError::InvalidFieldValue(
                "TCP header length must be at least 20 bytes".to_string()
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_builder() {
        let mut flags = TcpFlags::new();
        flags.syn = true;
        
        let packet = TcpPacket::builder()
            .src_port(12345)
            .dst_port(80)
            .sequence(1000)
            .flags(flags)
            .add_option(TcpOption::MaximumSegmentSize(1460))
            .payload(vec![1, 2, 3, 4])
            .build()
            .unwrap();

        assert!(packet.validate().is_ok());
        
        // Test missing fields
        let result = TcpPacket::builder()
            .src_port(12345)
            .sequence(1000)
            .build();
        assert!(result.is_err());
    }
} 