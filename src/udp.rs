use serde::{Deserialize, Serialize};
use crate::{PacketBuilder, PacketError, PacketHeader, Checksumable};

/// UDP Header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpHeader {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
}

impl UdpHeader {
    pub fn new(src_port: u16, dst_port: u16) -> Self {
        Self {
            src_port,
            dst_port,
            length: 8, // Initial length is just the header size
            checksum: 0,
        }
    }
}

/// UDP Packet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpPacket {
    header: UdpHeader,
    payload: Vec<u8>,
}

impl UdpPacket {
    pub fn new(src_port: u16, dst_port: u16) -> Self {
        Self {
            header: UdpHeader::new(src_port, dst_port),
            payload: Vec::new(),
        }
    }

    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        let payload_len = payload.len();
        self.payload = payload;
        self.header.length = (self.header.header_length() + payload_len) as u16;
        self
    }
}

impl PacketHeader for UdpHeader {
    fn header_length(&self) -> usize {
        8 // UDP header is always 8 bytes
    }

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
    fn calculate_checksum(&self) -> u16 {
        // Note: This is a simplified checksum calculation
        // In practice, UDP checksum includes a pseudo-header with IP addresses
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

impl PacketBuilder for UdpPacket {
    fn build(&self) -> Result<Vec<u8>, PacketError> {
        let mut packet = self.header.as_bytes()?;
        packet.extend_from_slice(&self.payload);
        Ok(packet)
    }

    fn length(&self) -> usize {
        self.header.header_length() + self.payload.len()
    }

    fn validate(&self) -> Result<(), PacketError> {
        if self.length() > 65535 {
            return Err(PacketError::InvalidLength);
        }
        Ok(())
    }
} 