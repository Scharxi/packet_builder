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
    fn new(src_port: u16, dst_port: u16, length: u16) -> Self {
        Self {
            src_port,
            dst_port,
            length,
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

/// Builder for UDP packets
#[derive(Debug, Default)]
pub struct UdpBuilder {
    src_port: Option<u16>,
    dst_port: Option<u16>,
    payload: Vec<u8>,
}

impl UdpBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn src_port(mut self, port: u16) -> Self {
        self.src_port = Some(port);
        self
    }

    pub fn dst_port(mut self, port: u16) -> Self {
        self.dst_port = Some(port);
        self
    }

    pub fn payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }

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
    pub fn builder() -> UdpBuilder {
        UdpBuilder::new()
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