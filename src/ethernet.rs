use serde::{Deserialize, Serialize};
use crate::{PacketBuilder, PacketError, PacketHeader};

/// MAC address representation
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    pub fn new(addr: [u8; 6]) -> Self {
        Self(addr)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// EtherType values
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u16)]
pub enum EtherType {
    IPv4 = 0x0800,
    IPv6 = 0x86DD,
    ARP = 0x0806,
}

/// Ethernet frame header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthernetHeader {
    dst_mac: MacAddress,
    src_mac: MacAddress,
    ether_type: EtherType,
}

impl EthernetHeader {
    pub fn new(dst_mac: MacAddress, src_mac: MacAddress, ether_type: EtherType) -> Self {
        Self {
            dst_mac,
            src_mac,
            ether_type,
        }
    }
}

/// Ethernet frame builder
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthernetPacket {
    header: EthernetHeader,
    payload: Vec<u8>,
}

impl EthernetPacket {
    pub fn new(dst_mac: MacAddress, src_mac: MacAddress, ether_type: EtherType) -> Self {
        Self {
            header: EthernetHeader::new(dst_mac, src_mac, ether_type),
            payload: Vec::new(),
        }
    }

    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }

    /// Get the required padding length to meet minimum frame size
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