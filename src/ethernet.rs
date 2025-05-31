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

/// Builder for Ethernet packets
#[derive(Debug, Default)]
pub struct EthernetBuilder {
    src_mac: Option<MacAddress>,
    dst_mac: Option<MacAddress>,
    ether_type: Option<EtherType>,
    payload: Vec<u8>,
}

impl EthernetBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn src_mac(mut self, mac: MacAddress) -> Self {
        self.src_mac = Some(mac);
        self
    }

    pub fn dst_mac(mut self, mac: MacAddress) -> Self {
        self.dst_mac = Some(mac);
        self
    }

    pub fn ether_type(mut self, ether_type: EtherType) -> Self {
        self.ether_type = Some(ether_type);
        self
    }

    pub fn payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }

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
    pub fn builder() -> EthernetBuilder {
        EthernetBuilder::new()
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