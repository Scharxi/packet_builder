use serde::{Deserialize, Serialize};
use crate::{PacketBuilder, PacketError, PacketHeader, Checksumable};

/// IP Protocol Numbers
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
pub enum IpProtocol {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
}

/// IPv4 address representation
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
pub struct Ipv4Address([u8; 4]);

impl Ipv4Address {
    pub fn new(addr: [u8; 4]) -> Self {
        Self(addr)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// IPv4 header flags
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Ipv4Flags {
    reserved: bool,
    dont_fragment: bool,
    more_fragments: bool,
}

impl Ipv4Flags {
    pub fn new(dont_fragment: bool, more_fragments: bool) -> Self {
        Self {
            reserved: false,
            dont_fragment,
            more_fragments,
        }
    }

    pub fn as_u8(&self) -> u8 {
        let mut flags = 0u8;
        if self.reserved { flags |= 0b100; }
        if self.dont_fragment { flags |= 0b010; }
        if self.more_fragments { flags |= 0b001; }
        flags
    }
}

/// IPv4 header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv4Header {
    version: u8,
    ihl: u8,
    dscp: u8,
    ecn: u8,
    total_length: u16,
    identification: u16,
    flags: Ipv4Flags,
    fragment_offset: u16,
    ttl: u8,
    protocol: IpProtocol,
    checksum: u16,
    src_addr: Ipv4Address,
    dst_addr: Ipv4Address,
}

impl Ipv4Header {
    pub fn new(
        protocol: IpProtocol,
        src_addr: Ipv4Address,
        dst_addr: Ipv4Address,
    ) -> Self {
        Self {
            version: 4,
            ihl: 5, // 5 32-bit words (20 bytes, no options)
            dscp: 0,
            ecn: 0,
            total_length: 20, // Will be updated when payload is added
            identification: 0,
            flags: Ipv4Flags::new(true, false),
            fragment_offset: 0,
            ttl: 64,
            protocol,
            checksum: 0,
            src_addr,
            dst_addr,
        }
    }
}

/// IPv4 packet builder
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv4Packet {
    header: Ipv4Header,
    payload: Vec<u8>,
}

impl Ipv4Packet {
    pub fn new(
        protocol: IpProtocol,
        src_addr: Ipv4Address,
        dst_addr: Ipv4Address,
    ) -> Self {
        Self {
            header: Ipv4Header::new(protocol, src_addr, dst_addr),
            payload: Vec::new(),
        }
    }

    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        let payload_len = payload.len();
        self.payload = payload;
        self.header.total_length = (self.header.ihl * 4 + payload_len as u8) as u16;
        self
    }
}

impl PacketHeader for Ipv4Header {
    fn header_length(&self) -> usize {
        (self.ihl * 4) as usize
    }

    fn as_bytes(&self) -> Result<Vec<u8>, PacketError> {
        let mut bytes = Vec::with_capacity(self.header_length());
        
        // Version & IHL
        bytes.push((self.version << 4) | self.ihl);
        
        // DSCP & ECN
        bytes.push((self.dscp << 2) | self.ecn);
        
        // Total Length
        bytes.extend_from_slice(&self.total_length.to_be_bytes());
        
        // Identification
        bytes.extend_from_slice(&self.identification.to_be_bytes());
        
        // Flags & Fragment Offset
        let flags_and_offset = ((self.flags.as_u8() as u16) << 13) | (self.fragment_offset & 0x1FFF);
        bytes.extend_from_slice(&flags_and_offset.to_be_bytes());
        
        // TTL
        bytes.push(self.ttl);
        
        // Protocol
        bytes.push(self.protocol as u8);
        
        // Checksum
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        
        // Source Address
        bytes.extend_from_slice(self.src_addr.as_bytes());
        
        // Destination Address
        bytes.extend_from_slice(self.dst_addr.as_bytes());
        
        Ok(bytes)
    }
}

impl Checksumable for Ipv4Header {
    fn calculate_checksum(&self) -> u16 {
        let mut sum = 0u32;
        let bytes = self.as_bytes().unwrap();
        
        // Process each 16-bit word
        for i in (0..bytes.len()).step_by(2) {
            let word = if i + 1 < bytes.len() {
                ((bytes[i] as u32) << 8) | (bytes[i + 1] as u32)
            } else {
                (bytes[i] as u32) << 8
            };
            sum += word;
        }
        
        // Add carry bits
        while (sum >> 16) > 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        
        !sum as u16
    }

    fn verify_checksum(&self) -> bool {
        self.calculate_checksum() == 0
    }
}

impl PacketBuilder for Ipv4Packet {
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