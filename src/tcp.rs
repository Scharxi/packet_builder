use serde::{Deserialize, Serialize};
use crate::{PacketBuilder, PacketError, PacketHeader, Checksumable};

/// TCP Flags
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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
    pub fn new() -> Self {
        Self {
            fin: false,
            syn: false,
            rst: false,
            psh: false,
            ack: false,
            urg: false,
            ece: false,
            cwr: false,
        }
    }

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

/// TCP Header Options
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

/// TCP Header
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
    pub fn new(src_port: u16, dst_port: u16) -> Self {
        Self {
            src_port,
            dst_port,
            sequence_number: 0,
            acknowledgment_number: 0,
            data_offset: 5, // 5 32-bit words (20 bytes, no options)
            flags: TcpFlags::new(),
            window_size: 65535,
            checksum: 0,
            urgent_pointer: 0,
            options: Vec::new(),
        }
    }

    pub fn with_flags(mut self, flags: TcpFlags) -> Self {
        self.flags = flags;
        self
    }

    pub fn with_sequence(mut self, seq: u32) -> Self {
        self.sequence_number = seq;
        self
    }

    pub fn with_ack(mut self, ack: u32) -> Self {
        self.acknowledgment_number = ack;
        self.flags.ack = true;
        self
    }

    pub fn with_window_size(mut self, size: u16) -> Self {
        self.window_size = size;
        self
    }

    pub fn add_option(mut self, option: TcpOption) -> Self {
        self.options.push(option);
        // Update data offset to account for options
        let total_length = self.calculate_total_length();
        self.data_offset = (total_length / 4) as u8;
        self
    }

    fn calculate_total_length(&self) -> usize {
        let mut length = 20; // Base header length
        for option in &self.options {
            length += option.as_bytes().len();
        }
        // Pad to 4-byte boundary
        (length + 3) & !3
    }
}

/// TCP Packet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpPacket {
    header: TcpHeader,
    payload: Vec<u8>,
}

impl TcpPacket {
    pub fn new(src_port: u16, dst_port: u16) -> Self {
        Self {
            header: TcpHeader::new(src_port, dst_port),
            payload: Vec::new(),
        }
    }

    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }

    pub fn with_flags(mut self, flags: TcpFlags) -> Self {
        self.header.flags = flags;
        self
    }

    pub fn with_sequence(mut self, seq: u32) -> Self {
        self.header.sequence_number = seq;
        self
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