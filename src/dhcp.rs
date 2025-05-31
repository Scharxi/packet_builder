//! DHCP (Dynamic Host Configuration Protocol) implementation.
//!
//! This module provides types and functionality for working with DHCP packets,
//! including message types, options, and packet construction.

use serde::{Deserialize, Serialize};
use crate::{PacketBuilder, PacketError, PacketHeader};
use crate::ethernet::MacAddress;
use crate::ip::Ipv4Address;

/// DHCP message types.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    /// DHCP Discover message
    Discover = 1,
    /// DHCP Offer message
    Offer = 2,
    /// DHCP Request message
    Request = 3,
    /// DHCP Decline message
    Decline = 4,
    /// DHCP Acknowledge message
    Ack = 5,
    /// DHCP Not Acknowledge message
    Nak = 6,
    /// DHCP Release message
    Release = 7,
    /// DHCP Inform message
    Inform = 8,
}

/// DHCP option codes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[repr(u8)]
pub enum OptionCode {
    /// Pad Option
    Pad = 0,
    /// Subnet Mask
    SubnetMask = 1,
    /// Router Option
    Router = 3,
    /// Domain Name Server Option
    DomainNameServer = 6,
    /// Host Name Option
    HostName = 12,
    /// Domain Name
    DomainName = 15,
    /// Interface MTU
    InterfaceMtu = 26,
    /// Broadcast Address
    BroadcastAddress = 28,
    /// Network Time Protocol Servers
    NtpServers = 42,
    /// Requested IP Address
    RequestedIpAddress = 50,
    /// IP Address Lease Time
    IpAddressLeaseTime = 51,
    /// Message Type
    MessageType = 53,
    /// Server Identifier
    ServerIdentifier = 54,
    /// Parameter Request List
    ParameterRequestList = 55,
    /// Maximum DHCP Message Size
    MaxDhcpMessageSize = 57,
    /// Renewal Time Value
    RenewalTimeValue = 58,
    /// Rebinding Time Value
    RebindingTimeValue = 59,
    /// Client Identifier
    ClientIdentifier = 61,
    /// End Option
    End = 255,
}

/// DHCP option structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpOption {
    code: OptionCode,
    length: u8,
    data: Vec<u8>,
}

impl DhcpOption {
    /// Creates a new DHCP option.
    pub fn new(code: OptionCode, data: Vec<u8>) -> Self {
        Self {
            code,
            length: data.len() as u8,
            data,
        }
    }

    /// Creates a message type option.
    pub fn message_type(message_type: MessageType) -> Self {
        Self::new(OptionCode::MessageType, vec![message_type as u8])
    }

    /// Creates a requested IP address option.
    pub fn requested_ip_address(addr: Ipv4Address) -> Self {
        Self::new(OptionCode::RequestedIpAddress, addr.as_bytes().to_vec())
    }

    /// Creates a server identifier option.
    pub fn server_identifier(addr: Ipv4Address) -> Self {
        Self::new(OptionCode::ServerIdentifier, addr.as_bytes().to_vec())
    }

    /// Creates a client identifier option.
    pub fn client_identifier(hardware_type: u8, mac: MacAddress) -> Self {
        let mut data = Vec::with_capacity(7);
        data.push(hardware_type);
        data.extend_from_slice(mac.as_bytes());
        Self::new(OptionCode::ClientIdentifier, data)
    }

    /// Converts the option to its byte representation.
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 + self.data.len());
        bytes.push(self.code as u8);
        bytes.push(self.length);
        bytes.extend_from_slice(&self.data);
        bytes
    }
}

/// DHCP header structure.
///
/// Contains the fields defined in the DHCP packet format:
/// - Op: Message op code / message type
/// - Htype: Hardware address type
/// - Hlen: Hardware address length
/// - Hops: Client sets to zero, optionally used by relay agents
/// - Xid: Transaction ID
/// - Secs: Seconds elapsed since client began address acquisition
/// - Flags: Flags
/// - Ciaddr: Client IP address
/// - Yiaddr: 'your' (client) IP address
/// - Siaddr: IP address of next server to use in bootstrap
/// - Giaddr: Relay agent IP address
/// - Chaddr: Client hardware address
/// - Options: Optional parameters field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpHeader {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: Ipv4Address,
    pub yiaddr: Ipv4Address,
    pub siaddr: Ipv4Address,
    pub giaddr: Ipv4Address,
    pub chaddr: MacAddress,
    pub options: Vec<DhcpOption>,
}

impl DhcpHeader {
    /// Creates a new DHCP header with the specified parameters.
    fn new(
        op: u8,
        xid: u32,
        ciaddr: Ipv4Address,
        yiaddr: Ipv4Address,
        siaddr: Ipv4Address,
        giaddr: Ipv4Address,
        chaddr: MacAddress,
        options: Vec<DhcpOption>,
    ) -> Self {
        Self {
            op,
            htype: 1, // Ethernet
            hlen: 6,  // MAC address length
            hops: 0,
            xid,
            secs: 0,
            flags: 0,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            options,
        }
    }
}

/// Complete DHCP packet structure.
///
/// Contains the DHCP header and any additional options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpPacket {
    pub header: DhcpHeader,
}

/// Builder for constructing DHCP packets.
///
/// Provides a fluent interface for creating DHCP packets with proper
/// validation and error handling.
#[derive(Debug, Default)]
pub struct DhcpBuilder {
    op: Option<u8>,
    xid: Option<u32>,
    ciaddr: Option<Ipv4Address>,
    yiaddr: Option<Ipv4Address>,
    siaddr: Option<Ipv4Address>,
    giaddr: Option<Ipv4Address>,
    chaddr: Option<MacAddress>,
    options: Vec<DhcpOption>,
}

impl DhcpBuilder {
    /// Creates a new DHCP packet builder with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the operation code.
    pub fn op(mut self, op: u8) -> Self {
        self.op = Some(op);
        self
    }

    /// Sets the transaction ID.
    pub fn xid(mut self, xid: u32) -> Self {
        self.xid = Some(xid);
        self
    }

    /// Sets the client IP address.
    pub fn ciaddr(mut self, addr: Ipv4Address) -> Self {
        self.ciaddr = Some(addr);
        self
    }

    /// Sets the 'your' IP address.
    pub fn yiaddr(mut self, addr: Ipv4Address) -> Self {
        self.yiaddr = Some(addr);
        self
    }

    /// Sets the server IP address.
    pub fn siaddr(mut self, addr: Ipv4Address) -> Self {
        self.siaddr = Some(addr);
        self
    }

    /// Sets the relay agent IP address.
    pub fn giaddr(mut self, addr: Ipv4Address) -> Self {
        self.giaddr = Some(addr);
        self
    }

    /// Sets the client hardware address.
    pub fn chaddr(mut self, addr: MacAddress) -> Self {
        self.chaddr = Some(addr);
        self
    }

    /// Adds a DHCP option.
    pub fn add_option(mut self, option: DhcpOption) -> Self {
        self.options.push(option);
        self
    }

    /// Builds the DHCP packet.
    ///
    /// # Returns
    /// - `Ok(DhcpPacket)` - The constructed DHCP packet
    /// - `Err(PacketError)` - If any required fields are missing
    pub fn build(self) -> Result<DhcpPacket, PacketError> {
        let op = self.op.ok_or_else(|| 
            PacketError::InvalidFieldValue("Operation code not set".to_string()))?;
        let xid = self.xid.ok_or_else(|| 
            PacketError::InvalidFieldValue("Transaction ID not set".to_string()))?;
        let ciaddr = self.ciaddr.unwrap_or_else(|| Ipv4Address::new([0, 0, 0, 0]));
        let yiaddr = self.yiaddr.unwrap_or_else(|| Ipv4Address::new([0, 0, 0, 0]));
        let siaddr = self.siaddr.unwrap_or_else(|| Ipv4Address::new([0, 0, 0, 0]));
        let giaddr = self.giaddr.unwrap_or_else(|| Ipv4Address::new([0, 0, 0, 0]));
        let chaddr = self.chaddr.ok_or_else(|| 
            PacketError::InvalidFieldValue("Client hardware address not set".to_string()))?;

        let packet = DhcpPacket {
            header: DhcpHeader::new(
                op,
                xid,
                ciaddr,
                yiaddr,
                siaddr,
                giaddr,
                chaddr,
                self.options,
            ),
        };

        packet.validate()?;
        Ok(packet)
    }
}

impl DhcpPacket {
    /// Creates a new DHCP packet builder.
    pub fn builder() -> DhcpBuilder {
        DhcpBuilder::new()
    }

    /// Creates a new DHCP Discover packet.
    ///
    /// # Arguments
    /// * `xid` - Transaction ID
    /// * `chaddr` - Client hardware address
    pub fn discover(xid: u32, chaddr: MacAddress) -> Result<Self, PacketError> {
        DhcpBuilder::new()
            .op(1) // BOOTREQUEST
            .xid(xid)
            .chaddr(chaddr)
            .add_option(DhcpOption::message_type(MessageType::Discover))
            .add_option(DhcpOption::client_identifier(1, chaddr))
            .build()
    }

    /// Creates a new DHCP Request packet.
    ///
    /// # Arguments
    /// * `xid` - Transaction ID
    /// * `chaddr` - Client hardware address
    /// * `requested_ip` - Requested IP address
    /// * `server_id` - Server identifier
    pub fn request(
        xid: u32,
        chaddr: MacAddress,
        requested_ip: Ipv4Address,
        server_id: Ipv4Address,
    ) -> Result<Self, PacketError> {
        DhcpBuilder::new()
            .op(1) // BOOTREQUEST
            .xid(xid)
            .chaddr(chaddr)
            .add_option(DhcpOption::message_type(MessageType::Request))
            .add_option(DhcpOption::client_identifier(1, chaddr))
            .add_option(DhcpOption::requested_ip_address(requested_ip))
            .add_option(DhcpOption::server_identifier(server_id))
            .build()
    }
}

impl PacketHeader for DhcpHeader {
    fn header_length(&self) -> usize {
        let mut length = 240; // Fixed DHCP header size
        for option in &self.options {
            length += 2 + option.data.len(); // Code + Length + Data
        }
        length + 1 // End option
    }

    fn as_bytes(&self) -> Result<Vec<u8>, PacketError> {
        let mut bytes = Vec::with_capacity(self.header_length());
        
        // Fixed header fields
        bytes.push(self.op);
        bytes.push(self.htype);
        bytes.push(self.hlen);
        bytes.push(self.hops);
        bytes.extend_from_slice(&self.xid.to_be_bytes());
        bytes.extend_from_slice(&self.secs.to_be_bytes());
        bytes.extend_from_slice(&self.flags.to_be_bytes());
        bytes.extend_from_slice(self.ciaddr.as_bytes());
        bytes.extend_from_slice(self.yiaddr.as_bytes());
        bytes.extend_from_slice(self.siaddr.as_bytes());
        bytes.extend_from_slice(self.giaddr.as_bytes());
        bytes.extend_from_slice(self.chaddr.as_bytes());
        
        // Add padding to reach 236 bytes (16 bytes for chaddr + 64 bytes for sname + 128 bytes for file)
        bytes.extend(std::iter::repeat(0).take(236 - bytes.len()));
        
        // Magic cookie (required for DHCP)
        bytes.extend_from_slice(&[99, 130, 83, 99]);
        
        // Options
        for option in &self.options {
            bytes.extend_from_slice(&option.as_bytes());
        }
        
        // End option
        bytes.push(255);
        
        Ok(bytes)
    }
}

impl PacketBuilder for DhcpPacket {
    fn build(&self) -> Result<Vec<u8>, PacketError> {
        self.header.as_bytes()
    }

    fn length(&self) -> usize {
        self.header.header_length()
    }

    fn validate(&self) -> Result<(), PacketError> {
        // Validate message type option is present
        let has_message_type = self.header.options.iter().any(|opt| 
            opt.code == OptionCode::MessageType
        );
        
        if !has_message_type {
            return Err(PacketError::InvalidFieldValue(
                "DHCP message type option is required".to_string()
            ));
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_addresses() -> (MacAddress, Ipv4Address) {
        let chaddr = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let server_id = Ipv4Address::new([192, 168, 1, 1]);
        (chaddr, server_id)
    }

    #[test]
    fn test_dhcp_discover() {
        let (chaddr, _) = create_test_addresses();
        let xid = 0x12345678;
        
        let packet = DhcpPacket::discover(xid, chaddr).unwrap();
        
        assert_eq!(packet.header.op, 1);
        assert_eq!(packet.header.xid, xid);
        assert_eq!(packet.header.chaddr, chaddr);
        assert!(packet.validate().is_ok());
    }

    #[test]
    fn test_dhcp_request() {
        let (chaddr, server_id) = create_test_addresses();
        let xid = 0x12345678;
        let requested_ip = Ipv4Address::new([192, 168, 1, 100]);
        
        let packet = DhcpPacket::request(xid, chaddr, requested_ip, server_id).unwrap();
        
        assert_eq!(packet.header.op, 1);
        assert_eq!(packet.header.xid, xid);
        assert_eq!(packet.header.chaddr, chaddr);
        assert!(packet.validate().is_ok());
    }

    #[test]
    fn test_dhcp_builder() {
        let (chaddr, server_id) = create_test_addresses();
        
        let packet = DhcpPacket::builder()
            .op(1)
            .xid(0x12345678)
            .chaddr(chaddr)
            .add_option(DhcpOption::message_type(MessageType::Discover))
            .add_option(DhcpOption::server_identifier(server_id))
            .build()
            .unwrap();

        assert_eq!(packet.header.op, 1);
        assert_eq!(packet.header.chaddr, chaddr);
        assert!(packet.validate().is_ok());
    }

    #[test]
    fn test_invalid_dhcp_packet() {
        let (chaddr, _) = create_test_addresses();
        
        // Create packet without message type option
        let result = DhcpPacket::builder()
            .op(1)
            .xid(0x12345678)
            .chaddr(chaddr)
            .build();
            
        // The build should fail with the appropriate error
        assert!(result.is_err());
        match result {
            Err(PacketError::InvalidFieldValue(msg)) => {
                assert_eq!(msg, "DHCP message type option is required");
            }
            _ => panic!("Expected InvalidFieldValue error"),
        }
    }
} 