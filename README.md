# Packet Builder

A modular network packet builder library in Rust for creating, manipulating, and serializing network packets.

## Features

- Modular design with separate modules for different protocols
- Support for Ethernet, IPv4, TCP, UDP, ICMP, ARP, and DHCP packets
- Type-safe packet construction with validation
- Checksum calculation and verification
- Extensible architecture through traits
- Serialization support using serde

## Supported Protocols

- Ethernet (IEEE 802.3)
  - MAC addressing
  - EtherType selection
  - Payload encapsulation

- IPv4
  - Address handling
  - Protocol selection
  - Flags and fragmentation
  - Header checksum calculation

- TCP
  - Port management
  - Sequence and acknowledgment numbers
  - Flags (SYN, ACK, FIN, etc.)
  - Window size
  - Options support
  - Checksum calculation

- UDP
  - Port management
  - Length calculation
  - Checksum calculation

- ICMP
  - Message types (Echo, Destination Unreachable, etc.)
  - Code values
  - Sequence numbers
  - Identifier values
  - Checksum calculation

- ARP
  - Hardware types
  - Protocol types
  - Operation codes (Request/Reply)
  - Address resolution
  - Hardware and protocol address handling

- DHCP
  - Message types (Discover, Offer, Request, etc.)
  - Options handling
  - Address assignment
  - Configuration parameters
  - Client/Server communication

## Usage Examples

### Creating an Ethernet Packet

```rust
use packet_builder::ethernet::{EthernetPacket, MacAddress, EtherType};

let src_mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
let dst_mac = MacAddress::new([0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]);

let packet = EthernetPacket::builder()
    .src_mac(src_mac)
    .dst_mac(dst_mac)
    .ether_type(EtherType::IPv4)
    .payload(vec![1, 2, 3, 4])
    .build()
    .unwrap();

let bytes = packet.build().unwrap();
```

### Creating an IPv4 Packet

```rust
use packet_builder::ip::{Ipv4Packet, Ipv4Address, IpProtocol};

let src_ip = Ipv4Address::new([192, 168, 1, 1]);
let dst_ip = Ipv4Address::new([192, 168, 1, 2]);

let packet = Ipv4Packet::builder()
    .protocol(IpProtocol::TCP)
    .src_addr(src_ip)
    .dst_addr(dst_ip)
    .payload(vec![1, 2, 3, 4])
    .build()
    .unwrap();

let bytes = packet.build().unwrap();
```

### Creating a TCP Packet

```rust
use packet_builder::tcp::{TcpPacket, TcpFlags};

let mut flags = TcpFlags::new();
flags.syn = true;

let packet = TcpPacket::builder()
    .src_port(12345)
    .dst_port(80)
    .sequence(1000)
    .flags(flags)
    .payload(vec![1, 2, 3, 4])
    .build()
    .unwrap();

let bytes = packet.build().unwrap();
```

### Creating a UDP Packet

```rust
use packet_builder::udp::UdpPacket;

let packet = UdpPacket::builder()
    .src_port(12345)
    .dst_port(53)
    .payload(vec![1, 2, 3, 4])
    .build()
    .unwrap();

let bytes = packet.build().unwrap();
```

### Creating an ICMP Echo Request Packet

```rust
use packet_builder::icmp::{IcmpPacket, IcmpType};

let packet = IcmpPacket::echo_request(1, 1, b"Hello, World!".to_vec()).unwrap();
let bytes = packet.build().unwrap();
```

### Creating an ARP Request Packet

```rust
use packet_builder::arp::ArpPacket;
use packet_builder::ethernet::MacAddress;
use packet_builder::ip::Ipv4Address;

let src_mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
let src_ip = Ipv4Address::new([192, 168, 1, 1]);
let target_ip = Ipv4Address::new([192, 168, 1, 2]);

let packet = ArpPacket::request(src_mac, src_ip, target_ip).unwrap();
let bytes = packet.build().unwrap();
```

### Creating a DHCP Discover Packet

```rust
use packet_builder::dhcp::{DhcpPacket, MessageType};
use packet_builder::ethernet::MacAddress;

let chaddr = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
let xid = 0x12345678;

let packet = DhcpPacket::discover(xid, chaddr).unwrap();
let bytes = packet.build().unwrap();
```

## Error Handling

The library uses a custom error type `PacketError` for handling various error conditions:

- Invalid packet length
- Invalid checksum
- Serialization errors
- Invalid field values
- Buffer size issues
- Protocol version mismatches
- Header format errors
- Unsupported protocol errors

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 