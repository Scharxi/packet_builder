# Packet Builder

A modular network packet builder library in Rust for creating, manipulating, and serializing network packets.

## Features

- Modular design with separate modules for different protocols
- Support for Ethernet, IPv4, TCP, and UDP packets
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

## Usage Examples

### Creating an Ethernet Packet

```rust
use packet_builder::ethernet::{EthernetPacket, MacAddress, EtherType};

let src_mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
let dst_mac = MacAddress::new([0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]);

let packet = EthernetPacket::new(dst_mac, src_mac, EtherType::IPv4)
    .with_payload(vec![1, 2, 3, 4]);

let bytes = packet.build().unwrap();
```

### Creating an IPv4 Packet

```rust
use packet_builder::ip::{Ipv4Packet, Ipv4Address, IpProtocol};

let src_ip = Ipv4Address::new([192, 168, 1, 1]);
let dst_ip = Ipv4Address::new([192, 168, 1, 2]);

let packet = Ipv4Packet::new(IpProtocol::TCP, src_ip, dst_ip)
    .with_payload(vec![1, 2, 3, 4]);

let bytes = packet.build().unwrap();
```

### Creating a TCP Packet

```rust
use packet_builder::tcp::{TcpPacket, TcpFlags};

let mut flags = TcpFlags::new();
flags.syn = true;

let packet = TcpPacket::new(12345, 80)
    .with_flags(flags)
    .with_sequence(1000)
    .with_payload(vec![1, 2, 3, 4]);

let bytes = packet.build().unwrap();
```

### Creating a UDP Packet

```rust
use packet_builder::udp::UdpPacket;

let packet = UdpPacket::new(12345, 53)
    .with_payload(vec![1, 2, 3, 4]);

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