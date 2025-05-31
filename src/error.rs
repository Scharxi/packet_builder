//! Error types for the packet builder library.
//!
//! This module defines the various error types that can occur during packet
//! construction, validation, and transmission.

use std::io;
use thiserror::Error;

/// Represents errors that can occur during packet operations.
///
/// This enum covers all possible error cases when working with network packets,
/// including construction, validation, serialization, and I/O operations.
#[derive(Debug, Error)]
pub enum PacketError {
    /// The packet length is invalid (too short or too long).
    #[error("Invalid packet length")]
    InvalidLength,
    
    /// The packet checksum is invalid or verification failed.
    #[error("Invalid checksum")]
    InvalidChecksum,
    
    /// An error occurred during packet serialization.
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    /// A field in the packet contains an invalid value.
    #[error("Invalid field value: {0}")]
    InvalidFieldValue(String),
    
    /// The provided buffer is too small to hold the packet.
    #[error("Buffer too small")]
    BufferTooSmall,
    
    /// The protocol version is not supported or invalid.
    #[error("Invalid protocol version")]
    InvalidProtocolVersion,
    
    /// The packet header format is invalid or corrupted.
    #[error("Invalid header format")]
    InvalidHeaderFormat,
    
    /// The specified protocol is not supported.
    #[error("Unsupported protocol: {0}")]
    UnsupportedProtocol(String),
    
    /// The requested operation is invalid in the current context.
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
    
    /// The network address is invalid or in an incorrect format.
    #[error("Invalid address")]
    InvalidAddress,
    
    /// A non-blocking operation would block.
    #[error("Operation would block")]
    WouldBlock,
    
    /// An I/O error occurred during packet operations.
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),
} 