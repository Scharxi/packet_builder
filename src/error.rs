use thiserror::Error;

#[derive(Debug, Error)]
pub enum PacketError {
    #[error("Invalid packet length")]
    InvalidLength,
    
    #[error("Invalid checksum")]
    InvalidChecksum,
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Invalid field value: {0}")]
    InvalidFieldValue(String),
    
    #[error("Buffer too small")]
    BufferTooSmall,
    
    #[error("Invalid protocol version")]
    InvalidProtocolVersion,
    
    #[error("Invalid header format")]
    InvalidHeaderFormat,
    
    #[error("Unsupported protocol: {0}")]
    UnsupportedProtocol(String),
} 