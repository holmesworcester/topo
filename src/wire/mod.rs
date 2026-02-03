pub mod header;
pub mod envelope;
pub mod message;

pub use envelope::Envelope;

/// Total envelope size (header + payload, no signatures)
pub const ENVELOPE_SIZE: usize = 512;
/// Header size in bytes
pub const HEADER_SIZE: usize = 64;
/// Payload size in bytes
pub const PAYLOAD_SIZE: usize = 448;

/// Event types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EventType {
    Message = 1,
}

impl TryFrom<u8> for EventType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(EventType::Message),
            _ => Err(()),
        }
    }
}
