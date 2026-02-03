use nom::{
    bytes::complete::take,
    number::complete::{le_u16, le_u32, le_u64, u8},
    IResult,
};

use super::{EventType, HEADER_SIZE};

/// Wire header: 64 bytes
///
/// Layout:
/// - version: u8 (1 byte)
/// - event_type: u8 (1 byte)
/// - flags: u16 LE (2 bytes)
/// - signer_type: u8 (1 byte)
/// - count: u8 (1 byte)
/// - created_at_ms: u64 LE (8 bytes)
/// - ttl_ms: u32 LE (4 bytes)
/// - signer_id: [u8; 32] (32 bytes)
/// - reserved: [u8; 14] (14 bytes)
/// Total: 64 bytes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireHeader {
    pub version: u8,
    pub event_type: u8,
    pub flags: u16,
    pub signer_type: u8,
    pub count: u8,
    pub created_at_ms: u64,
    pub ttl_ms: u32,
    pub signer_id: [u8; 32],
    pub reserved: [u8; 14],
}

impl Default for WireHeader {
    fn default() -> Self {
        Self {
            version: 1,
            event_type: EventType::Message as u8,
            flags: 0,
            signer_type: 0,
            count: 1,
            created_at_ms: 0,
            ttl_ms: 0,
            signer_id: [0u8; 32],
            reserved: [0u8; 14],
        }
    }
}

impl WireHeader {
    /// Parse header from bytes using nom
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, version) = u8(input)?;
        let (input, event_type) = u8(input)?;
        let (input, flags) = le_u16(input)?;
        let (input, signer_type) = u8(input)?;
        let (input, count) = u8(input)?;
        let (input, created_at_ms) = le_u64(input)?;
        let (input, ttl_ms) = le_u32(input)?;
        let (input, signer_id_bytes) = take(32usize)(input)?;
        let (input, reserved_bytes) = take(14usize)(input)?;

        let mut signer_id = [0u8; 32];
        signer_id.copy_from_slice(signer_id_bytes);

        let mut reserved = [0u8; 14];
        reserved.copy_from_slice(reserved_bytes);

        Ok((
            input,
            WireHeader {
                version,
                event_type,
                flags,
                signer_type,
                count,
                created_at_ms,
                ttl_ms,
                signer_id,
                reserved,
            },
        ))
    }

    /// Encode header to bytes
    pub fn encode(&self, buf: &mut [u8]) {
        assert!(buf.len() >= HEADER_SIZE);
        buf[0] = self.version;
        buf[1] = self.event_type;
        buf[2..4].copy_from_slice(&self.flags.to_le_bytes());
        buf[4] = self.signer_type;
        buf[5] = self.count;
        buf[6..14].copy_from_slice(&self.created_at_ms.to_le_bytes());
        buf[14..18].copy_from_slice(&self.ttl_ms.to_le_bytes());
        buf[18..50].copy_from_slice(&self.signer_id);
        buf[50..64].copy_from_slice(&self.reserved);
    }

    /// Create header with current timestamp
    pub fn new_message(signer_id: [u8; 32]) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let created_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        Self {
            version: 1,
            event_type: EventType::Message as u8,
            flags: 0,
            signer_type: 0,
            count: 1,
            created_at_ms,
            ttl_ms: 0,
            signer_id,
            reserved: [0u8; 14],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let mut signer_id = [0u8; 32];
        for i in 0..32 {
            signer_id[i] = (i + 1) as u8;
        }

        let header = WireHeader {
            version: 1,
            event_type: 1,
            flags: 0x1234,
            signer_type: 2,
            count: 5,
            created_at_ms: 1234567890123,
            ttl_ms: 60000,
            signer_id,
            reserved: [0u8; 14],
        };

        let mut buf = [0u8; HEADER_SIZE];
        header.encode(&mut buf);

        let (remaining, parsed) = WireHeader::parse(&buf).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(header, parsed);
    }

    #[test]
    fn test_header_size() {
        assert_eq!(HEADER_SIZE, 64);
    }
}
