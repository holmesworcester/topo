use nom::{bytes::complete::take, number::complete::le_u16, number::complete::le_u64, IResult};

use super::PAYLOAD_SIZE;

/// Message payload layout (448 bytes):
/// - channel_id: [u8; 32]
/// - author_id: [u8; 32]
/// - created_at_ms: u64 LE
/// - content_len: u16 LE
/// - content: [u8; 256] (UTF-8, zero-padded)
/// - reserved: [u8; 118]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessagePayload {
    pub channel_id: [u8; 32],
    pub author_id: [u8; 32],
    pub created_at_ms: u64,
    pub content: String,
}

impl MessagePayload {
    pub const CONTENT_MAX_LEN: usize = 256;

    /// Parse message payload from bytes
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, channel_id_bytes) = take(32usize)(input)?;
        let (input, author_id_bytes) = take(32usize)(input)?;
        let (input, created_at_ms) = le_u64(input)?;
        let (input, content_len) = le_u16(input)?;
        let (input, content_bytes) = take(256usize)(input)?;
        let (input, _reserved) = take(118usize)(input)?;

        let mut channel_id = [0u8; 32];
        channel_id.copy_from_slice(channel_id_bytes);

        let mut author_id = [0u8; 32];
        author_id.copy_from_slice(author_id_bytes);

        let content_len = content_len as usize;
        let content = String::from_utf8_lossy(&content_bytes[..content_len.min(256)]).to_string();

        Ok((
            input,
            MessagePayload {
                channel_id,
                author_id,
                created_at_ms,
                content,
            },
        ))
    }

    /// Encode message payload to bytes
    pub fn encode(&self, buf: &mut [u8]) {
        assert!(buf.len() >= PAYLOAD_SIZE);

        // Zero the buffer first
        buf[..PAYLOAD_SIZE].fill(0);

        buf[0..32].copy_from_slice(&self.channel_id);
        buf[32..64].copy_from_slice(&self.author_id);
        buf[64..72].copy_from_slice(&self.created_at_ms.to_le_bytes());

        let content_bytes = self.content.as_bytes();
        let content_len = content_bytes.len().min(Self::CONTENT_MAX_LEN);
        buf[72..74].copy_from_slice(&(content_len as u16).to_le_bytes());
        buf[74..74 + content_len].copy_from_slice(&content_bytes[..content_len]);
        // reserved bytes 330..448 are already zero
    }

    /// Create a new message
    pub fn new(
        channel_id: [u8; 32],
        author_id: [u8; 32],
        content: String,
    ) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let created_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        Self {
            channel_id,
            author_id,
            created_at_ms,
            content,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_roundtrip() {
        let msg = MessagePayload {
            channel_id: [1u8; 32],
            author_id: [2u8; 32],
            created_at_ms: 1234567890123,
            content: "Hello, world!".to_string(),
        };

        let mut buf = [0u8; PAYLOAD_SIZE];
        msg.encode(&mut buf);

        let (remaining, parsed) = MessagePayload::parse(&buf).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(msg, parsed);
    }

    #[test]
    fn test_message_new() {
        let msg = MessagePayload::new([1u8; 32], [2u8; 32], "test".to_string());
        assert_eq!(msg.channel_id, [1u8; 32]);
        assert_eq!(msg.author_id, [2u8; 32]);
        assert_eq!(msg.content, "test");
    }

    #[test]
    fn test_payload_size() {
        assert_eq!(PAYLOAD_SIZE, 448);
    }
}
