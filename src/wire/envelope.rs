use nom::IResult;

use super::{header::WireHeader, message::MessagePayload, EventType, ENVELOPE_SIZE, HEADER_SIZE, PAYLOAD_SIZE};
use crate::crypto::{hash_event, EventId};

/// Complete 448-byte envelope (header + payload)
#[derive(Debug, Clone)]
pub struct Envelope {
    pub header: WireHeader,
    pub payload: MessagePayload,
}

impl Envelope {
    /// Parse envelope from 448 bytes
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, header) = WireHeader::parse(input)?;
        let (input, payload) = MessagePayload::parse(input)?;
        Ok((input, Envelope { header, payload }))
    }

    /// Encode envelope to 448 bytes
    pub fn encode(&self) -> [u8; ENVELOPE_SIZE] {
        let mut buf = [0u8; ENVELOPE_SIZE];
        self.header.encode(&mut buf[..HEADER_SIZE]);
        self.payload.encode(&mut buf[HEADER_SIZE..]);
        buf
    }

    /// Compute event ID (Blake2b-256 hash of full envelope)
    pub fn compute_id(&self) -> EventId {
        let blob = self.encode();
        hash_event(&blob)
    }

    /// Create a new message envelope
    pub fn new_message(
        signer_id: [u8; 32],
        channel_id: [u8; 32],
        author_id: [u8; 32],
        prev_message_id: Option<[u8; 32]>,
        content: String,
    ) -> Self {
        let header = WireHeader::new_message(signer_id);
        let payload = MessagePayload::new(channel_id, author_id, prev_message_id, content);
        Self { header, payload }
    }

    /// Extract prev_message_id from blob without full parse
    pub fn extract_prev_id(blob: &[u8]) -> Option<EventId> {
        if blob.len() < ENVELOPE_SIZE {
            return None;
        }
        // prev_message_id is at offset 64 in payload (after header at 64, after channel_id and author_id)
        let offset = HEADER_SIZE + 64;
        let mut prev_id = [0u8; 32];
        prev_id.copy_from_slice(&blob[offset..offset + 32]);

        // Return None if all zeros
        if prev_id == [0u8; 32] {
            None
        } else {
            Some(prev_id)
        }
    }

    /// Extract created_at timestamp from blob without full parse (from header)
    pub fn extract_created_at(blob: &[u8]) -> Option<u64> {
        if blob.len() < ENVELOPE_SIZE {
            return None;
        }
        // created_at_ms is at offset 6 in header
        let bytes: [u8; 8] = blob[6..14].try_into().ok()?;
        Some(u64::from_le_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_roundtrip() {
        let envelope = Envelope::new_message(
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            Some([4u8; 32]),
            "Hello!".to_string(),
        );

        let blob = envelope.encode();
        assert_eq!(blob.len(), ENVELOPE_SIZE);

        let (remaining, parsed) = Envelope::parse(&blob).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(envelope.header, parsed.header);
        assert_eq!(envelope.payload, parsed.payload);
    }

    #[test]
    fn test_envelope_id_deterministic() {
        let envelope = Envelope::new_message(
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            None,
            "Test".to_string(),
        );

        let id1 = envelope.compute_id();
        let id2 = envelope.compute_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_extract_prev_id() {
        let envelope = Envelope::new_message(
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            Some([4u8; 32]),
            "Test".to_string(),
        );
        let blob = envelope.encode();

        let prev_id = Envelope::extract_prev_id(&blob).unwrap();
        assert_eq!(prev_id, [4u8; 32]);
    }

    #[test]
    fn test_extract_prev_id_none() {
        let envelope = Envelope::new_message(
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            None,
            "Test".to_string(),
        );
        let blob = envelope.encode();

        assert!(Envelope::extract_prev_id(&blob).is_none());
    }

    #[test]
    fn test_envelope_size() {
        assert_eq!(ENVELOPE_SIZE, 512);
        assert_eq!(HEADER_SIZE + PAYLOAD_SIZE, ENVELOPE_SIZE);
    }
}
