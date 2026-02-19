use crate::event_modules::EVENT_MAX_BLOB_BYTES;
use super::{MSG_TYPE_NEG_OPEN, MSG_TYPE_NEG_MSG, MSG_TYPE_HAVE_LIST, MSG_TYPE_EVENT, MSG_TYPE_DONE, MSG_TYPE_DONE_ACK, MSG_TYPE_DATA_DONE, MSG_TYPE_INTRO_OFFER};

/// Max negentropy message payload: 4 MiB (generous for large reconciliation rounds)
const MAX_NEG_MSG_BYTES: usize = 4 * 1024 * 1024;
/// Max number of event IDs in a HaveList message
const MAX_HAVE_LIST_IDS: usize = 100_000;

/// Sync protocol messages
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncMessage {
    /// Initial negentropy reconciliation message
    NegOpen { msg: Vec<u8> },
    /// Negentropy reconciliation response
    NegMsg { msg: Vec<u8> },
    /// List of event IDs the client needs from server (32 bytes each)
    HaveList { ids: Vec<[u8; 32]> },
    /// Send full event blob (variable length)
    Event { blob: Vec<u8> },
    /// Initiator signals all outgoing events have been sent
    Done,
    /// Responder acknowledges Done after draining its own queues
    DoneAck,
    /// Sent on data stream to signal no more events will follow
    DataDone,
    /// Intro offer for QUIC hole punching via a third peer
    IntroOffer {
        intro_id: [u8; 16],
        other_peer_id: [u8; 32],
        origin_family: u8,
        origin_ip: [u8; 16],
        origin_port: u16,
        observed_at_ms: u64,
        expires_at_ms: u64,
        attempt_window_ms: u32,
    },
}


/// Parse a sync message from bytes
pub fn parse_sync_message(input: &[u8]) -> Result<(SyncMessage, usize), ParseError> {
    if input.is_empty() {
        return Err(ParseError::InsufficientData);
    }

    let msg_type = input[0];

    match msg_type {
        MSG_TYPE_NEG_OPEN | MSG_TYPE_NEG_MSG => {
            // Variable length: type(1) + len(4) + data(len)
            if input.len() < 5 {
                return Err(ParseError::InsufficientData);
            }
            let len = u32::from_le_bytes([input[1], input[2], input[3], input[4]]) as usize;
            if len > MAX_NEG_MSG_BYTES {
                return Err(ParseError::NegMessageTooLarge(len));
            }
            let total_size = 5 + len;
            if input.len() < total_size {
                return Err(ParseError::InsufficientData);
            }
            let msg = input[5..total_size].to_vec();
            let sync_msg = if msg_type == MSG_TYPE_NEG_OPEN {
                SyncMessage::NegOpen { msg }
            } else {
                SyncMessage::NegMsg { msg }
            };
            Ok((sync_msg, total_size))
        }
        MSG_TYPE_HAVE_LIST => {
            // Variable length: type(1) + count(4) + ids(count * 32)
            if input.len() < 5 {
                return Err(ParseError::InsufficientData);
            }
            let count = u32::from_le_bytes([input[1], input[2], input[3], input[4]]) as usize;
            if count > MAX_HAVE_LIST_IDS {
                return Err(ParseError::TooManyIds(count));
            }
            let total_size = 5 + count * 32;
            if input.len() < total_size {
                return Err(ParseError::InsufficientData);
            }
            let mut ids = Vec::with_capacity(count);
            for i in 0..count {
                let start = 5 + i * 32;
                let mut id = [0u8; 32];
                id.copy_from_slice(&input[start..start + 32]);
                ids.push(id);
            }
            Ok((SyncMessage::HaveList { ids }, total_size))
        }
        MSG_TYPE_EVENT => {
            // Variable length: type(1) + len(4) + blob(len)
            if input.len() < 5 {
                return Err(ParseError::InsufficientData);
            }
            let len = u32::from_le_bytes([input[1], input[2], input[3], input[4]]) as usize;
            if len > EVENT_MAX_BLOB_BYTES {
                return Err(ParseError::EventTooLarge(len));
            }
            let total_size = 5 + len;
            if input.len() < total_size {
                return Err(ParseError::InsufficientData);
            }
            let blob = input[5..total_size].to_vec();
            Ok((SyncMessage::Event { blob }, total_size))
        }
        MSG_TYPE_DONE => Ok((SyncMessage::Done, 1)),
        MSG_TYPE_DONE_ACK => Ok((SyncMessage::DoneAck, 1)),
        MSG_TYPE_DATA_DONE => Ok((SyncMessage::DataDone, 1)),
        MSG_TYPE_INTRO_OFFER => {
            // Fixed layout: type(1) + intro_id(16) + other_peer_id(32)
            //   + origin_family(1) + origin_ip(16) + origin_port(2)
            //   + observed_at_ms(8) + expires_at_ms(8) + attempt_window_ms(4) = 88
            const INTRO_OFFER_SIZE: usize = 1 + 16 + 32 + 1 + 16 + 2 + 8 + 8 + 4;
            if input.len() < INTRO_OFFER_SIZE {
                return Err(ParseError::InsufficientData);
            }
            let mut pos = 1;
            let mut intro_id = [0u8; 16];
            intro_id.copy_from_slice(&input[pos..pos + 16]);
            pos += 16;
            let mut other_peer_id = [0u8; 32];
            other_peer_id.copy_from_slice(&input[pos..pos + 32]);
            pos += 32;
            let origin_family = input[pos];
            pos += 1;
            let mut origin_ip = [0u8; 16];
            origin_ip.copy_from_slice(&input[pos..pos + 16]);
            pos += 16;
            let origin_port = u16::from_le_bytes([input[pos], input[pos + 1]]);
            pos += 2;
            let observed_at_ms = u64::from_le_bytes(input[pos..pos + 8].try_into().unwrap());
            pos += 8;
            let expires_at_ms = u64::from_le_bytes(input[pos..pos + 8].try_into().unwrap());
            pos += 8;
            let attempt_window_ms = u32::from_le_bytes(input[pos..pos + 4].try_into().unwrap());
            pos += 4;
            debug_assert_eq!(pos, INTRO_OFFER_SIZE);
            Ok((SyncMessage::IntroOffer {
                intro_id,
                other_peer_id,
                origin_family,
                origin_ip,
                origin_port,
                observed_at_ms,
                expires_at_ms,
                attempt_window_ms,
            }, INTRO_OFFER_SIZE))
        }
        _ => Err(ParseError::UnknownType(msg_type)),
    }
}

/// Encode a sync message to bytes
pub fn encode_sync_message(msg: &SyncMessage) -> Vec<u8> {
    match msg {
        SyncMessage::NegOpen { msg: data } => {
            let mut buf = Vec::with_capacity(5 + data.len());
            buf.push(MSG_TYPE_NEG_OPEN);
            buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
            buf.extend_from_slice(data);
            buf
        }
        SyncMessage::NegMsg { msg: data } => {
            let mut buf = Vec::with_capacity(5 + data.len());
            buf.push(MSG_TYPE_NEG_MSG);
            buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
            buf.extend_from_slice(data);
            buf
        }
        SyncMessage::HaveList { ids } => {
            let mut buf = Vec::with_capacity(5 + ids.len() * 32);
            buf.push(MSG_TYPE_HAVE_LIST);
            buf.extend_from_slice(&(ids.len() as u32).to_le_bytes());
            for id in ids {
                buf.extend_from_slice(id);
            }
            buf
        }
        SyncMessage::Event { blob } => {
            let mut buf = Vec::with_capacity(5 + blob.len());
            buf.push(MSG_TYPE_EVENT);
            buf.extend_from_slice(&(blob.len() as u32).to_le_bytes());
            buf.extend_from_slice(blob);
            buf
        }
        SyncMessage::Done => vec![MSG_TYPE_DONE],
        SyncMessage::DoneAck => vec![MSG_TYPE_DONE_ACK],
        SyncMessage::DataDone => vec![MSG_TYPE_DATA_DONE],
        SyncMessage::IntroOffer {
            intro_id,
            other_peer_id,
            origin_family,
            origin_ip,
            origin_port,
            observed_at_ms,
            expires_at_ms,
            attempt_window_ms,
        } => {
            let mut buf = Vec::with_capacity(88);
            buf.push(MSG_TYPE_INTRO_OFFER);
            buf.extend_from_slice(intro_id);
            buf.extend_from_slice(other_peer_id);
            buf.push(*origin_family);
            buf.extend_from_slice(origin_ip);
            buf.extend_from_slice(&origin_port.to_le_bytes());
            buf.extend_from_slice(&observed_at_ms.to_le_bytes());
            buf.extend_from_slice(&expires_at_ms.to_le_bytes());
            buf.extend_from_slice(&attempt_window_ms.to_le_bytes());
            buf
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    InsufficientData,
    UnknownType(u8),
    EventTooLarge(usize),
    NegMessageTooLarge(usize),
    TooManyIds(usize),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::InsufficientData => write!(f, "insufficient data"),
            ParseError::UnknownType(t) => write!(f, "unknown message type: {}", t),
            ParseError::EventTooLarge(len) => write!(f, "event too large: {} bytes", len),
            ParseError::NegMessageTooLarge(len) => write!(f, "negentropy message too large: {} bytes", len),
            ParseError::TooManyIds(count) => write!(f, "too many IDs in have_list: {}", count),
        }
    }
}

impl std::error::Error for ParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_neg_open_roundtrip() {
        let msg = SyncMessage::NegOpen { msg: vec![1, 2, 3, 4, 5] };
        let encoded = encode_sync_message(&msg);
        assert_eq!(encoded.len(), 10); // 1 + 4 + 5

        let (parsed, consumed) = parse_sync_message(&encoded).unwrap();
        assert_eq!(consumed, 10);
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_neg_msg_roundtrip() {
        let msg = SyncMessage::NegMsg { msg: vec![10, 20, 30] };
        let encoded = encode_sync_message(&msg);
        assert_eq!(encoded.len(), 8); // 1 + 4 + 3

        let (parsed, consumed) = parse_sync_message(&encoded).unwrap();
        assert_eq!(consumed, 8);
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_event_roundtrip() {
        let blob = vec![3u8; 100];
        let msg = SyncMessage::Event { blob: blob.clone() };
        let encoded = encode_sync_message(&msg);
        assert_eq!(encoded.len(), 5 + 100); // type(1) + len(4) + blob(100)

        let (parsed, consumed) = parse_sync_message(&encoded).unwrap();
        assert_eq!(consumed, 105);
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_event_variable_sizes() {
        for size in [0, 1, 75, 100, 512, 1000, 10000] {
            let blob = vec![0xABu8; size];
            let msg = SyncMessage::Event { blob: blob.clone() };
            let encoded = encode_sync_message(&msg);
            assert_eq!(encoded.len(), 5 + size);
            let (parsed, consumed) = parse_sync_message(&encoded).unwrap();
            assert_eq!(consumed, 5 + size);
            assert_eq!(parsed, msg);
        }
    }

    #[test]
    fn test_event_too_large() {
        let len = EVENT_MAX_BLOB_BYTES + 1;
        // Craft a header that claims a too-large length
        let mut buf = vec![MSG_TYPE_EVENT];
        buf.extend_from_slice(&(len as u32).to_le_bytes());
        // Don't need actual data — parser should reject based on length
        buf.extend_from_slice(&vec![0u8; len]);
        let result = parse_sync_message(&buf);
        assert_eq!(result, Err(ParseError::EventTooLarge(len)));
    }

    #[test]
    fn test_parse_insufficient_data() {
        let result = parse_sync_message(&[MSG_TYPE_NEG_OPEN]);
        assert_eq!(result, Err(ParseError::InsufficientData));
    }

    #[test]
    fn test_parse_unknown_type() {
        let result = parse_sync_message(&[0xFF, 0, 0, 0, 0]);
        assert_eq!(result, Err(ParseError::UnknownType(0xFF)));
    }
    #[test]
    fn test_done_roundtrip() {
        let msg = SyncMessage::Done;
        let encoded = encode_sync_message(&msg);
        assert_eq!(encoded.len(), 1);
        let (parsed, consumed) = parse_sync_message(&encoded).unwrap();
        assert_eq!(consumed, 1);
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_done_ack_roundtrip() {
        let msg = SyncMessage::DoneAck;
        let encoded = encode_sync_message(&msg);
        assert_eq!(encoded.len(), 1);
        let (parsed, consumed) = parse_sync_message(&encoded).unwrap();
        assert_eq!(consumed, 1);
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_data_done_roundtrip() {
        let msg = SyncMessage::DataDone;
        let encoded = encode_sync_message(&msg);
        assert_eq!(encoded.len(), 1);
        let (parsed, consumed) = parse_sync_message(&encoded).unwrap();
        assert_eq!(consumed, 1);
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_intro_offer_roundtrip() {
        let msg = SyncMessage::IntroOffer {
            intro_id: [0xAA; 16],
            other_peer_id: [0xBB; 32],
            origin_family: 4,
            origin_ip: {
                // IPv4 192.168.1.100 mapped to 16-byte field
                let mut ip = [0u8; 16];
                ip[12] = 192; ip[13] = 168; ip[14] = 1; ip[15] = 100;
                ip
            },
            origin_port: 12345,
            observed_at_ms: 1700000000000,
            expires_at_ms: 1700000030000,
            attempt_window_ms: 4000,
        };
        let encoded = encode_sync_message(&msg);
        assert_eq!(encoded.len(), 88); // type(1) + fixed payload(87)
        let (parsed, consumed) = parse_sync_message(&encoded).unwrap();
        assert_eq!(consumed, 88);
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_intro_offer_ipv6_roundtrip() {
        let msg = SyncMessage::IntroOffer {
            intro_id: [0x01; 16],
            other_peer_id: [0x02; 32],
            origin_family: 6,
            origin_ip: [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            origin_port: 443,
            observed_at_ms: u64::MAX - 1,
            expires_at_ms: u64::MAX,
            attempt_window_ms: 10000,
        };
        let encoded = encode_sync_message(&msg);
        assert_eq!(encoded.len(), 88);
        let (parsed, consumed) = parse_sync_message(&encoded).unwrap();
        assert_eq!(consumed, 88);
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_intro_offer_insufficient_data() {
        // Just the type byte, no payload
        let result = parse_sync_message(&[MSG_TYPE_INTRO_OFFER]);
        assert_eq!(result, Err(ParseError::InsufficientData));

        // Partial payload (50 of 87 needed)
        let mut buf = vec![MSG_TYPE_INTRO_OFFER];
        buf.extend_from_slice(&[0u8; 50]);
        let result = parse_sync_message(&buf);
        assert_eq!(result, Err(ParseError::InsufficientData));
    }

    #[test]
    fn test_neg_message_too_large() {
        let oversized_len = (MAX_NEG_MSG_BYTES + 1) as u32;
        let mut buf = vec![MSG_TYPE_NEG_OPEN];
        buf.extend_from_slice(&oversized_len.to_le_bytes());
        buf.extend_from_slice(&vec![0u8; MAX_NEG_MSG_BYTES + 1]);
        let result = parse_sync_message(&buf);
        assert_eq!(result, Err(ParseError::NegMessageTooLarge(MAX_NEG_MSG_BYTES + 1)));

        // Also test NEG_MSG
        buf[0] = MSG_TYPE_NEG_MSG;
        let result = parse_sync_message(&buf);
        assert_eq!(result, Err(ParseError::NegMessageTooLarge(MAX_NEG_MSG_BYTES + 1)));
    }

    #[test]
    fn test_neg_message_at_limit_ok() {
        let max_len = MAX_NEG_MSG_BYTES as u32;
        let mut buf = vec![MSG_TYPE_NEG_OPEN];
        buf.extend_from_slice(&max_len.to_le_bytes());
        buf.extend_from_slice(&vec![0u8; MAX_NEG_MSG_BYTES]);
        let (msg, consumed) = parse_sync_message(&buf).unwrap();
        assert_eq!(consumed, 5 + MAX_NEG_MSG_BYTES);
        assert!(matches!(msg, SyncMessage::NegOpen { .. }));
    }

    #[test]
    fn test_have_list_too_many_ids() {
        let oversized_count = (MAX_HAVE_LIST_IDS + 1) as u32;
        let mut buf = vec![MSG_TYPE_HAVE_LIST];
        buf.extend_from_slice(&oversized_count.to_le_bytes());
        // Don't need full data — parser should reject based on count
        let result = parse_sync_message(&buf);
        assert_eq!(result, Err(ParseError::TooManyIds(MAX_HAVE_LIST_IDS + 1)));
    }

    #[test]
    fn test_have_list_at_limit_ok() {
        let max_count = MAX_HAVE_LIST_IDS as u32;
        let mut buf = vec![MSG_TYPE_HAVE_LIST];
        buf.extend_from_slice(&max_count.to_le_bytes());
        buf.extend_from_slice(&vec![0u8; MAX_HAVE_LIST_IDS * 32]);
        let (msg, consumed) = parse_sync_message(&buf).unwrap();
        assert_eq!(consumed, 5 + MAX_HAVE_LIST_IDS * 32);
        if let SyncMessage::HaveList { ids } = msg {
            assert_eq!(ids.len(), MAX_HAVE_LIST_IDS);
        } else {
            panic!("expected HaveList");
        }
    }
}
