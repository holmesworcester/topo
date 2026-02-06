use crate::wire::ENVELOPE_SIZE;
use super::{MSG_TYPE_NEG_OPEN, MSG_TYPE_NEG_MSG, MSG_TYPE_HAVE_LIST, MSG_TYPE_EVENT, MSG_TYPE_DONE, MSG_TYPE_DONE_ACK, EVENT_SIZE};

/// Sync protocol messages
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncMessage {
    /// Initial negentropy reconciliation message
    NegOpen { msg: Vec<u8> },
    /// Negentropy reconciliation response
    NegMsg { msg: Vec<u8> },
    /// List of event IDs the client needs from server (32 bytes each)
    HaveList { ids: Vec<[u8; 32]> },
    /// Send full event blob
    Event { blob: Vec<u8> },
    /// Initiator signals all outgoing events have been sent
    Done,
    /// Responder acknowledges Done after draining its own queues
    DoneAck,
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
            if input.len() < EVENT_SIZE {
                return Err(ParseError::InsufficientData);
            }
            let blob = input[1..1 + ENVELOPE_SIZE].to_vec();
            Ok((SyncMessage::Event { blob }, EVENT_SIZE))
        }
        MSG_TYPE_DONE => Ok((SyncMessage::Done, 1)),
        MSG_TYPE_DONE_ACK => Ok((SyncMessage::DoneAck, 1)),
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
            let mut buf = Vec::with_capacity(EVENT_SIZE);
            buf.push(MSG_TYPE_EVENT);
            buf.extend_from_slice(blob);
            buf
        }
        SyncMessage::Done => vec![MSG_TYPE_DONE],
        SyncMessage::DoneAck => vec![MSG_TYPE_DONE_ACK],
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    InsufficientData,
    UnknownType(u8),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::InsufficientData => write!(f, "insufficient data"),
            ParseError::UnknownType(t) => write!(f, "unknown message type: {}", t),
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
        let blob = vec![3u8; ENVELOPE_SIZE];
        let msg = SyncMessage::Event { blob: blob.clone() };
        let encoded = encode_sync_message(&msg);
        assert_eq!(encoded.len(), EVENT_SIZE);

        let (parsed, consumed) = parse_sync_message(&encoded).unwrap();
        assert_eq!(consumed, EVENT_SIZE);
        assert_eq!(parsed, msg);
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
    fn test_message_sizes() {
        assert_eq!(EVENT_SIZE, 513);
    }
}
