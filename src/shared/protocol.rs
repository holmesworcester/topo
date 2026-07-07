use crate::crypto::EventId;
use crate::event_modules::EVENT_MAX_BLOB_BYTES;
use negentropy::Id;

/// Convert negentropy Id to our EventId
pub fn neg_id_to_event_id(id: &Id) -> EventId {
    *id.as_bytes()
}

/// Sync message types
pub const MSG_TYPE_NEG_OPEN: u8 = 0x10; // Initial negentropy message
pub const MSG_TYPE_NEG_MSG: u8 = 0x11; // Negentropy response
pub const MSG_TYPE_RATELESS_OPEN: u8 = 0x12; // Initial rateless snapshot message
pub const MSG_TYPE_RATELESS_HEADER: u8 = 0x13; // Rateless snapshot metadata
pub const MSG_TYPE_RATELESS_SYMBOL: u8 = 0x14; // Rateless coded symbol
pub const MSG_TYPE_RANGE_POLICY_REJECT: u8 = 0x15; // Peer explicitly rejects a sync window policy
pub const MSG_TYPE_EVENT: u8 = 0x03; // Event blob (variable length)
pub const MSG_TYPE_RANGE_SUPPRESS_IDS: u8 = 0x04; // Suppress queued event ids on the active data session
pub const MSG_TYPE_RANGE_DATA_DONE: u8 = 0x05; // No more event blobs will be sent on this data session
pub const MSG_TYPE_OPEN_SESSION_AUTH_INVITE: u8 = 0x31;
pub const MSG_TYPE_OPEN_SESSION_AUTH_ACK: u8 = 0x32;
pub const MSG_TYPE_OPEN_SESSION_ROUTE: u8 = 0x33;

/// Max negentropy message payload.  With frame_size_limit=0 (unlimited), the
/// negentropy library may produce multi-MB messages for large divergent sets
/// (e.g. 500k items ≈ 18 MB of IdLists in worst case).  128 MiB leaves ample
/// headroom without risking OOM from a single malformed frame.
const MAX_NEG_MSG_BYTES: usize = 128 * 1024 * 1024;
const MAX_SUPPRESSION_IDS_PER_FRAME: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenSessionAuthInvite {
    pub source_peer_id: [u8; 32],
    pub source_peer_public_key: [u8; 32],
    pub target_invite_event_id: EventId,
    pub local_daemon_peer_id: [u8; 32],
    pub remote_daemon_peer_id: [u8; 32],
    pub expires_at_ms: u64,
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenSessionAuthAck {
    pub target_tenant_id: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenSessionRoute {
    pub source_peer_id: [u8; 32],
    pub target_tenant_id: [u8; 32],
}

/// Sync protocol messages
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// Initial negentropy reconciliation message
    NegOpen {
        msg: Vec<u8>,
    },
    /// Negentropy reconciliation response
    NegMsg {
        msg: Vec<u8>,
    },
    /// Initial rateless snapshot/spray message
    RatelessOpen {
        msg: Vec<u8>,
    },
    /// Rateless snapshot metadata for one spray generation
    RatelessHeader {
        chunk_size: u32,
        source_symbols: u32,
        symbols_sent: u32,
        total_bytes: u64,
        total_events: u32,
        seed: [u8; 32],
    },
    /// One coded rateless symbol for the current snapshot generation
    RatelessSymbol {
        symbol_index: u32,
        payload: Vec<u8>,
    },
    /// Peer explicitly rejected the requested sync window and advertises the
    /// oldest window kind it is willing to accept.
    RangePolicyReject {
        rejected_window_kind: u8,
        oldest_allowed_window_kind: u8,
    },
    /// Send full event blob (variable length)
    Event {
        blob: Vec<u8>,
    },
    /// Best-effort request to stop sending these ids on the current data session.
    SuppressIds {
        ids: Vec<EventId>,
    },
    /// Sender has finished emitting event blobs for the current data session.
    RangeDataDone,
    OpenSessionAuthInvite {
        auth: OpenSessionAuthInvite,
    },
    OpenSessionAuthAck {
        ack: OpenSessionAuthAck,
    },
    OpenSessionRoute {
        route: OpenSessionRoute,
    },
}

/// Parse a frame from bytes
pub fn parse_frame(input: &[u8]) -> Result<(Frame, usize), ParseError> {
    if input.is_empty() {
        return Err(ParseError::InsufficientData);
    }

    let msg_type = input[0];

    match msg_type {
        MSG_TYPE_NEG_OPEN | MSG_TYPE_NEG_MSG | MSG_TYPE_RATELESS_OPEN => {
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
            let sync_msg = match msg_type {
                MSG_TYPE_NEG_OPEN => Frame::NegOpen { msg },
                MSG_TYPE_NEG_MSG => Frame::NegMsg { msg },
                MSG_TYPE_RATELESS_OPEN => Frame::RatelessOpen { msg },
                _ => unreachable!("unexpected control message type"),
            };
            Ok((sync_msg, total_size))
        }
        MSG_TYPE_RATELESS_HEADER => {
            const HEADER_SIZE: usize = 1 + 4 + 4 + 4 + 8 + 4 + 32;
            if input.len() < HEADER_SIZE {
                return Err(ParseError::InsufficientData);
            }
            let chunk_size = u32::from_le_bytes(input[1..5].try_into().unwrap());
            let source_symbols = u32::from_le_bytes(input[5..9].try_into().unwrap());
            let symbols_sent = u32::from_le_bytes(input[9..13].try_into().unwrap());
            let total_bytes = u64::from_le_bytes(input[13..21].try_into().unwrap());
            let total_events = u32::from_le_bytes(input[21..25].try_into().unwrap());
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&input[25..57]);
            Ok((
                Frame::RatelessHeader {
                    chunk_size,
                    source_symbols,
                    symbols_sent,
                    total_bytes,
                    total_events,
                    seed,
                },
                HEADER_SIZE,
            ))
        }
        MSG_TYPE_RATELESS_SYMBOL => {
            if input.len() < 9 {
                return Err(ParseError::InsufficientData);
            }
            let symbol_index = u32::from_le_bytes(input[1..5].try_into().unwrap());
            let len = u32::from_le_bytes(input[5..9].try_into().unwrap()) as usize;
            if len > MAX_NEG_MSG_BYTES {
                return Err(ParseError::NegMessageTooLarge(len));
            }
            let total_size = 9 + len;
            if input.len() < total_size {
                return Err(ParseError::InsufficientData);
            }
            let payload = input[9..total_size].to_vec();
            Ok((
                Frame::RatelessSymbol {
                    symbol_index,
                    payload,
                },
                total_size,
            ))
        }
        MSG_TYPE_RANGE_POLICY_REJECT => {
            const RANGE_POLICY_REJECT_SIZE: usize = 3;
            if input.len() < RANGE_POLICY_REJECT_SIZE {
                return Err(ParseError::InsufficientData);
            }
            Ok((
                Frame::RangePolicyReject {
                    rejected_window_kind: input[1],
                    oldest_allowed_window_kind: input[2],
                },
                RANGE_POLICY_REJECT_SIZE,
            ))
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
            Ok((Frame::Event { blob }, total_size))
        }
        MSG_TYPE_RANGE_SUPPRESS_IDS => {
            if input.len() < 3 {
                return Err(ParseError::InsufficientData);
            }
            let count = u16::from_le_bytes([input[1], input[2]]) as usize;
            if count > MAX_SUPPRESSION_IDS_PER_FRAME {
                return Err(ParseError::TooManyIds(count));
            }
            let total_size = 3 + (count * 32);
            if input.len() < total_size {
                return Err(ParseError::InsufficientData);
            }
            let mut ids = Vec::with_capacity(count);
            let mut pos = 3;
            for _ in 0..count {
                let mut event_id = [0u8; 32];
                event_id.copy_from_slice(&input[pos..pos + 32]);
                ids.push(event_id);
                pos += 32;
            }
            Ok((Frame::SuppressIds { ids }, total_size))
        }
        MSG_TYPE_RANGE_DATA_DONE => Ok((Frame::RangeDataDone, 1)),
        MSG_TYPE_OPEN_SESSION_AUTH_INVITE => {
            const AUTH_SIZE: usize = 1 + 32 + 32 + 32 + 32 + 32 + 8 + 64;
            if input.len() < AUTH_SIZE {
                return Err(ParseError::InsufficientData);
            }
            let mut pos = 1;
            let mut source_peer_id = [0u8; 32];
            source_peer_id.copy_from_slice(&input[pos..pos + 32]);
            pos += 32;
            let mut source_peer_public_key = [0u8; 32];
            source_peer_public_key.copy_from_slice(&input[pos..pos + 32]);
            pos += 32;
            let mut target_invite_event_id = [0u8; 32];
            target_invite_event_id.copy_from_slice(&input[pos..pos + 32]);
            pos += 32;
            let mut local_daemon_peer_id = [0u8; 32];
            local_daemon_peer_id.copy_from_slice(&input[pos..pos + 32]);
            pos += 32;
            let mut remote_daemon_peer_id = [0u8; 32];
            remote_daemon_peer_id.copy_from_slice(&input[pos..pos + 32]);
            pos += 32;
            let expires_at_ms = u64::from_le_bytes(input[pos..pos + 8].try_into().unwrap());
            pos += 8;
            let mut signature = [0u8; 64];
            signature.copy_from_slice(&input[pos..pos + 64]);
            pos += 64;
            debug_assert_eq!(pos, AUTH_SIZE);
            Ok((
                Frame::OpenSessionAuthInvite {
                    auth: OpenSessionAuthInvite {
                        source_peer_id,
                        source_peer_public_key,
                        target_invite_event_id,
                        local_daemon_peer_id,
                        remote_daemon_peer_id,
                        expires_at_ms,
                        signature,
                    },
                },
                AUTH_SIZE,
            ))
        }
        MSG_TYPE_OPEN_SESSION_AUTH_ACK => {
            const ACK_SIZE: usize = 1 + 32;
            if input.len() < ACK_SIZE {
                return Err(ParseError::InsufficientData);
            }
            let mut target_tenant_id = [0u8; 32];
            target_tenant_id.copy_from_slice(&input[1..33]);
            Ok((
                Frame::OpenSessionAuthAck {
                    ack: OpenSessionAuthAck { target_tenant_id },
                },
                ACK_SIZE,
            ))
        }
        MSG_TYPE_OPEN_SESSION_ROUTE => {
            const ROUTE_SIZE: usize = 1 + 32 + 32;
            if input.len() < ROUTE_SIZE {
                return Err(ParseError::InsufficientData);
            }
            let mut source_peer_id = [0u8; 32];
            source_peer_id.copy_from_slice(&input[1..33]);
            let mut target_tenant_id = [0u8; 32];
            target_tenant_id.copy_from_slice(&input[33..65]);
            Ok((
                Frame::OpenSessionRoute {
                    route: OpenSessionRoute {
                        source_peer_id,
                        target_tenant_id,
                    },
                },
                ROUTE_SIZE,
            ))
        }
        _ => Err(ParseError::UnknownType(msg_type)),
    }
}

/// Encode a frame to bytes
pub fn encode_frame(msg: &Frame) -> Vec<u8> {
    match msg {
        Frame::NegOpen { msg: data } => {
            let mut buf = Vec::with_capacity(5 + data.len());
            buf.push(MSG_TYPE_NEG_OPEN);
            buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
            buf.extend_from_slice(data);
            buf
        }
        Frame::NegMsg { msg: data } => {
            let mut buf = Vec::with_capacity(5 + data.len());
            buf.push(MSG_TYPE_NEG_MSG);
            buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
            buf.extend_from_slice(data);
            buf
        }
        Frame::RatelessOpen { msg: data } => {
            let mut buf = Vec::with_capacity(5 + data.len());
            buf.push(MSG_TYPE_RATELESS_OPEN);
            buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
            buf.extend_from_slice(data);
            buf
        }
        Frame::RatelessHeader {
            chunk_size,
            source_symbols,
            symbols_sent,
            total_bytes,
            total_events,
            seed,
        } => {
            let mut buf = Vec::with_capacity(1 + 4 + 4 + 4 + 8 + 4 + 32);
            buf.push(MSG_TYPE_RATELESS_HEADER);
            buf.extend_from_slice(&chunk_size.to_le_bytes());
            buf.extend_from_slice(&source_symbols.to_le_bytes());
            buf.extend_from_slice(&symbols_sent.to_le_bytes());
            buf.extend_from_slice(&total_bytes.to_le_bytes());
            buf.extend_from_slice(&total_events.to_le_bytes());
            buf.extend_from_slice(seed);
            buf
        }
        Frame::RatelessSymbol {
            symbol_index,
            payload,
        } => {
            let mut buf = Vec::with_capacity(9 + payload.len());
            buf.push(MSG_TYPE_RATELESS_SYMBOL);
            buf.extend_from_slice(&symbol_index.to_le_bytes());
            buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            buf.extend_from_slice(payload);
            buf
        }
        Frame::RangePolicyReject {
            rejected_window_kind,
            oldest_allowed_window_kind,
        } => {
            let mut buf = Vec::with_capacity(3);
            buf.push(MSG_TYPE_RANGE_POLICY_REJECT);
            buf.push(*rejected_window_kind);
            buf.push(*oldest_allowed_window_kind);
            buf
        }
        Frame::Event { blob } => {
            let mut buf = Vec::with_capacity(5 + blob.len());
            buf.push(MSG_TYPE_EVENT);
            buf.extend_from_slice(&(blob.len() as u32).to_le_bytes());
            buf.extend_from_slice(blob);
            buf
        }
        Frame::SuppressIds { ids } => {
            let id_count = u16::try_from(ids.len()).expect("suppression id count must fit in u16");
            let mut buf = Vec::with_capacity(3 + ids.len() * 32);
            buf.push(MSG_TYPE_RANGE_SUPPRESS_IDS);
            buf.extend_from_slice(&id_count.to_le_bytes());
            for event_id in ids {
                buf.extend_from_slice(event_id);
            }
            buf
        }
        Frame::RangeDataDone => vec![MSG_TYPE_RANGE_DATA_DONE],
        Frame::OpenSessionAuthInvite { auth } => {
            let mut buf = Vec::with_capacity(1 + 32 + 32 + 32 + 32 + 32 + 8 + 64);
            buf.push(MSG_TYPE_OPEN_SESSION_AUTH_INVITE);
            buf.extend_from_slice(&auth.source_peer_id);
            buf.extend_from_slice(&auth.source_peer_public_key);
            buf.extend_from_slice(&auth.target_invite_event_id);
            buf.extend_from_slice(&auth.local_daemon_peer_id);
            buf.extend_from_slice(&auth.remote_daemon_peer_id);
            buf.extend_from_slice(&auth.expires_at_ms.to_le_bytes());
            buf.extend_from_slice(&auth.signature);
            buf
        }
        Frame::OpenSessionAuthAck { ack } => {
            let mut buf = Vec::with_capacity(1 + 32);
            buf.push(MSG_TYPE_OPEN_SESSION_AUTH_ACK);
            buf.extend_from_slice(&ack.target_tenant_id);
            buf
        }
        Frame::OpenSessionRoute { route } => {
            let mut buf = Vec::with_capacity(1 + 32 + 32);
            buf.push(MSG_TYPE_OPEN_SESSION_ROUTE);
            buf.extend_from_slice(&route.source_peer_id);
            buf.extend_from_slice(&route.target_tenant_id);
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
            ParseError::NegMessageTooLarge(len) => {
                write!(f, "negentropy message too large: {} bytes", len)
            }
            ParseError::TooManyIds(count) => write!(f, "too many IDs in control frame: {}", count),
        }
    }
}

impl std::error::Error for ParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_neg_open_roundtrip() {
        let msg = Frame::NegOpen {
            msg: vec![1, 2, 3, 4, 5],
        };
        let encoded = encode_frame(&msg);
        assert_eq!(encoded.len(), 10); // 1 + 4 + 5

        let (parsed, consumed) = parse_frame(&encoded).unwrap();
        assert_eq!(consumed, 10);
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_neg_msg_roundtrip() {
        let msg = Frame::NegMsg {
            msg: vec![10, 20, 30],
        };
        let encoded = encode_frame(&msg);
        assert_eq!(encoded.len(), 8); // 1 + 4 + 3

        let (parsed, consumed) = parse_frame(&encoded).unwrap();
        assert_eq!(consumed, 8);
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_rateless_open_roundtrip() {
        let msg = Frame::RatelessOpen {
            msg: vec![4, 5, 6],
        };
        let encoded = encode_frame(&msg);
        let (parsed, consumed) = parse_frame(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_rateless_header_roundtrip() {
        let msg = Frame::RatelessHeader {
            chunk_size: 32 * 1024,
            source_symbols: 7,
            symbols_sent: 11,
            total_bytes: 123_456,
            total_events: 9,
            seed: [0x55; 32],
        };
        let encoded = encode_frame(&msg);
        let (parsed, consumed) = parse_frame(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_rateless_symbol_roundtrip() {
        let msg = Frame::RatelessSymbol {
            symbol_index: 42,
            payload: vec![0xAA; 2048],
        };
        let encoded = encode_frame(&msg);
        let (parsed, consumed) = parse_frame(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_event_roundtrip() {
        let blob = vec![3u8; 100];
        let msg = Frame::Event { blob: blob.clone() };
        let encoded = encode_frame(&msg);
        assert_eq!(encoded.len(), 5 + 100); // type(1) + len(4) + blob(100)

        let (parsed, consumed) = parse_frame(&encoded).unwrap();
        assert_eq!(consumed, 105);
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_suppress_ids_roundtrip() {
        let msg = Frame::SuppressIds {
            ids: vec![[0x11; 32], [0x22; 32], [0x33; 32]],
        };
        let encoded = encode_frame(&msg);
        assert_eq!(encoded.len(), 1 + 2 + (3 * 32));

        let (parsed, consumed) = parse_frame(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_range_data_done_roundtrip() {
        let msg = Frame::RangeDataDone;
        let encoded = encode_frame(&msg);
        assert_eq!(encoded, vec![MSG_TYPE_RANGE_DATA_DONE]);

        let (parsed, consumed) = parse_frame(&encoded).unwrap();
        assert_eq!(consumed, 1);
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_event_variable_sizes() {
        for size in [0, 1, 75, 100, 512, 1000, 10000] {
            let blob = vec![0xABu8; size];
            let msg = Frame::Event { blob: blob.clone() };
            let encoded = encode_frame(&msg);
            assert_eq!(encoded.len(), 5 + size);
            let (parsed, consumed) = parse_frame(&encoded).unwrap();
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
        let result = parse_frame(&buf);
        assert_eq!(result, Err(ParseError::EventTooLarge(len)));
    }

    #[test]
    fn test_parse_insufficient_data() {
        let result = parse_frame(&[MSG_TYPE_NEG_OPEN]);
        assert_eq!(result, Err(ParseError::InsufficientData));
    }

    #[test]
    fn test_parse_unknown_type() {
        let result = parse_frame(&[0xFF, 0, 0, 0, 0]);
        assert_eq!(result, Err(ParseError::UnknownType(0xFF)));
    }

    #[test]
    fn test_suppress_ids_rejects_oversized_batch() {
        let count = MAX_SUPPRESSION_IDS_PER_FRAME + 1;
        let mut encoded = vec![MSG_TYPE_RANGE_SUPPRESS_IDS];
        encoded.extend_from_slice(&(count as u16).to_le_bytes());
        encoded.extend(std::iter::repeat_n(0u8, count * 32));

        assert_eq!(parse_frame(&encoded), Err(ParseError::TooManyIds(count)));
    }
    #[test]
    fn test_open_session_auth_invite_roundtrip() {
        let msg = Frame::OpenSessionAuthInvite {
            auth: OpenSessionAuthInvite {
                source_peer_id: [0x11; 32],
                source_peer_public_key: [0x22; 32],
                target_invite_event_id: [0x33; 32],
                local_daemon_peer_id: [0x44; 32],
                remote_daemon_peer_id: [0x55; 32],
                expires_at_ms: 123456789,
                signature: [0x66; 64],
            },
        };
        let encoded = encode_frame(&msg);
        let (parsed, consumed) = parse_frame(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_open_session_auth_ack_roundtrip() {
        let msg = Frame::OpenSessionAuthAck {
            ack: OpenSessionAuthAck {
                target_tenant_id: [0x77; 32],
            },
        };
        let encoded = encode_frame(&msg);
        let (parsed, consumed) = parse_frame(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_open_session_route_roundtrip() {
        let msg = Frame::OpenSessionRoute {
            route: OpenSessionRoute {
                source_peer_id: [0x11; 32],
                target_tenant_id: [0x22; 32],
            },
        };
        let encoded = encode_frame(&msg);
        let (parsed, consumed) = parse_frame(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_neg_message_too_large() {
        let oversized_len = (MAX_NEG_MSG_BYTES + 1) as u32;
        let mut buf = vec![MSG_TYPE_NEG_OPEN];
        buf.extend_from_slice(&oversized_len.to_le_bytes());
        buf.extend_from_slice(&vec![0u8; MAX_NEG_MSG_BYTES + 1]);
        let result = parse_frame(&buf);
        assert_eq!(
            result,
            Err(ParseError::NegMessageTooLarge(MAX_NEG_MSG_BYTES + 1))
        );

        // Also test NEG_MSG
        buf[0] = MSG_TYPE_NEG_MSG;
        let result = parse_frame(&buf);
        assert_eq!(
            result,
            Err(ParseError::NegMessageTooLarge(MAX_NEG_MSG_BYTES + 1))
        );
    }

    #[test]
    fn test_neg_message_at_limit_ok() {
        let max_len = MAX_NEG_MSG_BYTES as u32;
        let mut buf = vec![MSG_TYPE_NEG_OPEN];
        buf.extend_from_slice(&max_len.to_le_bytes());
        buf.extend_from_slice(&vec![0u8; MAX_NEG_MSG_BYTES]);
        let (msg, consumed) = parse_frame(&buf).unwrap();
        assert_eq!(consumed, 5 + MAX_NEG_MSG_BYTES);
        assert!(matches!(msg, Frame::NegOpen { .. }));
    }

    #[test]
    fn test_range_policy_reject_roundtrip() {
        let msg = Frame::RangePolicyReject {
            rejected_window_kind: 3,
            oldest_allowed_window_kind: 2,
        };
        let encoded = encode_frame(&msg);
        let (parsed, consumed) = parse_frame(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(parsed, msg);
    }
}
