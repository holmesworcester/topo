pub mod message;
pub mod peer_key;
pub mod reaction;
pub mod registry;
pub mod signed_memo;

use std::sync::OnceLock;

pub use message::MessageEvent;
pub use peer_key::PeerKeyEvent;
pub use reaction::ReactionEvent;
pub use registry::{EventRegistry, EventTypeMeta, ShareScope};
pub use signed_memo::SignedMemoEvent;

pub const EVENT_TYPE_MESSAGE: u8 = 1;
pub const EVENT_TYPE_REACTION: u8 = 2;
pub const EVENT_TYPE_PEER_KEY: u8 = 3;
pub const EVENT_TYPE_SIGNED_MEMO: u8 = 4;

/// Max event blob size: 1 MiB
pub const EVENT_MAX_BLOB_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedEvent {
    Message(MessageEvent),
    Reaction(ReactionEvent),
    PeerKey(PeerKeyEvent),
    SignedMemo(SignedMemoEvent),
}

impl ParsedEvent {
    pub fn created_at_ms(&self) -> u64 {
        match self {
            ParsedEvent::Message(m) => m.created_at_ms,
            ParsedEvent::Reaction(r) => r.created_at_ms,
            ParsedEvent::PeerKey(p) => p.created_at_ms,
            ParsedEvent::SignedMemo(s) => s.created_at_ms,
        }
    }

    /// Extract dependency event IDs from schema-marked fields.
    /// Returns (field_name, raw_32_byte_id) pairs.
    pub fn dep_field_values(&self) -> Vec<(&'static str, [u8; 32])> {
        match self {
            ParsedEvent::Message(_) => vec![],
            ParsedEvent::Reaction(r) => vec![("target_event_id", r.target_event_id)],
            ParsedEvent::PeerKey(_) => vec![],
            ParsedEvent::SignedMemo(s) => vec![("signed_by", s.signed_by)],
        }
    }

    pub fn event_type_code(&self) -> u8 {
        match self {
            ParsedEvent::Message(_) => EVENT_TYPE_MESSAGE,
            ParsedEvent::Reaction(_) => EVENT_TYPE_REACTION,
            ParsedEvent::PeerKey(_) => EVENT_TYPE_PEER_KEY,
            ParsedEvent::SignedMemo(_) => EVENT_TYPE_SIGNED_MEMO,
        }
    }

    /// Return signer info for signed event types: (signer_event_id, signer_type).
    /// Returns None for unsigned types.
    pub fn signer_fields(&self) -> Option<([u8; 32], u8)> {
        match self {
            ParsedEvent::SignedMemo(m) => Some((m.signed_by, m.signer_type)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventError {
    TooShort { expected: usize, actual: usize },
    WrongType { expected: u8, actual: u8 },
    WrongVariant,
    ContentTooLong(usize),
    UnknownType(u8),
}

impl std::fmt::Display for EventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventError::TooShort { expected, actual } => {
                write!(f, "blob too short: expected {} bytes, got {}", expected, actual)
            }
            EventError::WrongType { expected, actual } => {
                write!(f, "wrong event type: expected {}, got {}", expected, actual)
            }
            EventError::WrongVariant => write!(f, "wrong ParsedEvent variant for encoder"),
            EventError::ContentTooLong(len) => write!(f, "content too long: {} bytes", len),
            EventError::UnknownType(t) => write!(f, "unknown event type: {}", t),
        }
    }
}

impl std::error::Error for EventError {}

/// Extract created_at_ms from the common 9-byte prefix without full parsing.
/// Returns None if blob is too short.
pub fn extract_created_at_ms(blob: &[u8]) -> Option<u64> {
    if blob.len() < 9 {
        return None;
    }
    Some(u64::from_le_bytes(blob[1..9].try_into().unwrap()))
}

/// Extract event_type from the first byte of the blob.
pub fn extract_event_type(blob: &[u8]) -> Option<u8> {
    blob.first().copied()
}

static REGISTRY: OnceLock<EventRegistry> = OnceLock::new();

pub fn registry() -> &'static EventRegistry {
    REGISTRY.get_or_init(|| {
        EventRegistry::new(&[
            &message::MESSAGE_META,
            &reaction::REACTION_TYPE_META,
            &peer_key::PEER_KEY_META,
            &signed_memo::SIGNED_MEMO_META,
        ])
    })
}

/// Parse a blob using the global registry.
pub fn parse_event(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let type_code = blob.first().copied().ok_or(EventError::TooShort {
        expected: 1,
        actual: 0,
    })?;
    let meta = registry().lookup(type_code).ok_or(EventError::UnknownType(type_code))?;
    (meta.parse)(blob)
}

/// Encode a ParsedEvent using the global registry.
pub fn encode_event(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let type_code = event.event_type_code();
    let meta = registry().lookup(type_code).ok_or(EventError::UnknownType(type_code))?;
    (meta.encode)(event)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_roundtrip() {
        let msg = MessageEvent {
            created_at_ms: 1234567890123,
            channel_id: [1u8; 32],
            author_id: [2u8; 32],
            content: "Hello, world!".to_string(),
        };

        let event = ParsedEvent::Message(msg.clone());
        let blob = encode_event(&event).unwrap();
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_reaction_roundtrip() {
        let rxn = ReactionEvent {
            created_at_ms: 9876543210000,
            target_event_id: [3u8; 32],
            author_id: [4u8; 32],
            emoji: "\u{1f44d}".to_string(),
        };

        let event = ParsedEvent::Reaction(rxn.clone());
        let blob = encode_event(&event).unwrap();
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_peer_key_roundtrip() {
        let pk = PeerKeyEvent {
            created_at_ms: 1111111111111,
            public_key: [5u8; 32],
        };

        let event = ParsedEvent::PeerKey(pk.clone());
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), 41);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_signed_memo_roundtrip() {
        let memo = SignedMemoEvent {
            created_at_ms: 2222222222222,
            signed_by: [6u8; 32],
            signer_type: 0,
            content: "signed content".to_string(),
            signature: [7u8; 64],
        };

        let event = ParsedEvent::SignedMemo(memo.clone());
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), 44 + 14 + 64); // 122
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_registry_lookup() {
        let reg = registry();
        let msg_meta = reg.lookup(EVENT_TYPE_MESSAGE).unwrap();
        assert_eq!(msg_meta.type_name, "message");
        assert_eq!(msg_meta.projection_table, "messages");

        let rxn_meta = reg.lookup(EVENT_TYPE_REACTION).unwrap();
        assert_eq!(rxn_meta.type_name, "reaction");
        assert_eq!(rxn_meta.projection_table, "reactions");

        let pk_meta = reg.lookup(EVENT_TYPE_PEER_KEY).unwrap();
        assert_eq!(pk_meta.type_name, "peer_key");
        assert_eq!(pk_meta.projection_table, "peer_keys");

        let sm_meta = reg.lookup(EVENT_TYPE_SIGNED_MEMO).unwrap();
        assert_eq!(sm_meta.type_name, "signed_memo");
        assert_eq!(sm_meta.projection_table, "signed_memos");
        assert!(sm_meta.signer_required);
        assert_eq!(sm_meta.signature_byte_len, 64);

        assert!(reg.lookup(99).is_none());
    }

    #[test]
    fn test_variable_length_content() {
        // Empty content
        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: 100,
            channel_id: [0u8; 32],
            author_id: [0u8; 32],
            content: "".to_string(),
        });
        let blob = encode_event(&msg).unwrap();
        assert_eq!(blob.len(), 75); // minimum
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, msg);

        // Large content
        let big_content = "x".repeat(1000);
        let msg2 = ParsedEvent::Message(MessageEvent {
            created_at_ms: 200,
            channel_id: [0u8; 32],
            author_id: [0u8; 32],
            content: big_content.clone(),
        });
        let blob2 = encode_event(&msg2).unwrap();
        assert_eq!(blob2.len(), 75 + 1000);
        let parsed2 = parse_event(&blob2).unwrap();
        assert_eq!(parsed2, msg2);
    }

    #[test]
    fn test_extract_created_at_ms() {
        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: 42424242424242,
            channel_id: [0u8; 32],
            author_id: [0u8; 32],
            content: "test".to_string(),
        });
        let blob = encode_event(&msg).unwrap();
        assert_eq!(extract_created_at_ms(&blob), Some(42424242424242));
    }

    #[test]
    fn test_dep_field_values_message() {
        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: 100,
            channel_id: [1u8; 32],
            author_id: [2u8; 32],
            content: "hello".to_string(),
        });
        assert!(msg.dep_field_values().is_empty());
    }

    #[test]
    fn test_dep_field_values_reaction() {
        let target = [42u8; 32];
        let rxn = ParsedEvent::Reaction(ReactionEvent {
            created_at_ms: 200,
            target_event_id: target,
            author_id: [3u8; 32],
            emoji: "\u{1f44d}".to_string(),
        });
        let deps = rxn.dep_field_values();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].0, "target_event_id");
        assert_eq!(deps[0].1, target);
    }

    #[test]
    fn test_dep_field_values_peer_key() {
        let pk = ParsedEvent::PeerKey(PeerKeyEvent {
            created_at_ms: 100,
            public_key: [1u8; 32],
        });
        assert!(pk.dep_field_values().is_empty());
    }

    #[test]
    fn test_dep_field_values_signed_memo() {
        let signer_id = [42u8; 32];
        let memo = ParsedEvent::SignedMemo(SignedMemoEvent {
            created_at_ms: 300,
            signed_by: signer_id,
            signer_type: 0,
            content: "test".to_string(),
            signature: [0u8; 64],
        });
        let deps = memo.dep_field_values();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].0, "signed_by");
        assert_eq!(deps[0].1, signer_id);
    }

    #[test]
    fn test_signer_fields_unsigned() {
        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: 100,
            channel_id: [0u8; 32],
            author_id: [0u8; 32],
            content: "".to_string(),
        });
        assert!(msg.signer_fields().is_none());

        let rxn = ParsedEvent::Reaction(ReactionEvent {
            created_at_ms: 100,
            target_event_id: [0u8; 32],
            author_id: [0u8; 32],
            emoji: "x".to_string(),
        });
        assert!(rxn.signer_fields().is_none());

        let pk = ParsedEvent::PeerKey(PeerKeyEvent {
            created_at_ms: 100,
            public_key: [0u8; 32],
        });
        assert!(pk.signer_fields().is_none());
    }

    #[test]
    fn test_signer_fields_signed() {
        let signer_id = [42u8; 32];
        let memo = ParsedEvent::SignedMemo(SignedMemoEvent {
            created_at_ms: 300,
            signed_by: signer_id,
            signer_type: 0,
            content: "test".to_string(),
            signature: [0u8; 64],
        });
        let (id, st) = memo.signer_fields().unwrap();
        assert_eq!(id, signer_id);
        assert_eq!(st, 0);
    }

    #[test]
    fn test_extract_event_type() {
        let msg_blob = encode_event(&ParsedEvent::Message(MessageEvent {
            created_at_ms: 0,
            channel_id: [0u8; 32],
            author_id: [0u8; 32],
            content: "".to_string(),
        }))
        .unwrap();
        assert_eq!(extract_event_type(&msg_blob), Some(EVENT_TYPE_MESSAGE));

        let rxn_blob = encode_event(&ParsedEvent::Reaction(ReactionEvent {
            created_at_ms: 0,
            target_event_id: [0u8; 32],
            author_id: [0u8; 32],
            emoji: "x".to_string(),
        }))
        .unwrap();
        assert_eq!(extract_event_type(&rxn_blob), Some(EVENT_TYPE_REACTION));

        let pk_blob = encode_event(&ParsedEvent::PeerKey(PeerKeyEvent {
            created_at_ms: 0,
            public_key: [0u8; 32],
        }))
        .unwrap();
        assert_eq!(extract_event_type(&pk_blob), Some(EVENT_TYPE_PEER_KEY));

        let memo_blob = encode_event(&ParsedEvent::SignedMemo(SignedMemoEvent {
            created_at_ms: 0,
            signed_by: [0u8; 32],
            signer_type: 0,
            content: "".to_string(),
            signature: [0u8; 64],
        }))
        .unwrap();
        assert_eq!(extract_event_type(&memo_blob), Some(EVENT_TYPE_SIGNED_MEMO));
    }
}
