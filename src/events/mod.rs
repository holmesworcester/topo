pub mod message;
pub mod reaction;
pub mod registry;

use std::sync::OnceLock;

pub use message::MessageEvent;
pub use reaction::ReactionEvent;
pub use registry::{EventRegistry, EventTypeMeta, ShareScope};

pub const EVENT_TYPE_MESSAGE: u8 = 1;
pub const EVENT_TYPE_REACTION: u8 = 2;

/// Max event blob size: 1 MiB
pub const EVENT_MAX_BLOB_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedEvent {
    Message(MessageEvent),
    Reaction(ReactionEvent),
}

impl ParsedEvent {
    pub fn created_at_ms(&self) -> u64 {
        match self {
            ParsedEvent::Message(m) => m.created_at_ms,
            ParsedEvent::Reaction(r) => r.created_at_ms,
        }
    }

    pub fn event_type_code(&self) -> u8 {
        match self {
            ParsedEvent::Message(_) => EVENT_TYPE_MESSAGE,
            ParsedEvent::Reaction(_) => EVENT_TYPE_REACTION,
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
    fn test_registry_lookup() {
        let reg = registry();
        let msg_meta = reg.lookup(EVENT_TYPE_MESSAGE).unwrap();
        assert_eq!(msg_meta.type_name, "message");
        assert_eq!(msg_meta.projection_table, "messages");

        let rxn_meta = reg.lookup(EVENT_TYPE_REACTION).unwrap();
        assert_eq!(rxn_meta.type_name, "reaction");
        assert_eq!(rxn_meta.projection_table, "reactions");

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
    }
}
