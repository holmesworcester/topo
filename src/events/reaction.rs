use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_REACTION};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactionEvent {
    pub created_at_ms: u64,
    pub target_event_id: [u8; 32],
    pub author_id: [u8; 32],
    pub emoji: String,
}

pub fn parse_reaction(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    // Minimum: event_type(1) + created_at_ms(8) + target_event_id(32) + author_id(32) + emoji_len(2) = 75
    if blob.len() < 75 {
        return Err(EventError::TooShort {
            expected: 75,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_REACTION {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_REACTION,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());

    let mut target_event_id = [0u8; 32];
    target_event_id.copy_from_slice(&blob[9..41]);

    let mut author_id = [0u8; 32];
    author_id.copy_from_slice(&blob[41..73]);

    let emoji_len = u16::from_le_bytes(blob[73..75].try_into().unwrap()) as usize;
    if blob.len() < 75 + emoji_len {
        return Err(EventError::TooShort {
            expected: 75 + emoji_len,
            actual: blob.len(),
        });
    }

    let emoji = String::from_utf8_lossy(&blob[75..75 + emoji_len]).to_string();

    Ok(ParsedEvent::Reaction(ReactionEvent {
        created_at_ms,
        target_event_id,
        author_id,
        emoji,
    }))
}

pub fn encode_reaction(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let rxn = match event {
        ParsedEvent::Reaction(r) => r,
        _ => return Err(EventError::WrongVariant),
    };

    let emoji_bytes = rxn.emoji.as_bytes();
    if emoji_bytes.len() > 64 {
        return Err(EventError::ContentTooLong(emoji_bytes.len()));
    }

    let total = 75 + emoji_bytes.len();
    let mut buf = Vec::with_capacity(total);

    buf.push(EVENT_TYPE_REACTION);
    buf.extend_from_slice(&rxn.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&rxn.target_event_id);
    buf.extend_from_slice(&rxn.author_id);
    buf.extend_from_slice(&(emoji_bytes.len() as u16).to_le_bytes());
    buf.extend_from_slice(emoji_bytes);

    Ok(buf)
}

pub static REACTION_META: ReactionMeta = ReactionMeta;

// Use a wrapper to produce the static EventTypeMeta
pub struct ReactionMeta;

pub static REACTION_TYPE_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_REACTION,
    type_name: "reaction",
    projection_table: "reactions",
    share_scope: ShareScope::Shared,
    dep_fields: &["target_event_id"],
    parse: parse_reaction,
    encode: encode_reaction,
};
