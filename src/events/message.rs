use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_MESSAGE};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageEvent {
    pub created_at_ms: u64,
    pub channel_id: [u8; 32],
    pub author_id: [u8; 32],
    pub content: String,
}

pub fn parse_message(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    // Minimum: event_type(1) + created_at_ms(8) + channel_id(32) + author_id(32) + content_len(2) = 75
    if blob.len() < 75 {
        return Err(EventError::TooShort {
            expected: 75,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_MESSAGE {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_MESSAGE,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());

    let mut channel_id = [0u8; 32];
    channel_id.copy_from_slice(&blob[9..41]);

    let mut author_id = [0u8; 32];
    author_id.copy_from_slice(&blob[41..73]);

    let content_len = u16::from_le_bytes(blob[73..75].try_into().unwrap()) as usize;
    if blob.len() < 75 + content_len {
        return Err(EventError::TooShort {
            expected: 75 + content_len,
            actual: blob.len(),
        });
    }

    let content = String::from_utf8_lossy(&blob[75..75 + content_len]).to_string();

    Ok(ParsedEvent::Message(MessageEvent {
        created_at_ms,
        channel_id,
        author_id,
        content,
    }))
}

pub fn encode_message(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let msg = match event {
        ParsedEvent::Message(m) => m,
        _ => return Err(EventError::WrongVariant),
    };

    let content_bytes = msg.content.as_bytes();
    if content_bytes.len() > 65535 {
        return Err(EventError::ContentTooLong(content_bytes.len()));
    }

    let total = 75 + content_bytes.len();
    let mut buf = Vec::with_capacity(total);

    buf.push(EVENT_TYPE_MESSAGE);
    buf.extend_from_slice(&msg.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&msg.channel_id);
    buf.extend_from_slice(&msg.author_id);
    buf.extend_from_slice(&(content_bytes.len() as u16).to_le_bytes());
    buf.extend_from_slice(content_bytes);

    Ok(buf)
}

pub static MESSAGE_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_MESSAGE,
    type_name: "message",
    projection_table: "messages",
    share_scope: ShareScope::Shared,
    dep_fields: &[],
    parse: parse_message,
    encode: encode_message,
};
