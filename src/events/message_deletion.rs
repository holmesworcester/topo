use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_MESSAGE_DELETION};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageDeletionEvent {
    pub created_at_ms: u64,
    pub target_event_id: [u8; 32], // message being deleted
    pub author_id: [u8; 32],       // must match message author
}

/// Wire format (73 bytes fixed):
/// [0]      type_code = 7
/// [1..9]   created_at_ms (u64 LE)
/// [9..41]  target_event_id (32 bytes)
/// [41..73] author_id (32 bytes)
pub fn parse_message_deletion(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < 73 {
        return Err(EventError::TooShort {
            expected: 73,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_MESSAGE_DELETION {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_MESSAGE_DELETION,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());

    let mut target_event_id = [0u8; 32];
    target_event_id.copy_from_slice(&blob[9..41]);

    let mut author_id = [0u8; 32];
    author_id.copy_from_slice(&blob[41..73]);

    Ok(ParsedEvent::MessageDeletion(MessageDeletionEvent {
        created_at_ms,
        target_event_id,
        author_id,
    }))
}

pub fn encode_message_deletion(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let del = match event {
        ParsedEvent::MessageDeletion(d) => d,
        _ => return Err(EventError::WrongVariant),
    };

    let mut buf = Vec::with_capacity(73);
    buf.push(EVENT_TYPE_MESSAGE_DELETION);
    buf.extend_from_slice(&del.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&del.target_event_id);
    buf.extend_from_slice(&del.author_id);
    Ok(buf)
}

pub static MESSAGE_DELETION_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_MESSAGE_DELETION,
    type_name: "message_deletion",
    projection_table: "deleted_messages",
    share_scope: ShareScope::Shared,
    dep_fields: &["target_event_id"],
    signer_required: false,
    signature_byte_len: 0,
    parse: parse_message_deletion,
    encode: encode_message_deletion,
};
