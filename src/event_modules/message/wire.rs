use super::super::fixed_layout::{self, MESSAGE_WIRE_SIZE, MESSAGE_CONTENT_BYTES, message_offsets as off};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_MESSAGE};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageEvent {
    pub created_at_ms: u64,
    pub workspace_id: [u8; 32],
    pub author_id: [u8; 32],
    pub content: String,
    pub signed_by: [u8; 32],
    pub signer_type: u8,
    pub signature: [u8; 64],
}

/// Wire format (1194 bytes fixed, signed):
/// [0]            type=1
/// [1..9]         created_at_ms (u64 LE)
/// [9..41]        workspace_id (32 bytes)
/// [41..73]       author_id (32 bytes)
/// [73..1097]     content (1024 bytes, UTF-8 zero-padded)
/// [1097..1129]   signed_by (32 bytes)
/// [1129]         signer_type (1 byte)
/// [1130..1194]   signature (64 bytes)
pub fn parse_message(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < MESSAGE_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: MESSAGE_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > MESSAGE_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: MESSAGE_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_MESSAGE {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_MESSAGE,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[off::CREATED_AT..off::WORKSPACE_ID].try_into().unwrap());

    let mut workspace_id = [0u8; 32];
    workspace_id.copy_from_slice(&blob[off::WORKSPACE_ID..off::AUTHOR_ID]);

    let mut author_id = [0u8; 32];
    author_id.copy_from_slice(&blob[off::AUTHOR_ID..off::CONTENT]);

    let content = fixed_layout::read_text_slot(&blob[off::CONTENT..off::CONTENT + MESSAGE_CONTENT_BYTES])
        .map_err(EventError::TextSlot)?;

    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[off::SIGNED_BY..off::SIGNER_TYPE]);

    let signer_type = blob[off::SIGNER_TYPE];

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[off::SIGNATURE..off::SIGNATURE + 64]);

    Ok(ParsedEvent::Message(MessageEvent {
        created_at_ms,
        workspace_id,
        author_id,
        content,
        signed_by,
        signer_type,
        signature,
    }))
}

pub fn encode_message(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let msg = match event {
        ParsedEvent::Message(m) => m,
        _ => return Err(EventError::WrongVariant),
    };

    let content_bytes = msg.content.as_bytes();
    if content_bytes.len() > MESSAGE_CONTENT_BYTES {
        return Err(EventError::ContentTooLong(content_bytes.len()));
    }

    let mut buf = vec![0u8; MESSAGE_WIRE_SIZE];

    buf[off::TYPE_CODE] = EVENT_TYPE_MESSAGE;
    buf[off::CREATED_AT..off::WORKSPACE_ID].copy_from_slice(&msg.created_at_ms.to_le_bytes());
    buf[off::WORKSPACE_ID..off::AUTHOR_ID].copy_from_slice(&msg.workspace_id);
    buf[off::AUTHOR_ID..off::CONTENT].copy_from_slice(&msg.author_id);
    fixed_layout::write_text_slot(&msg.content, &mut buf[off::CONTENT..off::CONTENT + MESSAGE_CONTENT_BYTES])
        .map_err(EventError::TextSlot)?;
    buf[off::SIGNED_BY..off::SIGNER_TYPE].copy_from_slice(&msg.signed_by);
    buf[off::SIGNER_TYPE] = msg.signer_type;
    buf[off::SIGNATURE..off::SIGNATURE + 64].copy_from_slice(&msg.signature);

    Ok(buf)
}

pub static MESSAGE_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_MESSAGE,
    type_name: "message",
    projection_table: "messages",
    share_scope: ShareScope::Shared,
    dep_fields: &["author_id", "signed_by"],
    dep_field_type_codes: &[&[14, 15], &[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: true,
    parse: parse_message,
    encode: encode_message,
    projector: super::projector::project_pure,
};
