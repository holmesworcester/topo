use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_MESSAGE};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageEvent {
    pub created_at_ms: u64,
    pub channel_id: [u8; 32],
    pub author_id: [u8; 32],
    pub content: String,
    pub signed_by: [u8; 32],
    pub signer_type: u8,
    pub signature: [u8; 64],
}

/// Wire format (min 172 bytes, signed):
/// [0]            type=1
/// [1..9]         created_at_ms (u64 LE)
/// [9..41]        channel_id (32 bytes)
/// [41..73]       author_id (32 bytes)
/// [73..75]       content_len (u16 LE)
/// [75..75+N]     content (UTF-8)
/// --- signature trailer (97 bytes) ---
/// [75+N..75+N+32]  signed_by (32 bytes)
/// [75+N+32]        signer_type (1 byte)
/// [75+N+33..75+N+97] signature (64 bytes)
pub fn parse_message(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    // Minimum: type(1) + created_at_ms(8) + channel_id(32) + author_id(32) + content_len(2)
    //        + signed_by(32) + signer_type(1) + signature(64) = 172
    if blob.len() < 172 {
        return Err(EventError::TooShort {
            expected: 172,
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
    let expected_len = 75 + content_len + 97; // 97 = signed_by(32) + signer_type(1) + signature(64)
    if blob.len() < expected_len {
        return Err(EventError::TooShort {
            expected: expected_len,
            actual: blob.len(),
        });
    }

    let content = String::from_utf8_lossy(&blob[75..75 + content_len]).to_string();

    let trailer_start = 75 + content_len;
    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[trailer_start..trailer_start + 32]);

    let signer_type = blob[trailer_start + 32];

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[trailer_start + 33..trailer_start + 97]);

    Ok(ParsedEvent::Message(MessageEvent {
        created_at_ms,
        channel_id,
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
    if content_bytes.len() > 65535 {
        return Err(EventError::ContentTooLong(content_bytes.len()));
    }

    let total = 75 + content_bytes.len() + 97;
    let mut buf = Vec::with_capacity(total);

    buf.push(EVENT_TYPE_MESSAGE);
    buf.extend_from_slice(&msg.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&msg.channel_id);
    buf.extend_from_slice(&msg.author_id);
    buf.extend_from_slice(&(content_bytes.len() as u16).to_le_bytes());
    buf.extend_from_slice(content_bytes);
    buf.extend_from_slice(&msg.signed_by);
    buf.push(msg.signer_type);
    buf.extend_from_slice(&msg.signature);

    Ok(buf)
}

pub static MESSAGE_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_MESSAGE,
    type_name: "message",
    projection_table: "messages",
    share_scope: ShareScope::Shared,
    dep_fields: &["signed_by"],
    signer_required: true,
    signature_byte_len: 64,
    parse: parse_message,
    encode: encode_message,
};
