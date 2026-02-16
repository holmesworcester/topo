use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_SIGNED_MEMO};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedMemoEvent {
    pub created_at_ms: u64,
    pub signed_by: [u8; 32],  // event_id of signer key event
    pub signer_type: u8,      // 0=peer (future: 1=user, 2=workspace, 3=invite)
    pub content: String,
    pub signature: [u8; 64],  // Ed25519 signature (trailing in blob)
}

/// Wire format (variable):
/// [0]            type_code = 4
/// [1..9]         created_at_ms (u64 LE)
/// [9..41]        signed_by (32 bytes)
/// [41]           signer_type (1 byte)
/// [42..44]       content_len (u16 LE)
/// [44..44+N]     content (UTF-8)
/// [44+N..44+N+64] signature (64 bytes, trailing)
pub fn parse_signed_memo(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    // Minimum: type(1) + created_at(8) + signed_by(32) + signer_type(1) + content_len(2) + signature(64) = 108
    if blob.len() < 108 {
        return Err(EventError::TooShort {
            expected: 108,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_SIGNED_MEMO {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_SIGNED_MEMO,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());

    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[9..41]);

    let signer_type = blob[41];

    let content_len = u16::from_le_bytes(blob[42..44].try_into().unwrap()) as usize;
    let expected_len = 44 + content_len + 64;
    if blob.len() < expected_len {
        return Err(EventError::TooShort {
            expected: expected_len,
            actual: blob.len(),
        });
    }
    if blob.len() > expected_len {
        return Err(EventError::TrailingData {
            expected: expected_len,
            actual: blob.len(),
        });
    }

    let content = String::from_utf8_lossy(&blob[44..44 + content_len]).to_string();

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[44 + content_len..44 + content_len + 64]);

    Ok(ParsedEvent::SignedMemo(SignedMemoEvent {
        created_at_ms,
        signed_by,
        signer_type,
        content,
        signature,
    }))
}

pub fn encode_signed_memo(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let memo = match event {
        ParsedEvent::SignedMemo(m) => m,
        _ => return Err(EventError::WrongVariant),
    };

    let content_bytes = memo.content.as_bytes();
    if content_bytes.len() > 65535 {
        return Err(EventError::ContentTooLong(content_bytes.len()));
    }

    let total = 44 + content_bytes.len() + 64;
    let mut buf = Vec::with_capacity(total);

    buf.push(EVENT_TYPE_SIGNED_MEMO);
    buf.extend_from_slice(&memo.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&memo.signed_by);
    buf.push(memo.signer_type);
    buf.extend_from_slice(&(content_bytes.len() as u16).to_le_bytes());
    buf.extend_from_slice(content_bytes);
    buf.extend_from_slice(&memo.signature);

    Ok(buf)
}

pub static SIGNED_MEMO_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_SIGNED_MEMO,
    type_name: "signed_memo",
    projection_table: "signed_memos",
    share_scope: ShareScope::Shared,
    dep_fields: &["signed_by"],
    dep_field_type_codes: &[&[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: true,
    parse: parse_signed_memo,
    encode: encode_signed_memo,
};
