use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_SECRET_KEY};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretKeyEvent {
    pub created_at_ms: u64,
    pub key_bytes: [u8; 32], // AES-256 symmetric key
}

/// Wire format (41 bytes fixed):
/// [0]      type_code = 6
/// [1..9]   created_at_ms (u64 LE)
/// [9..41]  key_bytes (32 bytes)
pub fn parse_secret_key(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < 41 {
        return Err(EventError::TooShort {
            expected: 41,
            actual: blob.len(),
        });
    }
    if blob.len() > 41 {
        return Err(EventError::TrailingData {
            expected: 41,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_SECRET_KEY {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_SECRET_KEY,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&blob[9..41]);

    Ok(ParsedEvent::SecretKey(SecretKeyEvent {
        created_at_ms,
        key_bytes,
    }))
}

pub fn encode_secret_key(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let sk = match event {
        ParsedEvent::SecretKey(s) => s,
        _ => return Err(EventError::WrongVariant),
    };

    let mut buf = Vec::with_capacity(41);
    buf.push(EVENT_TYPE_SECRET_KEY);
    buf.extend_from_slice(&sk.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&sk.key_bytes);
    Ok(buf)
}

pub static SECRET_KEY_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_SECRET_KEY,
    type_name: "secret_key",
    projection_table: "secret_keys",
    share_scope: ShareScope::Local,
    dep_fields: &[],
    dep_field_type_codes: &[],
    signer_required: false,
    signature_byte_len: 0,
    parse: parse_secret_key,
    encode: encode_secret_key,
};
