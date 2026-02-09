use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_ENCRYPTED};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedEvent {
    pub created_at_ms: u64,
    pub key_event_id: [u8; 32],
    pub inner_type_code: u8,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub auth_tag: [u8; 16],
}

/// Wire format:
/// [0]             type_code = 5
/// [1..9]          created_at_ms (u64 LE)
/// [9..41]         key_event_id (32B)
/// [41]            inner_type_code (1B)
/// [42..54]        nonce (12B, AES-256-GCM)
/// [54..56]        ciphertext_len (u16 LE)
/// [56..56+N]      ciphertext
/// [56+N..56+N+16] auth_tag (16B)
/// Min size: 72 bytes (empty ciphertext)
pub fn parse_encrypted(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < 72 {
        return Err(EventError::TooShort {
            expected: 72,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_ENCRYPTED {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_ENCRYPTED,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());

    let mut key_event_id = [0u8; 32];
    key_event_id.copy_from_slice(&blob[9..41]);

    let inner_type_code = blob[41];

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blob[42..54]);

    let ciphertext_len = u16::from_le_bytes(blob[54..56].try_into().unwrap()) as usize;
    let expected_len = 56 + ciphertext_len + 16;
    if blob.len() < expected_len {
        return Err(EventError::TooShort {
            expected: expected_len,
            actual: blob.len(),
        });
    }

    let ciphertext = blob[56..56 + ciphertext_len].to_vec();

    let mut auth_tag = [0u8; 16];
    auth_tag.copy_from_slice(&blob[56 + ciphertext_len..56 + ciphertext_len + 16]);

    Ok(ParsedEvent::Encrypted(EncryptedEvent {
        created_at_ms,
        key_event_id,
        inner_type_code,
        nonce,
        ciphertext,
        auth_tag,
    }))
}

pub fn encode_encrypted(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let enc = match event {
        ParsedEvent::Encrypted(e) => e,
        _ => return Err(EventError::WrongVariant),
    };

    if enc.ciphertext.len() > 65535 {
        return Err(EventError::ContentTooLong(enc.ciphertext.len()));
    }

    let total = 56 + enc.ciphertext.len() + 16;
    let mut buf = Vec::with_capacity(total);

    buf.push(EVENT_TYPE_ENCRYPTED);
    buf.extend_from_slice(&enc.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&enc.key_event_id);
    buf.push(enc.inner_type_code);
    buf.extend_from_slice(&enc.nonce);
    buf.extend_from_slice(&(enc.ciphertext.len() as u16).to_le_bytes());
    buf.extend_from_slice(&enc.ciphertext);
    buf.extend_from_slice(&enc.auth_tag);

    Ok(buf)
}

pub static ENCRYPTED_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_ENCRYPTED,
    type_name: "encrypted",
    projection_table: "",
    share_scope: ShareScope::Shared,
    dep_fields: &["key_event_id"],
    dep_field_type_codes: &[&[6]],
    signer_required: false,
    signature_byte_len: 0,
    parse: parse_encrypted,
    encode: encode_encrypted,
};
