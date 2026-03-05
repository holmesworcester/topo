use super::layout::common::COMMON_HEADER_BYTES;
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_LOCAL_KEY};

pub const LOCAL_KEY_WIRE_SIZE: usize = COMMON_HEADER_BYTES + 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalKeyEvent {
    pub created_at_ms: u64,
    /// Event ID of the identity event whose private key material is present locally.
    pub recipient_event_id: [u8; 32],
}

pub fn parse_local_key(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < LOCAL_KEY_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: LOCAL_KEY_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > LOCAL_KEY_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: LOCAL_KEY_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_LOCAL_KEY {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_LOCAL_KEY,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());
    let mut recipient_event_id = [0u8; 32];
    recipient_event_id.copy_from_slice(&blob[9..41]);

    Ok(ParsedEvent::LocalKey(LocalKeyEvent {
        created_at_ms,
        recipient_event_id,
    }))
}

pub fn encode_local_key(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::LocalKey(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    let mut buf = Vec::with_capacity(LOCAL_KEY_WIRE_SIZE);
    buf.push(EVENT_TYPE_LOCAL_KEY);
    buf.extend_from_slice(&e.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&e.recipient_event_id);
    Ok(buf)
}

pub fn deterministic_local_key_created_at_ms(recipient_event_id: &[u8; 32]) -> u64 {
    use blake2::digest::consts::U8;
    use blake2::{Blake2b, Digest};

    let mut hasher = Blake2b::<U8>::new();
    hasher.update(b"poc7-local-key-created-at-v1");
    hasher.update(recipient_event_id);
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(out)
}

pub fn deterministic_local_key_event(recipient_event_id: [u8; 32]) -> ParsedEvent {
    ParsedEvent::LocalKey(LocalKeyEvent {
        created_at_ms: deterministic_local_key_created_at_ms(&recipient_event_id),
        recipient_event_id,
    })
}

pub fn deterministic_local_key_event_id(recipient_event_id: &[u8; 32]) -> [u8; 32] {
    let event = deterministic_local_key_event(*recipient_event_id);
    let blob = super::encode_event(&event).expect("deterministic local_key encoding should succeed");
    crate::crypto::hash_event(&blob)
}

// === Projector (event-module locality) ===

use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS local_keys (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            recipient_event_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        ",
    )?;
    Ok(())
}

pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let e = match parsed {
        ParsedEvent::LocalKey(v) => v,
        _ => return ProjectorResult::reject("not a local_key event".to_string()),
    };

    ProjectorResult::valid(vec![WriteOp::InsertOrIgnore {
        table: "local_keys",
        columns: vec!["recorded_by", "event_id", "recipient_event_id", "created_at"],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(event_id_to_base64(&e.recipient_event_id)),
            SqlVal::Int(e.created_at_ms as i64),
        ],
    }])
}

pub static LOCAL_KEY_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_LOCAL_KEY,
    type_name: "local_key",
    projection_table: "local_keys",
    share_scope: ShareScope::Local,
    dep_fields: &["recipient_event_id"],
    dep_field_type_codes: &[&[10, 11, 12, 13, 16, 17]],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_local_key,
    encode: encode_local_key,
    projector: project_pure,
    context_loader: crate::event_modules::registry::load_empty_context,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::{encode_event, parse_event};

    #[test]
    fn test_roundtrip_local_key() {
        let e = ParsedEvent::LocalKey(LocalKeyEvent {
            created_at_ms: 12345,
            recipient_event_id: [9u8; 32],
        });
        let blob = encode_event(&e).unwrap();
        assert_eq!(blob.len(), LOCAL_KEY_WIRE_SIZE);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, e);
    }

    #[test]
    fn test_deterministic_local_key_event_id_stable() {
        let recipient = [4u8; 32];
        let a = deterministic_local_key_event_id(&recipient);
        let b = deterministic_local_key_event_id(&recipient);
        assert_eq!(a, b);
    }
}
