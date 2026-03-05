use super::layout::common::COMMON_HEADER_BYTES;
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_SECRET_KEY};
use crate::crypto::EventId;

// ─── Layout (owned by this module) ───

/// Secret (type 6): type(1) + created_at(8) + key_bytes(32) = 41
pub const SECRET_KEY_WIRE_SIZE: usize = COMMON_HEADER_BYTES + 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretKeyEvent {
    pub created_at_ms: u64,
    pub key_bytes: [u8; 32], // AES-256 symmetric key
}

impl super::Describe for SecretKeyEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![("key_bytes", super::trunc_hex(&self.key_bytes, 16))]
    }
}

/// Wire format (41 bytes fixed):
/// [0]      type_code = 6
/// [1..9]   created_at_ms (u64 LE)
/// [9..41]  key_bytes (32 bytes)
pub fn parse_secret_key(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < SECRET_KEY_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: SECRET_KEY_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > SECRET_KEY_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: SECRET_KEY_WIRE_SIZE,
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

    let mut buf = Vec::with_capacity(SECRET_KEY_WIRE_SIZE);
    buf.push(EVENT_TYPE_SECRET_KEY);
    buf.extend_from_slice(&sk.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&sk.key_bytes);
    Ok(buf)
}

/// Deterministic timestamp derivation for key materialized Secret events.
pub fn deterministic_secret_key_created_at_ms(key_bytes: &[u8; 32]) -> u64 {
    use blake2::digest::consts::U8;
    use blake2::{Blake2b, Digest};

    let mut hasher = Blake2b::<U8>::new();
    hasher.update(b"poc7-content-key-created-at-v1");
    hasher.update(key_bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(out)
}

pub fn deterministic_secret_key_event(key_bytes: [u8; 32]) -> ParsedEvent {
    ParsedEvent::SecretKey(SecretKeyEvent {
        created_at_ms: deterministic_secret_key_created_at_ms(&key_bytes),
        key_bytes,
    })
}

pub fn deterministic_secret_key_event_id(key_bytes: &[u8; 32]) -> EventId {
    let event = deterministic_secret_key_event(*key_bytes);
    let blob =
        super::encode_event(&event).expect("deterministic secret_key encoding should succeed");
    crate::crypto::hash_event(&blob)
}

// === Projector (event-module locality) ===

use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS secret_keys (
            event_id TEXT NOT NULL,
            key_bytes BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            recorded_by TEXT NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        ",
    )?;
    Ok(())
}

/// Pure projector: Secret -> secret_keys table insert.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let sk = match parsed {
        ParsedEvent::SecretKey(s) => s,
        _ => return ProjectorResult::reject("not a secret_key event".to_string()),
    };

    let ops = vec![WriteOp::InsertOrIgnore {
        table: "secret_keys",
        columns: vec!["event_id", "key_bytes", "created_at", "recorded_by"],
        values: vec![
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Blob(sk.key_bytes.to_vec()),
            SqlVal::Int(sk.created_at_ms as i64),
            SqlVal::Text(recorded_by.to_string()),
        ],
    }];
    ProjectorResult::valid(ops)
}

pub static SECRET_KEY_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_SECRET_KEY,
    type_name: "secret",
    projection_table: "secret_keys",
    share_scope: ShareScope::Local,
    dep_fields: &[],
    dep_field_type_codes: &[],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: true,
    parse: parse_secret_key,
    encode: encode_secret_key,
    projector: project_pure,
    context_loader: crate::event_modules::registry::load_empty_context,
};
