use super::layout::common::{COMMON_HEADER_BYTES, SIGNATURE_TRAILER_BYTES};
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_SECRET_SHARED};

// ─── Layout (owned by this module) ───

/// SecretShared (type 22): type(1) + created_at(8) + key_event_id(32) + recipient_event_id(32)
///                        + wrapped_key(32) + signed_by(32) + signer_type(1) + signature(64) = 202
pub const SECRET_SHARED_WIRE_SIZE: usize =
    COMMON_HEADER_BYTES + 32 + 32 + 32 + SIGNATURE_TRAILER_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretSharedEvent {
    pub created_at_ms: u64,
    pub key_event_id: [u8; 32],       // dep: SecretKey event
    pub recipient_event_id: [u8; 32], // dep: invite or peer_shared event of recipient
    pub wrapped_key: [u8; 32],        // key bytes wrapped for recipient
    pub signed_by: [u8; 32],          // signer event_id (PeerShared event — sender)
    pub signer_type: u8,              // 5 = peer_shared
    pub signature: [u8; 64],
}

/// Wire format (202 bytes fixed):
/// [0]          type_code = 22
/// [1..9]       created_at_ms (u64 LE)
/// [9..41]      key_event_id (32 bytes)
/// [41..73]     recipient_event_id (32 bytes)
/// [73..105]    wrapped_key (32 bytes)
/// [105..137]   signed_by (32 bytes)
/// [137]        signer_type (1 byte)
/// [138..202]   signature (64 bytes)
pub fn parse_secret_shared(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < SECRET_SHARED_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: SECRET_SHARED_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > SECRET_SHARED_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: SECRET_SHARED_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_SECRET_SHARED {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_SECRET_SHARED,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());
    let mut key_event_id = [0u8; 32];
    key_event_id.copy_from_slice(&blob[9..41]);
    let mut recipient_event_id = [0u8; 32];
    recipient_event_id.copy_from_slice(&blob[41..73]);
    let mut wrapped_key = [0u8; 32];
    wrapped_key.copy_from_slice(&blob[73..105]);
    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[105..137]);
    let signer_type = blob[137];
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[138..202]);

    Ok(ParsedEvent::SecretShared(SecretSharedEvent {
        created_at_ms,
        key_event_id,
        recipient_event_id,
        wrapped_key,
        signed_by,
        signer_type,
        signature,
    }))
}

pub fn encode_secret_shared(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::SecretShared(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    let mut buf = Vec::with_capacity(SECRET_SHARED_WIRE_SIZE);
    buf.push(EVENT_TYPE_SECRET_SHARED);
    buf.extend_from_slice(&e.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&e.key_event_id);
    buf.extend_from_slice(&e.recipient_event_id);
    buf.extend_from_slice(&e.wrapped_key);
    buf.extend_from_slice(&e.signed_by);
    buf.push(e.signer_type);
    buf.extend_from_slice(&e.signature);
    Ok(buf)
}

// === Projector (event-module locality) ===

use crate::crypto::event_id_to_base64;
use crate::projection::result::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS secret_shared (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            key_event_id TEXT NOT NULL,
            recipient_event_id TEXT NOT NULL,
            wrapped_key BLOB NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        ",
    )?;
    Ok(())
}

/// Pure projector: SecretShared → secret_shared table.
/// Rejects if recipient has been removed (InvRemovalExclusion).
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let ss = match parsed {
        ParsedEvent::SecretShared(s) => s,
        _ => return ProjectorResult::reject("not a secret_shared event".to_string()),
    };

    let key_b64 = event_id_to_base64(&ss.key_event_id);
    let recipient_b64 = event_id_to_base64(&ss.recipient_event_id);

    if ctx.recipient_removed {
        return ProjectorResult::reject(format!("recipient {} has been removed", recipient_b64));
    }

    let ops = vec![WriteOp::InsertOrIgnore {
        table: "secret_shared",
        columns: vec![
            "recorded_by",
            "event_id",
            "key_event_id",
            "recipient_event_id",
            "wrapped_key",
        ],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(key_b64),
            SqlVal::Text(recipient_b64),
            SqlVal::Blob(ss.wrapped_key.to_vec()),
        ],
    }];
    ProjectorResult::valid(ops)
}

pub static SECRET_SHARED_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_SECRET_SHARED,
    type_name: "secret_shared",
    projection_table: "secret_shared",
    share_scope: ShareScope::Shared,
    dep_fields: &["recipient_event_id", "signed_by"],
    dep_field_type_codes: &[&[10, 11, 12, 13, 16, 17], &[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: false,
    parse: parse_secret_shared,
    encode: encode_secret_shared,
    projector: project_pure,
};
