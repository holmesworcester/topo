use super::layout::common::COMMON_HEADER_BYTES;
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_UNWRAP_SECRET};

pub const UNWRAP_SECRET_WIRE_SIZE: usize = COMMON_HEADER_BYTES + 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwrapSecretEvent {
    pub created_at_ms: u64,
    /// Event ID of the identity event whose private key material is present locally.
    pub recipient_event_id: [u8; 32],
}

pub fn parse_unwrap_secret(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < UNWRAP_SECRET_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: UNWRAP_SECRET_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > UNWRAP_SECRET_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: UNWRAP_SECRET_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_UNWRAP_SECRET {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_UNWRAP_SECRET,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());
    let mut recipient_event_id = [0u8; 32];
    recipient_event_id.copy_from_slice(&blob[9..41]);

    Ok(ParsedEvent::UnwrapSecret(UnwrapSecretEvent {
        created_at_ms,
        recipient_event_id,
    }))
}

pub fn encode_unwrap_secret(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::UnwrapSecret(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    let mut buf = Vec::with_capacity(UNWRAP_SECRET_WIRE_SIZE);
    buf.push(EVENT_TYPE_UNWRAP_SECRET);
    buf.extend_from_slice(&e.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&e.recipient_event_id);
    Ok(buf)
}

pub fn deterministic_unwrap_secret_created_at_ms(recipient_event_id: &[u8; 32]) -> u64 {
    use blake2::digest::consts::U8;
    use blake2::{Blake2b, Digest};

    let mut hasher = Blake2b::<U8>::new();
    hasher.update(b"poc7-unwrap-secret-created-at-v1");
    hasher.update(recipient_event_id);
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(out)
}

pub fn deterministic_unwrap_secret_event(recipient_event_id: [u8; 32]) -> ParsedEvent {
    ParsedEvent::UnwrapSecret(UnwrapSecretEvent {
        created_at_ms: deterministic_unwrap_secret_created_at_ms(&recipient_event_id),
        recipient_event_id,
    })
}

pub fn deterministic_unwrap_secret_event_id(recipient_event_id: &[u8; 32]) -> [u8; 32] {
    let event = deterministic_unwrap_secret_event(*recipient_event_id);
    let blob =
        super::encode_event(&event).expect("deterministic unwrap_secret encoding should succeed");
    crate::crypto::hash_event(&blob)
}

// === Projector (event-module locality) ===

use crate::crypto::event_id_to_base64;
use crate::projection::contract::{
    ContextSnapshot, ProjectorResult, SqlVal, UnwrapSecretMaterial, WriteOp,
};
use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS unwrap_secrets (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            recipient_event_id TEXT NOT NULL,
            signer_kind INTEGER NOT NULL,
            private_key BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        ",
    )?;
    Ok(())
}

pub fn build_projector_context(
    conn: &Connection,
    recorded_by: &str,
    _event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let e = match parsed {
        ParsedEvent::UnwrapSecret(v) => v,
        _ => return Err("unwrap_secret context loader called for non-unwrap_secret event".into()),
    };
    let recipient_b64 = event_id_to_base64(&e.recipient_event_id);

    let unwrap_secret_row: Option<(Vec<u8>, u8)> = conn
        .query_row(
            "SELECT private_key, signer_kind
             FROM local_signer_material
             WHERE recorded_by = ?1
               AND signer_event_id = ?2
               AND private_key != X'0000000000000000000000000000000000000000000000000000000000000000'
             LIMIT 1",
            rusqlite::params![recorded_by, &recipient_b64],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .ok();

    let (private_key_bytes, signer_kind) = match unwrap_secret_row {
        Some(v) => v,
        None => return Ok(ContextSnapshot::default()),
    };
    if private_key_bytes.len() != 32 {
        return Ok(ContextSnapshot::default());
    }

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&private_key_bytes);
    Ok(ContextSnapshot {
        unwrap_secret_material: Some(UnwrapSecretMaterial {
            signer_kind,
            private_key_bytes: key_arr,
        }),
        ..ContextSnapshot::default()
    })
}

pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let e = match parsed {
        ParsedEvent::UnwrapSecret(v) => v,
        _ => return ProjectorResult::reject("not an unwrap_secret event".to_string()),
    };
    let material = match &ctx.unwrap_secret_material {
        Some(v) => v,
        None => return ProjectorResult::valid(Vec::new()),
    };

    ProjectorResult::valid(vec![WriteOp::InsertOrIgnore {
        table: "unwrap_secrets",
        columns: vec![
            "recorded_by",
            "event_id",
            "recipient_event_id",
            "signer_kind",
            "private_key",
            "created_at",
        ],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(event_id_to_base64(&e.recipient_event_id)),
            SqlVal::Int(material.signer_kind as i64),
            SqlVal::Blob(material.private_key_bytes.to_vec()),
            SqlVal::Int(e.created_at_ms as i64),
        ],
    }])
}

pub static UNWRAP_SECRET_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_UNWRAP_SECRET,
    type_name: "unwrap_secret",
    projection_table: "unwrap_secrets",
    share_scope: ShareScope::Local,
    dep_fields: &["recipient_event_id"],
    dep_field_type_codes: &[&[10, 11, 12, 13, 16, 17]],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_unwrap_secret,
    encode: encode_unwrap_secret,
    projector: project_pure,
    context_loader: build_projector_context,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::{encode_event, parse_event};

    #[test]
    fn test_roundtrip_unwrap_secret() {
        let e = ParsedEvent::UnwrapSecret(UnwrapSecretEvent {
            created_at_ms: 12345,
            recipient_event_id: [9u8; 32],
        });
        let blob = encode_event(&e).unwrap();
        assert_eq!(blob.len(), UNWRAP_SECRET_WIRE_SIZE);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, e);
    }

    #[test]
    fn test_deterministic_unwrap_secret_event_id_stable() {
        let recipient = [4u8; 32];
        let a = deterministic_unwrap_secret_event_id(&recipient);
        let b = deterministic_unwrap_secret_event_id(&recipient);
        assert_eq!(a, b);
    }
}
