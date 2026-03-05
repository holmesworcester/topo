use super::layout::common::COMMON_HEADER_BYTES;
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, SecretSharedEvent, EVENT_TYPE_SECRET_SHARED_UNWRAP};

/// SecretSharedUnwrap (type 29, local):
/// type(1) + created_at(8) + secret_shared_event_id(32) + recipient_event_id(32)
/// + wrapped_key(32) + signed_by(32) + signer_type(1) = 138 bytes
pub const SECRET_SHARED_UNWRAP_WIRE_SIZE: usize = COMMON_HEADER_BYTES + 32 + 32 + 32 + 32 + 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretSharedUnwrapEvent {
    pub created_at_ms: u64,
    pub secret_shared_event_id: [u8; 32],
    pub recipient_event_id: [u8; 32],
    pub wrapped_key: [u8; 32],
    pub signed_by: [u8; 32],
    pub signer_type: u8,
}

pub fn parse_secret_shared_unwrap(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < SECRET_SHARED_UNWRAP_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: SECRET_SHARED_UNWRAP_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > SECRET_SHARED_UNWRAP_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: SECRET_SHARED_UNWRAP_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_SECRET_SHARED_UNWRAP {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_SECRET_SHARED_UNWRAP,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());
    let mut secret_shared_event_id = [0u8; 32];
    secret_shared_event_id.copy_from_slice(&blob[9..41]);
    let mut recipient_event_id = [0u8; 32];
    recipient_event_id.copy_from_slice(&blob[41..73]);
    let mut wrapped_key = [0u8; 32];
    wrapped_key.copy_from_slice(&blob[73..105]);
    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[105..137]);
    let signer_type = blob[137];

    Ok(ParsedEvent::SecretSharedUnwrap(SecretSharedUnwrapEvent {
        created_at_ms,
        secret_shared_event_id,
        recipient_event_id,
        wrapped_key,
        signed_by,
        signer_type,
    }))
}

pub fn encode_secret_shared_unwrap(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::SecretSharedUnwrap(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    let mut buf = Vec::with_capacity(SECRET_SHARED_UNWRAP_WIRE_SIZE);
    buf.push(EVENT_TYPE_SECRET_SHARED_UNWRAP);
    buf.extend_from_slice(&e.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&e.secret_shared_event_id);
    buf.extend_from_slice(&e.recipient_event_id);
    buf.extend_from_slice(&e.wrapped_key);
    buf.extend_from_slice(&e.signed_by);
    buf.push(e.signer_type);
    Ok(buf)
}

pub fn deterministic_secret_shared_unwrap_created_at_ms(secret_shared_event_id: &[u8; 32]) -> u64 {
    use blake2::digest::consts::U8;
    use blake2::{Blake2b, Digest};

    let mut hasher = Blake2b::<U8>::new();
    hasher.update(b"poc7-secret-shared-unwrap-created-at-v1");
    hasher.update(secret_shared_event_id);
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(out)
}

pub fn from_secret_shared_event(
    secret_shared_event_id: [u8; 32],
    ss: &SecretSharedEvent,
) -> ParsedEvent {
    ParsedEvent::SecretSharedUnwrap(SecretSharedUnwrapEvent {
        created_at_ms: deterministic_secret_shared_unwrap_created_at_ms(&secret_shared_event_id),
        secret_shared_event_id,
        recipient_event_id: ss.recipient_event_id,
        wrapped_key: ss.wrapped_key,
        signed_by: ss.signed_by,
        signer_type: ss.signer_type,
    })
}

// === Projector (event-module locality) ===

use crate::crypto::event_id_to_base64;
use crate::projection::contract::{
    ContextSnapshot, EmitCommand, ProjectorResult, SqlVal, UnwrappedSecretMaterial, WriteOp,
};
use crate::projection::encrypted::unwrap_key_from_sender;
use crate::projection::signer::{resolve_signer_key, SignerResolution};
use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS secret_shared_unwrap (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            secret_shared_event_id TEXT NOT NULL,
            recipient_event_id TEXT NOT NULL,
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
        ParsedEvent::SecretSharedUnwrap(v) => v,
        _ => return Err("secret_shared_unwrap context loader called for non-matching event".into()),
    };

    let recipient_b64 = event_id_to_base64(&e.recipient_event_id);
    let local_key_row: Option<(Vec<u8>, u8)> = conn
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
    let (private_key_bytes, signer_kind) = match local_key_row {
        Some(v) => v,
        None => return Ok(ContextSnapshot::default()),
    };
    if private_key_bytes.len() != 32 {
        return Ok(ContextSnapshot::default());
    }

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&private_key_bytes);
    let local_signing_key = ed25519_dalek::SigningKey::from_bytes(&key_arr);

    let sender_key = match resolve_signer_key(conn, recorded_by, e.signer_type, &e.signed_by) {
        Ok(SignerResolution::Found(k)) => k,
        _ => return Ok(ContextSnapshot::default()),
    };
    let sender_pub = match ed25519_dalek::VerifyingKey::from_bytes(&sender_key) {
        Ok(vk) => vk,
        Err(_) => return Ok(ContextSnapshot::default()),
    };

    let plaintext_key = unwrap_key_from_sender(&local_signing_key, &sender_pub, &e.wrapped_key);
    let clear_invite = if signer_kind
        == crate::event_modules::local_signer_secret::SIGNER_KIND_PENDING_INVITE_UNWRAP
    {
        Some(e.recipient_event_id)
    } else {
        None
    };

    Ok(ContextSnapshot {
        unwrapped_secret_material: Some(UnwrappedSecretMaterial {
            key_bytes: plaintext_key,
            clear_invite_signer_event_id: clear_invite,
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
        ParsedEvent::SecretSharedUnwrap(v) => v,
        _ => return ProjectorResult::reject("not a secret_shared_unwrap event".to_string()),
    };

    let mut ops = vec![WriteOp::InsertOrIgnore {
        table: "secret_shared_unwrap",
        columns: vec![
            "recorded_by",
            "event_id",
            "secret_shared_event_id",
            "recipient_event_id",
            "created_at",
        ],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(event_id_to_base64(&e.secret_shared_event_id)),
            SqlVal::Text(event_id_to_base64(&e.recipient_event_id)),
            SqlVal::Int(e.created_at_ms as i64),
        ],
    }];

    let material = match &ctx.unwrapped_secret_material {
        Some(v) => v,
        None => return ProjectorResult::valid(ops),
    };

    let secret_key_event =
        crate::event_modules::secret_key::deterministic_secret_key_event(material.key_bytes);
    let secret_blob = match crate::event_modules::encode_event(&secret_key_event) {
        Ok(v) => v,
        Err(err) => {
            return ProjectorResult::reject(format!(
                "failed to encode deterministic secret_key event: {}",
                err
            ))
        }
    };

    let mut commands = vec![EmitCommand::EmitDeterministicBlob { blob: secret_blob }];

    if let Some(clear_invite_signer_event_id) = material.clear_invite_signer_event_id {
        let clear_evt = crate::event_modules::local_signer_secret::deterministic_pending_invite_tombstone_event(
            clear_invite_signer_event_id,
        );
        let clear_blob = match crate::event_modules::encode_event(&clear_evt) {
            Ok(v) => v,
            Err(err) => {
                return ProjectorResult::reject(format!(
                    "failed to encode invite-key clear tombstone: {}",
                    err
                ))
            }
        };
        commands.push(EmitCommand::EmitDeterministicBlob { blob: clear_blob });
    }

    ProjectorResult::valid_with_commands(std::mem::take(&mut ops), commands)
}

pub static SECRET_SHARED_UNWRAP_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_SECRET_SHARED_UNWRAP,
    type_name: "secret_shared_unwrap",
    projection_table: "secret_shared_unwrap",
    share_scope: ShareScope::Local,
    dep_fields: &["secret_shared_event_id", "local_key_event_id"],
    dep_field_type_codes: &[&[22], &[28]],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_secret_shared_unwrap,
    encode: encode_secret_shared_unwrap,
    projector: project_pure,
    context_loader: build_projector_context,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::{encode_event, parse_event};

    #[test]
    fn test_roundtrip_secret_shared_unwrap() {
        let e = ParsedEvent::SecretSharedUnwrap(SecretSharedUnwrapEvent {
            created_at_ms: 99,
            secret_shared_event_id: [1u8; 32],
            recipient_event_id: [2u8; 32],
            wrapped_key: [3u8; 32],
            signed_by: [4u8; 32],
            signer_type: 5,
        });
        let blob = encode_event(&e).unwrap();
        assert_eq!(blob.len(), SECRET_SHARED_UNWRAP_WIRE_SIZE);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, e);
    }
}
