use super::layout::common::{COMMON_HEADER_BYTES, SIGNATURE_TRAILER_BYTES};
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_KEY_SHARED};

// ─── Layout (owned by this module) ───

/// KeyShared (type 22): type(1) + created_at(8) + key_event_id(32) + recipient_event_id(32)
///                        + unwrap_key_event_id(32) + wrapped_key(32) + signed_by(32)
///                        + signer_type(1) + signature(64) = 234
pub const KEY_SHARED_WIRE_SIZE: usize =
    COMMON_HEADER_BYTES + 32 + 32 + 32 + 32 + SIGNATURE_TRAILER_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySharedEvent {
    pub created_at_ms: u64,
    pub key_event_id: [u8; 32],        // dep: Secret event
    pub recipient_event_id: [u8; 32],  // dep: invite event of recipient
    pub unwrap_key_event_id: [u8; 32], // dep: local InviteSecret event (recipient side)
    pub wrapped_key: [u8; 32],         // key bytes wrapped for recipient
    pub signed_by: [u8; 32],           // signer event_id (PeerShared event — sender)
    pub signer_type: u8,               // 5 = peer_shared
    pub signature: [u8; 64],
}

impl super::Describe for KeySharedEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("key_event_id", super::short_id_b64(&self.key_event_id)),
            ("wrapped_key", super::trunc_hex(&self.wrapped_key, 16)),
        ]
    }
}

/// Wire format (234 bytes fixed):
/// [0]          type_code = 22
/// [1..9]       created_at_ms (u64 LE)
/// [9..41]      key_event_id (32 bytes)
/// [41..73]     recipient_event_id (32 bytes)
/// [73..105]    unwrap_key_event_id (32 bytes)
/// [105..137]   wrapped_key (32 bytes)
/// [137..169]   signed_by (32 bytes)
/// [169]        signer_type (1 byte)
/// [170..234]   signature (64 bytes)
pub fn parse_key_shared(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < KEY_SHARED_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: KEY_SHARED_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > KEY_SHARED_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: KEY_SHARED_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_KEY_SHARED {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_KEY_SHARED,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());
    let mut key_event_id = [0u8; 32];
    key_event_id.copy_from_slice(&blob[9..41]);
    let mut recipient_event_id = [0u8; 32];
    recipient_event_id.copy_from_slice(&blob[41..73]);
    let mut unwrap_key_event_id = [0u8; 32];
    unwrap_key_event_id.copy_from_slice(&blob[73..105]);
    let mut wrapped_key = [0u8; 32];
    wrapped_key.copy_from_slice(&blob[105..137]);
    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[137..169]);
    let signer_type = blob[169];
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[170..234]);

    Ok(ParsedEvent::KeyShared(KeySharedEvent {
        created_at_ms,
        key_event_id,
        recipient_event_id,
        unwrap_key_event_id,
        wrapped_key,
        signed_by,
        signer_type,
        signature,
    }))
}

pub fn encode_key_shared(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::KeyShared(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    let mut buf = Vec::with_capacity(KEY_SHARED_WIRE_SIZE);
    buf.push(EVENT_TYPE_KEY_SHARED);
    buf.extend_from_slice(&e.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&e.key_event_id);
    buf.extend_from_slice(&e.recipient_event_id);
    buf.extend_from_slice(&e.unwrap_key_event_id);
    buf.extend_from_slice(&e.wrapped_key);
    buf.extend_from_slice(&e.signed_by);
    buf.push(e.signer_type);
    buf.extend_from_slice(&e.signature);
    Ok(buf)
}

// === Projector (event-module locality) ===

use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ContextSnapshot, EmitCommand, ProjectorResult, SqlVal, WriteOp};
use crate::projection::encrypted::unwrap_key_from_sender;
use crate::projection::signer::{resolve_signer_key, SignerResolution};
use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS key_shared (
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

/// Build projector-local context for KeyShared projection.
pub fn build_projector_context(
    conn: &Connection,
    recorded_by: &str,
    _event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let ss = match parsed {
        ParsedEvent::KeyShared(ss) => ss,
        _ => return Err("key_shared context loader called for non-key_shared event".into()),
    };

    let recipient_b64 = event_id_to_base64(&ss.recipient_event_id);
    let unwrap_key_b64 = event_id_to_base64(&ss.unwrap_key_event_id);
    let recipient_removed = conn.query_row(
        "SELECT COUNT(*) > 0 FROM removed_entities WHERE recorded_by = ?1 AND target_event_id = ?2",
        rusqlite::params![recorded_by, &recipient_b64],
        |row| row.get(0),
    )?;

    let invite_secret_row: Option<Vec<u8>> = conn
        .query_row(
            "SELECT private_key
             FROM invite_secrets
             WHERE recorded_by = ?1
               AND event_id = ?2
               AND invite_event_id = ?3
             LIMIT 1",
            rusqlite::params![recorded_by, &unwrap_key_b64, &recipient_b64],
            |row| row.get(0),
        )
        .ok();

    let private_key_bytes = match invite_secret_row {
        Some(v) => v,
        None => {
            return Ok(ContextSnapshot {
                recipient_removed,
                ..ContextSnapshot::default()
            });
        }
    };
    if private_key_bytes.len() != 32 {
        return Ok(ContextSnapshot {
            recipient_removed,
            ..ContextSnapshot::default()
        });
    }

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&private_key_bytes);
    let local_signing_key = ed25519_dalek::SigningKey::from_bytes(&key_arr);

    let sender_key = match resolve_signer_key(conn, recorded_by, ss.signer_type, &ss.signed_by) {
        Ok(SignerResolution::Found(k)) => k,
        _ => {
            return Ok(ContextSnapshot {
                recipient_removed,
                ..ContextSnapshot::default()
            });
        }
    };
    let sender_pub = match ed25519_dalek::VerifyingKey::from_bytes(&sender_key) {
        Ok(vk) => vk,
        Err(_) => {
            return Ok(ContextSnapshot {
                recipient_removed,
                ..ContextSnapshot::default()
            });
        }
    };

    let plaintext_key = unwrap_key_from_sender(&local_signing_key, &sender_pub, &ss.wrapped_key);

    Ok(ContextSnapshot {
        recipient_removed,
        unwrapped_secret_material: Some(crate::projection::contract::UnwrappedSecretMaterial {
            key_bytes: plaintext_key,
        }),
        ..ContextSnapshot::default()
    })
}

/// Pure projector: KeyShared → key_shared table.
/// Rejects if recipient has been removed (InvRemovalExclusion).
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let ss = match parsed {
        ParsedEvent::KeyShared(s) => s,
        _ => return ProjectorResult::reject("not a key_shared event".to_string()),
    };

    let key_b64 = event_id_to_base64(&ss.key_event_id);
    let recipient_b64 = event_id_to_base64(&ss.recipient_event_id);

    if ctx.recipient_removed {
        return ProjectorResult::reject(format!("recipient {} has been removed", recipient_b64));
    }

    let ops = vec![WriteOp::InsertOrIgnore {
        table: "key_shared",
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

    let material = match &ctx.unwrapped_secret_material {
        Some(v) => v,
        None => return ProjectorResult::valid(ops),
    };

    let secret_event =
        crate::event_modules::key_secret::deterministic_key_secret_event(material.key_bytes);
    let secret_blob = match crate::event_modules::encode_event(&secret_event) {
        Ok(v) => v,
        Err(err) => {
            return ProjectorResult::reject(format!(
                "failed to encode deterministic secret event: {}",
                err
            ))
        }
    };
    let derived_key_event_id = crate::crypto::hash_event(&secret_blob);
    if derived_key_event_id != ss.key_event_id {
        return ProjectorResult::reject(
            "unwrapped key material does not match claimed key_event_id".to_string(),
        );
    }

    ProjectorResult::valid_with_commands(
        ops,
        vec![EmitCommand::EmitDeterministicBlob { blob: secret_blob }],
    )
}

pub static KEY_SHARED_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_KEY_SHARED,
    type_name: "key_shared",
    projection_table: "key_shared",
    share_scope: ShareScope::Shared,
    dep_fields: &["recipient_event_id", "unwrap_key_event_id", "signed_by"],
    dep_field_type_codes: &[&[10, 12], &[28], &[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: false,
    parse: parse_key_shared,
    encode: encode_key_shared,
    projector: project_pure,
    context_loader: build_projector_context,
};
