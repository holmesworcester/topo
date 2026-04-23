use super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_KEY_SECRET};
use crate::crypto::EventId;

// ─── Layout (owned by this module) ───

pub const KEY_SECRET_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("key_bytes"),
];

/// Secret (type 6): type(1) + created_at(8) + key_bytes(32) = 41
pub const KEY_SECRET_WIRE_SIZE: usize = wire_size_for_fields(KEY_SECRET_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySecretEvent {
    pub created_at_ms: u64,
    pub key_bytes: [u8; 32], // AES-256 symmetric key
}

impl super::Describe for KeySecretEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![("key_bytes", super::trunc_hex(&self.key_bytes, 16))]
    }
}

/// Wire format (41 bytes fixed):
/// [0]      type_code = 6
/// [1..9]   created_at_ms (u64 LE)
/// [9..41]  key_bytes (32 bytes)
pub fn parse_key_secret(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if let Some((created_at_ms, key_bytes)) =
        topo_verus_proofs::event_modules::layout::ts_id::parse_ts_id(EVENT_TYPE_KEY_SECRET, blob)
    {
        return Ok(ParsedEvent::KeySecret(KeySecretEvent {
            created_at_ms,
            key_bytes,
        }));
    }
    let values = decode_fields(EVENT_TYPE_KEY_SECRET, KEY_SECRET_FIELDS, blob)?;
    Ok(ParsedEvent::KeySecret(KeySecretEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        key_bytes: values[1].as_event_id().unwrap(),
    }))
}

pub fn encode_key_secret(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let sk = match event {
        ParsedEvent::KeySecret(s) => s,
        _ => return Err(EventError::WrongVariant),
    };
    Ok(topo_verus_proofs::event_modules::layout::ts_id::encode_ts_id(
        EVENT_TYPE_KEY_SECRET,
        sk.created_at_ms,
        &sk.key_bytes,
    ))
}

/// Deterministic timestamp derivation for key materialized Secret events.
pub fn deterministic_key_secret_created_at_ms(key_bytes: &[u8; 32]) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"poc7-content-key-created-at-v1");
    hasher.update(key_bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest.as_bytes()[..8]);
    u64::from_le_bytes(out)
}

pub fn deterministic_key_secret_event(key_bytes: [u8; 32]) -> ParsedEvent {
    ParsedEvent::KeySecret(KeySecretEvent {
        created_at_ms: deterministic_key_secret_created_at_ms(&key_bytes),
        key_bytes,
    })
}

pub fn deterministic_key_secret_event_id(key_bytes: &[u8; 32]) -> EventId {
    let event = deterministic_key_secret_event(*key_bytes);
    let blob =
        super::encode_event(&event).expect("deterministic key_secret encoding should succeed");
    crate::crypto::hash_event(&blob)
}

// === Projector (event-module locality) ===

use crate::projection::projector::{ProjectorDecisionContext, ProjectorResult, SqlVal, WriteOp};
use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS key_secrets (
            event_id TEXT NOT NULL,
            key_bytes BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            recorded_by TEXT NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );

        -- Strong-FS Case B (`docs/DESIGN.md` §9.6.5,
        -- `docs/PLAN.md` §22.3.2): once a K_bundle has been shredded
        -- locally due to a MessageDeletion cascade, any future
        -- projection attempting to write THAT SPECIFIC K_bundle row
        -- back into `key_secrets` must be refused. The gate is keyed
        -- by `(recorded_by, k_bundle_local_event_id)` — it does NOT
        -- block rehydration of K_m rows for un-deleted messages in
        -- the retired bundle. Those K_m rows live in `key_secrets`
        -- under the message_key's own event id, a different key,
        -- and MUST be allowed to rematerialize via Case A's K_m
        -- slots in `key_history_bundle` or via the heal-path
        -- `key_message_share` event (if/when it lands) so
        -- un-deleted messages stay decryptable for late joiners.
        -- Populated by `delete_tenant_rows` at the same site that
        -- shreds the K_bundle row. Consulted in `write_exec.rs` at
        -- every `InsertOrIgnore` into `key_secrets` — the gate
        -- matches by event_id so it's table-specific and narrow.
        CREATE TABLE IF NOT EXISTS retired_bundles (
            recorded_by TEXT NOT NULL,
            k_bundle_local_event_id TEXT NOT NULL,
            retired_at_ms INTEGER NOT NULL,
            PRIMARY KEY (recorded_by, k_bundle_local_event_id)
        );
        ",
    )?;
    Ok(())
}

/// Pure projector: Secret -> key_secrets table insert.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ProjectorDecisionContext,
) -> ProjectorResult {
    let sk = match parsed {
        ParsedEvent::KeySecret(s) => s,
        _ => return ProjectorResult::reject("not a key_secret event".to_string()),
    };

    let ops = vec![WriteOp::InsertOrIgnore {
        table: "key_secrets",
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

pub static KEY_SECRET_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_KEY_SECRET,
    type_name: "key_secret",
    projection_table: "key_secrets",
    share_scope: ShareScope::Local,
    dep_fields: &[],
    dep_field_type_codes: &[],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: true,
    parse: parse_key_secret,
    encode: encode_key_secret,
    projector: project_pure,
    context_loader: crate::event_modules::registry::load_empty_context,
};
