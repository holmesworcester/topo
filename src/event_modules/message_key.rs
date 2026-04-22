//! message_key (type 40) — per-message K_m wrap. Deterministic,
//! content-addressed, unsigned.
//!
//! Each outgoing `message` event carries a fresh unique K_m in its
//! ciphertext. The `message_key` event carries that K_m symmetrically
//! wrapped under the sender device's current `K_bundle` at send time:
//!
//!     wrapped_k_m = AEAD(K_bundle, K_m)
//!
//! The owning `message` references this event via its outer
//! `key_event_id` field (semantically retargeted from "transport key
//! id" to "message_key event id"). When `message_key` projects Valid,
//! it inserts K_m into `key_secrets` keyed by its own event id;
//! cascade unblocks the owning `message` which looks up K_m via
//! `SELECT key_bytes FROM key_secrets WHERE event_id = enc.key_event_id`.
//!
//! **Self-drop on tombstoned owner:** before materializing K_m, the
//! projector checks `deleted_messages` for `owning_message_event_id`
//! and if present, terminal-drops without side effects. Defends
//! against late-arriving `message_key` re-materializing K_m
//! post-delete. Admin-signed `deletion_intents` are also honored
//! (pre-creation tombstones by admin authority).

use super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_MESSAGE_KEY};

// Wire layout.
pub const MESSAGE_KEY_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("bundle_id"),
    FieldSpec::EventId("owning_message_event_id"),
    FieldSpec::FixedBytes("nonce", 12),
    FieldSpec::FixedBytes("wrapped_k_m", 48),
];

/// message_key wire size: type(1) + created_at(8) + bundle_id(32)
///   + owning_message(32) + nonce(12) + wrapped_k_m(48) = 133 bytes.
pub const MESSAGE_KEY_WIRE_SIZE: usize = wire_size_for_fields(MESSAGE_KEY_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageKeyEvent {
    pub created_at_ms: u64,
    /// The K_bundle used to wrap K_m. Sender device's current bundle
    /// at send time.
    pub bundle_id: [u8; 32],
    /// The `message` event this key is for. Self-drop check uses this.
    pub owning_message_event_id: [u8; 32],
    /// AEAD nonce (12 bytes).
    pub nonce: [u8; 12],
    /// AEAD(K_bundle, K_m) — 32-byte K_m + 16-byte GCM tag.
    pub wrapped_k_m: [u8; 48],
}

impl super::Describe for MessageKeyEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("bundle_id", super::short_id_b64(&self.bundle_id)),
            (
                "owning_message_event_id",
                super::short_id_b64(&self.owning_message_event_id),
            ),
        ]
    }
}

pub fn parse_message_key(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_MESSAGE_KEY, MESSAGE_KEY_FIELDS, blob)?;
    let nonce_bytes = values[3]
        .clone()
        .into_fixed_bytes()
        .ok_or(EventError::WrongVariant)?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_bytes);
    let wrapped_bytes = values[4]
        .clone()
        .into_fixed_bytes()
        .ok_or(EventError::WrongVariant)?;
    let mut wrapped_k_m = [0u8; 48];
    wrapped_k_m.copy_from_slice(&wrapped_bytes);
    Ok(ParsedEvent::MessageKey(MessageKeyEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        bundle_id: values[1].as_event_id().unwrap(),
        owning_message_event_id: values[2].as_event_id().unwrap(),
        nonce,
        wrapped_k_m,
    }))
}

pub fn encode_message_key(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let mk = match event {
        ParsedEvent::MessageKey(m) => m,
        _ => return Err(EventError::WrongVariant),
    };
    let values = vec![
        FieldValue::Timestamp(mk.created_at_ms),
        FieldValue::EventId(mk.bundle_id),
        FieldValue::EventId(mk.owning_message_event_id),
        FieldValue::FixedBytes(mk.nonce.to_vec()),
        FieldValue::FixedBytes(mk.wrapped_k_m.to_vec()),
    ];
    Ok(encode_fields(EVENT_TYPE_MESSAGE_KEY, MESSAGE_KEY_FIELDS, &values)?)
}

/// Deterministic `created_at_ms` for content-addressed message_key.
/// Derived from the wrapped K_m + bundle_id so any peer that
/// re-emits produces byte-identical events.
pub fn deterministic_message_key_created_at_ms(
    bundle_id: &[u8; 32],
    owning_message_event_id: &[u8; 32],
    wrapped_k_m: &[u8; 48],
) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"poc7-message-key-created-at-v1");
    hasher.update(bundle_id);
    hasher.update(owning_message_event_id);
    hasher.update(wrapped_k_m);
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest.as_bytes()[..8]);
    u64::from_le_bytes(out)
}

// ─── Projector ───

use crate::projection::projector::{ProjectorDecisionContext, ProjectorResult, SqlVal, WriteOp};
use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS message_keys (
            event_id TEXT NOT NULL,
            bundle_id TEXT NOT NULL,
            owning_message_event_id TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            recorded_by TEXT NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_message_keys_owning
            ON message_keys (recorded_by, owning_message_event_id);
        CREATE INDEX IF NOT EXISTS idx_message_keys_bundle
            ON message_keys (recorded_by, bundle_id);
        ",
    )?;
    Ok(())
}

/// Projector for message_key. Inserts the header row into
/// `message_keys` and, when K_bundle is locally available, inserts
/// the decrypted K_m into `key_secrets` keyed by this event's own
/// event_id so the owning message's encrypted projection can decrypt.
///
/// Owner-tombstone pre-check: if the owning message is already
/// tombstoned (`deleted_messages` has a row), terminal-drop without
/// writing anything. Replay of the same message_key will also see
/// the persistent `deleted_messages` row and drop.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ProjectorDecisionContext,
) -> ProjectorResult {
    let mk = match parsed {
        ParsedEvent::MessageKey(m) => m,
        _ => return ProjectorResult::reject("not a message_key event".to_string()),
    };
    let owning_b64 = crate::crypto::event_id_to_base64(&mk.owning_message_event_id);

    // Owner-tombstone pre-check. Self-drop if either `deleted_messages`
    // row or admin-signed `deletion_intent` exists.
    if ctx.owning_message_tombstoned.unwrap_or(false) {
        // Terminal drop via Valid + no writes. The already_processed()
        // check suppresses replay via events.event_id presence, and
        // the durable `deleted_messages` row keeps the tombstone
        // visible for future arrivals of the same message_key.
        return ProjectorResult::valid(vec![]);
    }

    let mut ops = vec![WriteOp::InsertOrIgnore {
        table: "message_keys",
        columns: vec![
            "event_id",
            "bundle_id",
            "owning_message_event_id",
            "created_at_ms",
            "recorded_by",
        ],
        values: vec![
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(crate::crypto::event_id_to_base64(&mk.bundle_id)),
            SqlVal::Text(owning_b64),
            SqlVal::Int(mk.created_at_ms as i64),
            SqlVal::Text(recorded_by.to_string()),
        ],
    }];

    // If K_bundle was locally materialized and the context loaded the
    // decrypted K_m, insert into key_secrets keyed by this event's
    // own id. Cascade unblocks the owning Encrypted message.
    if let Some(k_m) = ctx.decrypted_k_m_bytes {
        ops.push(WriteOp::InsertOrIgnore {
            table: "key_secrets",
            columns: vec!["event_id", "key_bytes", "created_at", "recorded_by"],
            values: vec![
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Blob(k_m.to_vec()),
                SqlVal::Int(mk.created_at_ms as i64),
                SqlVal::Text(recorded_by.to_string()),
            ],
        });
    }
    ProjectorResult::valid(ops)
}

pub static MESSAGE_KEY_META: EventTypeMeta = crate::event_modules::registry::event_type_meta! {
    type_code: EVENT_TYPE_MESSAGE_KEY,
    type_name: "message_key",
    projection_table: "message_keys",
    share_scope: ShareScope::Shared,
    dep_fields: &["owning_message_event_id"],
    dep_field_type_codes: &[&[]],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_message_key,
    encode: encode_message_key,
    projector: project_pure,
    context_loader: crate::event_modules::registry::load_empty_context,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_size_is_133_bytes() {
        // type(1) + created_at(8) + bundle(32) + owning(32) + nonce(12) + wrap(48) = 133
        assert_eq!(MESSAGE_KEY_WIRE_SIZE, 133);
    }

    #[test]
    fn parse_encode_roundtrip() {
        let original = ParsedEvent::MessageKey(MessageKeyEvent {
            created_at_ms: 1_700_000_000_000,
            bundle_id: [1u8; 32],
            owning_message_event_id: [2u8; 32],
            nonce: [3u8; 12],
            wrapped_k_m: [4u8; 48],
        });
        let blob = encode_message_key(&original).expect("encode");
        assert_eq!(blob.len(), MESSAGE_KEY_WIRE_SIZE);
        assert_eq!(blob[0], EVENT_TYPE_MESSAGE_KEY);
        let parsed = parse_message_key(&blob).expect("parse");
        assert_eq!(original, parsed);
    }

    #[test]
    fn deterministic_created_at_is_stable() {
        let bundle_id = [5u8; 32];
        let owning = [6u8; 32];
        let wrapped = [7u8; 48];
        let a = deterministic_message_key_created_at_ms(&bundle_id, &owning, &wrapped);
        let b = deterministic_message_key_created_at_ms(&bundle_id, &owning, &wrapped);
        assert_eq!(a, b);
        let c = deterministic_message_key_created_at_ms(&[8u8; 32], &owning, &wrapped);
        assert_ne!(a, c);
    }
}
