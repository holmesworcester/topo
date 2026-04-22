//! message_key (type 40) — per-message K_m wrap. Deterministic,
//! content-addressed, unsigned.
//!
//! Each outgoing `message` event uses a fresh unique K_m to encrypt
//! its ciphertext. The `message_key` event carries that K_m
//! symmetrically wrapped under the sender device's current K_bundle:
//!
//!     wrapped_k_m = AEAD(K_bundle, K_m)
//!
//! The owning Encrypted wrapper references this event via its outer
//! `key_event_id` field (semantically retargeted from "transport
//! key id" to "message_key event id"). When `message_key` projects
//! Valid, it inserts K_m into `key_secrets` keyed by its own event
//! id; cascade unblocks the owning Encrypted message which looks up
//! K_m via `SELECT key_bytes FROM key_secrets WHERE event_id =
//! enc.key_event_id`.
//!
//! **Option C design**: `message_key` deliberately does NOT carry
//! `owning_message_event_id`. The link is established when the
//! Encrypted projects (it knows its own event_id AND its
//! enc.key_event_id = mkey_evid) — that linkage is written into
//! the `messages_to_message_keys` reverse index. Purge cascade uses
//! the reverse index to enumerate what to remove on tombstone. This
//! avoids the content-addressing chicken-and-egg where message_key
//! and message each depend on the other's hash.

use super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_MESSAGE_KEY};

// Wire layout.
pub const MESSAGE_KEY_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("bundle_id"),
    FieldSpec::EventId("k_bundle_local_event_id"),
    FieldSpec::FixedBytes("nonce", 12),
    FieldSpec::FixedBytes("wrapped_k_m", 48),
];

/// message_key wire size: type(1) + created_at(8) + bundle_id(32)
///   + k_bundle_local_event_id(32) + nonce(12) + wrapped_k_m(48) = 133 bytes.
pub const MESSAGE_KEY_WIRE_SIZE: usize = wire_size_for_fields(MESSAGE_KEY_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageKeyEvent {
    pub created_at_ms: u64,
    /// The K_bundle used to wrap K_m. Sender device's current bundle
    /// at send time.
    pub bundle_id: [u8; 32],
    /// Deterministic local `KeySecret(K_bundle)` event id
    /// (= `deterministic_key_secret_event_id(K_bundle_bytes)`).
    /// This is the blocking dep: stable regardless of which producer
    /// (`key_broadcast`, `key_history_bundle`, `key_bundle_share`)
    /// delivers K_bundle.
    pub k_bundle_local_event_id: [u8; 32],
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
                "k_bundle_local_event_id",
                super::short_id_b64(&self.k_bundle_local_event_id),
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
        k_bundle_local_event_id: values[2].as_event_id().unwrap(),
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
        FieldValue::EventId(mk.k_bundle_local_event_id),
        FieldValue::FixedBytes(mk.nonce.to_vec()),
        FieldValue::FixedBytes(mk.wrapped_k_m.to_vec()),
    ];
    Ok(encode_fields(EVENT_TYPE_MESSAGE_KEY, MESSAGE_KEY_FIELDS, &values)?)
}

/// Deterministic `created_at_ms` for content-addressed message_key.
/// Derived from (bundle_id, k_bundle_local_event_id, wrapped_k_m) so
/// any peer that re-emits with the same inputs produces a
/// byte-identical event.
pub fn deterministic_message_key_created_at_ms(
    bundle_id: &[u8; 32],
    k_bundle_local_event_id: &[u8; 32],
    wrapped_k_m: &[u8; 48],
) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"poc7-message-key-created-at-v2");
    hasher.update(bundle_id);
    hasher.update(k_bundle_local_event_id);
    hasher.update(wrapped_k_m);
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest.as_bytes()[..8]);
    u64::from_le_bytes(out)
}

/// Deterministic nonce for AEAD(K_bundle, K_m).
/// Any peer that re-wraps the same K_m under the same K_bundle
/// produces the same ciphertext + tag — content-address dedupe.
pub fn deterministic_message_key_nonce(
    k_bundle_local_event_id: &[u8; 32],
    k_m: &[u8; 32],
) -> [u8; 12] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"poc7-message-key-nonce-v1");
    hasher.update(k_bundle_local_event_id);
    hasher.update(k_m);
    let digest = hasher.finalize();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&digest.as_bytes()[..12]);
    nonce
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
            k_bundle_local_event_id TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            recorded_by TEXT NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_message_keys_bundle
            ON message_keys (recorded_by, bundle_id);

        -- Option C reverse index: links message event id to the
        -- message_key event that carries its K_m. Populated when an
        -- Encrypted event successfully projects via its mkey. Read
        -- by purge cascade on MessageDeletion to enumerate the
        -- message_keys to purge for a given message.
        CREATE TABLE IF NOT EXISTS messages_to_message_keys (
            message_event_id TEXT NOT NULL,
            message_key_event_id TEXT NOT NULL,
            recorded_by TEXT NOT NULL,
            PRIMARY KEY (recorded_by, message_event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_messages_to_message_keys_mkey
            ON messages_to_message_keys (recorded_by, message_key_event_id);
        ",
    )?;
    Ok(())
}

/// Projector for message_key. Inserts the header row and — when
/// K_bundle is locally available — AEAD-decrypts `wrapped_k_m` to
/// recover K_m, then writes K_m into `key_secrets` keyed by this
/// event's own event_id so the standard Encrypted hot path finds
/// it on cascade retry.
///
/// Late-arrival defense: under Option C, there is no
/// owning_message_event_id to pre-check against `deleted_messages`
/// here. Instead, if a message_key's owning message has already
/// been tombstoned + hard-purged, the Encrypted event that would
/// have used this K_m is gone — the K_m row produced here is an
/// orphan that occupies local state but cannot decrypt anything
/// (no ciphertext exists for it). Orphan GC for such rows is a
/// periodic sweep in the heal loop (see
/// PHASE_8_PENDING_SIM_TESTS.md).
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

    let mut ops = vec![WriteOp::InsertOrIgnore {
        table: "message_keys",
        columns: vec![
            "event_id",
            "bundle_id",
            "k_bundle_local_event_id",
            "created_at_ms",
            "recorded_by",
        ],
        values: vec![
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(crate::crypto::event_id_to_base64(&mk.bundle_id)),
            SqlVal::Text(crate::crypto::event_id_to_base64(&mk.k_bundle_local_event_id)),
            SqlVal::Int(mk.created_at_ms as i64),
            SqlVal::Text(recorded_by.to_string()),
        ],
    }];

    // Pattern (b): if K_bundle is locally materialized, do the AEAD
    // decrypt here in the projector (pure, deterministic) to recover
    // K_m. wrapped_k_m is 48 bytes = 32-byte ciphertext + 16-byte
    // GCM tag. Emit K_m into key_secrets keyed by this message_key's
    // own event_id so the owning Encrypted message's cascade finds
    // it via the standard key_secrets lookup path.
    if let Some(k_bundle) = ctx.unwrapped_k_bundle {
        let ciphertext = &mk.wrapped_k_m[0..32];
        let mut auth_tag = [0u8; 16];
        auth_tag.copy_from_slice(&mk.wrapped_k_m[32..48]);
        if let Ok(plaintext) = crate::projection::encrypted::decrypt_event_blob(
            &k_bundle,
            &mk.nonce,
            ciphertext,
            &auth_tag,
        ) {
            if plaintext.len() == 32 {
                ops.push(WriteOp::InsertOrIgnore {
                    table: "key_secrets",
                    columns: vec!["event_id", "key_bytes", "created_at", "recorded_by"],
                    values: vec![
                        SqlVal::Text(event_id_b64.to_string()),
                        SqlVal::Blob(plaintext),
                        SqlVal::Int(mk.created_at_ms as i64),
                        SqlVal::Text(recorded_by.to_string()),
                    ],
                });
            }
        }
    }
    ProjectorResult::valid(ops)
}

crate::projection::decision_context::define_query_context_loader!(
    build_projector_context,
    MessageKey,
    load_message_key_context,
    "message_key"
);

pub static MESSAGE_KEY_META: EventTypeMeta = crate::event_modules::registry::event_type_meta! {
    type_code: EVENT_TYPE_MESSAGE_KEY,
    type_name: "message_key",
    projection_table: "message_keys",
    share_scope: ShareScope::Shared,
    // Blocking dep: the local deterministic KeySecret(K_bundle). Any
    // of the three producers (key_broadcast, key_history_bundle,
    // key_bundle_share) materializes this identically, so cascade
    // unblocks uniformly.
    dep_fields: &["k_bundle_local_event_id"],
    dep_field_type_codes: &[&[crate::event_modules::EVENT_TYPE_KEY_SECRET]],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_message_key,
    encode: encode_message_key,
    projector: project_pure,
    context_loader: build_projector_context,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_size_is_133_bytes() {
        // type(1) + created_at(8) + bundle(32) + k_bundle_local(32)
        //   + nonce(12) + wrap(48) = 133
        assert_eq!(MESSAGE_KEY_WIRE_SIZE, 133);
    }

    #[test]
    fn parse_encode_roundtrip() {
        let original = ParsedEvent::MessageKey(MessageKeyEvent {
            created_at_ms: 1_700_000_000_000,
            bundle_id: [1u8; 32],
            k_bundle_local_event_id: [9u8; 32],
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
        let k_bundle_local = [6u8; 32];
        let wrapped = [7u8; 48];
        let a = deterministic_message_key_created_at_ms(&bundle_id, &k_bundle_local, &wrapped);
        let b = deterministic_message_key_created_at_ms(&bundle_id, &k_bundle_local, &wrapped);
        assert_eq!(a, b);
        let c = deterministic_message_key_created_at_ms(&[8u8; 32], &k_bundle_local, &wrapped);
        assert_ne!(a, c);
    }

    #[test]
    fn deterministic_nonce_stable_and_unique_per_k_m() {
        let k_bundle_local = [0xAAu8; 32];
        let k_m_a = [0x11u8; 32];
        let k_m_b = [0x22u8; 32];
        let nonce_a = deterministic_message_key_nonce(&k_bundle_local, &k_m_a);
        let nonce_a2 = deterministic_message_key_nonce(&k_bundle_local, &k_m_a);
        let nonce_b = deterministic_message_key_nonce(&k_bundle_local, &k_m_b);
        assert_eq!(nonce_a, nonce_a2);
        assert_ne!(nonce_a, nonce_b);
    }
}
