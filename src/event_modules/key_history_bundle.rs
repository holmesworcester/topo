//! key_history_bundle (type 39) — bootstrap fanout of many historical
//! K_bundle values to a single new-joiner recipient.
//!
//! Wire: 1 recipient wrap (anchor K_bundle asymmetric-wrapped to the
//! joiner's WrapPubkey) + 8192 historical-bundle slots, each carrying
//! (historical_bundle_id, AEAD_encrypt(K_bundle, historical_K_bundle_bytes)).
//!
//! Joiner unwraps the anchor K_bundle via their wrap_privkeys, then
//! uses it to AEAD-decrypt each historical slot. Each successful
//! decrypt materializes a deterministic local
//! `KeySecret(historical_K_bundle)`.
//!
//! Retargets master's `KeyHistory` shape for the per-message FS design.

use super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_KEY_HISTORY_BUNDLE};

pub const KEY_HISTORY_BUNDLE_CAP: usize = 8192;
/// Each historical slot is 32B bundle_id + 48B AEAD ciphertext
/// (32B K_bundle_bytes + 16B GCM tag) = 80 bytes.
pub const HISTORICAL_SLOT_BYTES: usize = 32 + 48;
pub const KEY_HISTORY_BUNDLE_SLOTS_TOTAL: usize = KEY_HISTORY_BUNDLE_CAP * HISTORICAL_SLOT_BYTES;

/// Capacity for per-message K_m slots carried alongside historical
/// K_bundle slots. These are populated for un-deleted messages that
/// reside in a bundle that was RETIRED (K_bundle purged on every
/// honest peer) before the invite was created. Case A recovery per
/// `docs/DESIGN.md` §9.6.5.
pub const MESSAGE_KEY_SLOT_CAP: usize = 4096;
/// Each message_key slot is 32B target_mkey_event_id + 48B AEAD
/// ciphertext (32B K_m_bytes + 16B GCM tag) = 80 bytes. Same layout
/// as historical K_bundle slots — we dispatch by the separate field
/// position rather than by a per-slot type tag.
pub const MESSAGE_KEY_SLOT_BYTES: usize = 32 + 48;
pub const MESSAGE_KEY_SLOTS_TOTAL: usize = MESSAGE_KEY_SLOT_CAP * MESSAGE_KEY_SLOT_BYTES;

pub const KEY_HISTORY_BUNDLE_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("anchor_bundle_id"),
    FieldSpec::EventId("recipient_wrappubkey_event_id"),
    FieldSpec::EventId("wrapped_anchor_bundle"),
    FieldSpec::FixedBytes("nonce", 12),
    FieldSpec::FixedBytes("historical_slots", KEY_HISTORY_BUNDLE_SLOTS_TOTAL),
    FieldSpec::FixedBytes("message_key_slots", MESSAGE_KEY_SLOTS_TOTAL),
];

pub const KEY_HISTORY_BUNDLE_WIRE_SIZE: usize = wire_size_for_fields(KEY_HISTORY_BUNDLE_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyHistoryBundleEvent {
    pub created_at_ms: u64,
    pub anchor_bundle_id: [u8; 32],
    pub recipient_wrappubkey_event_id: [u8; 32],
    pub wrapped_anchor_bundle: [u8; 32],
    pub nonce: [u8; 12],
    /// 8192 slots × 80 bytes each. Each populated slot is
    /// (bundle_id 32B, AEAD(K_anchor, K_bundle_bytes) 48B). Used for
    /// historical K_bundle delivery — each slot materializes a
    /// canonical `KeySecret(K_bundle)` event on unwrap. Unused slots
    /// zero-filled.
    pub historical_slots: Vec<u8>,
    /// 4096 slots × 80 bytes each. Each populated slot is
    /// (target_message_key_event_id 32B, AEAD(K_anchor, K_m_bytes)
    /// 48B). Populated for un-deleted messages whose bundle was
    /// retired on every honest peer before the invite was created
    /// (Case A per `docs/DESIGN.md` §9.6.5). Projector unwraps K_m
    /// and writes it into `key_secrets` keyed by the target
    /// message_key event id, then emits
    /// `RetryBlockedEncryptedByKey` so the joiner's Encrypted
    /// wrappers can decrypt. Unused slots zero-filled.
    pub message_key_slots: Vec<u8>,
}

impl super::Describe for KeyHistoryBundleEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        let populated = self
            .historical_slots
            .chunks_exact(HISTORICAL_SLOT_BYTES)
            .filter(|slot| slot.iter().any(|b| *b != 0))
            .count();
        vec![
            ("anchor_bundle_id", super::short_id_b64(&self.anchor_bundle_id)),
            ("slot_cap", KEY_HISTORY_BUNDLE_CAP.to_string()),
            ("populated_history", populated.to_string()),
        ]
    }
}

pub fn parse_key_history_bundle(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_KEY_HISTORY_BUNDLE, KEY_HISTORY_BUNDLE_FIELDS, blob)?;
    let nonce_bytes = values[4]
        .clone()
        .into_fixed_bytes()
        .ok_or(EventError::WrongVariant)?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_bytes);
    let historical_slots = values[5]
        .clone()
        .into_fixed_bytes()
        .ok_or(EventError::WrongVariant)?;
    let message_key_slots = values[6]
        .clone()
        .into_fixed_bytes()
        .ok_or(EventError::WrongVariant)?;
    Ok(ParsedEvent::KeyHistoryBundle(KeyHistoryBundleEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        anchor_bundle_id: values[1].as_event_id().unwrap(),
        recipient_wrappubkey_event_id: values[2].as_event_id().unwrap(),
        wrapped_anchor_bundle: values[3].as_event_id().unwrap(),
        nonce,
        historical_slots,
        message_key_slots,
    }))
}

pub fn encode_key_history_bundle(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let kh = match event {
        ParsedEvent::KeyHistoryBundle(k) => k,
        _ => return Err(EventError::WrongVariant),
    };
    if kh.historical_slots.len() != KEY_HISTORY_BUNDLE_SLOTS_TOTAL {
        return Err(EventError::InvalidMetadata(
            "historical_slots size does not match key_history_bundle cap",
        ));
    }
    if kh.message_key_slots.len() != MESSAGE_KEY_SLOTS_TOTAL {
        return Err(EventError::InvalidMetadata(
            "message_key_slots size does not match key_history_bundle cap",
        ));
    }
    let values = vec![
        FieldValue::Timestamp(kh.created_at_ms),
        FieldValue::EventId(kh.anchor_bundle_id),
        FieldValue::EventId(kh.recipient_wrappubkey_event_id),
        FieldValue::EventId(kh.wrapped_anchor_bundle),
        FieldValue::FixedBytes(kh.nonce.to_vec()),
        FieldValue::FixedBytes(kh.historical_slots.clone()),
        FieldValue::FixedBytes(kh.message_key_slots.clone()),
    ];
    Ok(encode_fields(
        EVENT_TYPE_KEY_HISTORY_BUNDLE,
        KEY_HISTORY_BUNDLE_FIELDS,
        &values,
    )?)
}

// ─── Projector ───

use crate::projection::projector::{
    EmitCommand, ProjectorDecisionContext, ProjectorResult, SqlVal, WriteOp,
};
use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS key_history_bundles (
            event_id TEXT NOT NULL,
            anchor_bundle_id TEXT NOT NULL,
            recipient_wrappubkey_event_id TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            signer_event_id TEXT NOT NULL,
            recorded_by TEXT NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_key_history_bundles_recipient
            ON key_history_bundles (recorded_by, recipient_wrappubkey_event_id, created_at_ms DESC);
        ",
    )?;
    Ok(())
}

pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ProjectorDecisionContext,
) -> ProjectorResult {
    let kh = match parsed {
        ParsedEvent::KeyHistoryBundle(k) => k,
        _ => return ProjectorResult::reject("not a key_history_bundle event".to_string()),
    };
    let signer_event_id_b64 = ctx
        .current_signer
        .as_ref()
        .map(|s| s.event_id.clone())
        .unwrap_or_default();
    let mut ops = vec![WriteOp::InsertOrIgnore {
        table: "key_history_bundles",
        columns: vec![
            "event_id",
            "anchor_bundle_id",
            "recipient_wrappubkey_event_id",
            "created_at_ms",
            "signer_event_id",
            "recorded_by",
        ],
        values: vec![
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(crate::crypto::event_id_to_base64(&kh.anchor_bundle_id)),
            SqlVal::Text(crate::crypto::event_id_to_base64(
                &kh.recipient_wrappubkey_event_id,
            )),
            SqlVal::Int(kh.created_at_ms as i64),
            SqlVal::Text(signer_event_id_b64),
            SqlVal::Text(recorded_by.to_string()),
        ],
    }];

    // Pattern (b): if the loader matched our WrapPubkey, unwrap the
    // anchor K_bundle and emit its canonical KeySecret event. Then
    // walk the historical slots under that anchor, AEAD-decrypting
    // each populated slot and emitting a canonical
    // KeySecret(historical_K_bundle) event per successful decode.
    // Each emit goes through the normal event pipeline so its Valid
    // transition cascades to waiting message_key rows.
    let mut emit_commands = Vec::new();
    if let (Some(sk_bytes), Some(vk_bytes), Some(wrapped)) = (
        ctx.local_signing_key_bytes,
        ctx.sender_verifying_key_bytes,
        ctx.wrapped_key_bytes,
    ) {
        let anchor_k_bundle = crate::event_modules::key_broadcast::unwrap_k_bundle(
            &sk_bytes, &vk_bytes, &wrapped,
        );
        emit_commands.push(
            crate::event_modules::key_broadcast::emit_deterministic_key_secret_command(
                &anchor_k_bundle,
            ),
        );

        // Walk historical_slots (80 bytes each: 32B bundle_id + 48B
        // AEAD ciphertext under anchor K_bundle). For each populated
        // slot, decrypt and emit a canonical KeySecret event.
        for chunk in kh.historical_slots.chunks_exact(HISTORICAL_SLOT_BYTES) {
            if chunk.iter().all(|b| *b == 0) {
                continue; // unused slot
            }
            // 48-byte AEAD = 32-byte ciphertext + 16-byte tag.
            let ciphertext = &chunk[32..64];
            let mut auth_tag = [0u8; 16];
            auth_tag.copy_from_slice(&chunk[64..80]);
            if let Ok(plaintext) = crate::projection::encrypted::decrypt_event_blob(
                &anchor_k_bundle,
                &kh.nonce,
                ciphertext,
                &auth_tag,
            ) {
                if plaintext.len() == 32 {
                    let mut k_bytes = [0u8; 32];
                    k_bytes.copy_from_slice(&plaintext);
                    emit_commands.push(
                        crate::event_modules::key_broadcast::emit_deterministic_key_secret_command(
                            &k_bytes,
                        ),
                    );
                }
            }
        }

        // Walk message_key_slots (80 bytes each: 32B target_mkey_event_id
        // + 48B AEAD ciphertext under anchor K_bundle). Case A recovery
        // per `docs/DESIGN.md` §9.6.5: these slots carry K_m for un-
        // deleted messages whose bundle had been retired on every
        // honest peer before the invite was created. We write K_m
        // directly into `key_secrets` keyed by the target message_key
        // event id — bypassing the normal `message_key` projection
        // path, since that path requires a live K_bundle which is
        // gone by definition for retired bundles. Then emit
        // `RetryBlockedEncryptedByKey(target_mkey)` so the joiner's
        // Encrypted wrappers can decrypt via the standard
        // `enc.key_event_id` lookup against `key_secrets`.
        for chunk in kh.message_key_slots.chunks_exact(MESSAGE_KEY_SLOT_BYTES) {
            if chunk.iter().all(|b| *b == 0) {
                continue;
            }
            let mut target_mkey_event_id = [0u8; 32];
            target_mkey_event_id.copy_from_slice(&chunk[0..32]);
            let ciphertext = &chunk[32..64];
            let mut auth_tag = [0u8; 16];
            auth_tag.copy_from_slice(&chunk[64..80]);
            if let Ok(plaintext) = crate::projection::encrypted::decrypt_event_blob(
                &anchor_k_bundle,
                &kh.nonce,
                ciphertext,
                &auth_tag,
            ) {
                if plaintext.len() == 32 {
                    let target_b64 =
                        crate::crypto::event_id_to_base64(&target_mkey_event_id);
                    ops.push(WriteOp::InsertOrIgnore {
                        table: "key_secrets",
                        columns: vec![
                            "event_id",
                            "key_bytes",
                            "created_at",
                            "recorded_by",
                        ],
                        values: vec![
                            SqlVal::Text(target_b64.clone()),
                            SqlVal::Blob(plaintext),
                            SqlVal::Int(kh.created_at_ms as i64),
                            SqlVal::Text(recorded_by.to_string()),
                        ],
                    });
                    emit_commands.push(EmitCommand::RetryBlockedEncryptedByKey {
                        key_event_id: target_b64,
                    });
                }
            }
        }
    }
    ProjectorResult::valid_with_commands(ops, emit_commands)
}

crate::projection::decision_context::define_query_context_loader!(
    build_projector_context,
    KeyHistoryBundle,
    load_key_history_bundle_context,
    "key_history_bundle"
);

pub static KEY_HISTORY_BUNDLE_META: EventTypeMeta =
    crate::event_modules::registry::event_type_meta! {
        type_code: EVENT_TYPE_KEY_HISTORY_BUNDLE,
        type_name: "key_history_bundle",
        projection_table: "key_history_bundles",
        share_scope: ShareScope::Shared,
        dep_fields: &[],
        dep_field_type_codes: &[],
        signer_required: true,
        signature_byte_len: 0,
        encryptable: false,
        parse: parse_key_history_bundle,
        encode: encode_key_history_bundle,
        projector: project_pure,
        context_loader: build_projector_context,
    };

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_size_class() {
        // type(1) + created_at(8) + anchor(32) + recipient(32) + wrapped(32)
        //   + nonce(12) + historical_slots(8192*80) + message_key_slots(4096*80)
        assert_eq!(
            KEY_HISTORY_BUNDLE_WIRE_SIZE,
            1 + 8 + 32 + 32 + 32 + 12 + KEY_HISTORY_BUNDLE_SLOTS_TOTAL + MESSAGE_KEY_SLOTS_TOTAL
        );
    }

    #[test]
    fn parse_encode_roundtrip() {
        let original = ParsedEvent::KeyHistoryBundle(KeyHistoryBundleEvent {
            created_at_ms: 1_700_000_000_000,
            anchor_bundle_id: [1u8; 32],
            recipient_wrappubkey_event_id: [2u8; 32],
            wrapped_anchor_bundle: [3u8; 32],
            nonce: [4u8; 12],
            historical_slots: vec![0u8; KEY_HISTORY_BUNDLE_SLOTS_TOTAL],
            message_key_slots: vec![0u8; MESSAGE_KEY_SLOTS_TOTAL],
        });
        let blob = encode_key_history_bundle(&original).expect("encode");
        assert_eq!(blob.len(), KEY_HISTORY_BUNDLE_WIRE_SIZE);
        assert_eq!(blob[0], EVENT_TYPE_KEY_HISTORY_BUNDLE);
        let parsed = parse_key_history_bundle(&blob).expect("parse");
        assert_eq!(original, parsed);
    }
}
