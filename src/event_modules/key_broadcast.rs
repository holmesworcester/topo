//! key_broadcast (type 38) — bulk fanout of one `K_bundle` to up to
//! 8192 recipients. Each slot carries a (recipient_WrapPubkey_event_id,
//! asymmetric_wrap(recipient_pubkey, K_bundle)) pair.
//!
//! Retargets master's `KeyRotation` semantics for the per-message FS
//! design: a `key_broadcast` is one of three producers that can
//! materialize the same deterministic local `KeySecret(K_bundle)` for
//! blocked `message_key`s. The other two are `key_history_bundle`
//! (bootstrap) and `key_shared` (targeted heal).
//!
//! Wire shape follows master's 8192-slot convention (~524 KB).

use super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_KEY_BROADCAST};

pub const KEY_BROADCAST_CAP: usize = 8192;
/// Each recipient slot is 32B pubkey_event_id + 32B wrapped K_bundle.
pub const KEY_BROADCAST_SLOT_BYTES: usize = KEY_BROADCAST_CAP * 32;

pub const KEY_BROADCAST_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("bundle_id"),
    FieldSpec::FixedBytes("recipient_pubkey_slots", KEY_BROADCAST_SLOT_BYTES),
    FieldSpec::FixedBytes("wrapped_bundle_slots", KEY_BROADCAST_SLOT_BYTES),
];

pub const KEY_BROADCAST_WIRE_SIZE: usize = wire_size_for_fields(KEY_BROADCAST_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBroadcastEvent {
    pub created_at_ms: u64,
    pub bundle_id: [u8; 32],
    /// 8192 slots of recipient WrapPubkey event ids. Unused slots are
    /// zero-filled.
    pub recipient_pubkey_slots: Vec<[u8; 32]>,
    /// 8192 slots of asymmetric_wrap(recipient_pubkey, K_bundle). Each
    /// is 32 bytes (curve25519 sealed-box output). Unused slots zero.
    pub wrapped_bundle_slots: Vec<[u8; 32]>,
}

impl super::Describe for KeyBroadcastEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        let populated = self
            .recipient_pubkey_slots
            .iter()
            .filter(|slot| *slot != &[0u8; 32])
            .count();
        vec![
            ("bundle_id", super::short_id_b64(&self.bundle_id)),
            ("slot_cap", KEY_BROADCAST_CAP.to_string()),
            ("populated_recipients", populated.to_string()),
        ]
    }
}

fn split_slots(bytes: &[u8], what: &'static str) -> Result<Vec<[u8; 32]>, EventError> {
    if bytes.len() != KEY_BROADCAST_SLOT_BYTES {
        return Err(EventError::InvalidMetadata(match what {
            "recipient_pubkey_slots" => {
                "recipient_pubkey_slots size does not match key_broadcast cap"
            }
            _ => "wrapped_bundle_slots size does not match key_broadcast cap",
        }));
    }
    let mut out = Vec::with_capacity(KEY_BROADCAST_CAP);
    for chunk in bytes.chunks_exact(32) {
        let mut slot = [0u8; 32];
        slot.copy_from_slice(chunk);
        out.push(slot);
    }
    Ok(out)
}

fn flatten_slots(slots: &[[u8; 32]], what: &'static str) -> Result<Vec<u8>, EventError> {
    if slots.len() != KEY_BROADCAST_CAP {
        return Err(EventError::InvalidMetadata(match what {
            "recipient_pubkey_slots" => {
                "recipient_pubkey_slots len does not match key_broadcast cap"
            }
            _ => "wrapped_bundle_slots len does not match key_broadcast cap",
        }));
    }
    let mut out = Vec::with_capacity(KEY_BROADCAST_SLOT_BYTES);
    for slot in slots {
        out.extend_from_slice(slot);
    }
    Ok(out)
}

pub fn parse_key_broadcast(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_KEY_BROADCAST, KEY_BROADCAST_FIELDS, blob)?;
    let recipient_pubkey_slots = split_slots(
        values[2]
            .clone()
            .into_fixed_bytes()
            .ok_or(EventError::WrongVariant)?
            .as_slice(),
        "recipient_pubkey_slots",
    )?;
    let wrapped_bundle_slots = split_slots(
        values[3]
            .clone()
            .into_fixed_bytes()
            .ok_or(EventError::WrongVariant)?
            .as_slice(),
        "wrapped_bundle_slots",
    )?;
    Ok(ParsedEvent::KeyBroadcast(KeyBroadcastEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        bundle_id: values[1].as_event_id().unwrap(),
        recipient_pubkey_slots,
        wrapped_bundle_slots,
    }))
}

pub fn encode_key_broadcast(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let kb = match event {
        ParsedEvent::KeyBroadcast(k) => k,
        _ => return Err(EventError::WrongVariant),
    };
    let recipient_bytes = flatten_slots(&kb.recipient_pubkey_slots, "recipient_pubkey_slots")?;
    let wrapped_bytes = flatten_slots(&kb.wrapped_bundle_slots, "wrapped_bundle_slots")?;
    let values = vec![
        FieldValue::Timestamp(kb.created_at_ms),
        FieldValue::EventId(kb.bundle_id),
        FieldValue::FixedBytes(recipient_bytes),
        FieldValue::FixedBytes(wrapped_bytes),
    ];
    Ok(encode_fields(
        EVENT_TYPE_KEY_BROADCAST,
        KEY_BROADCAST_FIELDS,
        &values,
    )?)
}

// ─── Projector ───

use crate::projection::projector::{ProjectorDecisionContext, ProjectorResult, SqlVal, WriteOp};
use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS key_broadcasts (
            event_id TEXT NOT NULL,
            bundle_id TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            signer_event_id TEXT NOT NULL,
            recorded_by TEXT NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_key_broadcasts_bundle
            ON key_broadcasts (recorded_by, bundle_id);
        CREATE INDEX IF NOT EXISTS idx_key_broadcasts_signer
            ON key_broadcasts (recorded_by, signer_event_id, created_at_ms DESC);
        ",
    )?;
    Ok(())
}

/// Projector: records the broadcast header. Local unwrap (attempt to
/// decrypt one of the recipient slots against `wrap_privkeys` to
/// materialize a deterministic local `KeySecret(K_bundle)`) is a
/// follow-up commit — it requires the `wrap_privkeys` lookup to be
/// exposed through the decision context.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ProjectorDecisionContext,
) -> ProjectorResult {
    let kb = match parsed {
        ParsedEvent::KeyBroadcast(k) => k,
        _ => return ProjectorResult::reject("not a key_broadcast event".to_string()),
    };
    let signer_event_id_b64 = ctx
        .current_signer
        .as_ref()
        .map(|s| s.event_id.clone())
        .unwrap_or_default();
    let ops = vec![WriteOp::InsertOrIgnore {
        table: "key_broadcasts",
        columns: vec![
            "event_id",
            "bundle_id",
            "created_at_ms",
            "signer_event_id",
            "recorded_by",
        ],
        values: vec![
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(crate::crypto::event_id_to_base64(&kb.bundle_id)),
            SqlVal::Int(kb.created_at_ms as i64),
            SqlVal::Text(signer_event_id_b64),
            SqlVal::Text(recorded_by.to_string()),
        ],
    }];
    ProjectorResult::valid(ops)
}

pub static KEY_BROADCAST_META: EventTypeMeta =
    crate::event_modules::registry::event_type_meta! {
        type_code: EVENT_TYPE_KEY_BROADCAST,
        type_name: "key_broadcast",
        projection_table: "key_broadcasts",
        share_scope: ShareScope::Shared,
        dep_fields: &[],
        dep_field_type_codes: &[],
        signer_required: true,
        signature_byte_len: 0,
        encryptable: false,
        parse: parse_key_broadcast,
        encode: encode_key_broadcast,
        projector: project_pure,
        context_loader: crate::event_modules::registry::load_empty_context,
    };

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_size_matches_524kb_class() {
        // type(1) + created_at(8) + bundle_id(32) + 2 × 8192 × 32 (slots) = 524_329
        assert_eq!(
            KEY_BROADCAST_WIRE_SIZE,
            1 + 8 + 32 + 2 * KEY_BROADCAST_SLOT_BYTES
        );
    }

    #[test]
    fn parse_encode_roundtrip_empty_slots() {
        let empty_slots = vec![[0u8; 32]; KEY_BROADCAST_CAP];
        let original = ParsedEvent::KeyBroadcast(KeyBroadcastEvent {
            created_at_ms: 1_700_000_000_000,
            bundle_id: [9u8; 32],
            recipient_pubkey_slots: empty_slots.clone(),
            wrapped_bundle_slots: empty_slots,
        });
        let blob = encode_key_broadcast(&original).expect("encode");
        assert_eq!(blob.len(), KEY_BROADCAST_WIRE_SIZE);
        assert_eq!(blob[0], EVENT_TYPE_KEY_BROADCAST);
        let parsed = parse_key_broadcast(&blob).expect("parse");
        assert_eq!(original, parsed);
    }
}
