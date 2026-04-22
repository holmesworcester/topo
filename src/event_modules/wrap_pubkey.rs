//! WrapPubkey (type 37) — short-lived curve25519 public key used for
//! ALL wrap operations targeting this peer. Long-lived `peer_shared`
//! keys are reserved for identity/signing only.
//!
//! Self-tombstoning: a new `WrapPubkey` emission from the same peer
//! supersedes prior ones — only the latest non-expired pubkey is
//! considered "current" for that peer. "Latest" is determined by
//! `(created_at_ms, event_id)` tie-break so replay convergence is
//! deterministic.
//!
//! The inner event carries the pubkey and expiry; the signing peer is
//! identified by the outer Signed envelope (`signer_required: true`,
//! `signature_byte_len: 0`).
//!
//! Private keys are stored locally in `wrap_privkeys` (never on the
//! wire). Populated at emission time, purged at
//! `valid_until_ms + grace`.

use super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_WRAP_PUBKEY};

// ─── Layout ───

pub const WRAP_PUBKEY_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::FixedBytes("pubkey", 32),
    FieldSpec::U64("valid_until_ms"),
];

/// WrapPubkey wire size: type(1) + created_at(8) + pubkey(32) +
/// valid_until(8) = 49 bytes. Signed envelope wraps this (signer
/// identified by outer Signed, `signature_byte_len: 0`).
pub const WRAP_PUBKEY_WIRE_SIZE: usize = wire_size_for_fields(WRAP_PUBKEY_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrapPubkeyEvent {
    pub created_at_ms: u64,
    pub pubkey: [u8; 32],
    pub valid_until_ms: u64,
}

impl super::Describe for WrapPubkeyEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("pubkey", super::trunc_hex(&self.pubkey, 16)),
            ("valid_until_ms", self.valid_until_ms.to_string()),
        ]
    }
}

pub fn parse_wrap_pubkey(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_WRAP_PUBKEY, WRAP_PUBKEY_FIELDS, blob)?;
    let pubkey = match &values[1] {
        FieldValue::FixedBytes(bytes) => {
            let mut out = [0u8; 32];
            out.copy_from_slice(bytes);
            out
        }
        _ => return Err(EventError::WrongVariant),
    };
    Ok(ParsedEvent::WrapPubkey(WrapPubkeyEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        pubkey,
        valid_until_ms: values[2].as_u64().unwrap(),
    }))
}

pub fn encode_wrap_pubkey(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let wp = match event {
        ParsedEvent::WrapPubkey(w) => w,
        _ => return Err(EventError::WrongVariant),
    };
    let values = vec![
        FieldValue::Timestamp(wp.created_at_ms),
        FieldValue::FixedBytes(wp.pubkey.to_vec()),
        FieldValue::U64(wp.valid_until_ms),
    ];
    Ok(encode_fields(EVENT_TYPE_WRAP_PUBKEY, WRAP_PUBKEY_FIELDS, &values)?)
}

// ─── Projector ───

use crate::projection::projector::{ProjectorDecisionContext, ProjectorResult, SqlVal, WriteOp};
use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS wrap_pubkeys (
            event_id TEXT NOT NULL,
            signer_event_id TEXT NOT NULL,
            pubkey BLOB NOT NULL,
            valid_until_ms INTEGER NOT NULL,
            created_at_ms INTEGER NOT NULL,
            recorded_by TEXT NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_wrap_pubkeys_signer
            ON wrap_pubkeys (recorded_by, signer_event_id, created_at_ms DESC, event_id DESC);

        -- Local-only: private keys for WrapPubkeys this device emitted.
        -- Never synced. Populated at emission time (not projection).
        -- Purged at valid_until_ms + grace.
        CREATE TABLE IF NOT EXISTS wrap_privkeys (
            pubkey_event_id TEXT PRIMARY KEY,
            privkey BLOB NOT NULL,
            valid_until_ms INTEGER NOT NULL,
            created_at_ms INTEGER NOT NULL
        );
        ",
    )?;
    Ok(())
}

/// Pure projector: insert row into `wrap_pubkeys`. The "latest" pubkey
/// for a given signer is computed at read time via
/// `(created_at_ms DESC, event_id DESC)` ordering — no explicit
/// tombstoning of prior rows is needed; readers select the max.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ProjectorDecisionContext,
) -> ProjectorResult {
    let wp = match parsed {
        ParsedEvent::WrapPubkey(w) => w,
        _ => return ProjectorResult::reject("not a wrap_pubkey event".to_string()),
    };
    // The signer is identified by the outer Signed envelope; the signer
    // event id comes through the ProjectorDecisionContext.
    let signer_event_id_b64 = ctx
        .current_signer
        .as_ref()
        .map(|s| s.event_id.clone())
        .unwrap_or_default();
    let ops = vec![WriteOp::InsertOrIgnore {
        table: "wrap_pubkeys",
        columns: vec![
            "event_id",
            "signer_event_id",
            "pubkey",
            "valid_until_ms",
            "created_at_ms",
            "recorded_by",
        ],
        values: vec![
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(signer_event_id_b64),
            SqlVal::Blob(wp.pubkey.to_vec()),
            SqlVal::Int(wp.valid_until_ms as i64),
            SqlVal::Int(wp.created_at_ms as i64),
            SqlVal::Text(recorded_by.to_string()),
        ],
    }];
    ProjectorResult::valid(ops)
}

pub static WRAP_PUBKEY_META: EventTypeMeta =
    crate::event_modules::registry::event_type_meta! {
        type_code: EVENT_TYPE_WRAP_PUBKEY,
        type_name: "wrap_pubkey",
        projection_table: "wrap_pubkeys",
        share_scope: ShareScope::Shared,
        dep_fields: &[],
        dep_field_type_codes: &[],
        signer_required: true,
        signature_byte_len: 0,
        encryptable: false,
        parse: parse_wrap_pubkey,
        encode: encode_wrap_pubkey,
        projector: project_pure,
        context_loader: crate::event_modules::registry::load_empty_context,
    };

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_size_is_49_bytes() {
        // type(1) + created_at(8) + pubkey(32) + valid_until(8) = 49
        assert_eq!(WRAP_PUBKEY_WIRE_SIZE, 49);
    }

    #[test]
    fn parse_encode_roundtrip() {
        let original = ParsedEvent::WrapPubkey(WrapPubkeyEvent {
            created_at_ms: 1_700_000_000_000,
            pubkey: [7u8; 32],
            valid_until_ms: 1_700_000_000_000 + 3_600_000,
        });
        let blob = encode_wrap_pubkey(&original).expect("encode");
        assert_eq!(blob.len(), WRAP_PUBKEY_WIRE_SIZE);
        assert_eq!(blob[0], EVENT_TYPE_WRAP_PUBKEY);
        let parsed = parse_wrap_pubkey(&blob).expect("parse");
        assert_eq!(original, parsed);
    }
}
