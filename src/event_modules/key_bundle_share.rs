//! key_bundle_share (type 42) — small targeted heal response under
//! Per-Message FS. Carries a single K_bundle wrapped to one recipient.
//!
//! Wire: ~150 bytes (vs ~524 KB for key_broadcast bulk fanout).
//! Projector does the same local unwrap as key_broadcast — on
//! successful asymmetric_unwrap against wrap_privkeys, emits the
//! same deterministic `KeySecret(K_bundle)` event that the bulk and
//! bootstrap producers would emit, so cascade unblocks every
//! pending message_key blocked on this bundle uniformly.

use super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_KEY_BUNDLE_SHARE};

pub const KEY_BUNDLE_SHARE_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("bundle_id"),
    FieldSpec::EventId("recipient_wrappubkey_event_id"),
    FieldSpec::EventId("wrapped_k_bundle"),
];

pub const KEY_BUNDLE_SHARE_WIRE_SIZE: usize = wire_size_for_fields(KEY_BUNDLE_SHARE_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBundleShareEvent {
    pub created_at_ms: u64,
    pub bundle_id: [u8; 32],
    pub recipient_wrappubkey_event_id: [u8; 32],
    pub wrapped_k_bundle: [u8; 32],
}

impl super::Describe for KeyBundleShareEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("bundle_id", super::short_id_b64(&self.bundle_id)),
            (
                "recipient_wrappubkey_event_id",
                super::short_id_b64(&self.recipient_wrappubkey_event_id),
            ),
        ]
    }
}

pub fn parse_key_bundle_share(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_KEY_BUNDLE_SHARE, KEY_BUNDLE_SHARE_FIELDS, blob)?;
    Ok(ParsedEvent::KeyBundleShare(KeyBundleShareEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        bundle_id: values[1].as_event_id().unwrap(),
        recipient_wrappubkey_event_id: values[2].as_event_id().unwrap(),
        wrapped_k_bundle: values[3].as_event_id().unwrap(),
    }))
}

pub fn encode_key_bundle_share(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let s = match event {
        ParsedEvent::KeyBundleShare(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    let values = vec![
        FieldValue::Timestamp(s.created_at_ms),
        FieldValue::EventId(s.bundle_id),
        FieldValue::EventId(s.recipient_wrappubkey_event_id),
        FieldValue::EventId(s.wrapped_k_bundle),
    ];
    Ok(encode_fields(
        EVENT_TYPE_KEY_BUNDLE_SHARE,
        KEY_BUNDLE_SHARE_FIELDS,
        &values,
    )?)
}

use crate::projection::projector::{ProjectorDecisionContext, ProjectorResult, SqlVal, WriteOp};
use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS key_bundle_shares (
            event_id TEXT NOT NULL,
            bundle_id TEXT NOT NULL,
            recipient_wrappubkey_event_id TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            signer_event_id TEXT NOT NULL,
            recorded_by TEXT NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_key_bundle_shares_recipient
            ON key_bundle_shares (recorded_by, recipient_wrappubkey_event_id);
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
    let s = match parsed {
        ParsedEvent::KeyBundleShare(v) => v,
        _ => return ProjectorResult::reject("not a key_bundle_share event".to_string()),
    };
    let signer_event_id_b64 = ctx
        .current_signer
        .as_ref()
        .map(|s| s.event_id.clone())
        .unwrap_or_default();
    let mut ops = vec![WriteOp::InsertOrIgnore {
        table: "key_bundle_shares",
        columns: vec![
            "event_id",
            "bundle_id",
            "recipient_wrappubkey_event_id",
            "created_at_ms",
            "signer_event_id",
            "recorded_by",
        ],
        values: vec![
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(crate::crypto::event_id_to_base64(&s.bundle_id)),
            SqlVal::Text(crate::crypto::event_id_to_base64(&s.recipient_wrappubkey_event_id)),
            SqlVal::Int(s.created_at_ms as i64),
            SqlVal::Text(signer_event_id_b64),
            SqlVal::Text(recorded_by.to_string()),
        ],
    }];

    // If the context loader successfully unwrapped K_bundle (recipient
    // is local and their wrap_privkey matched), emit a deterministic
    // local KeySecret(K_bundle) write so cascade unblocks every
    // message_key waiting on this bundle.
    if let Some(k_bundle) = ctx.unwrapped_k_bundle {
        let local_secret_id_bytes =
            crate::event_modules::key_secret::deterministic_key_secret_event_id(&k_bundle);
        let local_secret_id_b64 = crate::crypto::event_id_to_base64(&local_secret_id_bytes);
        let created_at =
            crate::event_modules::key_secret::deterministic_key_secret_created_at_ms(&k_bundle);
        ops.push(WriteOp::InsertOrIgnore {
            table: "key_secrets",
            columns: vec!["event_id", "key_bytes", "created_at", "recorded_by"],
            values: vec![
                SqlVal::Text(local_secret_id_b64),
                SqlVal::Blob(k_bundle.to_vec()),
                SqlVal::Int(created_at as i64),
                SqlVal::Text(recorded_by.to_string()),
            ],
        });
    }
    ProjectorResult::valid(ops)
}

crate::projection::decision_context::define_query_context_loader!(
    build_projector_context,
    KeyBundleShare,
    load_key_bundle_share_context,
    "key_bundle_share"
);

pub static KEY_BUNDLE_SHARE_META: EventTypeMeta =
    crate::event_modules::registry::event_type_meta! {
        type_code: EVENT_TYPE_KEY_BUNDLE_SHARE,
        type_name: "key_bundle_share",
        projection_table: "key_bundle_shares",
        share_scope: ShareScope::Shared,
        dep_fields: &[],
        dep_field_type_codes: &[],
        signer_required: true,
        signature_byte_len: 0,
        encryptable: false,
        parse: parse_key_bundle_share,
        encode: encode_key_bundle_share,
        projector: project_pure,
        context_loader: build_projector_context,
    };

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_size_small() {
        // type(1) + created_at(8) + bundle(32) + recipient(32) + wrapped(32) = 105
        assert_eq!(KEY_BUNDLE_SHARE_WIRE_SIZE, 105);
    }

    #[test]
    fn parse_encode_roundtrip() {
        let original = ParsedEvent::KeyBundleShare(KeyBundleShareEvent {
            created_at_ms: 1_700_000_000_000,
            bundle_id: [1u8; 32],
            recipient_wrappubkey_event_id: [2u8; 32],
            wrapped_k_bundle: [3u8; 32],
        });
        let blob = encode_key_bundle_share(&original).expect("encode");
        assert_eq!(blob.len(), KEY_BUNDLE_SHARE_WIRE_SIZE);
        assert_eq!(blob[0], EVENT_TYPE_KEY_BUNDLE_SHARE);
        let parsed = parse_key_bundle_share(&blob).expect("parse");
        assert_eq!(original, parsed);
    }
}
