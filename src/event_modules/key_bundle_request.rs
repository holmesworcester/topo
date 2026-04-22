//! key_bundle_request (type 41) — small heal trigger under
//! Per-Message FS. A peer that cannot locally unwrap a K_bundle
//! emits this event to request another peer re-wrap it targeted at
//! the requester's current WrapPubkey.
//!
//! Response is `key_bundle_share` (type 42). Unlike master's
//! KeyRequest which carries frontier / rotation metadata, this event
//! is a minimal rendezvous signal — the responder's authorization
//! check (requester is membership-current, WrapPubkey is fresh) still
//! applies at the heal-loop layer.

use super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_KEY_BUNDLE_REQUEST};

pub const KEY_BUNDLE_REQUEST_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("bundle_id"),
    FieldSpec::EventId("requester_wrappubkey_event_id"),
];

pub const KEY_BUNDLE_REQUEST_WIRE_SIZE: usize = wire_size_for_fields(KEY_BUNDLE_REQUEST_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBundleRequestEvent {
    pub created_at_ms: u64,
    pub bundle_id: [u8; 32],
    pub requester_wrappubkey_event_id: [u8; 32],
}

impl super::Describe for KeyBundleRequestEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("bundle_id", super::short_id_b64(&self.bundle_id)),
            (
                "requester_wrappubkey_event_id",
                super::short_id_b64(&self.requester_wrappubkey_event_id),
            ),
        ]
    }
}

pub fn parse_key_bundle_request(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_KEY_BUNDLE_REQUEST, KEY_BUNDLE_REQUEST_FIELDS, blob)?;
    Ok(ParsedEvent::KeyBundleRequest(KeyBundleRequestEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        bundle_id: values[1].as_event_id().unwrap(),
        requester_wrappubkey_event_id: values[2].as_event_id().unwrap(),
    }))
}

pub fn encode_key_bundle_request(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let r = match event {
        ParsedEvent::KeyBundleRequest(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    let values = vec![
        FieldValue::Timestamp(r.created_at_ms),
        FieldValue::EventId(r.bundle_id),
        FieldValue::EventId(r.requester_wrappubkey_event_id),
    ];
    Ok(encode_fields(
        EVENT_TYPE_KEY_BUNDLE_REQUEST,
        KEY_BUNDLE_REQUEST_FIELDS,
        &values,
    )?)
}

use crate::projection::projector::{ProjectorDecisionContext, ProjectorResult, SqlVal, WriteOp};
use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS key_bundle_requests (
            event_id TEXT NOT NULL,
            bundle_id TEXT NOT NULL,
            requester_wrappubkey_event_id TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            signer_event_id TEXT NOT NULL,
            recorded_by TEXT NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_key_bundle_requests_bundle
            ON key_bundle_requests (recorded_by, bundle_id);
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
    let r = match parsed {
        ParsedEvent::KeyBundleRequest(v) => v,
        _ => return ProjectorResult::reject("not a key_bundle_request event".to_string()),
    };
    let signer_event_id_b64 = ctx
        .current_signer
        .as_ref()
        .map(|s| s.event_id.clone())
        .unwrap_or_default();
    let ops = vec![WriteOp::InsertOrIgnore {
        table: "key_bundle_requests",
        columns: vec![
            "event_id",
            "bundle_id",
            "requester_wrappubkey_event_id",
            "created_at_ms",
            "signer_event_id",
            "recorded_by",
        ],
        values: vec![
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(crate::crypto::event_id_to_base64(&r.bundle_id)),
            SqlVal::Text(crate::crypto::event_id_to_base64(&r.requester_wrappubkey_event_id)),
            SqlVal::Int(r.created_at_ms as i64),
            SqlVal::Text(signer_event_id_b64),
            SqlVal::Text(recorded_by.to_string()),
        ],
    }];
    ProjectorResult::valid(ops)
}

pub static KEY_BUNDLE_REQUEST_META: EventTypeMeta =
    crate::event_modules::registry::event_type_meta! {
        type_code: EVENT_TYPE_KEY_BUNDLE_REQUEST,
        type_name: "key_bundle_request",
        projection_table: "key_bundle_requests",
        share_scope: ShareScope::Shared,
        dep_fields: &[],
        dep_field_type_codes: &[],
        signer_required: true,
        signature_byte_len: 0,
        encryptable: false,
        parse: parse_key_bundle_request,
        encode: encode_key_bundle_request,
        projector: project_pure,
        context_loader: crate::event_modules::registry::load_empty_context,
    };

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_size_small() {
        // type(1) + created_at(8) + bundle_id(32) + requester_pubkey(32) = 73
        assert_eq!(KEY_BUNDLE_REQUEST_WIRE_SIZE, 73);
    }

    #[test]
    fn parse_encode_roundtrip() {
        let original = ParsedEvent::KeyBundleRequest(KeyBundleRequestEvent {
            created_at_ms: 1_700_000_000_000,
            bundle_id: [1u8; 32],
            requester_wrappubkey_event_id: [2u8; 32],
        });
        let blob = encode_key_bundle_request(&original).expect("encode");
        assert_eq!(blob.len(), KEY_BUNDLE_REQUEST_WIRE_SIZE);
        assert_eq!(blob[0], EVENT_TYPE_KEY_BUNDLE_REQUEST);
        let parsed = parse_key_bundle_request(&blob).expect("parse");
        assert_eq!(original, parsed);
    }
}
