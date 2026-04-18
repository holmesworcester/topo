use super::key_request::delivery_target_id;
use super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::registry::{EventTypeMeta, ShareScope};
use super::removal::{
    frontier_hash_from_refs, frontier_refs_from_slots, validate_canonical_frontier_refs,
};
use super::{EventError, ParsedEvent, EVENT_TYPE_KEY_SHARED};

pub const KEY_SHARED_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("key_event_id"),
    FieldSpec::U8("frontier_count"),
    FieldSpec::EventId("frontier_ref_1"),
    FieldSpec::EventId("frontier_ref_2"),
    FieldSpec::EventId("frontier_ref_3"),
    FieldSpec::EventId("frontier_ref_4"),
    FieldSpec::EventId("frontier_hash"),
    FieldSpec::EventId("delivery_target_id"),
    FieldSpec::EventId("recipient_event_id"),
    FieldSpec::EventId("unwrap_key_event_id"),
    FieldSpec::EventId("wrapped_key"),
];

/// KeyShared (type 22): type(1) + created_at(8) + key_event_id(32) + frontier_count(1)
///   + frontier_ref_1..4(128) + frontier_hash(32) + delivery_target_id(32)
///   + recipient_event_id(32) + unwrap_key_event_id(32) + wrapped_key(32) = 330
pub const KEY_SHARED_WIRE_SIZE: usize = wire_size_for_fields(KEY_SHARED_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySharedEvent {
    pub created_at_ms: u64,
    pub key_event_id: [u8; 32],
    pub frontier_count: u8,
    pub frontier_ref_1: [u8; 32],
    pub frontier_ref_2: [u8; 32],
    pub frontier_ref_3: [u8; 32],
    pub frontier_ref_4: [u8; 32],
    pub frontier_hash: [u8; 32],
    pub delivery_target_id: [u8; 32],
    pub recipient_event_id: [u8; 32],
    pub unwrap_key_event_id: [u8; 32],
    pub wrapped_key: [u8; 32],
}

impl super::Describe for KeySharedEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("key_event_id", super::short_id_b64(&self.key_event_id)),
            ("frontier_hash", super::short_id_b64(&self.frontier_hash)),
            ("wrapped_key", super::trunc_hex(&self.wrapped_key, 16)),
        ]
    }
}

pub fn parse_key_shared(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_KEY_SHARED, KEY_SHARED_FIELDS, blob)?;

    Ok(ParsedEvent::KeyShared(KeySharedEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        key_event_id: values[1].as_event_id().unwrap(),
        frontier_count: values[2].as_u8().unwrap(),
        frontier_ref_1: values[3].as_event_id().unwrap(),
        frontier_ref_2: values[4].as_event_id().unwrap(),
        frontier_ref_3: values[5].as_event_id().unwrap(),
        frontier_ref_4: values[6].as_event_id().unwrap(),
        frontier_hash: values[7].as_event_id().unwrap(),
        delivery_target_id: values[8].as_event_id().unwrap(),
        recipient_event_id: values[9].as_event_id().unwrap(),
        unwrap_key_event_id: values[10].as_event_id().unwrap(),
        wrapped_key: values[11].as_event_id().unwrap(),
    }))
}

pub fn encode_key_shared(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::KeyShared(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    Ok(
        topo_verus_proofs::event_modules::layout::shapes::encode_ts_id_u8_id9(
            EVENT_TYPE_KEY_SHARED,
            e.created_at_ms,
            &e.key_event_id,
            e.frontier_count,
            &e.frontier_ref_1,
            &e.frontier_ref_2,
            &e.frontier_ref_3,
            &e.frontier_ref_4,
            &e.frontier_hash,
            &e.delivery_target_id,
            &e.recipient_event_id,
            &e.unwrap_key_event_id,
            &e.wrapped_key,
        ),
    )
}

use crate::crypto::event_id_to_base64;
use crate::projection::projector::{
    EmitCommand, ProjectorDecisionContext, ProjectorResult, SqlVal, WriteOp,
};
use crate::projection::decision_context::{ProjectionFrameContext, ProjectionQueries};
use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS key_shared (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            key_event_id TEXT NOT NULL,
            frontier_count INTEGER NOT NULL,
            frontier_ref_1 TEXT NOT NULL,
            frontier_ref_2 TEXT NOT NULL,
            frontier_ref_3 TEXT NOT NULL,
            frontier_ref_4 TEXT NOT NULL,
            frontier_hash TEXT NOT NULL,
            delivery_target_id TEXT NOT NULL,
            recipient_event_id TEXT NOT NULL,
            wrapped_key BLOB NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        ",
    )?;
    Ok(())
}

pub fn build_projector_context(
    queries: &dyn ProjectionQueries,
    frame: &ProjectionFrameContext,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<crate::projection::decision_context::ContextLoadResult, Box<dyn std::error::Error>> {
    let ss = match parsed {
        ParsedEvent::KeyShared(ss) => ss,
        _ => return Err("key_shared context loader called for non-key_shared event".into()),
    };

    Ok(crate::projection::decision_context::ContextLoadResult::ready(
        queries.load_key_shared_context(frame, recorded_by, event_id_b64, ss)?,
    ))
}

pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ProjectorDecisionContext,
) -> ProjectorResult {
    let ss = match parsed {
        ParsedEvent::KeyShared(s) => s,
        _ => return ProjectorResult::reject("not a key_shared event".to_string()),
    };

    let slots = [
        ss.frontier_ref_1,
        ss.frontier_ref_2,
        ss.frontier_ref_3,
        ss.frontier_ref_4,
    ];
    let refs = match frontier_refs_from_slots(ss.frontier_count, &slots) {
        Ok(refs) => refs,
        Err(reason) => return ProjectorResult::reject(reason),
    };
    if let Err(reason) = validate_canonical_frontier_refs(&refs) {
        return ProjectorResult::reject(reason);
    }
    let expected_frontier_hash = frontier_hash_from_refs(&refs);
    if ss.frontier_hash != expected_frontier_hash {
        return ProjectorResult::reject(
            "frontier_hash does not match key_shared frontier".to_string(),
        );
    }

    let expected_delivery_target_id = delivery_target_id(
        &ss.key_event_id,
        &ss.frontier_hash,
        &ss.recipient_event_id,
        &ss.unwrap_key_event_id,
    );
    if ss.delivery_target_id != expected_delivery_target_id {
        return ProjectorResult::reject(
            "delivery_target_id does not match key_shared target".to_string(),
        );
    }

    let key_b64 = event_id_to_base64(&ss.key_event_id);
    let frontier_b64 = event_id_to_base64(&ss.frontier_hash);
    let delivery_target_b64 = event_id_to_base64(&ss.delivery_target_id);
    let recipient_b64 = event_id_to_base64(&ss.recipient_event_id);

    let mut ops = vec![WriteOp::InsertOrIgnore {
        table: "key_shared",
        columns: vec![
            "recorded_by",
            "event_id",
            "key_event_id",
            "frontier_count",
            "frontier_ref_1",
            "frontier_ref_2",
            "frontier_ref_3",
            "frontier_ref_4",
            "frontier_hash",
            "delivery_target_id",
            "recipient_event_id",
            "wrapped_key",
        ],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(key_b64),
            SqlVal::Int(ss.frontier_count as i64),
            SqlVal::Text(event_id_to_base64(&ss.frontier_ref_1)),
            SqlVal::Text(event_id_to_base64(&ss.frontier_ref_2)),
            SqlVal::Text(event_id_to_base64(&ss.frontier_ref_3)),
            SqlVal::Text(event_id_to_base64(&ss.frontier_ref_4)),
            SqlVal::Text(frontier_b64),
            SqlVal::Text(delivery_target_b64),
            SqlVal::Text(recipient_b64),
            SqlVal::Blob(ss.wrapped_key.to_vec()),
        ],
    }];

    let material = match &ctx.unwrapped_secret_material {
        Some(v) => v,
        None => return ProjectorResult::valid(ops),
    };

    ops.push(WriteOp::InsertOrIgnore {
        table: "key_secrets",
        columns: vec!["event_id", "key_bytes", "created_at", "recorded_by"],
        values: vec![
            SqlVal::Text(event_id_to_base64(&ss.key_event_id)),
            SqlVal::Blob(material.key_bytes.to_vec()),
            SqlVal::Int(ss.created_at_ms as i64),
            SqlVal::Text(recorded_by.to_string()),
        ],
    });

    ProjectorResult::valid_with_commands(
        ops,
        vec![EmitCommand::RetryBlockedEncryptedByKey {
            key_event_id: event_id_to_base64(&ss.key_event_id),
        }],
    )
}

pub static KEY_SHARED_META: EventTypeMeta = crate::event_modules::registry::event_type_meta! {
    type_code: EVENT_TYPE_KEY_SHARED,
    type_name: "key_shared",
    projection_table: "key_shared",
    share_scope: ShareScope::Shared,
    dep_fields: &[
        "key_event_id",
        "recipient_event_id",
        "frontier_ref_1",
        "frontier_ref_2",
        "frontier_ref_3",
        "frontier_ref_4",
    ],
    dep_field_type_codes: &[&[super::EVENT_TYPE_KEY_ROTATION], &[10, 12, 16], &[], &[], &[], &[]],
    signer_required: true,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_key_shared,
    encode: encode_key_shared,
    projector: project_pure,
    context_loader: build_projector_context,
};
