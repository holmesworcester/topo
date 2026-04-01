use super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_KEY_REQUEST};

pub const KEY_REQUEST_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("blocked_event_id"),
    FieldSpec::EventId("key_event_id"),
    FieldSpec::EventId("frontier_hash"),
    FieldSpec::EventId("delivery_target_id"),
    FieldSpec::EventId("recipient_event_id"),
    FieldSpec::EventId("unwrap_key_event_id"),
];

/// KeyRequest (type 30): type(1) + created_at(8) + blocked_event_id(32)
///   + key_event_id(32) + frontier_hash(32) + delivery_target_id(32)
///   + recipient_event_id(32) + unwrap_key_event_id(32) = 201
pub const KEY_REQUEST_WIRE_SIZE: usize = wire_size_for_fields(KEY_REQUEST_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRequestEvent {
    pub created_at_ms: u64,
    pub blocked_event_id: [u8; 32],
    pub key_event_id: [u8; 32],
    pub frontier_hash: [u8; 32],
    pub delivery_target_id: [u8; 32],
    pub recipient_event_id: [u8; 32],
    pub unwrap_key_event_id: [u8; 32],
}

impl super::Describe for KeyRequestEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "blocked_event_id",
                super::short_id_b64(&self.blocked_event_id),
            ),
            ("key_event_id", super::short_id_b64(&self.key_event_id)),
            ("frontier_hash", super::short_id_b64(&self.frontier_hash)),
        ]
    }
}

pub fn delivery_target_id(
    key_event_id: &[u8; 32],
    frontier_hash: &[u8; 32],
    recipient_event_id: &[u8; 32],
    unwrap_key_event_id: &[u8; 32],
) -> [u8; 32] {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};

    let mut hasher = Blake2b::<U32>::new();
    hasher.update(b"poc7-key-delivery-target-v1");
    hasher.update(key_event_id);
    hasher.update(frontier_hash);
    hasher.update(recipient_event_id);
    hasher.update(unwrap_key_event_id);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

pub fn deterministic_key_request_created_at_ms(
    blocked_event_id: &[u8; 32],
    key_event_id: &[u8; 32],
    frontier_hash: &[u8; 32],
    recipient_event_id: &[u8; 32],
    unwrap_key_event_id: &[u8; 32],
    requester_signer_event_id: &[u8; 32],
) -> u64 {
    use blake2::digest::consts::U8;
    use blake2::{Blake2b, Digest};

    let mut hasher = Blake2b::<U8>::new();
    hasher.update(b"poc7-key-request-created-at-v1");
    hasher.update(blocked_event_id);
    hasher.update(key_event_id);
    hasher.update(frontier_hash);
    hasher.update(recipient_event_id);
    hasher.update(unwrap_key_event_id);
    hasher.update(requester_signer_event_id);
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(out)
}

pub fn parse_key_request(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_KEY_REQUEST, KEY_REQUEST_FIELDS, blob)?;
    Ok(ParsedEvent::KeyRequest(KeyRequestEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        blocked_event_id: values[1].as_event_id().unwrap(),
        key_event_id: values[2].as_event_id().unwrap(),
        frontier_hash: values[3].as_event_id().unwrap(),
        delivery_target_id: values[4].as_event_id().unwrap(),
        recipient_event_id: values[5].as_event_id().unwrap(),
        unwrap_key_event_id: values[6].as_event_id().unwrap(),
    }))
}

pub fn encode_key_request(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let kr = match event {
        ParsedEvent::KeyRequest(v) => v,
        _ => return Err(EventError::WrongVariant),
    };

    let values = vec![
        FieldValue::Timestamp(kr.created_at_ms),
        FieldValue::EventId(kr.blocked_event_id),
        FieldValue::EventId(kr.key_event_id),
        FieldValue::EventId(kr.frontier_hash),
        FieldValue::EventId(kr.delivery_target_id),
        FieldValue::EventId(kr.recipient_event_id),
        FieldValue::EventId(kr.unwrap_key_event_id),
    ];

    Ok(encode_fields(
        EVENT_TYPE_KEY_REQUEST,
        KEY_REQUEST_FIELDS,
        &values,
    )?)
}

use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS key_requests (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            blocked_event_id TEXT NOT NULL,
            key_event_id TEXT NOT NULL,
            frontier_hash TEXT NOT NULL,
            delivery_target_id TEXT NOT NULL,
            recipient_event_id TEXT NOT NULL,
            unwrap_key_event_id TEXT NOT NULL,
            requester_signer_event_id TEXT NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        ",
    )?;
    Ok(())
}

pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let kr = match parsed {
        ParsedEvent::KeyRequest(v) => v,
        _ => return ProjectorResult::reject("not a key_request event".to_string()),
    };
    let expected_delivery_target_id = delivery_target_id(
        &kr.key_event_id,
        &kr.frontier_hash,
        &kr.recipient_event_id,
        &kr.unwrap_key_event_id,
    );
    if kr.delivery_target_id != expected_delivery_target_id {
        return ProjectorResult::reject(
            "delivery_target_id does not match key request target".to_string(),
        );
    }

    let Some(current_signer) = ctx.current_signer.as_ref() else {
        return ProjectorResult::reject("key_request missing current signer envelope".to_string());
    };

    let ops = vec![WriteOp::InsertOrIgnore {
        table: "key_requests",
        columns: vec![
            "recorded_by",
            "event_id",
            "blocked_event_id",
            "key_event_id",
            "frontier_hash",
            "delivery_target_id",
            "recipient_event_id",
            "unwrap_key_event_id",
            "requester_signer_event_id",
        ],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(event_id_to_base64(&kr.blocked_event_id)),
            SqlVal::Text(event_id_to_base64(&kr.key_event_id)),
            SqlVal::Text(event_id_to_base64(&kr.frontier_hash)),
            SqlVal::Text(event_id_to_base64(&kr.delivery_target_id)),
            SqlVal::Text(event_id_to_base64(&kr.recipient_event_id)),
            SqlVal::Text(event_id_to_base64(&kr.unwrap_key_event_id)),
            SqlVal::Text(current_signer.event_id.clone()),
        ],
    }];

    ProjectorResult::valid(ops)
}

pub static KEY_REQUEST_META: EventTypeMeta = crate::event_modules::registry::event_type_meta! {
    type_code: EVENT_TYPE_KEY_REQUEST,
    type_name: "key_request",
    projection_table: "key_requests",
    share_scope: ShareScope::Shared,
    dep_fields: &[],
    dep_field_type_codes: &[],
    signer_required: true,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_key_request,
    encode: encode_key_request,
    projector: project_pure,
    context_loader: crate::event_modules::registry::load_empty_context,
};
