use super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::registry::{EventTypeMeta, ShareScope};
use super::removal::{
    frontier_hash_from_refs, frontier_refs_from_slots, validate_canonical_frontier_refs,
};
use super::{EventError, ParsedEvent, EVENT_TYPE_KEY_ROTATION};

pub const KEY_ROTATION_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("key_event_id"),
    FieldSpec::U8("frontier_count"),
    FieldSpec::EventId("frontier_ref_1"),
    FieldSpec::EventId("frontier_ref_2"),
    FieldSpec::EventId("frontier_ref_3"),
    FieldSpec::EventId("frontier_ref_4"),
    FieldSpec::EventId("frontier_hash"),
    FieldSpec::EventId("rotated_by"),
];

pub const KEY_ROTATION_WIRE_SIZE: usize = wire_size_for_fields(KEY_ROTATION_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRotationEvent {
    pub created_at_ms: u64,
    pub key_event_id: [u8; 32],
    pub frontier_count: u8,
    pub frontier_ref_1: [u8; 32],
    pub frontier_ref_2: [u8; 32],
    pub frontier_ref_3: [u8; 32],
    pub frontier_ref_4: [u8; 32],
    pub frontier_hash: [u8; 32],
    pub rotated_by: [u8; 32],
}

impl super::Describe for KeyRotationEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("key_event_id", super::short_id_b64(&self.key_event_id)),
            ("frontier_hash", super::short_id_b64(&self.frontier_hash)),
        ]
    }
}

pub fn parse_key_rotation(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_KEY_ROTATION, KEY_ROTATION_FIELDS, blob)?;
    Ok(ParsedEvent::KeyRotation(KeyRotationEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        key_event_id: values[1].as_event_id().unwrap(),
        frontier_count: values[2].as_u8().unwrap(),
        frontier_ref_1: values[3].as_event_id().unwrap(),
        frontier_ref_2: values[4].as_event_id().unwrap(),
        frontier_ref_3: values[5].as_event_id().unwrap(),
        frontier_ref_4: values[6].as_event_id().unwrap(),
        frontier_hash: values[7].as_event_id().unwrap(),
        rotated_by: values[8].as_event_id().unwrap(),
    }))
}

pub fn encode_key_rotation(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let rotation = match event {
        ParsedEvent::KeyRotation(event) => event,
        _ => return Err(EventError::WrongVariant),
    };
    let values = vec![
        FieldValue::Timestamp(rotation.created_at_ms),
        FieldValue::EventId(rotation.key_event_id),
        FieldValue::U8(rotation.frontier_count),
        FieldValue::EventId(rotation.frontier_ref_1),
        FieldValue::EventId(rotation.frontier_ref_2),
        FieldValue::EventId(rotation.frontier_ref_3),
        FieldValue::EventId(rotation.frontier_ref_4),
        FieldValue::EventId(rotation.frontier_hash),
        FieldValue::EventId(rotation.rotated_by),
    ];
    Ok(encode_fields(
        EVENT_TYPE_KEY_ROTATION,
        KEY_ROTATION_FIELDS,
        &values,
    )?)
}

use crate::crypto::event_id_to_base64;
use crate::projection::projector::{ProjectorDecisionContext, ProjectorResult, SqlVal, WriteOp};
use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS key_rotations (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            key_event_id TEXT NOT NULL,
            frontier_hash TEXT NOT NULL,
            frontier_count INTEGER NOT NULL,
            frontier_ref_1 TEXT NOT NULL,
            frontier_ref_2 TEXT NOT NULL,
            frontier_ref_3 TEXT NOT NULL,
            frontier_ref_4 TEXT NOT NULL,
            rotator_signer_event_id TEXT NOT NULL,
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
    ctx: &ProjectorDecisionContext,
) -> ProjectorResult {
    let rotation = match parsed {
        ParsedEvent::KeyRotation(event) => event,
        _ => return ProjectorResult::reject("not a key_rotation event".to_string()),
    };
    let Some(current_signer) = ctx.current_signer.as_ref() else {
        return ProjectorResult::reject("key_rotation missing current signer envelope".to_string());
    };
    if rotation.rotated_by
        != crate::crypto::event_id_from_base64(&current_signer.event_id).unwrap_or([0u8; 32])
    {
        return ProjectorResult::reject("rotated_by must equal current signer".to_string());
    }
    let slots = [
        rotation.frontier_ref_1,
        rotation.frontier_ref_2,
        rotation.frontier_ref_3,
        rotation.frontier_ref_4,
    ];
    let refs = match frontier_refs_from_slots(rotation.frontier_count, &slots) {
        Ok(refs) => refs,
        Err(reason) => return ProjectorResult::reject(reason),
    };
    if let Err(reason) = validate_canonical_frontier_refs(&refs) {
        return ProjectorResult::reject(reason);
    }
    let expected_hash = frontier_hash_from_refs(&refs);
    if expected_hash != rotation.frontier_hash {
        return ProjectorResult::reject("frontier_hash does not match frontier refs".to_string());
    }

    ProjectorResult::valid(vec![WriteOp::InsertOrIgnore {
        table: "key_rotations",
        columns: vec![
            "recorded_by",
            "event_id",
            "key_event_id",
            "frontier_hash",
            "frontier_count",
            "frontier_ref_1",
            "frontier_ref_2",
            "frontier_ref_3",
            "frontier_ref_4",
            "rotator_signer_event_id",
        ],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(event_id_to_base64(&rotation.key_event_id)),
            SqlVal::Text(event_id_to_base64(&rotation.frontier_hash)),
            SqlVal::Int(rotation.frontier_count as i64),
            SqlVal::Text(event_id_to_base64(&rotation.frontier_ref_1)),
            SqlVal::Text(event_id_to_base64(&rotation.frontier_ref_2)),
            SqlVal::Text(event_id_to_base64(&rotation.frontier_ref_3)),
            SqlVal::Text(event_id_to_base64(&rotation.frontier_ref_4)),
            SqlVal::Text(current_signer.event_id.clone()),
        ],
    }])
}

pub static KEY_ROTATION_META: EventTypeMeta = crate::event_modules::registry::event_type_meta! {
    type_code: EVENT_TYPE_KEY_ROTATION,
    type_name: "key_rotation",
    projection_table: "key_rotations",
    share_scope: ShareScope::Shared,
    dep_fields: &[
        "frontier_ref_1",
        "frontier_ref_2",
        "frontier_ref_3",
        "frontier_ref_4",
    ],
    dep_field_type_codes: &[&[], &[], &[], &[]],
    signer_required: true,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_key_rotation,
    encode: encode_key_rotation,
    projector: project_pure,
    context_loader: crate::event_modules::registry::load_empty_context,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::{encode_event, parse_event};

    #[test]
    fn test_key_rotation_roundtrip() {
        let frontier_refs = vec![[0x11; 32]];
        let event = ParsedEvent::KeyRotation(KeyRotationEvent {
            created_at_ms: 10_000,
            key_event_id: [0x22; 32],
            frontier_count: frontier_refs.len() as u8,
            frontier_ref_1: frontier_refs[0],
            frontier_ref_2: [0u8; 32],
            frontier_ref_3: [0u8; 32],
            frontier_ref_4: [0u8; 32],
            frontier_hash: frontier_hash_from_refs(&frontier_refs),
            rotated_by: [0x33; 32],
        });
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), KEY_ROTATION_WIRE_SIZE);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }
}
