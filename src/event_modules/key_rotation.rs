use super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::registry::{EventTypeMeta, ShareScope};
use super::removal::{
    frontier_hash_from_refs, frontier_refs_from_slots, validate_canonical_frontier_refs,
};
use super::{EventError, ParsedEvent, EVENT_TYPE_KEY_ROTATION};

pub const KEY_ROTATION_CAP: usize = 8192;
pub const KEY_ROTATION_SLOT_BYTES: usize = KEY_ROTATION_CAP * 32;

pub const KEY_ROTATION_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::U8("frontier_count"),
    FieldSpec::EventId("frontier_ref_1"),
    FieldSpec::EventId("frontier_ref_2"),
    FieldSpec::EventId("frontier_ref_3"),
    FieldSpec::EventId("frontier_ref_4"),
    FieldSpec::EventId("frontier_hash"),
    FieldSpec::EventId("rotated_by"),
    FieldSpec::FixedBytes("recipient_slots", KEY_ROTATION_SLOT_BYTES),
    FieldSpec::FixedBytes("wrapped_keys", KEY_ROTATION_SLOT_BYTES),
];

pub const KEY_ROTATION_WIRE_SIZE: usize = wire_size_for_fields(KEY_ROTATION_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRotationEvent {
    pub created_at_ms: u64,
    pub frontier_count: u8,
    pub frontier_ref_1: [u8; 32],
    pub frontier_ref_2: [u8; 32],
    pub frontier_ref_3: [u8; 32],
    pub frontier_ref_4: [u8; 32],
    pub frontier_hash: [u8; 32],
    pub rotated_by: [u8; 32],
    pub recipient_slots: Vec<[u8; 32]>,
    pub wrapped_keys: Vec<[u8; 32]>,
}

impl super::Describe for KeyRotationEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("frontier_hash", super::short_id_b64(&self.frontier_hash)),
            ("slot_cap", KEY_ROTATION_CAP.to_string()),
        ]
    }
}

fn split_slots(bytes: &[u8], what: &str) -> Result<Vec<[u8; 32]>, EventError> {
    if bytes.len() != KEY_ROTATION_SLOT_BYTES {
        return Err(EventError::InvalidMetadata(match what {
            "recipient_slots" => "recipient_slots size does not match key rotation cap",
            _ => "wrapped_keys size does not match key rotation cap",
        }));
    }
    let mut out = Vec::with_capacity(KEY_ROTATION_CAP);
    for chunk in bytes.chunks_exact(32) {
        let mut slot = [0u8; 32];
        slot.copy_from_slice(chunk);
        out.push(slot);
    }
    Ok(out)
}

fn flatten_slots(slots: &[[u8; 32]], what: &'static str) -> Result<Vec<u8>, EventError> {
    if slots.len() != KEY_ROTATION_CAP {
        return Err(EventError::InvalidMetadata(match what {
            "recipient_slots" => "recipient_slots len does not match key rotation cap",
            _ => "wrapped_keys len does not match key rotation cap",
        }));
    }
    let mut out = Vec::with_capacity(KEY_ROTATION_SLOT_BYTES);
    for slot in slots {
        out.extend_from_slice(slot);
    }
    Ok(out)
}

pub fn parse_key_rotation(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_KEY_ROTATION, KEY_ROTATION_FIELDS, blob)?;
    let recipient_slots = split_slots(
        values[8]
            .clone()
            .into_fixed_bytes()
            .ok_or(EventError::WrongVariant)?
            .as_slice(),
        "recipient_slots",
    )?;
    let wrapped_keys = split_slots(
        values[9]
            .clone()
            .into_fixed_bytes()
            .ok_or(EventError::WrongVariant)?
            .as_slice(),
        "wrapped_keys",
    )?;
    Ok(ParsedEvent::KeyRotation(KeyRotationEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        frontier_count: values[1].as_u8().unwrap(),
        frontier_ref_1: values[2].as_event_id().unwrap(),
        frontier_ref_2: values[3].as_event_id().unwrap(),
        frontier_ref_3: values[4].as_event_id().unwrap(),
        frontier_ref_4: values[5].as_event_id().unwrap(),
        frontier_hash: values[6].as_event_id().unwrap(),
        rotated_by: values[7].as_event_id().unwrap(),
        recipient_slots,
        wrapped_keys,
    }))
}

pub fn encode_key_rotation(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let rotation = match event {
        ParsedEvent::KeyRotation(event) => event,
        _ => return Err(EventError::WrongVariant),
    };
    let recipient_slots = flatten_slots(&rotation.recipient_slots, "recipient_slots")?;
    let wrapped_keys = flatten_slots(&rotation.wrapped_keys, "wrapped_keys")?;
    let values = vec![
        FieldValue::Timestamp(rotation.created_at_ms),
        FieldValue::U8(rotation.frontier_count),
        FieldValue::EventId(rotation.frontier_ref_1),
        FieldValue::EventId(rotation.frontier_ref_2),
        FieldValue::EventId(rotation.frontier_ref_3),
        FieldValue::EventId(rotation.frontier_ref_4),
        FieldValue::EventId(rotation.frontier_hash),
        FieldValue::EventId(rotation.rotated_by),
        FieldValue::FixedBytes(recipient_slots),
        FieldValue::FixedBytes(wrapped_keys),
    ];
    Ok(encode_fields(
        EVENT_TYPE_KEY_ROTATION,
        KEY_ROTATION_FIELDS,
        &values,
    )?)
}

use crate::crypto::event_id_to_base64;
use crate::projection::decision_context::{
    ContextLoadResult, ProjectionFrameContext, ProjectionQueries,
};
use crate::projection::projector::{
    EmitCommand, ProjectorDecisionContext, ProjectorResult, SqlVal, WriteOp,
};
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

pub fn build_projector_context(
    queries: &dyn ProjectionQueries,
    frame: &ProjectionFrameContext,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextLoadResult, Box<dyn std::error::Error>> {
    let rotation = match parsed {
        ParsedEvent::KeyRotation(rotation) => rotation,
        _ => return Err("key_rotation context loader called for non-key_rotation event".into()),
    };
    Ok(ContextLoadResult::ready(queries.load_key_rotation_context(
        frame,
        recorded_by,
        event_id_b64,
        rotation,
    )?))
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
    if rotation.recipient_slots.len() != KEY_ROTATION_CAP {
        return ProjectorResult::reject("recipient_slots len does not match key rotation cap".to_string());
    }
    if rotation.wrapped_keys.len() != KEY_ROTATION_CAP {
        return ProjectorResult::reject("wrapped_keys len does not match key rotation cap".to_string());
    }
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

    // `key_rotations.key_event_id` = deterministic KeySecret event_id (type 6),
    // when the projector has unwrapped material. Otherwise fall back to the
    // rotation's own event_id so downstream joins still produce a non-null
    // key column even if the local tenant cannot unwrap yet.
    let key_event_id_b64 = if let Some(material) = &ctx.unwrapped_secret_material {
        event_id_to_base64(
            &crate::event_modules::key_secret::deterministic_key_secret_event_id(
                &material.key_bytes,
            ),
        )
    } else {
        event_id_b64.to_string()
    };

    let ops = vec![WriteOp::InsertOrIgnore {
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
            SqlVal::Text(key_event_id_b64),
            SqlVal::Text(event_id_to_base64(&rotation.frontier_hash)),
            SqlVal::Int(rotation.frontier_count as i64),
            SqlVal::Text(event_id_to_base64(&rotation.frontier_ref_1)),
            SqlVal::Text(event_id_to_base64(&rotation.frontier_ref_2)),
            SqlVal::Text(event_id_to_base64(&rotation.frontier_ref_3)),
            SqlVal::Text(event_id_to_base64(&rotation.frontier_ref_4)),
            SqlVal::Text(current_signer.event_id.clone()),
        ],
    }];

    if let Some(material) = &ctx.unwrapped_secret_material {
        // Emit the deterministic KeySecret blob through the normal event
        // pipeline. The KeySecret projector writes `key_secrets` and the
        // encrypted wrapper dep resolves on the KeySecret event_id.
        let sk_event = crate::event_modules::key_secret::deterministic_key_secret_event(
            material.key_bytes,
        );
        let sk_blob = match crate::event_modules::encode_event(&sk_event) {
            Ok(blob) => blob,
            Err(err) => {
                return ProjectorResult::reject(format!(
                    "failed to encode deterministic key_secret: {err}"
                ));
            }
        };
        return ProjectorResult::valid_with_commands(
            ops,
            vec![EmitCommand::EmitDeterministicBlob { blob: sk_blob }],
        );
    }

    ProjectorResult::valid(ops)
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
    context_loader: build_projector_context,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::{encode_event, parse_event};

    fn empty_slots() -> Vec<[u8; 32]> {
        vec![[0u8; 32]; KEY_ROTATION_CAP]
    }

    #[test]
    fn test_key_rotation_roundtrip() {
        let frontier_refs = vec![[0x11; 32]];
        let mut recipient_slots = empty_slots();
        let mut wrapped_keys = empty_slots();
        recipient_slots[0] = [0x44; 32];
        wrapped_keys[0] = [0x55; 32];
        let event = ParsedEvent::KeyRotation(KeyRotationEvent {
            created_at_ms: 10_000,
            frontier_count: frontier_refs.len() as u8,
            frontier_ref_1: frontier_refs[0],
            frontier_ref_2: [0u8; 32],
            frontier_ref_3: [0u8; 32],
            frontier_ref_4: [0u8; 32],
            frontier_hash: frontier_hash_from_refs(&frontier_refs),
            rotated_by: [0x33; 32],
            recipient_slots,
            wrapped_keys,
        });
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), KEY_ROTATION_WIRE_SIZE);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }
}
