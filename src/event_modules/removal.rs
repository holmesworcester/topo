use super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_REMOVAL};

pub const MAX_REMOVAL_FRONTIER_REFS: usize = 4;

pub const REMOVAL_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("removed_member_ref"),
    FieldSpec::U8("parent_count"),
    FieldSpec::EventId("parent_1"),
    FieldSpec::EventId("parent_2"),
    FieldSpec::EventId("parent_3"),
    FieldSpec::EventId("parent_4"),
    FieldSpec::EventId("frontier_hash"),
    FieldSpec::EventId("removed_by"),
    FieldSpec::EventId("admin_authority_event_id"),
];

pub const REMOVAL_WIRE_SIZE: usize = wire_size_for_fields(REMOVAL_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalEvent {
    pub created_at_ms: u64,
    pub removed_member_ref: [u8; 32],
    pub parent_count: u8,
    pub parent_1: [u8; 32],
    pub parent_2: [u8; 32],
    pub parent_3: [u8; 32],
    pub parent_4: [u8; 32],
    pub frontier_hash: [u8; 32],
    pub removed_by: [u8; 32],
    /// Admin event that authorizes this removal. The event graph's
    /// dep-resolution must see this as a valid `admin` event, and its
    /// `user_event_id` must match the signer peer_shared's user. That
    /// equality is the positive-authority proof obligation; revocation
    /// remains a separate guard layer.
    pub admin_authority_event_id: [u8; 32],
}

impl super::Describe for RemovalEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "removed_member_ref",
                super::short_id_b64(&self.removed_member_ref),
            ),
            ("frontier_hash", super::short_id_b64(&self.frontier_hash)),
        ]
    }
}

pub fn frontier_hash_from_refs(refs: &[[u8; 32]]) -> [u8; 32] {
    let mut sorted = refs.to_vec();
    sorted.sort_unstable();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"poc7-removal-frontier-v1");
    hasher.update(&[sorted.len() as u8]);
    for event_id in &sorted {
        hasher.update(event_id);
    }
    *hasher.finalize().as_bytes()
}

pub fn canonicalize_frontier_refs(refs: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, String> {
    let mut sorted = refs.to_vec();
    sorted.sort_unstable();
    for pair in sorted.windows(2) {
        if pair[0] == pair[1] {
            return Err("frontier refs must be unique".to_string());
        }
    }
    Ok(sorted)
}

pub fn validate_canonical_frontier_refs(refs: &[[u8; 32]]) -> Result<(), String> {
    let sorted = canonicalize_frontier_refs(refs)?;
    if refs != sorted.as_slice() {
        return Err("frontier refs must be sorted in canonical order".to_string());
    }
    Ok(())
}

pub fn frontier_refs_from_slots(
    count: u8,
    slots: &[[u8; 32]; MAX_REMOVAL_FRONTIER_REFS],
) -> Result<Vec<[u8; 32]>, String> {
    let count = count as usize;
    if count > MAX_REMOVAL_FRONTIER_REFS {
        return Err(format!(
            "parent_count {} exceeds max {}",
            count, MAX_REMOVAL_FRONTIER_REFS
        ));
    }
    let mut refs = Vec::with_capacity(count);
    for (idx, slot) in slots.iter().enumerate() {
        let is_zero = *slot == [0u8; 32];
        if idx < count {
            if is_zero {
                return Err(format!(
                    "parent_{} missing within declared parent_count",
                    idx + 1
                ));
            }
            refs.push(*slot);
        } else if !is_zero {
            return Err(format!(
                "parent_{} must be zero when outside declared parent_count",
                idx + 1
            ));
        }
    }
    Ok(refs)
}

pub fn parse_removal(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if let Some((ts, removed_member_ref, parent_count, p1, p2, p3, p4, fh, rb, admin)) =
        topo_verus_proofs::event_modules::layout::shapes::parse_ts_id_u8_id7(EVENT_TYPE_REMOVAL, blob)
    {
        return Ok(ParsedEvent::Removal(RemovalEvent {
            created_at_ms: ts,
            removed_member_ref,
            parent_count,
            parent_1: p1,
            parent_2: p2,
            parent_3: p3,
            parent_4: p4,
            frontier_hash: fh,
            removed_by: rb,
            admin_authority_event_id: admin,
        }));
    }
    let values = decode_fields(EVENT_TYPE_REMOVAL, REMOVAL_FIELDS, blob)?;
    Ok(ParsedEvent::Removal(RemovalEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        removed_member_ref: values[1].as_event_id().unwrap(),
        parent_count: values[2].as_u8().unwrap(),
        parent_1: values[3].as_event_id().unwrap(),
        parent_2: values[4].as_event_id().unwrap(),
        parent_3: values[5].as_event_id().unwrap(),
        parent_4: values[6].as_event_id().unwrap(),
        frontier_hash: values[7].as_event_id().unwrap(),
        removed_by: values[8].as_event_id().unwrap(),
        admin_authority_event_id: values[9].as_event_id().unwrap(),
    }))
}

pub fn encode_removal(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let r = match event {
        ParsedEvent::Removal(event) => event,
        _ => return Err(EventError::WrongVariant),
    };
    Ok(
        topo_verus_proofs::event_modules::layout::shapes::encode_ts_id_u8_id7(
            EVENT_TYPE_REMOVAL,
            r.created_at_ms,
            &r.removed_member_ref,
            r.parent_count,
            &r.parent_1,
            &r.parent_2,
            &r.parent_3,
            &r.parent_4,
            &r.frontier_hash,
            &r.removed_by,
            &r.admin_authority_event_id,
        ),
    )
}

use crate::crypto::event_id_to_base64;
use crate::projection::decision_context::define_query_context_loader;
use crate::projection::projector::{
    ProjectorDecisionContext, ProjectorResult, SqlVal, WriteOp,
};
use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS removals (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            removed_member_ref TEXT NOT NULL,
            frontier_hash TEXT NOT NULL,
            parent_count INTEGER NOT NULL,
            parent_1 TEXT NOT NULL,
            parent_2 TEXT NOT NULL,
            parent_3 TEXT NOT NULL,
            parent_4 TEXT NOT NULL,
            remover_signer_event_id TEXT NOT NULL,
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
    let removal = match parsed {
        ParsedEvent::Removal(event) => event,
        _ => return ProjectorResult::reject("not a removal event".to_string()),
    };
    let Some(current_signer) = ctx.current_signer.as_ref() else {
        return ProjectorResult::reject("removal missing current signer envelope".to_string());
    };
    if removal.removed_by
        != crate::crypto::event_id_from_base64(&current_signer.event_id).unwrap_or([0u8; 32])
    {
        return ProjectorResult::reject("removed_by must equal current signer".to_string());
    }
    if let Some(reason) = ctx.removal_signer_reject_reason.as_ref() {
        return ProjectorResult::reject(reason.clone());
    }
    let slots = [
        removal.parent_1,
        removal.parent_2,
        removal.parent_3,
        removal.parent_4,
    ];
    let refs = match frontier_refs_from_slots(removal.parent_count, &slots) {
        Ok(refs) => refs,
        Err(reason) => return ProjectorResult::reject(reason),
    };
    if let Err(reason) = validate_canonical_frontier_refs(&refs) {
        return ProjectorResult::reject(reason);
    }
    let expected_hash = frontier_hash_from_refs(&refs);
    if expected_hash != removal.frontier_hash {
        return ProjectorResult::reject("frontier_hash does not match parent frontier".to_string());
    }

    let Some(target_kind) = ctx.removal_target_kind else {
        return ProjectorResult::reject(
            "removal target must be a projected user or peer_shared event".to_string(),
        );
    };
    let removed_member_ref_b64 = event_id_to_base64(&removal.removed_member_ref);
    ProjectorResult::valid(vec![
        WriteOp::InsertOrIgnore {
            table: "removals",
            columns: vec![
                "recorded_by",
                "event_id",
                "removed_member_ref",
                "frontier_hash",
                "parent_count",
                "parent_1",
                "parent_2",
                "parent_3",
                "parent_4",
                "remover_signer_event_id",
            ],
            values: vec![
                SqlVal::Text(recorded_by.to_string()),
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Text(removed_member_ref_b64.clone()),
                SqlVal::Text(event_id_to_base64(&removal.frontier_hash)),
                SqlVal::Int(removal.parent_count as i64),
                SqlVal::Text(event_id_to_base64(&removal.parent_1)),
                SqlVal::Text(event_id_to_base64(&removal.parent_2)),
                SqlVal::Text(event_id_to_base64(&removal.parent_3)),
                SqlVal::Text(event_id_to_base64(&removal.parent_4)),
                SqlVal::Text(current_signer.event_id.clone()),
            ],
        },
        WriteOp::InsertOrIgnore {
            table: "removed_entities",
            columns: vec!["recorded_by", "event_id", "target_event_id", "removal_type"],
            values: vec![
                SqlVal::Text(recorded_by.to_string()),
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Text(removed_member_ref_b64),
                SqlVal::Text(target_kind.as_str().to_string()),
            ],
        },
    ])
}

define_query_context_loader!(build_projector_context, Removal, load_removal_context, "removal");

pub static REMOVAL_META: EventTypeMeta = crate::event_modules::registry::event_type_meta! {
    type_code: EVENT_TYPE_REMOVAL,
    type_name: "removal",
    projection_table: "removals",
    share_scope: ShareScope::Shared,
    dep_fields: &[
        "removed_member_ref",
        "parent_1", "parent_2", "parent_3", "parent_4",
        "admin_authority_event_id",
    ],
    dep_field_type_codes: &[
        &[super::EVENT_TYPE_USER, super::EVENT_TYPE_PEER_SHARED],
        &[], &[], &[], &[],
        &[super::EVENT_TYPE_ADMIN],
    ],
    signer_required: true,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_removal,
    encode: encode_removal,
    projector: project_pure,
    context_loader: build_projector_context,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::{encode_event, parse_event};

    #[test]
    fn test_removal_roundtrip() {
        let frontier_refs = vec![[0x11; 32], [0x22; 32]];
        let event = ParsedEvent::Removal(RemovalEvent {
            created_at_ms: 9_000,
            removed_member_ref: [0x33; 32],
            parent_count: frontier_refs.len() as u8,
            parent_1: frontier_refs[0],
            parent_2: frontier_refs[1],
            parent_3: [0u8; 32],
            parent_4: [0u8; 32],
            frontier_hash: frontier_hash_from_refs(&frontier_refs),
            removed_by: [0x44; 32],
            admin_authority_event_id: [0x55; 32],
        });
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), REMOVAL_WIRE_SIZE);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_frontier_hash_is_order_independent_for_multi_parent_frontier() {
        let a = [0x11; 32];
        let b = [0x22; 32];
        let c = [0x33; 32];

        let left = frontier_hash_from_refs(&[a, b, c]);
        let right = frontier_hash_from_refs(&[c, a, b]);

        assert_eq!(
            left, right,
            "multi-parent frontier hash should converge independent of parent order"
        );
    }
}
