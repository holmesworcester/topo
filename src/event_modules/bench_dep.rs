use super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_BENCH_DEP};

// ─── Layout (owned by this module) ───

/// BenchDep: fixed number of dep slots (unused slots are all-zeros)
pub const BENCH_DEP_MAX_SLOTS: usize = 10;

/// BenchDep: total bytes for dep slots (10 × 32)
pub const BENCH_DEP_SLOTS_BYTES: usize = BENCH_DEP_MAX_SLOTS * 32;

pub const BENCH_DEP_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::FixedBytes("dep_slots", 320), // 10 × 32 bytes
    FieldSpec::FixedBytes("payload", 16),
];

/// BenchDep (type 26): type(1) + created_at(8) + dep_slots(320) + payload(16) = 345
pub const BENCH_DEP_WIRE_SIZE: usize = wire_size_for_fields(BENCH_DEP_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchDepEvent {
    pub created_at_ms: u64,
    pub dep_ids: Vec<[u8; 32]>,
    pub payload: [u8; 16],
}

impl super::Describe for BenchDepEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("deps", format!("{} dep(s)", self.dep_ids.len())),
            ("payload", super::trunc_hex(&self.payload, 16)),
        ]
    }
}

/// Wire format (345 bytes fixed, unsigned):
/// [0]      type_code = 26
/// [1..9]   created_at_ms (u64 LE)
/// [9..329] dep_slots (10 × 32 bytes; unused slots are all-zeros)
/// [329..345] payload (16 bytes)
///
/// No dep_count field. Application counts non-zero slots.
pub fn parse_bench_dep(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_BENCH_DEP, BENCH_DEP_FIELDS, blob)?;

    let created_at_ms = values[0].as_timestamp().unwrap();

    // Extract dep slots from raw bytes, collect non-zero ones as deps
    let slot_bytes = values[1].as_fixed_bytes().unwrap();
    let mut dep_ids = Vec::new();
    let zero = [0u8; 32];
    for i in 0..BENCH_DEP_MAX_SLOTS {
        let start = 32 * i;
        let mut id = [0u8; 32];
        id.copy_from_slice(&slot_bytes[start..start + 32]);
        if id != zero {
            dep_ids.push(id);
        }
    }

    let payload_bytes = values[2].as_fixed_bytes().unwrap();
    let mut payload = [0u8; 16];
    payload.copy_from_slice(payload_bytes);

    Ok(ParsedEvent::BenchDep(BenchDepEvent {
        created_at_ms,
        dep_ids,
        payload,
    }))
}

pub fn encode_bench_dep(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let b = match event {
        ParsedEvent::BenchDep(b) => b,
        _ => return Err(EventError::WrongVariant),
    };

    if b.dep_ids.len() > BENCH_DEP_MAX_SLOTS {
        return Err(EventError::ContentTooLong(b.dep_ids.len()));
    }

    // Build dep_slots as 320 bytes (10 × 32), remaining slots stay zero
    let mut slot_bytes = vec![0u8; BENCH_DEP_SLOTS_BYTES];
    for (i, id) in b.dep_ids.iter().enumerate() {
        let start = 32 * i;
        slot_bytes[start..start + 32].copy_from_slice(id);
    }

    let values = vec![
        FieldValue::Timestamp(b.created_at_ms),
        FieldValue::FixedBytes(slot_bytes),
        FieldValue::FixedBytes(b.payload.to_vec()),
    ];

    Ok(encode_fields(
        EVENT_TYPE_BENCH_DEP,
        BENCH_DEP_FIELDS,
        &values,
    )?)
}

// === Projector (event-module locality) ===

use crate::projection::contract::{ContextSnapshot, ProjectorResult};

/// Pure projector: BenchDep — no projection table, valid_events tracks completion.
pub fn project_pure(
    _recorded_by: &str,
    _event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    match parsed {
        ParsedEvent::BenchDep(_) => {}
        _ => return ProjectorResult::reject("not a bench_dep event".to_string()),
    }
    ProjectorResult::valid(vec![])
}

pub static BENCH_DEP_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_BENCH_DEP,
    type_name: "bench_dep_perf_testing",
    projection_table: "valid_events",
    share_scope: ShareScope::Shared,
    dep_fields: &["dep_id"],
    dep_field_type_codes: &[&[]],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_bench_dep,
    encode: encode_bench_dep,
    projector: project_pure,
    context_loader: crate::event_modules::registry::load_empty_context,
};

#[cfg(test)]
mod layout_tests {
    use super::*;
    use crate::event_modules::layout::field_spec::field_offset;
    #[test]
    fn offsets_consistent() {
        assert_eq!(field_offset(BENCH_DEP_FIELDS, 2) + 16, BENCH_DEP_WIRE_SIZE);
    }
}
