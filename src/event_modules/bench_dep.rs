use super::fixed_layout::{BENCH_DEP_WIRE_SIZE, BENCH_DEP_MAX_SLOTS, bench_dep_offsets as off};
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_BENCH_DEP};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchDepEvent {
    pub created_at_ms: u64,
    pub dep_ids: Vec<[u8; 32]>,
    pub payload: [u8; 16],
}

/// Wire format (345 bytes fixed, unsigned):
/// [0]      type_code = 26
/// [1..9]   created_at_ms (u64 LE)
/// [9..329] dep_slots (10 × 32 bytes; unused slots are all-zeros)
/// [329..345] payload (16 bytes)
///
/// No dep_count field. Application counts non-zero slots.
pub fn parse_bench_dep(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < BENCH_DEP_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: BENCH_DEP_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > BENCH_DEP_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: BENCH_DEP_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_BENCH_DEP {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_BENCH_DEP,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[off::CREATED_AT..off::DEP_SLOTS].try_into().unwrap());

    // Read all 10 slots, collect non-zero ones as deps
    let mut dep_ids = Vec::new();
    let zero = [0u8; 32];
    for i in 0..BENCH_DEP_MAX_SLOTS {
        let start = off::DEP_SLOTS + 32 * i;
        let mut id = [0u8; 32];
        id.copy_from_slice(&blob[start..start + 32]);
        if id != zero {
            dep_ids.push(id);
        }
    }

    let mut payload = [0u8; 16];
    payload.copy_from_slice(&blob[off::PAYLOAD..off::PAYLOAD + 16]);

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

    let mut buf = vec![0u8; BENCH_DEP_WIRE_SIZE];

    buf[off::TYPE_CODE] = EVENT_TYPE_BENCH_DEP;
    buf[off::CREATED_AT..off::DEP_SLOTS].copy_from_slice(&b.created_at_ms.to_le_bytes());

    // Write dep_ids into slots, remaining slots stay zero
    for (i, id) in b.dep_ids.iter().enumerate() {
        let start = off::DEP_SLOTS + 32 * i;
        buf[start..start + 32].copy_from_slice(id);
    }

    buf[off::PAYLOAD..off::PAYLOAD + 16].copy_from_slice(&b.payload);

    Ok(buf)
}

// === Projector (event-module locality) ===

use crate::projection::result::{ContextSnapshot, ProjectorResult};

/// Pure projector: BenchDep — no projection table, valid_events tracks completion.
pub fn project_pure(
    _recorded_by: &str,
    _event_id_b64: &str,
    _parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
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
};
