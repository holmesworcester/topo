use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_BENCH_DEP};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchDepEvent {
    pub created_at_ms: u64,
    pub dep_ids: Vec<[u8; 32]>,
    pub payload: [u8; 16],
}

/// Wire format (variable length):
/// [0]      type_code = 26
/// [1..9]   created_at_ms (u64 LE)
/// [9..11]  dep_count (u16 LE)
/// [11..11+32*count]  dep_ids (32 bytes each)
/// [11+32*count..11+32*count+16]  payload (16 bytes)
///
/// With 10 deps: 1 + 8 + 2 + 320 + 16 = 347 bytes
pub fn parse_bench_dep(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < 27 {
        return Err(EventError::TooShort {
            expected: 27,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_BENCH_DEP {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_BENCH_DEP,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());
    let dep_count = u16::from_le_bytes(blob[9..11].try_into().unwrap()) as usize;

    let expected_len = 11 + 32 * dep_count + 16;
    if blob.len() < expected_len {
        return Err(EventError::TooShort {
            expected: expected_len,
            actual: blob.len(),
        });
    }

    let mut dep_ids = Vec::with_capacity(dep_count);
    for i in 0..dep_count {
        let start = 11 + 32 * i;
        let mut id = [0u8; 32];
        id.copy_from_slice(&blob[start..start + 32]);
        dep_ids.push(id);
    }

    let payload_start = 11 + 32 * dep_count;
    let mut payload = [0u8; 16];
    payload.copy_from_slice(&blob[payload_start..payload_start + 16]);

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

    let dep_count = b.dep_ids.len();
    if dep_count > u16::MAX as usize {
        return Err(EventError::ContentTooLong(dep_count));
    }
    let total = 11 + 32 * dep_count + 16;
    let mut buf = Vec::with_capacity(total);
    buf.push(EVENT_TYPE_BENCH_DEP);
    buf.extend_from_slice(&b.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&(dep_count as u16).to_le_bytes());
    for id in &b.dep_ids {
        buf.extend_from_slice(id);
    }
    buf.extend_from_slice(&b.payload);
    Ok(buf)
}

pub static BENCH_DEP_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_BENCH_DEP,
    type_name: "bench_dep",
    projection_table: "valid_events",
    share_scope: ShareScope::Shared,
    dep_fields: &["dep_id"],
    dep_field_type_codes: &[&[]],
    signer_required: false,
    signature_byte_len: 0,
    parse: parse_bench_dep,
    encode: encode_bench_dep,
};
