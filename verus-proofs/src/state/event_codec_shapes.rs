//! Verified codecs for additional primitive-only wire shapes.
//! Each codec covers one or more runtime event modules with the same layout.

use vstd::prelude::*;
use vstd::bytes::{u64_from_le_bytes, u64_to_le_bytes};

verus! {

#[cfg(verus_keep_ghost)]
use vstd::bytes::{spec_u64_from_le_bytes, spec_u64_to_le_bytes};

// ══════════════════════════════════════════════════════════════════
// ts_id_fb64: Timestamp + EventId + FixedBytes(64) = 105 bytes
// Covers: endpoint_shared (the 64-byte field is a signature)
// ══════════════════════════════════════════════════════════════════

pub const TS_ID_FB64_WIRE_SIZE: usize = 105;

pub open spec fn ts_id_fb64_wire_spec(
    type_byte: u8, ts: u64, id: [u8; 32], sig: [u8; 64],
) -> Seq<u8> {
    seq![type_byte] + spec_u64_to_le_bytes(ts) + id@ + sig@
}

pub fn encode_ts_id_fb64(
    type_byte: u8, ts: u64, id: &[u8; 32], sig: &[u8; 64],
) -> (out: Vec<u8>)
    ensures
        out@ =~= ts_id_fb64_wire_spec(type_byte, ts, *id, *sig),
        out@.len() == TS_ID_FB64_WIRE_SIZE,
{
    let mut buf: Vec<u8> = Vec::with_capacity(TS_ID_FB64_WIRE_SIZE);
    buf.push(type_byte);
    let ts_bytes: Vec<u8> = u64_to_le_bytes(ts);
    buf.extend_from_slice(ts_bytes.as_slice());
    buf.extend_from_slice(id);
    buf.extend_from_slice(sig);
    proof { assert(buf@ =~= ts_id_fb64_wire_spec(type_byte, ts, *id, *sig)); }
    buf
}

pub fn parse_ts_id_fb64(
    expected_type_byte: u8, blob: &[u8],
) -> (out: Option<(u64, [u8; 32], [u8; 64])>)
    ensures
        out.is_some() <==> (blob@.len() == TS_ID_FB64_WIRE_SIZE && blob@[0] == expected_type_byte),
{
    if blob.len() != TS_ID_FB64_WIRE_SIZE { return None; }
    if blob[0] != expected_type_byte { return None; }
    let ts = u64_from_le_bytes(vstd::slice::slice_subrange(blob, 1, 9));
    let mut id: [u8; 32] = [0u8; 32];
    let mut sig: [u8; 64] = [0u8; 64];
    let mut i: usize = 0;
    while i < 32
        invariant blob@.len() == TS_ID_FB64_WIRE_SIZE, id@.len() == 32,
        decreases 32 - i,
    {
        id[i] = blob[i + 9];
        i += 1;
    }
    let mut j: usize = 0;
    while j < 64
        invariant blob@.len() == TS_ID_FB64_WIRE_SIZE, sig@.len() == 64,
        decreases 64 - j,
    {
        sig[j] = blob[j + 41];
        j += 1;
    }
    Some((ts, id, sig))
}

// ══════════════════════════════════════════════════════════════════
// ts_fb320_fb16: Timestamp + FixedBytes(320) + FixedBytes(16) = 345 bytes
// Covers: bench_dep
// ══════════════════════════════════════════════════════════════════

pub const TS_FB320_FB16_WIRE_SIZE: usize = 345;

pub open spec fn ts_fb320_fb16_wire_spec(
    type_byte: u8, ts: u64, blob320: Seq<u8>, blob16: Seq<u8>,
) -> Seq<u8> {
    seq![type_byte] + spec_u64_to_le_bytes(ts) + blob320 + blob16
}

pub fn encode_ts_fb320_fb16(
    type_byte: u8, ts: u64, blob320: &[u8; 320], blob16: &[u8; 16],
) -> (out: Vec<u8>)
    ensures
        out@ =~= ts_fb320_fb16_wire_spec(type_byte, ts, blob320@, blob16@),
        out@.len() == TS_FB320_FB16_WIRE_SIZE,
{
    let mut buf: Vec<u8> = Vec::with_capacity(TS_FB320_FB16_WIRE_SIZE);
    buf.push(type_byte);
    let ts_bytes: Vec<u8> = u64_to_le_bytes(ts);
    buf.extend_from_slice(ts_bytes.as_slice());
    buf.extend_from_slice(blob320);
    buf.extend_from_slice(blob16);
    proof { assert(buf@ =~= ts_fb320_fb16_wire_spec(type_byte, ts, blob320@, blob16@)); }
    buf
}

// ══════════════════════════════════════════════════════════════════
// ts_id6: Timestamp + 6 × EventId = 201 bytes
// Covers: key_request
// ══════════════════════════════════════════════════════════════════

pub const TS_ID6_WIRE_SIZE: usize = 201;

pub fn encode_ts_id6(
    type_byte: u8, ts: u64,
    id1: &[u8; 32], id2: &[u8; 32], id3: &[u8; 32],
    id4: &[u8; 32], id5: &[u8; 32], id6: &[u8; 32],
) -> (out: Vec<u8>)
    ensures
        out@.len() == TS_ID6_WIRE_SIZE,
        out@[0] == type_byte,
        out@.subrange(1, 9) =~= spec_u64_to_le_bytes(ts),
        out@.subrange(9, 41) =~= id1@,
        out@.subrange(41, 73) =~= id2@,
        out@.subrange(73, 105) =~= id3@,
        out@.subrange(105, 137) =~= id4@,
        out@.subrange(137, 169) =~= id5@,
        out@.subrange(169, 201) =~= id6@,
{
    let mut buf: Vec<u8> = Vec::with_capacity(TS_ID6_WIRE_SIZE);
    buf.push(type_byte);
    let ts_bytes: Vec<u8> = u64_to_le_bytes(ts);
    buf.extend_from_slice(ts_bytes.as_slice());
    buf.extend_from_slice(id1);
    buf.extend_from_slice(id2);
    buf.extend_from_slice(id3);
    buf.extend_from_slice(id4);
    buf.extend_from_slice(id5);
    buf.extend_from_slice(id6);
    buf
}

pub fn parse_ts_id6(
    expected_type_byte: u8, blob: &[u8],
) -> (out: Option<(u64, [u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32])>)
    ensures
        out.is_some() <==> (blob@.len() == TS_ID6_WIRE_SIZE && blob@[0] == expected_type_byte),
{
    if blob.len() != TS_ID6_WIRE_SIZE { return None; }
    if blob[0] != expected_type_byte { return None; }
    let ts = u64_from_le_bytes(vstd::slice::slice_subrange(blob, 1, 9));
    let id1 = copy_32(blob, 9);
    let id2 = copy_32(blob, 41);
    let id3 = copy_32(blob, 73);
    let id4 = copy_32(blob, 105);
    let id5 = copy_32(blob, 137);
    let id6 = copy_32(blob, 169);
    Some((ts, id1, id2, id3, id4, id5, id6))
}

/// Copy a 32-byte slice out of `blob` starting at `offset`. Precondition ensures
/// the offset is in-range. Shared helper used by multi-id parsers.
fn copy_32(blob: &[u8], offset: usize) -> (out: [u8; 32])
    requires
        blob.len() >= offset + 32,
    ensures
        out@.len() == 32,
{
    let mut out: [u8; 32] = [0u8; 32];
    let mut i: usize = 0;
    while i < 32
        invariant
            blob.len() >= offset + 32,
            out@.len() == 32,
        decreases 32 - i,
    {
        out[i] = blob[offset + i];
        i += 1;
    }
    out
}

// ══════════════════════════════════════════════════════════════════
// ts_id_u8_id6: Timestamp + EventId + U8 + 6 × EventId = 234 bytes
// Covers: removal, key_rotation (9 fields each)
//
// Shape: type(1) + ts(8) + head_id(32) + count(1) + 6*id(192)
// Total: 1 + 8 + 32 + 1 + 6*32 = 234
// ══════════════════════════════════════════════════════════════════

pub const TS_ID_U8_ID6_WIRE_SIZE: usize = 234;

pub fn encode_ts_id_u8_id6(
    type_byte: u8, ts: u64, head_id: &[u8; 32], count: u8,
    id1: &[u8; 32], id2: &[u8; 32], id3: &[u8; 32],
    id4: &[u8; 32], id5: &[u8; 32], id6: &[u8; 32],
) -> (out: Vec<u8>)
    ensures
        out@.len() == TS_ID_U8_ID6_WIRE_SIZE,
        out@[0] == type_byte,
        out@.subrange(1, 9) =~= spec_u64_to_le_bytes(ts),
        out@.subrange(9, 41) =~= head_id@,
        out@[41] == count,
        out@.subrange(42, 74) =~= id1@,
        out@.subrange(74, 106) =~= id2@,
        out@.subrange(106, 138) =~= id3@,
        out@.subrange(138, 170) =~= id4@,
        out@.subrange(170, 202) =~= id5@,
        out@.subrange(202, 234) =~= id6@,
{
    let mut buf: Vec<u8> = Vec::with_capacity(TS_ID_U8_ID6_WIRE_SIZE);
    buf.push(type_byte);
    let ts_bytes: Vec<u8> = u64_to_le_bytes(ts);
    buf.extend_from_slice(ts_bytes.as_slice());
    buf.extend_from_slice(head_id);
    buf.push(count);
    buf.extend_from_slice(id1);
    buf.extend_from_slice(id2);
    buf.extend_from_slice(id3);
    buf.extend_from_slice(id4);
    buf.extend_from_slice(id5);
    buf.extend_from_slice(id6);
    buf
}

pub fn parse_ts_id_u8_id6(
    expected_type_byte: u8, blob: &[u8],
) -> (out: Option<(u64, [u8; 32], u8, [u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32])>)
    ensures
        out.is_some() <==> (blob@.len() == TS_ID_U8_ID6_WIRE_SIZE
            && blob@[0] == expected_type_byte),
{
    if blob.len() != TS_ID_U8_ID6_WIRE_SIZE { return None; }
    if blob[0] != expected_type_byte { return None; }
    let ts = u64_from_le_bytes(vstd::slice::slice_subrange(blob, 1, 9));
    let head = copy_32(blob, 9);
    let count = blob[41];
    let id1 = copy_32(blob, 42);
    let id2 = copy_32(blob, 74);
    let id3 = copy_32(blob, 106);
    let id4 = copy_32(blob, 138);
    let id5 = copy_32(blob, 170);
    let id6 = copy_32(blob, 202);
    Some((ts, head, count, id1, id2, id3, id4, id5, id6))
}

} // verus!
