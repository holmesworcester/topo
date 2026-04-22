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

// ══════════════════════════════════════════════════════════════════
// ts_id_u8_id7: Timestamp + EventId + U8 + 7 EventIds
// Covers: removal (adds admin_authority_event_id as an explicit
// dep alongside the existing 6 ids: removed_member_ref is the head,
// parent_1..4 + frontier_hash + removed_by as id1..6, and
// admin_authority_event_id as id7).
//
// Shape: type(1) + ts(8) + head_id(32) + count(1) + 7*id(224)
// Total: 1 + 8 + 32 + 1 + 7*32 = 266
// ══════════════════════════════════════════════════════════════════

pub const TS_ID_U8_ID7_WIRE_SIZE: usize = 266;

pub fn encode_ts_id_u8_id7(
    type_byte: u8, ts: u64, head_id: &[u8; 32], count: u8,
    id1: &[u8; 32], id2: &[u8; 32], id3: &[u8; 32],
    id4: &[u8; 32], id5: &[u8; 32], id6: &[u8; 32],
    id7: &[u8; 32],
) -> (out: Vec<u8>)
    ensures
        out@.len() == TS_ID_U8_ID7_WIRE_SIZE,
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
        out@.subrange(234, 266) =~= id7@,
{
    let mut buf: Vec<u8> = Vec::with_capacity(TS_ID_U8_ID7_WIRE_SIZE);
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
    buf.extend_from_slice(id7);
    buf
}

pub fn parse_ts_id_u8_id7(
    expected_type_byte: u8, blob: &[u8],
) -> (out: Option<(u64, [u8; 32], u8, [u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32])>)
    ensures
        out.is_some() <==> (blob@.len() == TS_ID_U8_ID7_WIRE_SIZE
            && blob@[0] == expected_type_byte),
{
    if blob.len() != TS_ID_U8_ID7_WIRE_SIZE { return None; }
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
    let id7 = copy_32(blob, 234);
    Some((ts, head, count, id1, id2, id3, id4, id5, id6, id7))
}

// ══════════════════════════════════════════════════════════════════
// ts_id_u32_slice: Timestamp + EventId + U32 + variable-length slice
// Covers: file_slice (ciphertext is a large variable payload)
// The slice length is not fixed by the codec; the runtime supplies it.
// ══════════════════════════════════════════════════════════════════

pub fn encode_ts_id_u32_slice(
    type_byte: u8, ts: u64, id: &[u8; 32], n: u32, payload: &[u8],
) -> (out: Vec<u8>)
    requires
        payload@.len() <= 0x7fff_ffff,
    ensures
        out@.len() == 45 + payload@.len(),
        out@[0] == type_byte,
        out@.subrange(1, 9) =~= spec_u64_to_le_bytes(ts),
        out@.subrange(9, 41) =~= id@,
        out@.subrange(41, 45) =~= vstd::bytes::spec_u32_to_le_bytes(n),
        out@.subrange(45, 45 + payload@.len() as int) =~= payload@,
{
    let mut buf: Vec<u8> = Vec::with_capacity(45 + payload.len());
    buf.push(type_byte);
    let ts_bytes: Vec<u8> = u64_to_le_bytes(ts);
    buf.extend_from_slice(ts_bytes.as_slice());
    buf.extend_from_slice(id);
    let n_bytes: Vec<u8> = vstd::bytes::u32_to_le_bytes(n);
    buf.extend_from_slice(n_bytes.as_slice());
    buf.extend_from_slice(payload);
    buf
}

// ══════════════════════════════════════════════════════════════════
// ts_id2_fb64: Timestamp + 2 × EventId + FixedBytes(64) = 137 bytes
// Covers: reaction
// ══════════════════════════════════════════════════════════════════

pub const TS_ID2_FB64_WIRE_SIZE: usize = 137;

pub open spec fn ts_id2_fb64_wire_spec(
    type_byte: u8, ts: u64, id1: [u8; 32], id2: [u8; 32], fb: [u8; 64],
) -> Seq<u8> {
    seq![type_byte] + spec_u64_to_le_bytes(ts) + id1@ + id2@ + fb@
}

pub fn encode_ts_id2_fb64(
    type_byte: u8, ts: u64, id1: &[u8; 32], id2: &[u8; 32], fb: &[u8; 64],
) -> (out: Vec<u8>)
    ensures
        out@ =~= ts_id2_fb64_wire_spec(type_byte, ts, *id1, *id2, *fb),
        out@.len() == TS_ID2_FB64_WIRE_SIZE,
{
    let mut buf: Vec<u8> = Vec::with_capacity(TS_ID2_FB64_WIRE_SIZE);
    buf.push(type_byte);
    let ts_bytes: Vec<u8> = u64_to_le_bytes(ts);
    buf.extend_from_slice(ts_bytes.as_slice());
    buf.extend_from_slice(id1);
    buf.extend_from_slice(id2);
    buf.extend_from_slice(fb);
    proof { assert(buf@ =~= ts_id2_fb64_wire_spec(type_byte, ts, *id1, *id2, *fb)); }
    buf
}

pub fn parse_ts_id2_fb64(
    expected_type_byte: u8, blob: &[u8],
) -> (out: Option<(u64, [u8; 32], [u8; 32], [u8; 64])>)
    ensures
        out.is_some() <==> (blob@.len() == TS_ID2_FB64_WIRE_SIZE && blob@[0] == expected_type_byte),
{
    if blob.len() != TS_ID2_FB64_WIRE_SIZE { return None; }
    if blob[0] != expected_type_byte { return None; }
    let ts = u64_from_le_bytes(vstd::slice::slice_subrange(blob, 1, 9));
    let id1 = copy_32(blob, 9);
    let id2 = copy_32(blob, 41);
    let mut fb: [u8; 64] = [0u8; 64];
    let mut i: usize = 0;
    while i < 64
        invariant blob@.len() == TS_ID2_FB64_WIRE_SIZE, fb@.len() == 64,
        decreases 64 - i,
    {
        fb[i] = blob[i + 73];
        i += 1;
    }
    Some((ts, id1, id2, fb))
}

// ══════════════════════════════════════════════════════════════════
// ts_id3_fb64: Timestamp + 3 × EventId + FixedBytes(64) = 169 bytes
// Covers: peer_shared
// ══════════════════════════════════════════════════════════════════

pub const TS_ID3_FB64_WIRE_SIZE: usize = 169;

pub open spec fn ts_id3_fb64_wire_spec(
    type_byte: u8, ts: u64,
    id1: [u8; 32], id2: [u8; 32], id3: [u8; 32], fb: [u8; 64],
) -> Seq<u8> {
    seq![type_byte] + spec_u64_to_le_bytes(ts) + id1@ + id2@ + id3@ + fb@
}

pub fn encode_ts_id3_fb64(
    type_byte: u8, ts: u64,
    id1: &[u8; 32], id2: &[u8; 32], id3: &[u8; 32], fb: &[u8; 64],
) -> (out: Vec<u8>)
    ensures
        out@ =~= ts_id3_fb64_wire_spec(type_byte, ts, *id1, *id2, *id3, *fb),
        out@.len() == TS_ID3_FB64_WIRE_SIZE,
{
    let mut buf: Vec<u8> = Vec::with_capacity(TS_ID3_FB64_WIRE_SIZE);
    buf.push(type_byte);
    let ts_bytes: Vec<u8> = u64_to_le_bytes(ts);
    buf.extend_from_slice(ts_bytes.as_slice());
    buf.extend_from_slice(id1);
    buf.extend_from_slice(id2);
    buf.extend_from_slice(id3);
    buf.extend_from_slice(fb);
    proof { assert(buf@ =~= ts_id3_fb64_wire_spec(type_byte, ts, *id1, *id2, *id3, *fb)); }
    buf
}

pub fn parse_ts_id3_fb64(
    expected_type_byte: u8, blob: &[u8],
) -> (out: Option<(u64, [u8; 32], [u8; 32], [u8; 32], [u8; 64])>)
    ensures
        out.is_some() <==> (blob@.len() == TS_ID3_FB64_WIRE_SIZE && blob@[0] == expected_type_byte),
{
    if blob.len() != TS_ID3_FB64_WIRE_SIZE { return None; }
    if blob[0] != expected_type_byte { return None; }
    let ts = u64_from_le_bytes(vstd::slice::slice_subrange(blob, 1, 9));
    let id1 = copy_32(blob, 9);
    let id2 = copy_32(blob, 41);
    let id3 = copy_32(blob, 73);
    let mut fb: [u8; 64] = [0u8; 64];
    let mut i: usize = 0;
    while i < 64
        invariant blob@.len() == TS_ID3_FB64_WIRE_SIZE, fb@.len() == 64,
        decreases 64 - i,
    {
        fb[i] = blob[i + 105];
        i += 1;
    }
    Some((ts, id1, id2, id3, fb))
}

// ══════════════════════════════════════════════════════════════════
// encode_file_v1: File event shape (10 fields, 536 bytes).
// Wire: type(1) + ts(8) + message_id(32) + file_id(32) + blob_bytes(8)
//     + total_slices(4) + slice_bytes(4) + root_hash(32) + key_event_id(32)
//     + filename(255) + mime_type(128)
// ══════════════════════════════════════════════════════════════════

pub const FILE_V1_WIRE_SIZE: usize = 536;

pub fn encode_file_v1(
    type_byte: u8, ts: u64,
    message_id: &[u8; 32], file_id: &[u8; 32],
    blob_bytes: u64, total_slices: u32, slice_bytes: u32,
    root_hash: &[u8; 32], key_event_id: &[u8; 32],
    filename_slot: &[u8; 255], mime_slot: &[u8; 128],
) -> (out: Vec<u8>)
    ensures
        out@.len() == FILE_V1_WIRE_SIZE,
        out@[0] == type_byte,
        out@.subrange(1, 9) =~= spec_u64_to_le_bytes(ts),
        out@.subrange(9, 41) =~= message_id@,
        out@.subrange(41, 73) =~= file_id@,
        out@.subrange(73, 81) =~= spec_u64_to_le_bytes(blob_bytes),
        out@.subrange(81, 85) =~= vstd::bytes::spec_u32_to_le_bytes(total_slices),
        out@.subrange(85, 89) =~= vstd::bytes::spec_u32_to_le_bytes(slice_bytes),
        out@.subrange(89, 121) =~= root_hash@,
        out@.subrange(121, 153) =~= key_event_id@,
        out@.subrange(153, 408) =~= filename_slot@,
        out@.subrange(408, 536) =~= mime_slot@,
{
    let mut buf: Vec<u8> = Vec::with_capacity(FILE_V1_WIRE_SIZE);
    buf.push(type_byte);
    let ts_bytes: Vec<u8> = u64_to_le_bytes(ts);
    buf.extend_from_slice(ts_bytes.as_slice());
    buf.extend_from_slice(message_id);
    buf.extend_from_slice(file_id);
    let bb: Vec<u8> = u64_to_le_bytes(blob_bytes);
    buf.extend_from_slice(bb.as_slice());
    let ts_bytes: Vec<u8> = vstd::bytes::u32_to_le_bytes(total_slices);
    buf.extend_from_slice(ts_bytes.as_slice());
    let sb: Vec<u8> = vstd::bytes::u32_to_le_bytes(slice_bytes);
    buf.extend_from_slice(sb.as_slice());
    buf.extend_from_slice(root_hash);
    buf.extend_from_slice(key_event_id);
    buf.extend_from_slice(filename_slot);
    buf.extend_from_slice(mime_slot);
    buf
}

// ══════════════════════════════════════════════════════════════════
// encode_signed_envelope: [type=35][signer_id:32][payload:N][sig:64]
// Payload is a complete inner event blob (opaque to this codec).
// ══════════════════════════════════════════════════════════════════

pub const SIGNED_TYPE_BYTE: u8 = 35;

pub fn encode_signed_envelope(
    signer_event_id: &[u8; 32],
    payload: &[u8],
    signature: &[u8; 64],
) -> (out: Vec<u8>)
    requires payload@.len() <= 0x7fff_ffff,
    ensures
        out@.len() == 1 + 32 + payload@.len() + 64,
        out@[0] == SIGNED_TYPE_BYTE,
        out@.subrange(1, 33) =~= signer_event_id@,
        out@.subrange(33, 33 + payload@.len() as int) =~= payload@,
        out@.subrange(33 + payload@.len() as int, 33 + payload@.len() as int + 64) =~= signature@,
{
    let mut out: Vec<u8> = Vec::with_capacity(1 + 32 + payload.len() + 64);
    out.push(SIGNED_TYPE_BYTE);
    out.extend_from_slice(signer_event_id);
    out.extend_from_slice(payload);
    out.extend_from_slice(signature);
    out
}

// ══════════════════════════════════════════════════════════════════
// encode_encrypted_envelope: [type=5][ts:8][key_id:32][owner_id:32]
//   [inner_type:1][nonce:12][ciphertext:N][auth_tag:16]
// Ciphertext and auth_tag are opaque (AES-GCM trusted primitives).
// ══════════════════════════════════════════════════════════════════

pub const ENCRYPTED_TYPE_BYTE: u8 = 5;

pub fn encode_encrypted_envelope(
    ts: u64,
    key_event_id: &[u8; 32],
    owner_event_id: &[u8; 32],
    inner_type_code: u8,
    nonce: &[u8; 12],
    ciphertext: &[u8],
    auth_tag: &[u8; 16],
) -> (out: Vec<u8>)
    requires ciphertext@.len() <= 0x7fff_ffff,
    ensures
        out@.len() == 102 + ciphertext@.len(),
        out@[0] == ENCRYPTED_TYPE_BYTE,
        out@.subrange(1, 9) =~= spec_u64_to_le_bytes(ts),
        out@.subrange(9, 41) =~= key_event_id@,
        out@.subrange(41, 73) =~= owner_event_id@,
        out@[73] == inner_type_code,
        out@.subrange(74, 86) =~= nonce@,
        out@.subrange(86, 86 + ciphertext@.len() as int) =~= ciphertext@,
        out@.subrange(86 + ciphertext@.len() as int, 102 + ciphertext@.len() as int) =~= auth_tag@,
{
    let mut out: Vec<u8> = Vec::with_capacity(102 + ciphertext.len());
    out.push(ENCRYPTED_TYPE_BYTE);
    let ts_bytes: Vec<u8> = u64_to_le_bytes(ts);
    out.extend_from_slice(ts_bytes.as_slice());
    out.extend_from_slice(key_event_id);
    out.extend_from_slice(owner_event_id);
    out.push(inner_type_code);
    out.extend_from_slice(nonce);
    out.extend_from_slice(ciphertext);
    out.extend_from_slice(auth_tag);
    out
}

// ══════════════════════════════════════════════════════════════════
// ts_id2_fb1024: Timestamp + 2 × EventId + FixedBytes(1024) = 1097 bytes
// Covers: message (content is a 1024-byte text slot)
// ══════════════════════════════════════════════════════════════════

pub const TS_ID2_FB1024_WIRE_SIZE: usize = 1097;

pub fn encode_ts_id2_fb1024(
    type_byte: u8, ts: u64, id1: &[u8; 32], id2: &[u8; 32], fb: &[u8; 1024],
) -> (out: Vec<u8>)
    ensures
        out@.len() == TS_ID2_FB1024_WIRE_SIZE,
        out@[0] == type_byte,
        out@.subrange(1, 9) =~= spec_u64_to_le_bytes(ts),
        out@.subrange(9, 41) =~= id1@,
        out@.subrange(41, 73) =~= id2@,
        out@.subrange(73, 1097) =~= fb@,
{
    let mut buf: Vec<u8> = Vec::with_capacity(TS_ID2_FB1024_WIRE_SIZE);
    buf.push(type_byte);
    let ts_bytes: Vec<u8> = u64_to_le_bytes(ts);
    buf.extend_from_slice(ts_bytes.as_slice());
    buf.extend_from_slice(id1);
    buf.extend_from_slice(id2);
    buf.extend_from_slice(fb);
    buf
}

pub fn parse_ts_id2_fb1024(
    expected_type_byte: u8, blob: &[u8],
) -> (out: Option<(u64, [u8; 32], [u8; 32], [u8; 1024])>)
    ensures
        out.is_some() <==> (blob@.len() == TS_ID2_FB1024_WIRE_SIZE && blob@[0] == expected_type_byte),
{
    if blob.len() != TS_ID2_FB1024_WIRE_SIZE { return None; }
    if blob[0] != expected_type_byte { return None; }
    let ts = u64_from_le_bytes(vstd::slice::slice_subrange(blob, 1, 9));
    let id1 = copy_32(blob, 9);
    let id2 = copy_32(blob, 41);
    let mut fb: [u8; 1024] = [0u8; 1024];
    let mut i: usize = 0;
    while i < 1024
        invariant blob@.len() == TS_ID2_FB1024_WIRE_SIZE, fb@.len() == 1024,
        decreases 1024 - i,
    {
        fb[i] = blob[i + 73];
        i += 1;
    }
    Some((ts, id1, id2, fb))
}

// ══════════════════════════════════════════════════════════════════
// ts_id_u8_id9: Timestamp + EventId + U8 + 9 × EventId = 330 bytes
// Covers: key_shared
// ══════════════════════════════════════════════════════════════════

pub const TS_ID_U8_ID9_WIRE_SIZE: usize = 330;

pub fn encode_ts_id_u8_id9(
    type_byte: u8, ts: u64, head_id: &[u8; 32], count: u8,
    id1: &[u8; 32], id2: &[u8; 32], id3: &[u8; 32],
    id4: &[u8; 32], id5: &[u8; 32], id6: &[u8; 32],
    id7: &[u8; 32], id8: &[u8; 32], id9: &[u8; 32],
) -> (out: Vec<u8>)
    ensures
        out@.len() == TS_ID_U8_ID9_WIRE_SIZE,
        out@[0] == type_byte,
{
    let mut buf: Vec<u8> = Vec::with_capacity(TS_ID_U8_ID9_WIRE_SIZE);
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
    buf.extend_from_slice(id7);
    buf.extend_from_slice(id8);
    buf.extend_from_slice(id9);
    buf
}

} // verus!
