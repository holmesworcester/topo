//! Verified round-trip codec for the `Timestamp + EventId`-shape event family.
//!
//! Wire layout (41 bytes total):
//! - `[0]`      type byte
//! - `[1..9]`   little-endian u64 `created_at_ms`
//! - `[9..41]`  32-byte fixed field (event id / public key / private key / key bytes)
//!
//! Events matching this shape (any type byte, same two fields):
//! - `tenant`           (type 29, field: `public_key`)
//! - `key_secret`       (type 6,  field: `key_bytes`)
//! - `endpoint_secret`  (type 33, field: `private_key_bytes`)
//! - `message_deletion` (type 7,  field: `target_event_id`)
//!
//! The verified `encode` / `parse` pair below is parameterized over the type byte
//! and proves full round-trip: `parse(encode(ts, bytes), type_byte) == Some((ts, bytes))`.

use vstd::prelude::*;
use vstd::bytes::{u64_from_le_bytes, u64_to_le_bytes};

verus! {

#[cfg(verus_keep_ghost)]
use vstd::bytes::{spec_u64_from_le_bytes, spec_u64_to_le_bytes};


pub const TS_ID_WIRE_SIZE: usize = 41;

/// Spec model of the encoded blob.
pub open spec fn ts_id_wire_spec(type_byte: u8, ts: u64, id: [u8; 32]) -> Seq<u8> {
    seq![type_byte] + spec_u64_to_le_bytes(ts) + id@
}

pub fn encode_ts_id(type_byte: u8, ts: u64, id: &[u8; 32]) -> (out: Vec<u8>)
    ensures
        out@ =~= ts_id_wire_spec(type_byte, ts, *id),
        out@.len() == TS_ID_WIRE_SIZE,
{
    let mut buf: Vec<u8> = Vec::with_capacity(TS_ID_WIRE_SIZE);
    buf.push(type_byte);
    let ts_bytes = u64_to_le_bytes(ts);
    let mut i: usize = 0;
    while i < 8
        invariant
            ts_bytes@ == spec_u64_to_le_bytes(ts),
            ts_bytes@.len() == 8,
            i <= 8,
            buf@.len() == 1 + i as int,
            buf@[0] == type_byte,
            forall|k: int|
                #![trigger buf@[k + 1]]
                0 <= k < i as int ==> buf@[k + 1] == ts_bytes@[k],
        decreases 8 - i,
    {
        buf.push(ts_bytes[i]);
        i += 1;
    }
    let mut j: usize = 0;
    while j < 32
        invariant
            ts_bytes@ == spec_u64_to_le_bytes(ts),
            ts_bytes@.len() == 8,
            j <= 32,
            buf@.len() == 9 + j as int,
            buf@[0] == type_byte,
            forall|k: int|
                #![trigger buf@[k + 1]]
                0 <= k < 8 ==> buf@[k + 1] == ts_bytes@[k],
            forall|k: int|
                #![trigger buf@[k + 9]]
                0 <= k < j as int ==> buf@[k + 9] == id@[k],
        decreases 32 - j,
    {
        buf.push(id[j]);
        j += 1;
    }
    proof {
        assert(buf@.len() == 41);
        let expected = ts_id_wire_spec(type_byte, ts, *id);
        assert(expected.len() == 41);
        assert(buf@.subrange(1, 9) =~= ts_bytes@);
        assert(buf@.subrange(9, 41) =~= id@);
        assert(expected.subrange(1, 9) =~= spec_u64_to_le_bytes(ts));
        assert(expected.subrange(9, 41) =~= id@);
        assert(buf@ =~= expected);
    }
    buf
}

pub fn parse_ts_id(expected_type_byte: u8, blob: &[u8]) -> (out: Option<(u64, [u8; 32])>)
    ensures
        out.is_some() <==> (blob@.len() == TS_ID_WIRE_SIZE && blob@[0] == expected_type_byte),
        out.is_some() ==> ({
            let (ts, id) = out.unwrap();
            ts == spec_u64_from_le_bytes(blob@.subrange(1, 9))
            && id@ =~= blob@.subrange(9, 41)
        }),
{
    if blob.len() != TS_ID_WIRE_SIZE {
        return None;
    }
    if blob[0] != expected_type_byte {
        return None;
    }
    let ts_slice = vstd::slice::slice_subrange(blob, 1, 9);
    let ts = u64_from_le_bytes(ts_slice);
    let mut id: [u8; 32] = [0u8; 32];
    let mut i: usize = 0;
    while i < 32
        invariant
            blob@.len() == TS_ID_WIRE_SIZE,
            id@.len() == 32,
            forall|k: int|
                #![trigger id@[k]]
                0 <= k < i as int ==> id@[k] == blob@[k + 9],
        decreases 32 - i,
    {
        id[i] = blob[i + 9];
        i += 1;
    }
    proof {
        assert(id@ =~= blob@.subrange(9, 41));
    }
    Some((ts, id))
}

/// Round-trip lemma: `parse(encode(type, ts, id)) == Some((ts, id))`.
proof fn ts_id_roundtrip(type_byte: u8, ts: u64, id: [u8; 32])
    ensures
        ({
            let blob = ts_id_wire_spec(type_byte, ts, id);
            blob.len() == TS_ID_WIRE_SIZE
                && blob[0] == type_byte
                && spec_u64_from_le_bytes(blob.subrange(1, 9)) == ts
                && blob.subrange(9, 41) =~= id@
        }),
{
    vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
    let blob = ts_id_wire_spec(type_byte, ts, id);
    assert(blob.subrange(1, 9) =~= spec_u64_to_le_bytes(ts));
    assert(blob.subrange(9, 41) =~= id@);
}

} // verus!
