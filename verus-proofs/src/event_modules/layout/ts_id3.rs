//! Verified round-trip codec for (Timestamp + 3 × EventId) events (105 bytes).
//! Covers: invite_accepted, user_invite_shared (user_invite).

use vstd::bytes::{u64_from_le_bytes, u64_to_le_bytes};
use vstd::prelude::*;

verus! {

#[cfg(verus_keep_ghost)]
use vstd::bytes::{spec_u64_from_le_bytes, spec_u64_to_le_bytes};

pub const TS_ID3_WIRE_SIZE: usize = 105;

pub open spec fn ts_id3_wire_spec(
    type_byte: u8, ts: u64, id1: [u8; 32], id2: [u8; 32], id3: [u8; 32],
) -> Seq<u8> {
    seq![type_byte] + spec_u64_to_le_bytes(ts) + id1@ + id2@ + id3@
}

pub fn encode_ts_id3(
    type_byte: u8, ts: u64, id1: &[u8; 32], id2: &[u8; 32], id3: &[u8; 32],
) -> (out: Vec<u8>)
    ensures
        out@ =~= ts_id3_wire_spec(type_byte, ts, *id1, *id2, *id3),
        out@.len() == TS_ID3_WIRE_SIZE,
{
    let mut buf: Vec<u8> = Vec::with_capacity(TS_ID3_WIRE_SIZE);
    buf.push(type_byte);
    let ts_bytes: Vec<u8> = u64_to_le_bytes(ts);
    buf.extend_from_slice(ts_bytes.as_slice());
    buf.extend_from_slice(id1);
    buf.extend_from_slice(id2);
    buf.extend_from_slice(id3);
    proof { assert(buf@ =~= ts_id3_wire_spec(type_byte, ts, *id1, *id2, *id3)); }
    buf
}

pub fn parse_ts_id3(
    expected_type_byte: u8, blob: &[u8],
) -> (out: Option<(u64, [u8; 32], [u8; 32], [u8; 32])>)
    ensures
        out.is_some() <==> (blob@.len() == TS_ID3_WIRE_SIZE && blob@[0] == expected_type_byte),
        out.is_some() ==> ({
            let t = out.unwrap();
            t.0 == spec_u64_from_le_bytes(blob@.subrange(1, 9))
            && t.1@ =~= blob@.subrange(9, 41)
            && t.2@ =~= blob@.subrange(41, 73)
            && t.3@ =~= blob@.subrange(73, 105)
        }),
{
    if blob.len() != TS_ID3_WIRE_SIZE { return None; }
    if blob[0] != expected_type_byte { return None; }
    let ts = u64_from_le_bytes(vstd::slice::slice_subrange(blob, 1, 9));
    let mut id1: [u8; 32] = [0u8; 32];
    let mut id2: [u8; 32] = [0u8; 32];
    let mut id3: [u8; 32] = [0u8; 32];
    let mut i: usize = 0;
    while i < 32
        invariant
            blob@.len() == TS_ID3_WIRE_SIZE,
            id1@.len() == 32, id2@.len() == 32, id3@.len() == 32,
            forall|k: int| #![trigger id1@[k]] 0 <= k < i as int ==> id1@[k] == blob@[k + 9],
            forall|k: int| #![trigger id2@[k]] 0 <= k < i as int ==> id2@[k] == blob@[k + 41],
            forall|k: int| #![trigger id3@[k]] 0 <= k < i as int ==> id3@[k] == blob@[k + 73],
        decreases 32 - i,
    {
        id1[i] = blob[i + 9];
        id2[i] = blob[i + 41];
        id3[i] = blob[i + 73];
        i += 1;
    }
    proof {
        assert(id1@ =~= blob@.subrange(9, 41));
        assert(id2@ =~= blob@.subrange(41, 73));
        assert(id3@ =~= blob@.subrange(73, 105));
    }
    Some((ts, id1, id2, id3))
}

} // verus!
