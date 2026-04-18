//! Verified round-trip codec for (Timestamp + 2 × EventId) events (73 bytes).
//!
//! Covers: peer_secret, invite_secret, admin, peer_invite_shared (device_invite).

use vstd::prelude::*;
use vstd::bytes::{u64_from_le_bytes, u64_to_le_bytes};

verus! {

#[cfg(verus_keep_ghost)]
use vstd::bytes::{spec_u64_from_le_bytes, spec_u64_to_le_bytes};

pub const TS_ID2_WIRE_SIZE: usize = 73;

pub open spec fn ts_id2_wire_spec(type_byte: u8, ts: u64, id1: [u8; 32], id2: [u8; 32]) -> Seq<u8> {
    seq![type_byte] + spec_u64_to_le_bytes(ts) + id1@ + id2@
}

pub fn encode_ts_id2(
    type_byte: u8,
    ts: u64,
    id1: &[u8; 32],
    id2: &[u8; 32],
) -> (out: Vec<u8>)
    ensures
        out@ =~= ts_id2_wire_spec(type_byte, ts, *id1, *id2),
        out@.len() == TS_ID2_WIRE_SIZE,
{
    let mut buf: Vec<u8> = Vec::with_capacity(TS_ID2_WIRE_SIZE);
    buf.push(type_byte);
    let ts_bytes: Vec<u8> = u64_to_le_bytes(ts);
    buf.extend_from_slice(ts_bytes.as_slice());
    buf.extend_from_slice(id1);
    buf.extend_from_slice(id2);
    proof {
        assert(buf@ =~= ts_id2_wire_spec(type_byte, ts, *id1, *id2));
    }
    buf
}

pub fn parse_ts_id2(
    expected_type_byte: u8,
    blob: &[u8],
) -> (out: Option<(u64, [u8; 32], [u8; 32])>)
    ensures
        out.is_some() <==> (blob@.len() == TS_ID2_WIRE_SIZE && blob@[0] == expected_type_byte),
        out.is_some() ==> ({
            let tup = out.unwrap();
            tup.0 == spec_u64_from_le_bytes(blob@.subrange(1, 9))
            && tup.1@ =~= blob@.subrange(9, 41)
            && tup.2@ =~= blob@.subrange(41, 73)
        }),
{
    if blob.len() != TS_ID2_WIRE_SIZE {
        return None;
    }
    if blob[0] != expected_type_byte {
        return None;
    }
    let ts_slice = vstd::slice::slice_subrange(blob, 1, 9);
    let ts = u64_from_le_bytes(ts_slice);
    let mut id1: [u8; 32] = [0u8; 32];
    let mut id2: [u8; 32] = [0u8; 32];
    let mut i: usize = 0;
    while i < 32
        invariant
            blob@.len() == TS_ID2_WIRE_SIZE,
            id1@.len() == 32,
            id2@.len() == 32,
            forall|k: int|
                #![trigger id1@[k]]
                0 <= k < i as int ==> id1@[k] == blob@[k + 9],
            forall|k: int|
                #![trigger id2@[k]]
                0 <= k < i as int ==> id2@[k] == blob@[k + 41],
        decreases 32 - i,
    {
        id1[i] = blob[i + 9];
        id2[i] = blob[i + 41];
        i += 1;
    }
    proof {
        assert(id1@ =~= blob@.subrange(9, 41));
        assert(id2@ =~= blob@.subrange(41, 73));
    }
    Some((ts, id1, id2))
}

} // verus!
