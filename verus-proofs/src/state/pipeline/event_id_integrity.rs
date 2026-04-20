//! Wire-ingress event-id integrity — verified boundary check.
//!
//! Every `IngestItem` carries a claimed `event_id: [u8; 32]` and a `blob: Vec<u8>`.
//! The integrity invariant: `claimed_id == BLAKE3(blob)`. A peer that sends a blob
//! with a mismatched id is either buggy or adversarial; in either case, accepting
//! the blob under the wrong id would let it masquerade as another event and poison
//! every downstream identity-based lookup.
//!
//! BLAKE3 itself is cryptographic TCB — we don't verify its implementation. What we
//! verify here is the structural boundary: the claimed id must byte-for-byte equal
//! the computed hash. `ingest_now` calls this per item before writing to the
//! `events` table; a mismatch panics with the offending id.
//! The runtime pipeline now re-exports the direct-ingest helpers from
//! `src/state/pipeline/immediate.rs`, but those helpers still consume
//! `IngestItem` values produced at the same wire boundary.

use vstd::prelude::*;

verus! {

/// True iff the 32-byte claimed id matches the 32-byte computed hash.
/// Runtime passes the result of `crate::crypto::hash_event(blob)` as `computed`.
pub fn event_id_matches_blob_hash(
    claimed: &[u8; 32],
    computed: &[u8; 32],
) -> (ok: bool)
    ensures ok == (claimed@ =~= computed@),
{
    let mut i: usize = 0;
    while i < 32
        invariant
            0 <= i <= 32,
            forall|k: int| 0 <= k < i as int ==> claimed[k] == computed[k],
        decreases 32 - i,
    {
        if claimed[i] != computed[i] {
            return false;
        }
        i += 1;
    }
    true
}

} // verus!
