//! Signed-event wire structure — verified.
//!
//! A signed event blob has the wire layout `[type=35][signer_id:32][payload:N][sig:64]`,
//! minimum total length 98 bytes. The verified functions below pin the boundaries used
//! by `src/event_modules/signed.rs::outer_payload` and `::outer_signer_event_id`.

use vstd::prelude::*;

verus! {

pub const EVENT_TYPE_SIGNED: u8 = 35;
pub const SIGNED_MIN_LEN: usize = 98; // 1 + 32 + 64 + 1
pub const SIGNER_ID_OFFSET: usize = 1;
pub const SIGNER_ID_END: usize = 33;
pub const SIGNATURE_LEN: usize = 64;

/// True iff the blob has the minimum-length + correct-type-byte prefix of a signed
/// event. Used by the runtime's `outer_payload` and `outer_signer_event_id` to
/// decide whether to return Some(slice).
pub fn is_well_formed_signed_prefix(blob: &[u8]) -> (ok: bool)
    ensures
        ok == (blob.len() >= SIGNED_MIN_LEN && blob[0] == EVENT_TYPE_SIGNED),
{
    blob.len() >= SIGNED_MIN_LEN && blob[0] == EVENT_TYPE_SIGNED
}

/// Returns the inclusive-start / exclusive-end indices of the inner payload slice
/// within a well-formed signed blob. Precondition enforces the caller has already
/// verified the prefix — we compute the body range only for well-formed blobs.
pub fn signed_body_range(blob_len: usize) -> (range: (usize, usize))
    requires blob_len >= SIGNED_MIN_LEN,
    ensures
        range.0 == SIGNER_ID_END,
        range.1 == blob_len - SIGNATURE_LEN,
        range.0 < range.1,
{
    (SIGNER_ID_END, blob_len - SIGNATURE_LEN)
}

/// Returns the (start, end) index pair of the 64-byte signature suffix.
pub fn signature_range(blob_len: usize) -> (range: (usize, usize))
    requires blob_len >= SIGNED_MIN_LEN,
    ensures
        range.0 == blob_len - SIGNATURE_LEN,
        range.1 == blob_len,
        range.1 - range.0 == SIGNATURE_LEN,
{
    (blob_len - SIGNATURE_LEN, blob_len)
}

} // verus!
