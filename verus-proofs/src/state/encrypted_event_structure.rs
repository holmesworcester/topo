//! Encrypted-event wire structure — verified boundaries.
//!
//! An encrypted event has a fixed-offset header followed by a variable-length ciphertext
//! + fixed auth tag. Verified offsets below pin the layout used by
//! `src/event_modules/encrypted.rs`.
//!
//! Total size = `CIPHERTEXT_OFFSET + inner_wire_size + AUTH_TAG_LEN`. `inner_wire_size`
//! is a static lookup from inner_type_code, so a well-formed blob has a *deterministic*
//! length given its `inner_type_code` byte.

use vstd::prelude::*;

verus! {

pub const EVENT_TYPE_ENCRYPTED: u8 = 5;
pub const CREATED_AT_OFFSET: usize = 1;
pub const KEY_EVENT_ID_OFFSET: usize = 9;
pub const OWNER_EVENT_ID_OFFSET: usize = 41;
pub const INNER_TYPE_CODE_OFFSET: usize = 73;
pub const NONCE_OFFSET: usize = 74;
pub const CIPHERTEXT_OFFSET: usize = 86;
pub const AUTH_TAG_LEN: usize = 16;
pub const ENCRYPTED_HEADER_LEN: usize = CIPHERTEXT_OFFSET;
pub const NONCE_LEN: usize = 12;
pub const EVENT_ID_LEN: usize = 32;

/// True iff the blob is long enough to carry the encrypted header and has the right
/// type byte. The header-only prefix check used before ciphertext-size lookup.
pub fn is_well_formed_encrypted_header(blob: &[u8]) -> (ok: bool)
    ensures ok == (blob.len() >= ENCRYPTED_HEADER_LEN && blob[0] == EVENT_TYPE_ENCRYPTED),
{
    blob.len() >= ENCRYPTED_HEADER_LEN && blob[0] == EVENT_TYPE_ENCRYPTED
}

/// For a well-formed encrypted blob of given total length and known inner_wire_size,
/// returns the expected total length (header + ciphertext + auth tag). The runtime
/// checks `blob.len() == expected_total_len(inner_wire_size)` after looking up
/// `inner_wire_size` from the registry; a mismatch rejects.
pub fn expected_encrypted_total_len(inner_wire_size: usize) -> (total: usize)
    requires inner_wire_size <= usize::MAX - ENCRYPTED_HEADER_LEN - AUTH_TAG_LEN,
    ensures total == ENCRYPTED_HEADER_LEN + inner_wire_size + AUTH_TAG_LEN,
{
    ENCRYPTED_HEADER_LEN + inner_wire_size + AUTH_TAG_LEN
}

/// (start, end) for the owner_event_id field (32 bytes).
pub fn owner_event_id_range() -> (range: (usize, usize))
    ensures
        range.0 == OWNER_EVENT_ID_OFFSET,
        range.1 == INNER_TYPE_CODE_OFFSET,
        range.1 - range.0 == EVENT_ID_LEN,
{
    (OWNER_EVENT_ID_OFFSET, INNER_TYPE_CODE_OFFSET)
}

/// (start, end) for the nonce field (12 bytes).
pub fn nonce_range() -> (range: (usize, usize))
    ensures
        range.0 == NONCE_OFFSET,
        range.1 == CIPHERTEXT_OFFSET,
        range.1 - range.0 == NONCE_LEN,
{
    (NONCE_OFFSET, CIPHERTEXT_OFFSET)
}

} // verus!
