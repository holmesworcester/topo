//! Create-path encrypted wrapper construction.
//!
//! Runtime `create_encrypted_event_with_owner` resolves one local KeySecret by
//! the caller's requested `key_event_id`, encrypts the inner blob with those
//! exact key bytes, then writes that same `key_event_id` into the
//! `EncryptedEvent` wrapper. This mirror does not model AES-GCM internals; it
//! pins the wrapper-construction half of the seam so the runtime can
//! debug-assert that the built wrapper preserves the requested key id and the
//! exact crypto outputs produced for that request.

use vstd::prelude::*;

verus! {

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedCreatePlanCore {
    pub created_at_ms: u64,
    pub key_event_id: [u8; 32],
    pub owner_event_id: [u8; 32],
    pub inner_type_code: u8,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub auth_tag: [u8; 16],
}

pub fn build_encrypted_wrapper_core(
    created_at_ms: u64,
    key_event_id: &[u8; 32],
    owner_event_id: &[u8; 32],
    inner_type_code: u8,
    nonce: &[u8; 12],
    ciphertext: &[u8],
    auth_tag: &[u8; 16],
) -> (plan: EncryptedCreatePlanCore)
    ensures
        plan.created_at_ms == created_at_ms,
        plan.key_event_id == *key_event_id,
        plan.owner_event_id == *owner_event_id,
        plan.inner_type_code == inner_type_code,
        plan.nonce == *nonce,
        plan.auth_tag == *auth_tag,
        plan.ciphertext@ =~= ciphertext@,
{
    let mut copied_ciphertext = Vec::with_capacity(ciphertext.len());
    copied_ciphertext.extend_from_slice(ciphertext);
    EncryptedCreatePlanCore {
        created_at_ms,
        key_event_id: *key_event_id,
        owner_event_id: *owner_event_id,
        inner_type_code,
        nonce: *nonce,
        ciphertext: copied_ciphertext,
        auth_tag: *auth_tag,
    }
}

} // verus!
