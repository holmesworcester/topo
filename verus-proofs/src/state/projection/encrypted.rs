//! Verified core of the Encrypted projector's decryption-gate decision.
//!
//! `src/state/projection/encrypted.rs::project_encrypted` delegates its
//! structural acceptance checks to the verified core below.
//!
//! THE CRITICAL GATE: the FIRST check is "is there a key_secrets row for
//! this (recorded_by, key_event_id)?". If NOT, the projector BLOCKS
//! (returns BlockOnMissingDeps, never attempts decryption). This is the
//! closing link in the "user cannot read messages unless invited" chain:
//!
//!   - No valid PeerShared for peer P (gated by PeerShared verified core)
//!   ⟹ No KeyShared with recipient=P can have unwrap_successful_for_this_peer=true
//!     (the unwrap key is tied to P's peer_shared identity)
//!   ⟹ No key_secrets row written for P (KeyShared materialization gate)
//!   ⟹ Encrypted projection for P BLOCKS, plaintext never produced
//!
//! The verified core here proves the CLOSING step: if key_bytes_present is
//! false, the decision is Block; decryption is not attempted. A runtime
//! change that attempted decryption without checking key_bytes_present
//! would fail SMT here.

use vstd::prelude::*;

verus! {

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptedDecryptionCore {
    /// All gates passed; decryption attempted and downstream dep/signer/projector stages run.
    ProceedToDecryptAndProject,
    /// No key_secrets row for this peer — cannot decrypt. BLOCK (not reject).
    /// This is the ACCESS-CONTROL block: peer does not have the key.
    BlockOnMissingKeySecret,
    /// Key bytes found but wrong length (schema corruption). REJECT.
    RejectKeyWrongLength,
    /// Decryption itself failed (wrong key or corrupted ciphertext). REJECT.
    RejectDecryptionFailed,
    /// Inner parse failed. REJECT.
    RejectInnerParseFailed,
    /// Outer declared inner_type_code disagrees with decoded inner type. REJECT.
    RejectInnerTypeMismatch,
    /// Nested encryption (inner_type_code == EVENT_TYPE_ENCRYPTED). REJECT.
    RejectNestedEncryption,
    /// Inner type's registry meta says `encryptable: false`. REJECT.
    RejectInnerNotEncryptable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedDecryptionFlags {
    /// Output of `SELECT key_bytes FROM key_secrets WHERE recorded_by=? AND event_id=?`
    /// returning a row. If false, we cannot decrypt and must block.
    pub key_bytes_present: bool,
    /// `key_bytes.len() == 32` when key_bytes_present.
    pub key_bytes_length_valid: bool,
    /// `decrypt_event_blob(...)` succeeded.
    pub decryption_succeeded: bool,
    /// Inner plaintext re-parsed successfully.
    pub inner_parse_succeeded: bool,
    /// `inner_parsed.event_type_code() == outer.inner_type_code`.
    pub inner_type_matches_outer_claim: bool,
    /// `outer.inner_type_code != EVENT_TYPE_ENCRYPTED` (no nesting).
    pub inner_type_not_encrypted: bool,
    /// Inner type's registry meta has `encryptable: true`.
    pub inner_type_is_encryptable: bool,
}

pub open spec fn encrypted_decryption_spec(
    flags: EncryptedDecryptionFlags,
) -> EncryptedDecryptionCore {
    if !flags.key_bytes_present {
        EncryptedDecryptionCore::BlockOnMissingKeySecret
    } else if !flags.key_bytes_length_valid {
        EncryptedDecryptionCore::RejectKeyWrongLength
    } else if !flags.decryption_succeeded {
        EncryptedDecryptionCore::RejectDecryptionFailed
    } else if !flags.inner_parse_succeeded {
        EncryptedDecryptionCore::RejectInnerParseFailed
    } else if !flags.inner_type_matches_outer_claim {
        EncryptedDecryptionCore::RejectInnerTypeMismatch
    } else if !flags.inner_type_not_encrypted {
        EncryptedDecryptionCore::RejectNestedEncryption
    } else if !flags.inner_type_is_encryptable {
        EncryptedDecryptionCore::RejectInnerNotEncryptable
    } else {
        EncryptedDecryptionCore::ProceedToDecryptAndProject
    }
}

pub fn decide_encrypted_decryption_core(
    flags: EncryptedDecryptionFlags,
) -> (out: EncryptedDecryptionCore)
    ensures out == encrypted_decryption_spec(flags),
{
    if !flags.key_bytes_present {
        EncryptedDecryptionCore::BlockOnMissingKeySecret
    } else if !flags.key_bytes_length_valid {
        EncryptedDecryptionCore::RejectKeyWrongLength
    } else if !flags.decryption_succeeded {
        EncryptedDecryptionCore::RejectDecryptionFailed
    } else if !flags.inner_parse_succeeded {
        EncryptedDecryptionCore::RejectInnerParseFailed
    } else if !flags.inner_type_matches_outer_claim {
        EncryptedDecryptionCore::RejectInnerTypeMismatch
    } else if !flags.inner_type_not_encrypted {
        EncryptedDecryptionCore::RejectNestedEncryption
    } else if !flags.inner_type_is_encryptable {
        EncryptedDecryptionCore::RejectInnerNotEncryptable
    } else {
        EncryptedDecryptionCore::ProceedToDecryptAndProject
    }
}

// ---------------------------------------------------------------------------
// THE CRITICAL ACCESS-CONTROL THEOREM.

/// Proceed-to-decrypt ⟹ key_bytes_present. Contrapositive: a peer with no
/// key_secrets row for this Encrypted event CANNOT reach decryption.
/// This closes the "user cannot read messages unless invited" chain.
pub proof fn no_key_means_block(flags: EncryptedDecryptionFlags)
    ensures
        !flags.key_bytes_present
            ==> encrypted_decryption_spec(flags)
                == EncryptedDecryptionCore::BlockOnMissingKeySecret,
        encrypted_decryption_spec(flags) == EncryptedDecryptionCore::ProceedToDecryptAndProject
            ==> flags.key_bytes_present,
{
}

/// Block on missing key takes PRECEDENCE over any other failure. A peer
/// without the key cannot observe whether any other check would have failed.
pub proof fn key_check_is_first(flags: EncryptedDecryptionFlags)
    ensures
        !flags.key_bytes_present
            ==> encrypted_decryption_spec(flags)
                == EncryptedDecryptionCore::BlockOnMissingKeySecret,
{
}

/// Proceed requires ALL flags.
pub proof fn proceed_requires_all_flags(flags: EncryptedDecryptionFlags)
    ensures
        encrypted_decryption_spec(flags) == EncryptedDecryptionCore::ProceedToDecryptAndProject
            ==> flags.key_bytes_present
                && flags.key_bytes_length_valid
                && flags.decryption_succeeded
                && flags.inner_parse_succeeded
                && flags.inner_type_matches_outer_claim
                && flags.inner_type_not_encrypted
                && flags.inner_type_is_encryptable,
{
}

/// Reject-reason precedence.
pub proof fn reject_reason_precedence(flags: EncryptedDecryptionFlags)
    ensures
        (flags.key_bytes_present && !flags.key_bytes_length_valid)
            ==> encrypted_decryption_spec(flags)
                == EncryptedDecryptionCore::RejectKeyWrongLength,
        (flags.key_bytes_present && flags.key_bytes_length_valid
            && !flags.decryption_succeeded)
            ==> encrypted_decryption_spec(flags)
                == EncryptedDecryptionCore::RejectDecryptionFailed,
        (flags.key_bytes_present && flags.key_bytes_length_valid
            && flags.decryption_succeeded && !flags.inner_parse_succeeded)
            ==> encrypted_decryption_spec(flags)
                == EncryptedDecryptionCore::RejectInnerParseFailed,
{
}

} // verus!
