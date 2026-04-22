//! Verified core of the KeyShared projector's acceptance decision.
//!
//! `src/event_modules/key_shared.rs::project_pure` delegates its structural
//! acceptance checks to the verified core below. The projector additionally
//! decides (separately) whether to emit the `key_secrets` row based on
//! whether `ctx.unwrapped_secret_material` is present — that's the
//! access-control bridge: a KeyShared event may be Valid for recording,
//! but it only materializes the content key for THIS peer if the key was
//! wrapped for THIS peer's unwrap identity.
//!
//! Chain position: downstream of PeerShared, upstream of Encrypted.
//!   - KeyShared is Valid ⟹ the wrapper's frontier and delivery target are
//!     well-formed. This is the structural gate.
//!   - KeyShared materializes a key_secrets row for this peer ⟺ THIS peer's
//!     unwrap key successfully decrypted the wrapped key. This is the
//!     access-control gate.
//!
//! The second gate is what prevents non-invited peers from obtaining content
//! keys: `ctx.unwrapped_secret_material` is computed by the context loader
//! using THIS peer's unwrap key on the KeyShared's wrapped_key; it's
//! Some only if the unwrap succeeds.

use vstd::prelude::*;

verus! {

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySharedAcceptanceCore {
    Valid,
    RejectFrontierRefsMalformed,
    RejectFrontierRefsNotCanonical,
    RejectFrontierHashMismatch,
    RejectDeliveryTargetMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeySharedAcceptanceFlags {
    /// `frontier_refs_from_slots(count, slots).is_ok()`
    pub frontier_refs_well_formed: bool,
    /// `validate_canonical_frontier_refs(refs).is_ok()`
    pub frontier_refs_canonical: bool,
    /// `frontier_hash_from_refs(refs) == ss.frontier_hash`
    pub frontier_hash_matches: bool,
    /// `delivery_target_id(key_event_id, frontier_hash, recipient, unwrap)
    ///   == ss.delivery_target_id`
    pub delivery_target_matches: bool,
}

pub open spec fn key_shared_accepts_spec(
    flags: KeySharedAcceptanceFlags,
) -> KeySharedAcceptanceCore {
    if !flags.frontier_refs_well_formed {
        KeySharedAcceptanceCore::RejectFrontierRefsMalformed
    } else if !flags.frontier_refs_canonical {
        KeySharedAcceptanceCore::RejectFrontierRefsNotCanonical
    } else if !flags.frontier_hash_matches {
        KeySharedAcceptanceCore::RejectFrontierHashMismatch
    } else if !flags.delivery_target_matches {
        KeySharedAcceptanceCore::RejectDeliveryTargetMismatch
    } else {
        KeySharedAcceptanceCore::Valid
    }
}

pub fn decide_key_shared_acceptance_core(
    flags: KeySharedAcceptanceFlags,
) -> (out: KeySharedAcceptanceCore)
    ensures out == key_shared_accepts_spec(flags),
{
    if !flags.frontier_refs_well_formed {
        KeySharedAcceptanceCore::RejectFrontierRefsMalformed
    } else if !flags.frontier_refs_canonical {
        KeySharedAcceptanceCore::RejectFrontierRefsNotCanonical
    } else if !flags.frontier_hash_matches {
        KeySharedAcceptanceCore::RejectFrontierHashMismatch
    } else if !flags.delivery_target_matches {
        KeySharedAcceptanceCore::RejectDeliveryTargetMismatch
    } else {
        KeySharedAcceptanceCore::Valid
    }
}

/// Valid ⟹ all four structural flags hold.
pub proof fn valid_requires_all_structural_flags(flags: KeySharedAcceptanceFlags)
    ensures
        key_shared_accepts_spec(flags) == KeySharedAcceptanceCore::Valid
            ==> flags.frontier_refs_well_formed
                && flags.frontier_refs_canonical
                && flags.frontier_hash_matches
                && flags.delivery_target_matches,
{
}

/// Contrapositive for composition.
pub proof fn any_structural_flag_false_rejects(flags: KeySharedAcceptanceFlags)
    ensures
        (!flags.frontier_refs_well_formed
            || !flags.frontier_refs_canonical
            || !flags.frontier_hash_matches
            || !flags.delivery_target_matches)
            ==> key_shared_accepts_spec(flags) != KeySharedAcceptanceCore::Valid,
{
}

/// Reject reason precedence.
pub proof fn reject_reason_precedence(flags: KeySharedAcceptanceFlags)
    ensures
        !flags.frontier_refs_well_formed
            ==> key_shared_accepts_spec(flags)
                == KeySharedAcceptanceCore::RejectFrontierRefsMalformed,
        (flags.frontier_refs_well_formed && !flags.frontier_refs_canonical)
            ==> key_shared_accepts_spec(flags)
                == KeySharedAcceptanceCore::RejectFrontierRefsNotCanonical,
        (flags.frontier_refs_well_formed && flags.frontier_refs_canonical
            && !flags.frontier_hash_matches)
            ==> key_shared_accepts_spec(flags)
                == KeySharedAcceptanceCore::RejectFrontierHashMismatch,
        (flags.frontier_refs_well_formed && flags.frontier_refs_canonical
            && flags.frontier_hash_matches && !flags.delivery_target_matches)
            ==> key_shared_accepts_spec(flags)
                == KeySharedAcceptanceCore::RejectDeliveryTargetMismatch,
{
}

// ---------------------------------------------------------------------------
// Access-control gate: materialize key_secrets iff peer unwrapped successfully.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySecretsMaterializationCore {
    EmitKeySecretsRow,
    SkipKeySecretsRow,
}

/// Decides whether the KeyShared projector emits the key_secrets row.
/// Exactly and only when this peer's unwrap key decrypted the wrapper.
pub open spec fn key_secrets_materialization_spec(
    unwrap_successful_for_this_peer: bool,
) -> KeySecretsMaterializationCore {
    if unwrap_successful_for_this_peer {
        KeySecretsMaterializationCore::EmitKeySecretsRow
    } else {
        KeySecretsMaterializationCore::SkipKeySecretsRow
    }
}

pub fn decide_key_secrets_materialization_core(
    unwrap_successful_for_this_peer: bool,
) -> (out: KeySecretsMaterializationCore)
    ensures out == key_secrets_materialization_spec(unwrap_successful_for_this_peer),
{
    if unwrap_successful_for_this_peer {
        KeySecretsMaterializationCore::EmitKeySecretsRow
    } else {
        KeySecretsMaterializationCore::SkipKeySecretsRow
    }
}

/// THE ACCESS-CONTROL THEOREM for this seam:
/// A key_secrets row is emitted ONLY when the wrapper was successfully
/// unwrapped by THIS peer. Contrapositive: a peer that cannot unwrap
/// (because it doesn't have the right invite-derived identity) gets NO
/// key_secrets row, so downstream Encrypted decryption blocks.
pub proof fn emit_requires_successful_unwrap(unwrap_successful_for_this_peer: bool)
    ensures
        key_secrets_materialization_spec(unwrap_successful_for_this_peer)
            == KeySecretsMaterializationCore::EmitKeySecretsRow
            ==> unwrap_successful_for_this_peer,
{
}

pub proof fn no_unwrap_means_skip(unwrap_successful_for_this_peer: bool)
    ensures
        !unwrap_successful_for_this_peer
            ==> key_secrets_materialization_spec(unwrap_successful_for_this_peer)
                == KeySecretsMaterializationCore::SkipKeySecretsRow,
{
}

// ---------------------------------------------------------------------------
// Composed write-op count invariant: Valid + emit = 2 ops, Valid + skip = 1 op.

pub open spec fn required_valid_write_op_count_spec(
    acceptance: KeySharedAcceptanceCore,
    materialization: KeySecretsMaterializationCore,
) -> nat {
    if acceptance != KeySharedAcceptanceCore::Valid { 0 }
    else if materialization == KeySecretsMaterializationCore::EmitKeySecretsRow { 2 }
    else { 1 }
}

pub fn required_valid_write_op_count(
    acceptance: KeySharedAcceptanceCore,
    materialization: KeySecretsMaterializationCore,
) -> (n: u8)
    ensures n as nat == required_valid_write_op_count_spec(acceptance, materialization),
{
    match (acceptance, materialization) {
        (KeySharedAcceptanceCore::Valid, KeySecretsMaterializationCore::EmitKeySecretsRow) => 2,
        (KeySharedAcceptanceCore::Valid, KeySecretsMaterializationCore::SkipKeySecretsRow) => 1,
        _ => 0,
    }
}

} // verus!
