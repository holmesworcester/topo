//! Verified core of the Removal projector's acceptance decision.
//!
//! `src/event_modules/removal.rs::project_pure` delegates its seven
//! structural checks to the primitive exec fn `decide_removal_acceptance_core`
//! below. Each runtime condition is projected to a primitive boolean; the
//! verified fn's body is a conjunction, and its `ensures` pins that conjunction
//! to a spec predicate. If a future runtime change adds, drops, or reorders
//! a check without updating the verified core, `cargo-verus verify` fails;
//! symmetrically, changing the verified body without updating the runtime's
//! primitive-flag computation fails `cargo test -j1 --lib event_modules::removal::`.

use vstd::prelude::*;

verus! {

/// Reason-tagged reject outcome. Runtime maps these to the concrete reject
/// strings; the verified decision logic cares only about *which* rule fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemovalDecisionCore {
    Valid,
    RejectNoCurrentSigner,
    RejectRemovedByMismatch,
    RejectSignerItselfRejected,
    RejectFrontierRefsMalformed,
    RejectFrontierRefsNotCanonical,
    RejectFrontierHashMismatch,
    RejectTargetKindUnknown,
}

/// Primitive inputs — what the runtime has at project-time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemovalAcceptanceInputs {
    /// `ctx.current_signer.is_some()`
    pub has_current_signer: bool,
    /// `removal.removed_by == current_signer.event_id` (byte-equality on [u8;32])
    pub removed_by_matches_signer: bool,
    /// `ctx.removal_signer_reject_reason.is_none()`
    pub signer_not_rejected: bool,
    /// `frontier_refs_from_slots(parent_count, slots).is_ok()`
    pub frontier_refs_well_formed: bool,
    /// `validate_canonical_frontier_refs(refs).is_ok()`
    pub frontier_refs_canonical: bool,
    /// `frontier_hash_from_refs(refs) == removal.frontier_hash`
    pub frontier_hash_matches: bool,
    /// `ctx.removal_target_kind.is_some()`
    pub target_kind_present: bool,
}

/// Spec predicate: what does it mean for a Removal to be accepted?
/// The ordering here defines precedence of reject reasons, matching the
/// runtime's early-return structure.
pub open spec fn removal_accepts_spec(inputs: RemovalAcceptanceInputs) -> RemovalDecisionCore {
    if !inputs.has_current_signer {
        RemovalDecisionCore::RejectNoCurrentSigner
    } else if !inputs.removed_by_matches_signer {
        RemovalDecisionCore::RejectRemovedByMismatch
    } else if !inputs.signer_not_rejected {
        RemovalDecisionCore::RejectSignerItselfRejected
    } else if !inputs.frontier_refs_well_formed {
        RemovalDecisionCore::RejectFrontierRefsMalformed
    } else if !inputs.frontier_refs_canonical {
        RemovalDecisionCore::RejectFrontierRefsNotCanonical
    } else if !inputs.frontier_hash_matches {
        RemovalDecisionCore::RejectFrontierHashMismatch
    } else if !inputs.target_kind_present {
        RemovalDecisionCore::RejectTargetKindUnknown
    } else {
        RemovalDecisionCore::Valid
    }
}

/// Runtime-callable verified decision. Runtime extracts the seven primitive
/// flags from its rich inputs and calls this; the returned enum drives the
/// ProjectorResult::valid vs ::reject choice. Ensures pins behavior to
/// `removal_accepts_spec` — changing either side without the other fails SMT.
pub fn decide_removal_acceptance_core(
    inputs: RemovalAcceptanceInputs,
) -> (out: RemovalDecisionCore)
    ensures out == removal_accepts_spec(inputs),
{
    if !inputs.has_current_signer {
        RemovalDecisionCore::RejectNoCurrentSigner
    } else if !inputs.removed_by_matches_signer {
        RemovalDecisionCore::RejectRemovedByMismatch
    } else if !inputs.signer_not_rejected {
        RemovalDecisionCore::RejectSignerItselfRejected
    } else if !inputs.frontier_refs_well_formed {
        RemovalDecisionCore::RejectFrontierRefsMalformed
    } else if !inputs.frontier_refs_canonical {
        RemovalDecisionCore::RejectFrontierRefsNotCanonical
    } else if !inputs.frontier_hash_matches {
        RemovalDecisionCore::RejectFrontierHashMismatch
    } else if !inputs.target_kind_present {
        RemovalDecisionCore::RejectTargetKindUnknown
    } else {
        RemovalDecisionCore::Valid
    }
}

// ---------------------------------------------------------------------------
// Structural invariants about the decision — SMT-proven.

/// Valid is reached ONLY when every flag is true. This is the
/// "revocation safety precondition" theorem: an accepted Removal
/// necessarily passed all seven checks.
pub proof fn valid_requires_all_flags_true(inputs: RemovalAcceptanceInputs)
    ensures
        removal_accepts_spec(inputs) == RemovalDecisionCore::Valid
            ==> inputs.has_current_signer
                && inputs.removed_by_matches_signer
                && inputs.signer_not_rejected
                && inputs.frontier_refs_well_formed
                && inputs.frontier_refs_canonical
                && inputs.frontier_hash_matches
                && inputs.target_kind_present,
{
}

/// If any flag is false, Valid is not returned. Contrapositive of above.
pub proof fn any_false_flag_rejects(inputs: RemovalAcceptanceInputs)
    ensures
        (!inputs.has_current_signer
            || !inputs.removed_by_matches_signer
            || !inputs.signer_not_rejected
            || !inputs.frontier_refs_well_formed
            || !inputs.frontier_refs_canonical
            || !inputs.frontier_hash_matches
            || !inputs.target_kind_present)
            ==> removal_accepts_spec(inputs) != RemovalDecisionCore::Valid,
{
}

// ---------------------------------------------------------------------------
// Step 2: write-op structural invariant.
//
// When acceptance is Valid, the runtime emits exactly TWO write ops:
// one to `removals`, one to `removed_entities`. The table names and column
// counts are pinned below; the verified count function `required_valid_write_op_count`
// enforces "exactly 2" at the verified boundary, and `required_removal_op_tables`
// pins the table names.

/// Count of write ops produced for a Valid removal.
pub open spec fn required_valid_write_op_count_spec(decision: RemovalDecisionCore) -> nat {
    if decision == RemovalDecisionCore::Valid { 2 } else { 0 }
}

pub fn required_valid_write_op_count(decision: RemovalDecisionCore) -> (n: u8)
    ensures
        n as nat == required_valid_write_op_count_spec(decision),
        decision == RemovalDecisionCore::Valid ==> n == 2,
        decision != RemovalDecisionCore::Valid ==> n == 0,
{
    match decision {
        RemovalDecisionCore::Valid => 2,
        _ => 0,
    }
}

/// Pinned table names for the two Valid write ops, in order.
/// Index 0 = `removals`, index 1 = `removed_entities`.
pub open spec fn required_removal_op_table_spec(index: u8) -> &'static str {
    if index == 0 { "removals" }
    else if index == 1 { "removed_entities" }
    else { "" }
}

pub fn required_removal_op_table(index: u8) -> (name: &'static str)
    ensures name == required_removal_op_table_spec(index),
{
    match index {
        0 => "removals",
        1 => "removed_entities",
        _ => "",
    }
}

/// Pinned column count per Valid write op. The `removals` write has 10
/// columns; the `removed_entities` write has 4. Enforces schema stability
/// at the verified boundary.
pub open spec fn required_removal_op_column_count_spec(index: u8) -> nat {
    if index == 0 { 10 }
    else if index == 1 { 4 }
    else { 0 }
}

pub fn required_removal_op_column_count(index: u8) -> (n: u8)
    ensures n as nat == required_removal_op_column_count_spec(index),
{
    match index {
        0 => 10,
        1 => 4,
        _ => 0,
    }
}

/// Reject reason precedence matches the runtime's early-return structure:
/// the first-false flag determines the reject variant. Locks the reason
/// ordering into the proof, so reordering runtime checks without updating
/// the spec fails SMT.
pub proof fn reject_reason_precedence(inputs: RemovalAcceptanceInputs)
    ensures
        !inputs.has_current_signer
            ==> removal_accepts_spec(inputs) == RemovalDecisionCore::RejectNoCurrentSigner,
        (inputs.has_current_signer && !inputs.removed_by_matches_signer)
            ==> removal_accepts_spec(inputs) == RemovalDecisionCore::RejectRemovedByMismatch,
        (inputs.has_current_signer && inputs.removed_by_matches_signer
            && !inputs.signer_not_rejected)
            ==> removal_accepts_spec(inputs) == RemovalDecisionCore::RejectSignerItselfRejected,
{
}

} // verus!
