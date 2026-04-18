//! Projection-decision enum, shared between bug_hunt (spec world) and the
//! apply-stage codecs (exec world).
//!
//! The grounded effect-policy invariant (Valid → writes, Block/Reject/
//! AlreadyProcessed → no writes) lives in
//! `state/projection/apply/projector_result_discipline.rs` as an `ensures` on
//! the exec fn `projector_result_well_formed`, which the runtime asserts after
//! every `dispatch_pure_projector` call. This file intentionally defines only
//! the enum types; the abstract effect-policy predicates that used to live here
//! were redundant with that grounded check and have been removed.

use vstd::prelude::*;

verus! {

/// Spec-world ProjectionDecision (uses `nat` for missing_count). Used by
/// `bug_hunt.rs` to model the abstract cascade / block behavior. The runtime
/// does not call this directly.
pub enum ProjectionDecision {
    Valid,
    Block { missing_count: nat },
    Reject,
    AlreadyProcessed,
}

/// Exec-friendly counterpart using `u32`. Used by
/// `state/projection/apply/context_loading.rs` and
/// `state/projection/apply/project_one.rs` as the return type of verified
/// exec fns that the runtime calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionDecisionCore {
    Valid,
    Block { missing_count: u32 },
    Reject,
    AlreadyProcessed,
}

} // verus!
