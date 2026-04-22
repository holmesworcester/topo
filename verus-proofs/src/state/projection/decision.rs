//! Projection-decision enum used by `bug_hunt.rs` to model known-bug
//! counterexamples. The runtime's `ProjectionDecision` lives in
//! `src/state/projection/decision.rs` with richer payloads
//! (`String` reasons, `Vec<EventId>` missing lists); the Verus copy here
//! uses `nat` for missing counts so specs can reason abstractly.
//!
//! The grounded effect-policy invariant (Valid → writes, Block/Reject/
//! AlreadyProcessed → no writes) lives in
//! `state/projection/apply/projector_result_discipline.rs` as an `ensures`
//! on the exec fn `projector_result_well_formed`, which the runtime asserts
//! after every `dispatch_pure_projector` call. This file defines ONLY the
//! spec-world enum for bug_hunt; prior exec-world `*Core` models were
//! parallel abstractions without runtime callers and have been removed.

use vstd::prelude::*;

verus! {

/// Spec-world ProjectionDecision (uses `nat` for missing_count). Used by
/// `bug_hunt.rs` to model the abstract cascade / block behavior. The
/// runtime does not call this directly — the runtime's concrete
/// `ProjectionDecision` carries richer payloads.
pub enum ProjectionDecision {
    Valid,
    Block { missing_count: nat },
    Reject,
    AlreadyProcessed,
}

} // verus!
