//! Formal verification of the ContextLoadResult outcomes and
//! context loading phase properties.
//!
//! Context loading is the phase between dependency checking and projector
//! dispatch. It can:
//!   - Ready(ctx): proceed to pure projector with populated context
//!   - Block{missing}: event blocks on missing context (not deps)
//!   - Reject{reason}: event is rejected before projector runs
//!   - Purge{message_event_id}: emit hard-purge command and return without projector
//!
//! This models the new ContextLoadResult introduced to allow context loaders
//! to short-circuit projection without running the pure projector.
//!
//! Every `pub fn` below is an executable Rust abstract model of the corresponding
//! runtime composition in `src/state/projection/apply/stages.rs`. Postconditions
//! (`ensures`) are SMT-checked against the function body by `cargo-verus verify`.

use crate::state::projection::decision::*;
use vstd::prelude::*;

verus! {

pub const ONE: u32 = 1;
pub const TWO: u32 = 2;

/// The result of context loading (primitive-only Verus model).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextLoadResultCore {
    Ready,
    Block { missing_count: u32 },
    Reject,
    Purge,
}

/// Executable model of the apply_projection flow with ContextLoadResult:
///   1. Signer check (if required)
///   2. Context loading → may short-circuit
///   3. Pure projector dispatch
///   4. Side-effect execution
pub fn apply_with_context_loading(
    signer_ok: bool,
    signer_required: bool,
    ctx_result: ContextLoadResultCore,
    projector_decision: ProjectionDecisionCore,
) -> (decision: ProjectionDecisionCore)
    ensures
        (signer_required && !signer_ok) ==> decision == ProjectionDecisionCore::Reject,
        !(signer_required && !signer_ok) ==> match ctx_result {
            ContextLoadResultCore::Block { missing_count } =>
                decision == (ProjectionDecisionCore::Block { missing_count }),
            ContextLoadResultCore::Reject => decision == ProjectionDecisionCore::Reject,
            ContextLoadResultCore::Purge => decision == ProjectionDecisionCore::Valid,
            ContextLoadResultCore::Ready => decision == projector_decision,
        },
{
    if signer_required && !signer_ok {
        ProjectionDecisionCore::Reject
    } else {
        match ctx_result {
            ContextLoadResultCore::Block { missing_count } =>
                ProjectionDecisionCore::Block { missing_count },
            ContextLoadResultCore::Reject => ProjectionDecisionCore::Reject,
            ContextLoadResultCore::Purge => ProjectionDecisionCore::Valid,
            ContextLoadResultCore::Ready => projector_decision,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Workspace Context Loading
// ═══════════════════════════════════════════════════════════════════

/// Executable model of workspace context loading:
///   - No accepted_workspace_id → Block (workspace not yet accepted)
///   - accepted_workspace_id != event_id → Reject (wrong workspace)
///   - accepted_workspace_id == event_id → Ready
pub fn workspace_context_load(
    has_accepted_workspace: bool,
    workspace_matches_event: bool,
) -> (result: ContextLoadResultCore)
    ensures
        !has_accepted_workspace ==> result == (ContextLoadResultCore::Block { missing_count: ONE }),
        (has_accepted_workspace && !workspace_matches_event)
            ==> result == ContextLoadResultCore::Reject,
        (has_accepted_workspace && workspace_matches_event)
            ==> result == ContextLoadResultCore::Ready,
{
    if !has_accepted_workspace {
        ContextLoadResultCore::Block { missing_count: ONE }
    } else if !workspace_matches_event {
        ContextLoadResultCore::Reject
    } else {
        ContextLoadResultCore::Ready
    }
}

// ═══════════════════════════════════════════════════════════════════
// Signer-User Mismatch Early Rejection
// ═══════════════════════════════════════════════════════════════════

/// Many context loaders reject early on signer_user_mismatch.
/// This executable model captures the pattern: if mismatch is detected during
/// context loading, return ContextLoadResultCore::Reject before the projector runs.
pub fn content_event_context_load(
    has_signer_mismatch: bool,
) -> (result: ContextLoadResultCore)
    ensures
        has_signer_mismatch ==> result == ContextLoadResultCore::Reject,
        !has_signer_mismatch ==> result == ContextLoadResultCore::Ready,
{
    if has_signer_mismatch {
        ContextLoadResultCore::Reject
    } else {
        ContextLoadResultCore::Ready
    }
}

} // verus!
