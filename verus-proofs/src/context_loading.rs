//! Formal verification of the ContextLoadResult tri-state and
//! context loading phase properties.
//!
//! Context loading is the phase between dependency checking and projector
//! dispatch. It can:
//!   - Ready(ctx): proceed to pure projector with populated context
//!   - Block{missing}: event blocks on missing context (not deps)
//!   - Reject{reason}: event is rejected before projector runs
//!
//! This models the new ContextLoadResult introduced to allow context loaders
//! to short-circuit projection without running the pure projector.

use vstd::prelude::*;
use crate::decision::*;

verus! {

pub spec const ONE: nat = 1;
pub spec const TWO: nat = 2;

/// The tri-state result of context loading.
pub enum ContextLoadResult {
    Ready,
    Block { missing_count: nat },
    Reject,
}

/// Model of the apply_projection flow with ContextLoadResult:
///   1. Signer check (if required)
///   2. Context loading → may short-circuit
///   3. Pure projector dispatch
///   4. Side-effect execution
pub open spec fn apply_with_context_loading(
    signer_ok: bool,
    signer_required: bool,
    ctx_result: ContextLoadResult,
    projector_decision: ProjectionDecision,
) -> ProjectionDecision {
    if signer_required && !signer_ok {
        ProjectionDecision::Reject
    } else {
        match ctx_result {
            ContextLoadResult::Block { missing_count } =>
                ProjectionDecision::Block { missing_count },
            ContextLoadResult::Reject =>
                ProjectionDecision::Reject,
            ContextLoadResult::Ready =>
                projector_decision,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Context Loading Phase Proofs
// ═══════════════════════════════════════════════════════════════════

/// Proof: context Block prevents projector from running.
proof fn proof_context_block_prevents_projector()
    ensures
        ({
            let d = apply_with_context_loading(
                true, false, ContextLoadResult::Block { missing_count: ONE },
                ProjectionDecision::Valid,
            );
            matches!(d, ProjectionDecision::Block { .. })
        }),
{
}

/// Proof: context Reject prevents projector from running.
proof fn proof_context_reject_prevents_projector()
    ensures
        ({
            let d = apply_with_context_loading(
                true, false, ContextLoadResult::Reject,
                ProjectionDecision::Valid,
            );
            matches!(d, ProjectionDecision::Reject)
        }),
{
}

/// Proof: context Ready passes through to projector decision.
proof fn proof_context_ready_passes_through(projector_decision: ProjectionDecision)
    ensures
        apply_with_context_loading(true, false, ContextLoadResult::Ready, projector_decision)
            == projector_decision,
{
}

/// Proof: signer failure takes priority over context loading.
proof fn proof_signer_failure_overrides_context(ctx: ContextLoadResult, d: ProjectionDecision)
    ensures
        matches!(
            apply_with_context_loading(false, true, ctx, d),
            ProjectionDecision::Reject
        ),
{
}

/// Proof: signer check is skipped when not required.
proof fn proof_signer_skip_when_not_required(ctx: ContextLoadResult, d: ProjectionDecision)
    ensures
        apply_with_context_loading(false, false, ctx, d)
            == apply_with_context_loading(true, false, ctx, d),
{
}

/// Proof: the full pipeline check order is signer → context → projector.
/// Each earlier failure prevents later stages from executing.
proof fn proof_full_pipeline_check_order()
    ensures
        // Signer failure: context and projector don't matter
        matches!(apply_with_context_loading(false, true, ContextLoadResult::Ready, ProjectionDecision::Valid), ProjectionDecision::Reject),
        // Context block: projector doesn't matter
        matches!(apply_with_context_loading(true, true, ContextLoadResult::Block { missing_count: TWO }, ProjectionDecision::Valid), ProjectionDecision::Block { .. }),
        // Context reject: projector doesn't matter
        matches!(apply_with_context_loading(true, true, ContextLoadResult::Reject, ProjectionDecision::Valid), ProjectionDecision::Reject),
        // All pass: projector decision flows through
        matches!(apply_with_context_loading(true, true, ContextLoadResult::Ready, ProjectionDecision::Valid), ProjectionDecision::Valid),
{
}

// ═══════════════════════════════════════════════════════════════════
// Workspace Context Loading
// ═══════════════════════════════════════════════════════════════════

/// Model of workspace context loading:
///   - No accepted_workspace_id → Block (workspace not yet accepted)
///   - accepted_workspace_id != event_id → Reject (wrong workspace)
///   - accepted_workspace_id == event_id → Ready
pub open spec fn workspace_context_load(
    has_accepted_workspace: bool,
    workspace_matches_event: bool,
) -> ContextLoadResult {
    if !has_accepted_workspace {
        ContextLoadResult::Block { missing_count: ONE }
    } else if !workspace_matches_event {
        ContextLoadResult::Reject
    } else {
        ContextLoadResult::Ready
    }
}

proof fn proof_workspace_blocks_without_acceptance()
    ensures
        matches!(
            workspace_context_load(false, false),
            ContextLoadResult::Block { .. }
        ),
{
}

proof fn proof_workspace_rejects_wrong_workspace()
    ensures
        matches!(
            workspace_context_load(true, false),
            ContextLoadResult::Reject
        ),
{
}

proof fn proof_workspace_ready_on_match()
    ensures
        matches!(
            workspace_context_load(true, true),
            ContextLoadResult::Ready
        ),
{
}

// ═══════════════════════════════════════════════════════════════════
// Signer-User Mismatch Early Rejection
// ═══════════════════════════════════════════════════════════════════

/// Many context loaders reject early on signer_user_mismatch.
/// This models the pattern: if mismatch is detected during context loading,
/// return ContextLoadResult::Reject before the projector runs.
pub open spec fn content_event_context_load(
    has_signer_mismatch: bool,
) -> ContextLoadResult {
    if has_signer_mismatch {
        ContextLoadResult::Reject
    } else {
        ContextLoadResult::Ready
    }
}

/// Proof: signer mismatch in context loading always rejects,
/// regardless of what the projector would have decided.
proof fn proof_signer_mismatch_in_context_always_rejects(projector_decision: ProjectionDecision)
    ensures
        matches!(
            apply_with_context_loading(
                true, false,
                content_event_context_load(true),
                projector_decision,
            ),
            ProjectionDecision::Reject
        ),
{
}

/// Proof: no signer mismatch passes through to projector.
proof fn proof_no_signer_mismatch_passes_through(projector_decision: ProjectionDecision)
    ensures
        apply_with_context_loading(
            true, false,
            content_event_context_load(false),
            projector_decision,
        ) == projector_decision,
{
}

} // verus!
