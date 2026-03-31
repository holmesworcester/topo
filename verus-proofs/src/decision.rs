//! Formal verification of ProjectionDecision semantics.

use vstd::prelude::*;

verus! {

/// Model of ProjectionDecision — the four terminal states an event can reach.
/// We use simple int tags for missing deps count rather than Seq to avoid
/// derive issues with Verus ghost types.
pub enum ProjectionDecision {
    Valid,
    Block { missing_count: nat },
    Reject,
    AlreadyProcessed,
}

/// A decision is "permanently terminal" — the event will not be re-processed.
pub open spec fn is_permanently_terminal(d: &ProjectionDecision) -> bool {
    match d {
        ProjectionDecision::Valid => true,
        ProjectionDecision::Reject => true,
        ProjectionDecision::AlreadyProcessed => true,
        ProjectionDecision::Block { .. } => false,
    }
}

/// A decision requires write_ops execution.
pub open spec fn requires_write_ops(d: &ProjectionDecision) -> bool {
    match d {
        ProjectionDecision::Valid => true,
        _ => false,
    }
}

/// A decision allows emit_commands execution.
pub open spec fn allows_emit_commands(d: &ProjectionDecision) -> bool {
    match d {
        ProjectionDecision::Valid => true,
        ProjectionDecision::Block { .. } => true,
        _ => false,
    }
}

/// A decision forbids all side effects.
pub open spec fn forbids_all_effects(d: &ProjectionDecision) -> bool {
    match d {
        ProjectionDecision::Reject => true,
        ProjectionDecision::AlreadyProcessed => true,
        _ => false,
    }
}

// ═══════════════════════════════════════════════════════════════════
// Proofs
// ═══════════════════════════════════════════════════════════════════

/// Proof: every decision falls into exactly one effect-policy bucket.
proof fn proof_decision_categories_are_exhaustive_and_exclusive(d: &ProjectionDecision)
    ensures
        (requires_write_ops(d) && allows_emit_commands(d) && !forbids_all_effects(d))
        || (!requires_write_ops(d) && allows_emit_commands(d) && !forbids_all_effects(d))
        || (!requires_write_ops(d) && !allows_emit_commands(d) && forbids_all_effects(d)),
{
}

/// Proof: Valid is the only decision that triggers write_ops.
proof fn proof_only_valid_triggers_writes(d: &ProjectionDecision)
    ensures requires_write_ops(d) <==> matches!(*d, ProjectionDecision::Valid),
{
}

/// Proof: Reject and AlreadyProcessed forbid all effects.
proof fn proof_reject_and_already_processed_are_inert(d: &ProjectionDecision)
    ensures forbids_all_effects(d) <==> (
        matches!(*d, ProjectionDecision::Reject)
        || matches!(*d, ProjectionDecision::AlreadyProcessed)
    ),
{
}

/// Proof: Block decisions must carry missing dependency information.
proof fn proof_block_has_missing_deps(missing_count: nat)
    requires missing_count > 0
    ensures
        ({
            let d = ProjectionDecision::Block { missing_count };
            !is_permanently_terminal(&d) && allows_emit_commands(&d) && !requires_write_ops(&d)
        }),
{
}

/// Proof: write_ops implies emit_commands are also allowed.
proof fn proof_writes_imply_commands(d: &ProjectionDecision)
    ensures requires_write_ops(d) ==> allows_emit_commands(d),
{
}

/// Proof: forbids_all_effects implies permanently terminal.
proof fn proof_inert_implies_terminal(d: &ProjectionDecision)
    ensures forbids_all_effects(d) ==> is_permanently_terminal(d),
{
}

/// Proof: the effect policy partitions exactly cover all decisions.
proof fn proof_effect_policy_is_a_partition(d: &ProjectionDecision)
    ensures
        ({
            let w = requires_write_ops(d);
            let c = allows_emit_commands(d);
            let f = forbids_all_effects(d);
            (w && c && !f) || (!w && c && !f) || (!w && !c && f)
        }),
{
}

} // verus!
