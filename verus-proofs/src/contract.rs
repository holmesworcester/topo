//! Formal verification of the ProjectorResult contract.

use vstd::prelude::*;
use crate::decision::*;

verus! {

/// The pure projector contract: decision + counts of write_ops and emit_commands.
/// We model counts rather than actual ops to avoid Seq derive issues.
pub struct ProjectorResult {
    pub decision: ProjectionDecision,
    pub write_ops_count: nat,
    pub emit_commands_count: nat,
}

// ─── Convenience constructors ───

pub open spec fn mk_valid(write_ops_count: nat) -> ProjectorResult {
    ProjectorResult {
        decision: ProjectionDecision::Valid,
        write_ops_count,
        emit_commands_count: 0,
    }
}

pub open spec fn mk_valid_with_commands(
    write_ops_count: nat,
    emit_commands_count: nat,
) -> ProjectorResult {
    ProjectorResult {
        decision: ProjectionDecision::Valid,
        write_ops_count,
        emit_commands_count,
    }
}

pub open spec fn mk_reject() -> ProjectorResult {
    ProjectorResult {
        decision: ProjectionDecision::Reject,
        write_ops_count: 0,
        emit_commands_count: 0,
    }
}

pub open spec fn mk_block(missing_count: nat) -> ProjectorResult {
    ProjectorResult {
        decision: ProjectionDecision::Block { missing_count },
        write_ops_count: 0,
        emit_commands_count: 0,
    }
}

pub open spec fn mk_already_processed() -> ProjectorResult {
    ProjectorResult {
        decision: ProjectionDecision::AlreadyProcessed,
        write_ops_count: 0,
        emit_commands_count: 0,
    }
}

// ─── Invariants ───

/// A well-formed ProjectorResult.
pub open spec fn result_is_well_formed(r: &ProjectorResult) -> bool {
    match r.decision {
        ProjectionDecision::Valid => true,
        ProjectionDecision::Block { .. } => r.write_ops_count == 0,
        ProjectionDecision::Reject => r.write_ops_count == 0 && r.emit_commands_count == 0,
        ProjectionDecision::AlreadyProcessed => r.write_ops_count == 0 && r.emit_commands_count == 0,
    }
}

// ═══════════════════════════════════════════════════════════════════
// Proofs
// ═══════════════════════════════════════════════════════════════════

proof fn proof_mk_valid_is_well_formed(ops: nat)
    ensures result_is_well_formed(&mk_valid(ops)),
{
}

proof fn proof_mk_valid_with_commands_is_well_formed(ops: nat, cmds: nat)
    ensures
        ({
            let r = mk_valid_with_commands(ops, cmds);
            matches!(r.decision, ProjectionDecision::Valid)
            && r.write_ops_count == ops
            && r.emit_commands_count == cmds
        }),
{
}

proof fn proof_mk_reject_is_well_formed()
    ensures
        ({
            let r = mk_reject();
            result_is_well_formed(&r)
            && r.write_ops_count == 0
            && r.emit_commands_count == 0
            && forbids_all_effects(&r.decision)
        }),
{
}

proof fn proof_mk_block_is_well_formed(missing: nat)
    ensures
        ({
            let r = mk_block(missing);
            result_is_well_formed(&r)
            && r.write_ops_count == 0
        }),
{
}

proof fn proof_mk_already_processed_is_well_formed()
    ensures
        ({
            let r = mk_already_processed();
            result_is_well_formed(&r)
            && r.write_ops_count == 0
            && r.emit_commands_count == 0
            && forbids_all_effects(&r.decision)
        }),
{
}

proof fn proof_well_formed_inert_has_no_effects(r: &ProjectorResult)
    requires result_is_well_formed(r) && forbids_all_effects(&r.decision)
    ensures r.write_ops_count == 0 && r.emit_commands_count == 0,
{
}

proof fn proof_well_formed_block_has_no_writes(r: &ProjectorResult)
    requires
        result_is_well_formed(r),
        matches!(r.decision, ProjectionDecision::Block { .. }),
    ensures r.write_ops_count == 0,
{
}

/// Critical: the apply engine's side-effect policy is safe.
proof fn proof_apply_engine_policy_is_safe(r: &ProjectorResult)
    requires result_is_well_formed(r)
    ensures
        (matches!(r.decision, ProjectionDecision::Valid) ==> requires_write_ops(&r.decision)),
        (matches!(r.decision, ProjectionDecision::Block { .. }) ==> (
            !requires_write_ops(&r.decision)
            && allows_emit_commands(&r.decision)
            && r.write_ops_count == 0
        )),
        (forbids_all_effects(&r.decision) ==> (
            r.write_ops_count == 0
            && r.emit_commands_count == 0
        )),
{
}

} // verus!
