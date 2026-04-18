//! ProjectorResult well-formedness — verified discipline on projector outputs.
//!
//! Pure projectors return a `ProjectorResult { decision, write_ops, emit_commands, ... }`.
//! The rule: only `Valid` decisions may carry write_ops. `Block`, `Reject`, and
//! `AlreadyProcessed` must have an empty write_ops list — otherwise the apply path
//! would have to either silently drop those writes (violating "executors cannot exceed
//! their plan") or apply them anyway (violating block/reject semantics).
//!
//! The constructors in `src/state/projection/contract.rs` enforce this by construction,
//! but projectors can build a `ProjectorResult` via explicit field initialization and
//! subvert it. The runtime calls `assert_projector_result_well_formed` immediately
//! after `dispatch_pure_projector` — a malformed result panics at the dispatch
//! boundary, not downstream.

use vstd::prelude::*;

verus! {

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionDecisionKind {
    Valid,
    Block,
    Reject,
    AlreadyProcessed,
}

/// True iff the decision kind allows the given number of write_ops.
/// Only `Valid` may carry writes.
pub fn projector_result_well_formed(
    decision: ProjectionDecisionKind,
    write_op_count: u32,
) -> (ok: bool)
    ensures
        ok == match decision {
            ProjectionDecisionKind::Valid => true,
            ProjectionDecisionKind::Block
            | ProjectionDecisionKind::Reject
            | ProjectionDecisionKind::AlreadyProcessed => write_op_count == 0,
        },
{
    match decision {
        ProjectionDecisionKind::Valid => true,
        ProjectionDecisionKind::Block
        | ProjectionDecisionKind::Reject
        | ProjectionDecisionKind::AlreadyProcessed => write_op_count == 0,
    }
}

} // verus!
