//! Formal verification of context-load and projector-effect planning.

use vstd::prelude::*;

verus! {

pub enum ContextLoadDispositionPlan {
    Continue,
    RecordBlockAndReturn,
    Reject,
    EmitHardPurgeAndReturn,
}

pub enum ProjectionDecision {
    Valid,
    Block,
    Reject,
    AlreadyProcessed,
}

pub enum ProjectionDecisionEffectPlan {
    ApplyWriteOpsAndEmitCommands,
    EmitCommandsOnly,
    NoEffects,
}

pub open spec fn decide_context_load_disposition(
    context_ready: bool,
    context_blocked: bool,
    context_rejected: bool,
    context_purged: bool,
) -> ContextLoadDispositionPlan {
    if context_ready {
        ContextLoadDispositionPlan::Continue
    } else if context_blocked {
        ContextLoadDispositionPlan::RecordBlockAndReturn
    } else if context_rejected {
        ContextLoadDispositionPlan::Reject
    } else {
        let _ = context_purged;
        ContextLoadDispositionPlan::EmitHardPurgeAndReturn
    }
}

pub open spec fn decide_projection_decision_effect_plan(
    decision: ProjectionDecision,
) -> ProjectionDecisionEffectPlan {
    match decision {
        ProjectionDecision::Valid => ProjectionDecisionEffectPlan::ApplyWriteOpsAndEmitCommands,
        ProjectionDecision::Block => ProjectionDecisionEffectPlan::EmitCommandsOnly,
        ProjectionDecision::Reject | ProjectionDecision::AlreadyProcessed => {
            ProjectionDecisionEffectPlan::NoEffects
        }
    }
}

proof fn blocked_context_records_block_and_returns()
    ensures
        decide_context_load_disposition(false, true, false, false)
            == ContextLoadDispositionPlan::RecordBlockAndReturn,
{
}

proof fn purged_context_emits_only_hard_purge()
    ensures
        decide_context_load_disposition(false, false, false, true)
            == ContextLoadDispositionPlan::EmitHardPurgeAndReturn,
{
}

proof fn reject_and_already_processed_have_no_effects()
    ensures
        decide_projection_decision_effect_plan(ProjectionDecision::Reject)
            == ProjectionDecisionEffectPlan::NoEffects,
        decide_projection_decision_effect_plan(ProjectionDecision::AlreadyProcessed)
            == ProjectionDecisionEffectPlan::NoEffects,
{
}

} // verus!
