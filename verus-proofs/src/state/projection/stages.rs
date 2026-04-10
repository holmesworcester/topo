//! Formal verification of context-load and projector-effect planning.

use vstd::prelude::*;

verus! {

pub enum ContextLoadDispositionRawRows {
    Ready,
    Block,
    Reject,
    Purge,
}

pub enum ContextLoadDispositionDecisionContext {
    Ready,
    Block,
    Reject,
    Purge,
}

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

pub open spec fn normalize_context_load_disposition(
    raw_rows: ContextLoadDispositionRawRows,
) -> ContextLoadDispositionDecisionContext {
    match raw_rows {
        ContextLoadDispositionRawRows::Ready => ContextLoadDispositionDecisionContext::Ready,
        ContextLoadDispositionRawRows::Block => ContextLoadDispositionDecisionContext::Block,
        ContextLoadDispositionRawRows::Reject => ContextLoadDispositionDecisionContext::Reject,
        ContextLoadDispositionRawRows::Purge => ContextLoadDispositionDecisionContext::Purge,
    }
}

pub open spec fn decide_context_load_disposition(
    context: ContextLoadDispositionDecisionContext,
) -> ContextLoadDispositionPlan {
    match context {
        ContextLoadDispositionDecisionContext::Ready => ContextLoadDispositionPlan::Continue,
        ContextLoadDispositionDecisionContext::Block => {
            ContextLoadDispositionPlan::RecordBlockAndReturn
        }
        ContextLoadDispositionDecisionContext::Reject => ContextLoadDispositionPlan::Reject,
        ContextLoadDispositionDecisionContext::Purge => {
            ContextLoadDispositionPlan::EmitHardPurgeAndReturn
        }
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

proof fn context_load_disposition_normalizer_preserves_query_facts()
    ensures
        normalize_context_load_disposition(ContextLoadDispositionRawRows::Ready)
            == ContextLoadDispositionDecisionContext::Ready,
        normalize_context_load_disposition(ContextLoadDispositionRawRows::Block)
            == ContextLoadDispositionDecisionContext::Block,
        normalize_context_load_disposition(ContextLoadDispositionRawRows::Reject)
            == ContextLoadDispositionDecisionContext::Reject,
        normalize_context_load_disposition(ContextLoadDispositionRawRows::Purge)
            == ContextLoadDispositionDecisionContext::Purge,
{
}

proof fn ready_context_continues_to_projector()
    ensures
        decide_context_load_disposition(normalize_context_load_disposition(
            ContextLoadDispositionRawRows::Ready,
        ))
            == ContextLoadDispositionPlan::Continue,
{
}

proof fn blocked_context_records_block_and_returns()
    ensures
        decide_context_load_disposition(normalize_context_load_disposition(
            ContextLoadDispositionRawRows::Block,
        ))
            == ContextLoadDispositionPlan::RecordBlockAndReturn,
{
}

proof fn purged_context_emits_only_hard_purge()
    ensures
        decide_context_load_disposition(normalize_context_load_disposition(
            ContextLoadDispositionRawRows::Purge,
        ))
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

proof fn valid_applies_write_ops_and_commands()
    ensures
        decide_projection_decision_effect_plan(ProjectionDecision::Valid)
            == ProjectionDecisionEffectPlan::ApplyWriteOpsAndEmitCommands,
{
}

} // verus!
