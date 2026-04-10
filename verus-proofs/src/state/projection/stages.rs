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

pub enum ProjectionDecisionEffectRawRows {
    Valid,
    Block,
    Reject,
    AlreadyProcessed,
}

pub enum ProjectionDecisionEffectDecisionContext {
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

pub struct ProjectionEffectAllowance {
    pub allow_write_ops: bool,
    pub allow_emit_commands: bool,
    pub allow_record_block: bool,
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

pub open spec fn normalize_projection_decision_effect_context(
    raw_rows: ProjectionDecisionEffectRawRows,
) -> ProjectionDecisionEffectDecisionContext {
    match raw_rows {
        ProjectionDecisionEffectRawRows::Valid => ProjectionDecisionEffectDecisionContext::Valid,
        ProjectionDecisionEffectRawRows::Block => ProjectionDecisionEffectDecisionContext::Block,
        ProjectionDecisionEffectRawRows::Reject => ProjectionDecisionEffectDecisionContext::Reject,
        ProjectionDecisionEffectRawRows::AlreadyProcessed => {
            ProjectionDecisionEffectDecisionContext::AlreadyProcessed
        }
    }
}

pub open spec fn decide_projection_decision_effect_plan(
    context: ProjectionDecisionEffectDecisionContext,
) -> ProjectionDecisionEffectPlan {
    match context {
        ProjectionDecisionEffectDecisionContext::Valid => {
            ProjectionDecisionEffectPlan::ApplyWriteOpsAndEmitCommands
        }
        ProjectionDecisionEffectDecisionContext::Block => {
            ProjectionDecisionEffectPlan::EmitCommandsOnly
        }
        ProjectionDecisionEffectDecisionContext::Reject
        | ProjectionDecisionEffectDecisionContext::AlreadyProcessed => {
            ProjectionDecisionEffectPlan::NoEffects
        }
    }
}

pub open spec fn projection_effect_allowance(
    plan: ProjectionDecisionEffectPlan,
) -> ProjectionEffectAllowance {
    match plan {
        ProjectionDecisionEffectPlan::ApplyWriteOpsAndEmitCommands => ProjectionEffectAllowance {
            allow_write_ops: true,
            allow_emit_commands: true,
            allow_record_block: false,
        },
        ProjectionDecisionEffectPlan::EmitCommandsOnly => ProjectionEffectAllowance {
            allow_write_ops: false,
            allow_emit_commands: true,
            allow_record_block: true,
        },
        ProjectionDecisionEffectPlan::NoEffects => ProjectionEffectAllowance {
            allow_write_ops: false,
            allow_emit_commands: false,
            allow_record_block: false,
        },
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

proof fn projection_decision_effect_normalizer_preserves_query_facts()
    ensures
        normalize_projection_decision_effect_context(ProjectionDecisionEffectRawRows::Valid)
            == ProjectionDecisionEffectDecisionContext::Valid,
        normalize_projection_decision_effect_context(ProjectionDecisionEffectRawRows::Block)
            == ProjectionDecisionEffectDecisionContext::Block,
        normalize_projection_decision_effect_context(ProjectionDecisionEffectRawRows::Reject)
            == ProjectionDecisionEffectDecisionContext::Reject,
        normalize_projection_decision_effect_context(
            ProjectionDecisionEffectRawRows::AlreadyProcessed,
        ) == ProjectionDecisionEffectDecisionContext::AlreadyProcessed,
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
        decide_projection_decision_effect_plan(normalize_projection_decision_effect_context(
            ProjectionDecisionEffectRawRows::Reject,
        ))
            == ProjectionDecisionEffectPlan::NoEffects,
        decide_projection_decision_effect_plan(normalize_projection_decision_effect_context(
            ProjectionDecisionEffectRawRows::AlreadyProcessed,
        ))
            == ProjectionDecisionEffectPlan::NoEffects,
{
}

proof fn reject_and_already_processed_allow_no_executor_effects()
    ensures
        projection_effect_allowance(decide_projection_decision_effect_plan(
            normalize_projection_decision_effect_context(ProjectionDecisionEffectRawRows::Reject),
        )) == (ProjectionEffectAllowance {
            allow_write_ops: false,
            allow_emit_commands: false,
            allow_record_block: false,
        }),
        projection_effect_allowance(decide_projection_decision_effect_plan(
            normalize_projection_decision_effect_context(
                ProjectionDecisionEffectRawRows::AlreadyProcessed,
            ),
        )) == (ProjectionEffectAllowance {
            allow_write_ops: false,
            allow_emit_commands: false,
            allow_record_block: false,
        }),
{
}

proof fn valid_applies_write_ops_and_commands()
    ensures
        decide_projection_decision_effect_plan(normalize_projection_decision_effect_context(
            ProjectionDecisionEffectRawRows::Valid,
        ))
            == ProjectionDecisionEffectPlan::ApplyWriteOpsAndEmitCommands,
{
}

proof fn block_decision_never_allows_write_ops()
    ensures
        projection_effect_allowance(decide_projection_decision_effect_plan(
            normalize_projection_decision_effect_context(ProjectionDecisionEffectRawRows::Block),
        )) == (ProjectionEffectAllowance {
            allow_write_ops: false,
            allow_emit_commands: true,
            allow_record_block: true,
        }),
{
}

proof fn valid_decision_allows_write_ops_and_commands_only()
    ensures
        projection_effect_allowance(decide_projection_decision_effect_plan(
            normalize_projection_decision_effect_context(ProjectionDecisionEffectRawRows::Valid),
        )) == (ProjectionEffectAllowance {
            allow_write_ops: true,
            allow_emit_commands: true,
            allow_record_block: false,
        }),
{
}

} // verus!
