//! Formal verification of context-load and projector-effect planning.
//!
//! Every `pub fn` below is an executable Rust core consumed by
//! `src/state/projection/apply/stages.rs`. Postconditions (`ensures`) are SMT-checked
//! against the function body by `cargo-verus verify`.
//!
//! Runtime carries rich variants like `Block { missing: Vec<EventId> }` and
//! `Reject { reason: String }`. This Verus core reduces each state/plan/raw
//! variant to a payload-less tag. The runtime wraps the core by projecting its
//! concrete payloads to tags, calling the verified dispatcher, and rehydrating
//! the original payloads in the output plan.

use vstd::prelude::*;

verus! {

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextLoadDispositionRawRowsCore {
    Ready,
    Block,
    Reject,
    Purge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextLoadDispositionDecisionContextCore {
    Ready,
    Block,
    Reject,
    Purge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextLoadDispositionPlanCore {
    Continue,
    RecordBlockAndReturn,
    Reject,
    EmitHardPurgeAndReturn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionDecisionCore {
    Valid,
    Block,
    Reject,
    AlreadyProcessed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionDecisionEffectRawRowsCore {
    Valid,
    Block,
    Reject,
    AlreadyProcessed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionDecisionEffectDecisionContextCore {
    Valid,
    Block,
    Reject,
    AlreadyProcessed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionDecisionEffectPlanCore {
    ApplyWriteOpsAndEmitCommands,
    EmitCommandsOnly,
    NoEffects,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectionEffectAllowanceCore {
    pub allow_write_ops: bool,
    pub allow_emit_commands: bool,
    pub allow_record_block: bool,
}

pub fn normalize_context_load_disposition_core(
    raw_rows: ContextLoadDispositionRawRowsCore,
) -> (context: ContextLoadDispositionDecisionContextCore)
    ensures
        raw_rows == ContextLoadDispositionRawRowsCore::Ready
            ==> context == ContextLoadDispositionDecisionContextCore::Ready,
        raw_rows == ContextLoadDispositionRawRowsCore::Block
            ==> context == ContextLoadDispositionDecisionContextCore::Block,
        raw_rows == ContextLoadDispositionRawRowsCore::Reject
            ==> context == ContextLoadDispositionDecisionContextCore::Reject,
        raw_rows == ContextLoadDispositionRawRowsCore::Purge
            ==> context == ContextLoadDispositionDecisionContextCore::Purge,
{
    match raw_rows {
        ContextLoadDispositionRawRowsCore::Ready => ContextLoadDispositionDecisionContextCore::Ready,
        ContextLoadDispositionRawRowsCore::Block => ContextLoadDispositionDecisionContextCore::Block,
        ContextLoadDispositionRawRowsCore::Reject => ContextLoadDispositionDecisionContextCore::Reject,
        ContextLoadDispositionRawRowsCore::Purge => ContextLoadDispositionDecisionContextCore::Purge,
    }
}

pub fn decide_context_load_disposition_core(
    context: ContextLoadDispositionDecisionContextCore,
) -> (plan: ContextLoadDispositionPlanCore)
    ensures
        context == ContextLoadDispositionDecisionContextCore::Ready
            ==> plan == ContextLoadDispositionPlanCore::Continue,
        context == ContextLoadDispositionDecisionContextCore::Block
            ==> plan == ContextLoadDispositionPlanCore::RecordBlockAndReturn,
        context == ContextLoadDispositionDecisionContextCore::Reject
            ==> plan == ContextLoadDispositionPlanCore::Reject,
        context == ContextLoadDispositionDecisionContextCore::Purge
            ==> plan == ContextLoadDispositionPlanCore::EmitHardPurgeAndReturn,
{
    match context {
        ContextLoadDispositionDecisionContextCore::Ready => ContextLoadDispositionPlanCore::Continue,
        ContextLoadDispositionDecisionContextCore::Block => {
            ContextLoadDispositionPlanCore::RecordBlockAndReturn
        }
        ContextLoadDispositionDecisionContextCore::Reject => ContextLoadDispositionPlanCore::Reject,
        ContextLoadDispositionDecisionContextCore::Purge => {
            ContextLoadDispositionPlanCore::EmitHardPurgeAndReturn
        }
    }
}

pub fn normalize_projection_decision_effect_context_core(
    raw_rows: ProjectionDecisionEffectRawRowsCore,
) -> (context: ProjectionDecisionEffectDecisionContextCore)
    ensures
        raw_rows == ProjectionDecisionEffectRawRowsCore::Valid
            ==> context == ProjectionDecisionEffectDecisionContextCore::Valid,
        raw_rows == ProjectionDecisionEffectRawRowsCore::Block
            ==> context == ProjectionDecisionEffectDecisionContextCore::Block,
        raw_rows == ProjectionDecisionEffectRawRowsCore::Reject
            ==> context == ProjectionDecisionEffectDecisionContextCore::Reject,
        raw_rows == ProjectionDecisionEffectRawRowsCore::AlreadyProcessed
            ==> context == ProjectionDecisionEffectDecisionContextCore::AlreadyProcessed,
{
    match raw_rows {
        ProjectionDecisionEffectRawRowsCore::Valid => ProjectionDecisionEffectDecisionContextCore::Valid,
        ProjectionDecisionEffectRawRowsCore::Block => ProjectionDecisionEffectDecisionContextCore::Block,
        ProjectionDecisionEffectRawRowsCore::Reject => ProjectionDecisionEffectDecisionContextCore::Reject,
        ProjectionDecisionEffectRawRowsCore::AlreadyProcessed => {
            ProjectionDecisionEffectDecisionContextCore::AlreadyProcessed
        }
    }
}

pub fn decide_projection_decision_effect_plan_core(
    context: ProjectionDecisionEffectDecisionContextCore,
) -> (plan: ProjectionDecisionEffectPlanCore)
    ensures
        context == ProjectionDecisionEffectDecisionContextCore::Valid
            ==> plan == ProjectionDecisionEffectPlanCore::ApplyWriteOpsAndEmitCommands,
        context == ProjectionDecisionEffectDecisionContextCore::Block
            ==> plan == ProjectionDecisionEffectPlanCore::EmitCommandsOnly,
        context == ProjectionDecisionEffectDecisionContextCore::Reject
            ==> plan == ProjectionDecisionEffectPlanCore::NoEffects,
        context == ProjectionDecisionEffectDecisionContextCore::AlreadyProcessed
            ==> plan == ProjectionDecisionEffectPlanCore::NoEffects,
{
    match context {
        ProjectionDecisionEffectDecisionContextCore::Valid => {
            ProjectionDecisionEffectPlanCore::ApplyWriteOpsAndEmitCommands
        }
        ProjectionDecisionEffectDecisionContextCore::Block => {
            ProjectionDecisionEffectPlanCore::EmitCommandsOnly
        }
        ProjectionDecisionEffectDecisionContextCore::Reject
        | ProjectionDecisionEffectDecisionContextCore::AlreadyProcessed => {
            ProjectionDecisionEffectPlanCore::NoEffects
        }
    }
}

pub fn projection_effect_allowance_core(
    plan: ProjectionDecisionEffectPlanCore,
) -> (allowance: ProjectionEffectAllowanceCore)
    ensures
        plan == ProjectionDecisionEffectPlanCore::ApplyWriteOpsAndEmitCommands
            ==> allowance == (ProjectionEffectAllowanceCore {
                allow_write_ops: true,
                allow_emit_commands: true,
                allow_record_block: false,
            }),
        plan == ProjectionDecisionEffectPlanCore::EmitCommandsOnly
            ==> allowance == (ProjectionEffectAllowanceCore {
                allow_write_ops: false,
                allow_emit_commands: true,
                allow_record_block: true,
            }),
        plan == ProjectionDecisionEffectPlanCore::NoEffects
            ==> allowance == (ProjectionEffectAllowanceCore {
                allow_write_ops: false,
                allow_emit_commands: false,
                allow_record_block: false,
            }),
{
    match plan {
        ProjectionDecisionEffectPlanCore::ApplyWriteOpsAndEmitCommands => ProjectionEffectAllowanceCore {
            allow_write_ops: true,
            allow_emit_commands: true,
            allow_record_block: false,
        },
        ProjectionDecisionEffectPlanCore::EmitCommandsOnly => ProjectionEffectAllowanceCore {
            allow_write_ops: false,
            allow_emit_commands: true,
            allow_record_block: true,
        },
        ProjectionDecisionEffectPlanCore::NoEffects => ProjectionEffectAllowanceCore {
            allow_write_ops: false,
            allow_emit_commands: false,
            allow_record_block: false,
        },
    }
}

} // verus!
