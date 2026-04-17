//! Formal verification of the project_one 7-step algorithm.
//!
//! Every `pub fn` below is an executable Rust abstract model of the corresponding
//! runtime composition in `src/state/projection/apply/project_one.rs`.
//! Postconditions (`ensures`) are SMT-checked against the function body by
//! `cargo-verus verify`.

use vstd::prelude::*;
use crate::decision::*;

verus! {

pub const ZERO: u32 = 0;
pub const THREE: u32 = 3;
pub const FIVE: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextLoadDispositionPlanCore {
    Continue,
    RecordBlockAndReturn,
    Reject,
    EmitHardPurgeAndReturn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectOneApplyDecisionContextCore {
    pub already_valid: bool,
    pub already_rejected: bool,
    pub blob_exists: bool,
    pub parse_succeeds: bool,
    pub context_load_plan: ContextLoadDispositionPlanCore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectOneApplyPlanCore {
    AlreadyProcessed,
    RejectBeforeProjector,
    RecordBlockAndReturn,
    EmitHardPurgeAndReturn,
    RunProjector,
}

pub fn decide_project_one_apply_plan(
    context: ProjectOneApplyDecisionContextCore,
) -> (plan: ProjectOneApplyPlanCore)
    ensures
        (context.already_valid || context.already_rejected)
            ==> plan == ProjectOneApplyPlanCore::AlreadyProcessed,
        (!(context.already_valid || context.already_rejected)
         && (!context.blob_exists || !context.parse_succeeds))
            ==> plan == ProjectOneApplyPlanCore::RejectBeforeProjector,
        (!(context.already_valid || context.already_rejected)
         && context.blob_exists && context.parse_succeeds
         && context.context_load_plan == ContextLoadDispositionPlanCore::Continue)
            ==> plan == ProjectOneApplyPlanCore::RunProjector,
        (!(context.already_valid || context.already_rejected)
         && context.blob_exists && context.parse_succeeds
         && context.context_load_plan == ContextLoadDispositionPlanCore::RecordBlockAndReturn)
            ==> plan == ProjectOneApplyPlanCore::RecordBlockAndReturn,
        (!(context.already_valid || context.already_rejected)
         && context.blob_exists && context.parse_succeeds
         && context.context_load_plan == ContextLoadDispositionPlanCore::Reject)
            ==> plan == ProjectOneApplyPlanCore::RejectBeforeProjector,
        (!(context.already_valid || context.already_rejected)
         && context.blob_exists && context.parse_succeeds
         && context.context_load_plan == ContextLoadDispositionPlanCore::EmitHardPurgeAndReturn)
            ==> plan == ProjectOneApplyPlanCore::EmitHardPurgeAndReturn,
{
    if context.already_valid || context.already_rejected {
        ProjectOneApplyPlanCore::AlreadyProcessed
    } else if !context.blob_exists || !context.parse_succeeds {
        ProjectOneApplyPlanCore::RejectBeforeProjector
    } else {
        match context.context_load_plan {
            ContextLoadDispositionPlanCore::Continue => ProjectOneApplyPlanCore::RunProjector,
            ContextLoadDispositionPlanCore::RecordBlockAndReturn => {
                ProjectOneApplyPlanCore::RecordBlockAndReturn
            }
            ContextLoadDispositionPlanCore::Reject => ProjectOneApplyPlanCore::RejectBeforeProjector,
            ContextLoadDispositionPlanCore::EmitHardPurgeAndReturn => {
                ProjectOneApplyPlanCore::EmitHardPurgeAndReturn
            }
        }
    }
}

/// The full 7-step algorithm as an executable abstract model.
pub fn project_one_step_model(
    already_valid: bool,
    already_rejected: bool,
    blob_exists: bool,
    parse_succeeds: bool,
    all_deps_present: bool,
    missing_dep_count: u32,
    dep_types_valid: bool,
    projection_decision: ProjectionDecisionCore,
) -> (decision: ProjectionDecisionCore)
    ensures
        (already_valid || already_rejected)
            ==> decision == ProjectionDecisionCore::AlreadyProcessed,
        (!(already_valid || already_rejected) && !blob_exists)
            ==> decision == ProjectionDecisionCore::Reject,
        (!(already_valid || already_rejected) && blob_exists && !parse_succeeds)
            ==> decision == ProjectionDecisionCore::Reject,
        (!(already_valid || already_rejected) && blob_exists && parse_succeeds && !all_deps_present)
            ==> decision == (ProjectionDecisionCore::Block { missing_count: missing_dep_count }),
        (!(already_valid || already_rejected) && blob_exists && parse_succeeds && all_deps_present && !dep_types_valid)
            ==> decision == ProjectionDecisionCore::Reject,
        (!(already_valid || already_rejected) && blob_exists && parse_succeeds && all_deps_present && dep_types_valid)
            ==> decision == projection_decision,
{
    if already_valid || already_rejected {
        ProjectionDecisionCore::AlreadyProcessed
    } else if !blob_exists {
        ProjectionDecisionCore::Reject
    } else if !parse_succeeds {
        ProjectionDecisionCore::Reject
    } else if !all_deps_present {
        ProjectionDecisionCore::Block { missing_count: missing_dep_count }
    } else if !dep_types_valid {
        ProjectionDecisionCore::Reject
    } else {
        projection_decision
    }
}

// ═══════════════════════════════════════════════════════════════════
// project_one (with cascade)
// ═══════════════════════════════════════════════════════════════════

pub fn project_one_with_cascade(
    step_decision: ProjectionDecisionCore,
    cascade_would_unblock: u32,
) -> (out: (ProjectionDecisionCore, u32))
    ensures
        step_decision == ProjectionDecisionCore::Valid
            ==> out == (ProjectionDecisionCore::Valid, cascade_would_unblock),
        step_decision != ProjectionDecisionCore::Valid
            ==> out == (step_decision, 0u32),
{
    match step_decision {
        ProjectionDecisionCore::Valid => (ProjectionDecisionCore::Valid, cascade_would_unblock),
        _ => (step_decision, 0),
    }
}

} // verus!
