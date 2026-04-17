//! Bootstrap dial suppression for already-local workspaces — verified core.
//!
//! Security property: if the target workspace is already local under another tenant,
//! bootstrap dialing is suppressed. Attacker-controlled endpoint data cannot influence
//! the plan because it's not part of the decision context.

use vstd::prelude::*;

verus! {

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapDialRawRows {
    pub workspace_already_local_elsewhere: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapDialDecisionContext {
    pub workspace_already_local_elsewhere: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapDialPlan {
    IgnoreAlreadyLocalWorkspace,
    UseBootstrapTarget,
}

pub fn normalize_bootstrap_dial_decision_context(
    raw_rows: BootstrapDialRawRows,
) -> (context: BootstrapDialDecisionContext)
    ensures context.workspace_already_local_elsewhere == raw_rows.workspace_already_local_elsewhere,
{
    BootstrapDialDecisionContext {
        workspace_already_local_elsewhere: raw_rows.workspace_already_local_elsewhere,
    }
}

pub fn decide_bootstrap_dial_plan(
    context: &BootstrapDialDecisionContext,
) -> (plan: BootstrapDialPlan)
    ensures
        context.workspace_already_local_elsewhere
            ==> plan == BootstrapDialPlan::IgnoreAlreadyLocalWorkspace,
        !context.workspace_already_local_elsewhere
            ==> plan == BootstrapDialPlan::UseBootstrapTarget,
{
    if context.workspace_already_local_elsewhere {
        BootstrapDialPlan::IgnoreAlreadyLocalWorkspace
    } else {
        BootstrapDialPlan::UseBootstrapTarget
    }
}

} // verus!
