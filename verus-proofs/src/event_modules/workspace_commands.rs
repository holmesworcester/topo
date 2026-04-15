//! Abstract contracts for workspace command APIs.
//!
//! This models the local-vs-bootstrap split that workspace commands must
//! preserve, especially for already-local workspace joins.

use vstd::prelude::*;

verus! {

pub struct WorkspaceJoinInputs {
    pub workspace_already_local: bool,
    pub bootstrap_info_present: bool,
    pub bootstrap_scope_valid: bool,
}

pub enum WorkspaceJoinPlan {
    Reject,
    LocalOnlyReplay,
    BootstrapJoin,
}

pub open spec fn decide_workspace_join_plan(i: WorkspaceJoinInputs) -> WorkspaceJoinPlan {
    if i.workspace_already_local {
        WorkspaceJoinPlan::LocalOnlyReplay
    } else if i.bootstrap_info_present && i.bootstrap_scope_valid {
        WorkspaceJoinPlan::BootstrapJoin
    } else {
        WorkspaceJoinPlan::Reject
    }
}

proof fn already_local_workspace_ignores_bootstrap_inputs(
    has_bootstrap_info: bool,
    bootstrap_scope_valid: bool,
)
    ensures
        decide_workspace_join_plan(WorkspaceJoinInputs {
            workspace_already_local: true,
            bootstrap_info_present: has_bootstrap_info,
            bootstrap_scope_valid,
        }) == WorkspaceJoinPlan::LocalOnlyReplay,
{
}

proof fn nonlocal_workspace_requires_valid_bootstrap_scope()
    ensures
        decide_workspace_join_plan(WorkspaceJoinInputs {
            workspace_already_local: false,
            bootstrap_info_present: false,
            bootstrap_scope_valid: false,
        }) == WorkspaceJoinPlan::Reject,
        decide_workspace_join_plan(WorkspaceJoinInputs {
            workspace_already_local: false,
            bootstrap_info_present: true,
            bootstrap_scope_valid: false,
        }) == WorkspaceJoinPlan::Reject,
        decide_workspace_join_plan(WorkspaceJoinInputs {
            workspace_already_local: false,
            bootstrap_info_present: true,
            bootstrap_scope_valid: true,
        }) == WorkspaceJoinPlan::BootstrapJoin,
{
}

proof fn local_replay_choice_is_noninterfering_with_bootstrap_fields(
    a_bootstrap_info_present: bool,
    a_bootstrap_scope_valid: bool,
    b_bootstrap_info_present: bool,
    b_bootstrap_scope_valid: bool,
)
    ensures
        decide_workspace_join_plan(WorkspaceJoinInputs {
            workspace_already_local: true,
            bootstrap_info_present: a_bootstrap_info_present,
            bootstrap_scope_valid: a_bootstrap_scope_valid,
        }) == decide_workspace_join_plan(WorkspaceJoinInputs {
            workspace_already_local: true,
            bootstrap_info_present: b_bootstrap_info_present,
            bootstrap_scope_valid: b_bootstrap_scope_valid,
        }),
{
}

} // verus!
