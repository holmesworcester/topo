//! Formal verification of bootstrap dial suppression for already-local workspaces.
//!
//! The runtime query adapter reduces each candidate bootstrap dial target to
//! raw typed rows, normalizes them into a `DecisionContext`, and then uses a
//! pure planner to decide whether bootstrap endpoint/address data may
//! influence behavior.
//!
//! Security property:
//! if the target workspace is already local elsewhere, bootstrap dialing is
//! suppressed and attacker-controlled endpoint data is irrelevant.

use vstd::prelude::*;

verus! {

pub struct BootstrapDialRawRows {
    pub workspace_already_local_elsewhere: bool,
    pub endpoint_token: nat,
}

pub struct BootstrapDialDecisionContext {
    pub workspace_already_local_elsewhere: bool,
    pub endpoint_token: nat,
}

pub enum BootstrapDialPlan {
    Skip,
    Connect,
}

pub open spec fn normalize_bootstrap_dial_decision_context(
    raw_rows: &BootstrapDialRawRows,
) -> BootstrapDialDecisionContext {
    BootstrapDialDecisionContext {
        workspace_already_local_elsewhere: raw_rows.workspace_already_local_elsewhere,
        endpoint_token: raw_rows.endpoint_token,
    }
}

pub open spec fn decide_bootstrap_dial_plan(
    context: &BootstrapDialDecisionContext,
) -> BootstrapDialPlan {
    if context.workspace_already_local_elsewhere {
        BootstrapDialPlan::Skip
    } else {
        BootstrapDialPlan::Connect
    }
}

pub open spec fn same_except_endpoint(
    a: &BootstrapDialDecisionContext,
    b: &BootstrapDialDecisionContext,
) -> bool {
    a.workspace_already_local_elsewhere == b.workspace_already_local_elsewhere
}

proof fn proof_normalization_preserves_already_local_flag(raw_rows: BootstrapDialRawRows)
    ensures
        normalize_bootstrap_dial_decision_context(&raw_rows).workspace_already_local_elsewhere
            == raw_rows.workspace_already_local_elsewhere,
{
}

proof fn proof_already_local_workspace_skips_bootstrap(
    context: BootstrapDialDecisionContext,
)
    requires context.workspace_already_local_elsewhere
    ensures decide_bootstrap_dial_plan(&context) == BootstrapDialPlan::Skip,
{
}

proof fn proof_already_local_workspace_ignores_endpoint(
    a: BootstrapDialDecisionContext,
    b: BootstrapDialDecisionContext,
)
    requires
        same_except_endpoint(&a, &b),
        a.workspace_already_local_elsewhere,
        b.workspace_already_local_elsewhere,
    ensures
        decide_bootstrap_dial_plan(&a) == decide_bootstrap_dial_plan(&b),
{
}

} // verus!
