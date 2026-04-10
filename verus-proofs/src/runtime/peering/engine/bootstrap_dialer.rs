//! Formal verification of bootstrap dial suppression for already-local workspaces.
//!
//! The runtime query adapter reduces each candidate bootstrap dial target to a
//! small immutable snapshot. The pure planner then decides whether bootstrap
//! endpoint/address data may influence behavior.
//!
//! Security property:
//! if the target workspace is already local elsewhere, bootstrap dialing is
//! suppressed and attacker-controlled endpoint data is irrelevant.

use vstd::prelude::*;

verus! {

pub struct BootstrapDialSnapshot {
    pub workspace_already_local_elsewhere: bool,
    pub endpoint_token: nat,
}

pub enum BootstrapDialPlan {
    Skip,
    Connect,
}

pub open spec fn decide_bootstrap_dial_plan(snapshot: &BootstrapDialSnapshot) -> BootstrapDialPlan {
    if snapshot.workspace_already_local_elsewhere {
        BootstrapDialPlan::Skip
    } else {
        BootstrapDialPlan::Connect
    }
}

pub open spec fn same_except_endpoint(
    a: &BootstrapDialSnapshot,
    b: &BootstrapDialSnapshot,
) -> bool {
    a.workspace_already_local_elsewhere == b.workspace_already_local_elsewhere
}

proof fn proof_already_local_workspace_skips_bootstrap(snapshot: BootstrapDialSnapshot)
    requires snapshot.workspace_already_local_elsewhere
    ensures decide_bootstrap_dial_plan(&snapshot) == BootstrapDialPlan::Skip,
{
}

proof fn proof_already_local_workspace_ignores_endpoint(
    a: BootstrapDialSnapshot,
    b: BootstrapDialSnapshot,
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
