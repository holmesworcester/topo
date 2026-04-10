//! Formal verification of post-auth sync admission.
//!
//! The runtime queries accepted workspace binding state, reduces it to a small
//! snapshot, and uses a pure planner to decide whether shared sync may start.

use vstd::prelude::*;

verus! {

pub struct SyncAdmissionSnapshot {
    pub accepted_workspace_id: Option<nat>,
    pub used_bootstrap_auth: bool,
}

pub enum SyncAdmissionPlan {
    RejectMissingWorkspace,
    Start { workspace_id: nat },
}

pub open spec fn decide_sync_admission_plan(
    snapshot: &SyncAdmissionSnapshot,
) -> SyncAdmissionPlan {
    match snapshot.accepted_workspace_id {
        Some(workspace_id) => SyncAdmissionPlan::Start { workspace_id },
        None => SyncAdmissionPlan::RejectMissingWorkspace,
    }
}

proof fn proof_sync_admission_rejects_missing_workspace(used_bootstrap_auth: bool)
    ensures
        decide_sync_admission_plan(&SyncAdmissionSnapshot {
            accepted_workspace_id: None,
            used_bootstrap_auth,
        }) == SyncAdmissionPlan::RejectMissingWorkspace,
{
}

proof fn proof_sync_admission_starts_with_bound_workspace(
    workspace_id: nat,
    used_bootstrap_auth: bool,
)
    ensures
        decide_sync_admission_plan(&SyncAdmissionSnapshot {
            accepted_workspace_id: Some(workspace_id),
            used_bootstrap_auth,
        }) == (SyncAdmissionPlan::Start { workspace_id }),
{
}

proof fn proof_sync_admission_ignores_auth_mode_when_binding_same(
    workspace_id: nat,
)
    ensures
        decide_sync_admission_plan(&SyncAdmissionSnapshot {
            accepted_workspace_id: Some(workspace_id),
            used_bootstrap_auth: false,
        }) == decide_sync_admission_plan(&SyncAdmissionSnapshot {
            accepted_workspace_id: Some(workspace_id),
            used_bootstrap_auth: true,
        }),
{
}

} // verus!
