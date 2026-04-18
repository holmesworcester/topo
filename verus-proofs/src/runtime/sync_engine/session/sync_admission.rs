//! Formal verification of post-auth sync admission — verified core.
//!
//! The runtime queries accepted workspace binding state and then classifies it into one of
//! three outcomes: no binding, a unique binding, or an ambiguous (multi-workspace) binding.
//! The runtime's raw rows and decision context carry `String` workspace ids that can't cross
//! into verus-proofs without cyclic deps, so this module exposes a *core* classifier over
//! only the abstract shape (row_count + all_workspace_ids_equal). The runtime wraps this
//! with a thin adapter that re-attaches the concrete workspace_id string for Start plans.

use vstd::prelude::*;

verus! {

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncAdmissionCoreRawRows {
    pub row_count: u32,
    pub all_workspace_ids_equal: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncAdmissionCoreDecisionContext {
    MissingWorkspaceBinding,
    UniqueWorkspaceBinding,
    AmbiguousWorkspaceBinding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncAdmissionCorePlan {
    RejectMissingWorkspaceBinding,
    RejectAmbiguousWorkspaceBinding,
    Start,
}

pub fn normalize_sync_admission_core_context(
    raw_rows: SyncAdmissionCoreRawRows,
) -> (context: SyncAdmissionCoreDecisionContext)
    ensures
        raw_rows.row_count == 0 ==> context == SyncAdmissionCoreDecisionContext::MissingWorkspaceBinding,
        (raw_rows.row_count > 0 && raw_rows.all_workspace_ids_equal)
            ==> context == SyncAdmissionCoreDecisionContext::UniqueWorkspaceBinding,
        (raw_rows.row_count > 0 && !raw_rows.all_workspace_ids_equal)
            ==> context == SyncAdmissionCoreDecisionContext::AmbiguousWorkspaceBinding,
{
    if raw_rows.row_count == 0 {
        SyncAdmissionCoreDecisionContext::MissingWorkspaceBinding
    } else if raw_rows.all_workspace_ids_equal {
        SyncAdmissionCoreDecisionContext::UniqueWorkspaceBinding
    } else {
        SyncAdmissionCoreDecisionContext::AmbiguousWorkspaceBinding
    }
}

pub fn decide_sync_admission_core_plan(
    context: &SyncAdmissionCoreDecisionContext,
) -> (plan: SyncAdmissionCorePlan)
    ensures
        *context == SyncAdmissionCoreDecisionContext::MissingWorkspaceBinding
            ==> plan == SyncAdmissionCorePlan::RejectMissingWorkspaceBinding,
        *context == SyncAdmissionCoreDecisionContext::UniqueWorkspaceBinding
            ==> plan == SyncAdmissionCorePlan::Start,
        *context == SyncAdmissionCoreDecisionContext::AmbiguousWorkspaceBinding
            ==> plan == SyncAdmissionCorePlan::RejectAmbiguousWorkspaceBinding,
{
    match context {
        SyncAdmissionCoreDecisionContext::MissingWorkspaceBinding => {
            SyncAdmissionCorePlan::RejectMissingWorkspaceBinding
        }
        SyncAdmissionCoreDecisionContext::UniqueWorkspaceBinding => {
            SyncAdmissionCorePlan::Start
        }
        SyncAdmissionCoreDecisionContext::AmbiguousWorkspaceBinding => {
            SyncAdmissionCorePlan::RejectAmbiguousWorkspaceBinding
        }
    }
}

} // verus!
