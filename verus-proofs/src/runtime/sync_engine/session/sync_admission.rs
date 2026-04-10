//! Formal verification of post-auth sync admission.
//!
//! The runtime queries accepted workspace binding state, normalizes it into a
//! DecisionContext, and uses a pure planner to decide whether shared sync may
//! start.

use vstd::prelude::*;

verus! {

pub struct SyncAdmissionRawRows {
    pub row_count: nat,
    pub all_workspace_ids_equal: bool,
    pub representative_workspace_id: nat,
}

pub enum SyncAdmissionDecisionContext {
    MissingWorkspaceBinding,
    UniqueWorkspaceBinding { workspace_id: nat },
    AmbiguousWorkspaceBinding,
}

pub enum SyncAdmissionPlan {
    RejectMissingWorkspaceBinding,
    RejectAmbiguousWorkspaceBinding,
    Start { workspace_id: nat },
}

pub open spec fn normalize_sync_admission_decision_context(
    raw_rows: &SyncAdmissionRawRows,
) -> SyncAdmissionDecisionContext {
    if raw_rows.row_count == 0 {
        SyncAdmissionDecisionContext::MissingWorkspaceBinding
    } else if raw_rows.all_workspace_ids_equal {
        SyncAdmissionDecisionContext::UniqueWorkspaceBinding {
            workspace_id: raw_rows.representative_workspace_id,
        }
    } else {
        SyncAdmissionDecisionContext::AmbiguousWorkspaceBinding
    }
}

pub open spec fn decide_sync_admission_plan(
    context: &SyncAdmissionDecisionContext,
) -> SyncAdmissionPlan {
    match context {
        SyncAdmissionDecisionContext::MissingWorkspaceBinding => {
            SyncAdmissionPlan::RejectMissingWorkspaceBinding
        }
        SyncAdmissionDecisionContext::UniqueWorkspaceBinding { workspace_id } => {
            SyncAdmissionPlan::Start {
                workspace_id: *workspace_id,
            }
        }
        SyncAdmissionDecisionContext::AmbiguousWorkspaceBinding => {
            SyncAdmissionPlan::RejectAmbiguousWorkspaceBinding
        }
    }
}

proof fn proof_sync_admission_normalize_empty_to_missing()
    ensures
        normalize_sync_admission_decision_context(&SyncAdmissionRawRows {
            row_count: 0,
            all_workspace_ids_equal: true,
            representative_workspace_id: 0,
        }) == SyncAdmissionDecisionContext::MissingWorkspaceBinding,
{
}

proof fn proof_sync_admission_normalize_equal_rows_to_unique(
    row_count: nat,
    workspace_id: nat,
)
    requires row_count > 0
    ensures
        normalize_sync_admission_decision_context(&SyncAdmissionRawRows {
            row_count,
            all_workspace_ids_equal: true,
            representative_workspace_id: workspace_id,
        }) == (SyncAdmissionDecisionContext::UniqueWorkspaceBinding { workspace_id }),
{
}

proof fn proof_sync_admission_duplicate_row_count_is_noninterfering(
    row_count_a: nat,
    row_count_b: nat,
    workspace_id: nat,
)
    requires
        row_count_a > 0,
        row_count_b > 0,
    ensures
        decide_sync_admission_plan(&normalize_sync_admission_decision_context(
            &SyncAdmissionRawRows {
                row_count: row_count_a,
                all_workspace_ids_equal: true,
                representative_workspace_id: workspace_id,
            },
        )) == decide_sync_admission_plan(&normalize_sync_admission_decision_context(
            &SyncAdmissionRawRows {
                row_count: row_count_b,
                all_workspace_ids_equal: true,
                representative_workspace_id: workspace_id,
            },
        )),
        decide_sync_admission_plan(&normalize_sync_admission_decision_context(
            &SyncAdmissionRawRows {
                row_count: row_count_a,
                all_workspace_ids_equal: true,
                representative_workspace_id: workspace_id,
            },
        )) == (SyncAdmissionPlan::Start { workspace_id }),
{
}

proof fn proof_sync_admission_normalize_mixed_rows_to_ambiguous(
    row_count: nat,
    representative_workspace_id: nat,
)
    requires row_count > 0
    ensures
        normalize_sync_admission_decision_context(&SyncAdmissionRawRows {
            row_count,
            all_workspace_ids_equal: false,
            representative_workspace_id,
        }) == SyncAdmissionDecisionContext::AmbiguousWorkspaceBinding,
{
}

proof fn proof_sync_admission_rejects_missing_workspace_binding()
    ensures
        decide_sync_admission_plan(&SyncAdmissionDecisionContext::MissingWorkspaceBinding)
            == SyncAdmissionPlan::RejectMissingWorkspaceBinding,
{
}

proof fn proof_sync_admission_rejects_ambiguous_workspace_binding()
    ensures
        decide_sync_admission_plan(&SyncAdmissionDecisionContext::AmbiguousWorkspaceBinding)
            == SyncAdmissionPlan::RejectAmbiguousWorkspaceBinding,
{
}

proof fn proof_sync_admission_starts_with_unique_workspace_binding(workspace_id: nat)
    ensures
        decide_sync_admission_plan(&SyncAdmissionDecisionContext::UniqueWorkspaceBinding {
            workspace_id,
        }) == (SyncAdmissionPlan::Start { workspace_id }),
{
}

} // verus!
