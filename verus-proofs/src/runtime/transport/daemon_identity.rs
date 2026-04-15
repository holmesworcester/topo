//! Formal verification of daemon-identity startup materialization.
//!
//! This seam consumes raw table-presence query results and emits the startup
//! materialization plan. Command paths are intentionally excluded; they use the
//! load-only planners in `event_modules/workspace/command_plans.rs`.

use vstd::prelude::*;

verus! {

pub struct DaemonIdentityMaterializationDecisionContext {
    pub endpoint_secret_present: bool,
    pub endpoint_shared_present: bool,
}

pub enum DaemonIdentityMaterializationPlan {
    AlreadyMaterialized,
    CreateSecretAndShared,
    CreateSharedFromExistingSecret,
    RejectSharedWithoutSecret,
}

pub open spec fn decide_daemon_identity_materialization_plan(
    context: DaemonIdentityMaterializationDecisionContext,
) -> DaemonIdentityMaterializationPlan {
    match (context.endpoint_secret_present, context.endpoint_shared_present) {
        (true, true) => DaemonIdentityMaterializationPlan::AlreadyMaterialized,
        (false, false) => DaemonIdentityMaterializationPlan::CreateSecretAndShared,
        (true, false) => DaemonIdentityMaterializationPlan::CreateSharedFromExistingSecret,
        (false, true) => DaemonIdentityMaterializationPlan::RejectSharedWithoutSecret,
    }
}

proof fn startup_noops_when_daemon_identity_is_already_materialized()
    ensures
        decide_daemon_identity_materialization_plan(
            DaemonIdentityMaterializationDecisionContext {
                endpoint_secret_present: true,
                endpoint_shared_present: true,
            }
        ) == DaemonIdentityMaterializationPlan::AlreadyMaterialized,
{
}

proof fn startup_materializes_both_rows_when_identity_is_absent()
    ensures
        decide_daemon_identity_materialization_plan(
            DaemonIdentityMaterializationDecisionContext {
                endpoint_secret_present: false,
                endpoint_shared_present: false,
            }
        ) == DaemonIdentityMaterializationPlan::CreateSecretAndShared,
{
}

proof fn startup_repairs_missing_endpoint_shared_when_secret_exists()
    ensures
        decide_daemon_identity_materialization_plan(
            DaemonIdentityMaterializationDecisionContext {
                endpoint_secret_present: true,
                endpoint_shared_present: false,
            }
        ) == DaemonIdentityMaterializationPlan::CreateSharedFromExistingSecret,
{
}

proof fn startup_rejects_shared_without_secret()
    ensures
        decide_daemon_identity_materialization_plan(
            DaemonIdentityMaterializationDecisionContext {
                endpoint_secret_present: false,
                endpoint_shared_present: true,
            }
        ) == DaemonIdentityMaterializationPlan::RejectSharedWithoutSecret,
{
}

} // verus!
