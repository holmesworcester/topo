//! Formal verification of daemon-identity startup materialization.
//!
//! This seam consumes raw table-presence query results and emits the startup
//! materialization plan. Command paths are intentionally excluded; they use the
//! load-only planners in `event_modules/workspace/command_plans.rs`.
//! Runtime now also repairs mismatched `endpoint_shared` material deterministically
//! from the local secret, but that still reduces to the same four startup plan tags.
//!
//! Every `pub fn` below is executable Rust consumed by
//! `src/runtime/transport/daemon_identity.rs`. Postconditions (`ensures`) are
//! SMT-checked against the function body by `cargo-verus verify`.

use vstd::prelude::*;

verus! {

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonIdentityMaterializationDecisionContext {
    pub endpoint_secret_present: bool,
    pub endpoint_shared_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonIdentityMaterializationPlan {
    AlreadyMaterialized,
    CreateSecretAndShared,
    CreateSharedFromExistingSecret,
    RejectSharedWithoutSecret,
}

pub open spec fn daemon_identity_materialization_plan_spec(
    endpoint_secret_present: bool,
    endpoint_shared_present: bool,
) -> DaemonIdentityMaterializationPlan {
    match (endpoint_secret_present, endpoint_shared_present) {
        (true, true) => DaemonIdentityMaterializationPlan::AlreadyMaterialized,
        (false, false) => DaemonIdentityMaterializationPlan::CreateSecretAndShared,
        (true, false) => DaemonIdentityMaterializationPlan::CreateSharedFromExistingSecret,
        (false, true) => DaemonIdentityMaterializationPlan::RejectSharedWithoutSecret,
    }
}

pub fn decide_daemon_identity_materialization_plan(
    context: &DaemonIdentityMaterializationDecisionContext,
) -> (plan: DaemonIdentityMaterializationPlan)
    ensures
        plan == daemon_identity_materialization_plan_spec(
            context.endpoint_secret_present,
            context.endpoint_shared_present,
        ),
        context.endpoint_secret_present && context.endpoint_shared_present
            ==> plan == DaemonIdentityMaterializationPlan::AlreadyMaterialized,
        !context.endpoint_secret_present && !context.endpoint_shared_present
            ==> plan == DaemonIdentityMaterializationPlan::CreateSecretAndShared,
        context.endpoint_secret_present && !context.endpoint_shared_present
            ==> plan == DaemonIdentityMaterializationPlan::CreateSharedFromExistingSecret,
        !context.endpoint_secret_present && context.endpoint_shared_present
            ==> plan == DaemonIdentityMaterializationPlan::RejectSharedWithoutSecret,
{
    match (context.endpoint_secret_present, context.endpoint_shared_present) {
        (true, true) => DaemonIdentityMaterializationPlan::AlreadyMaterialized,
        (false, false) => DaemonIdentityMaterializationPlan::CreateSecretAndShared,
        (true, false) => DaemonIdentityMaterializationPlan::CreateSharedFromExistingSecret,
        (false, true) => DaemonIdentityMaterializationPlan::RejectSharedWithoutSecret,
    }
}

pub open spec fn materialized_daemon_identity_state_after_plan(
    plan: DaemonIdentityMaterializationPlan,
) -> Option<DaemonIdentityMaterializationDecisionContext> {
    match plan {
        DaemonIdentityMaterializationPlan::AlreadyMaterialized => Some(
            DaemonIdentityMaterializationDecisionContext {
                endpoint_secret_present: true,
                endpoint_shared_present: true,
            },
        ),
        DaemonIdentityMaterializationPlan::CreateSecretAndShared => Some(
            DaemonIdentityMaterializationDecisionContext {
                endpoint_secret_present: true,
                endpoint_shared_present: true,
            },
        ),
        DaemonIdentityMaterializationPlan::CreateSharedFromExistingSecret => Some(
            DaemonIdentityMaterializationDecisionContext {
                endpoint_secret_present: true,
                endpoint_shared_present: true,
            },
        ),
        DaemonIdentityMaterializationPlan::RejectSharedWithoutSecret => None,
    }
}

proof fn startup_noops_when_daemon_identity_is_already_materialized()
    ensures
        daemon_identity_materialization_plan_spec(true, true)
            == DaemonIdentityMaterializationPlan::AlreadyMaterialized,
{
}

proof fn startup_materializes_both_rows_when_identity_is_absent()
    ensures
        daemon_identity_materialization_plan_spec(false, false)
            == DaemonIdentityMaterializationPlan::CreateSecretAndShared,
{
}

proof fn startup_repairs_missing_endpoint_shared_when_secret_exists()
    ensures
        daemon_identity_materialization_plan_spec(true, false)
            == DaemonIdentityMaterializationPlan::CreateSharedFromExistingSecret,
{
}

proof fn startup_rejects_shared_without_secret()
    ensures
        daemon_identity_materialization_plan_spec(false, true)
            == DaemonIdentityMaterializationPlan::RejectSharedWithoutSecret,
{
}

proof fn non_reject_materialization_plans_end_with_secret_and_shared(
    plan: DaemonIdentityMaterializationPlan,
)
    requires plan != DaemonIdentityMaterializationPlan::RejectSharedWithoutSecret
    ensures materialized_daemon_identity_state_after_plan(plan).is_Some(),
        materialized_daemon_identity_state_after_plan(plan).unwrap().endpoint_secret_present,
        materialized_daemon_identity_state_after_plan(plan).unwrap().endpoint_shared_present,
{
}

proof fn reject_plan_has_no_materialized_result_state()
    ensures
        materialized_daemon_identity_state_after_plan(
            DaemonIdentityMaterializationPlan::RejectSharedWithoutSecret
        ).is_None(),
{
}
} // verus!
