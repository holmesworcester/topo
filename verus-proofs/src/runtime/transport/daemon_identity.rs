//! Formal verification of daemon-identity startup materialization.
//!
//! This seam consumes raw table-presence query results and emits the startup
//! materialization plan. Command paths are intentionally excluded; they use the
//! load-only planners in `event_modules/workspace/command_plans.rs`.
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

pub fn decide_daemon_identity_materialization_plan(
    context: &DaemonIdentityMaterializationDecisionContext,
) -> (plan: DaemonIdentityMaterializationPlan)
    ensures
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

} // verus!
