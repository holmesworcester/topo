//! Formal verification of workspace command planners that consume local daemon
//! identity query results and decide whether invite/device flows may proceed.

use vstd::prelude::*;

verus! {

pub enum ExplicitBootstrapEndpointState {
    Absent,
    Present { endpoint_id: nat },
    Invalid,
}

pub enum LocalDaemonEndpointState {
    Missing,
    Present { endpoint_id: nat },
    Malformed,
}

pub struct InviteBootstrapEndpointDecisionContext {
    pub explicit_endpoint: ExplicitBootstrapEndpointState,
    pub local_daemon_endpoint: LocalDaemonEndpointState,
}

pub enum InviteBootstrapEndpointPlan {
    UseExplicit { endpoint_id: nat },
    UseLocalDaemon { endpoint_id: nat },
    RejectInvalidExplicit,
    RejectMissingLocalDaemonIdentity,
    RejectMalformedLocalDaemonIdentity,
}

pub enum LocalEndpointSharedState {
    Missing,
    Present { event_id: nat },
    Malformed,
}

pub struct LocalEndpointSharedDecisionContext {
    pub local_endpoint_shared: LocalEndpointSharedState,
}

pub enum LocalEndpointSharedPlan {
    UseLocalEndpointShared { event_id: nat },
    RejectMissingLocalDaemonIdentity,
    RejectMalformedLocalDaemonIdentity,
}

pub open spec fn decide_invite_bootstrap_endpoint_plan(
    context: InviteBootstrapEndpointDecisionContext,
) -> InviteBootstrapEndpointPlan {
    match context.explicit_endpoint {
        ExplicitBootstrapEndpointState::Present { endpoint_id } => {
            InviteBootstrapEndpointPlan::UseExplicit { endpoint_id }
        }
        ExplicitBootstrapEndpointState::Invalid => {
            InviteBootstrapEndpointPlan::RejectInvalidExplicit
        }
        ExplicitBootstrapEndpointState::Absent => {
            match context.local_daemon_endpoint {
                LocalDaemonEndpointState::Present { endpoint_id } => {
                    InviteBootstrapEndpointPlan::UseLocalDaemon { endpoint_id }
                }
                LocalDaemonEndpointState::Missing => {
                    InviteBootstrapEndpointPlan::RejectMissingLocalDaemonIdentity
                }
                LocalDaemonEndpointState::Malformed => {
                    InviteBootstrapEndpointPlan::RejectMalformedLocalDaemonIdentity
                }
            }
        }
    }
}

pub open spec fn decide_local_endpoint_shared_plan(
    context: LocalEndpointSharedDecisionContext,
) -> LocalEndpointSharedPlan {
    match context.local_endpoint_shared {
        LocalEndpointSharedState::Present { event_id } => {
            LocalEndpointSharedPlan::UseLocalEndpointShared { event_id }
        }
        LocalEndpointSharedState::Missing => {
            LocalEndpointSharedPlan::RejectMissingLocalDaemonIdentity
        }
        LocalEndpointSharedState::Malformed => {
            LocalEndpointSharedPlan::RejectMalformedLocalDaemonIdentity
        }
    }
}

proof fn explicit_bootstrap_endpoint_wins_even_without_local_daemon_identity(endpoint_id: nat)
    ensures
        decide_invite_bootstrap_endpoint_plan(InviteBootstrapEndpointDecisionContext {
            explicit_endpoint: ExplicitBootstrapEndpointState::Present { endpoint_id },
            local_daemon_endpoint: LocalDaemonEndpointState::Missing,
        }) == (InviteBootstrapEndpointPlan::UseExplicit { endpoint_id }),
{
}

proof fn missing_local_daemon_identity_rejects_bootstrap_without_explicit()
    ensures
        decide_invite_bootstrap_endpoint_plan(InviteBootstrapEndpointDecisionContext {
            explicit_endpoint: ExplicitBootstrapEndpointState::Absent,
            local_daemon_endpoint: LocalDaemonEndpointState::Missing,
        }) == InviteBootstrapEndpointPlan::RejectMissingLocalDaemonIdentity,
{
}

proof fn malformed_local_daemon_identity_rejects_bootstrap_without_explicit()
    ensures
        decide_invite_bootstrap_endpoint_plan(InviteBootstrapEndpointDecisionContext {
            explicit_endpoint: ExplicitBootstrapEndpointState::Absent,
            local_daemon_endpoint: LocalDaemonEndpointState::Malformed,
        }) == InviteBootstrapEndpointPlan::RejectMalformedLocalDaemonIdentity,
{
}

proof fn invalid_explicit_bootstrap_endpoint_rejects_even_if_local_daemon_exists(endpoint_id: nat)
    ensures
        decide_invite_bootstrap_endpoint_plan(InviteBootstrapEndpointDecisionContext {
            explicit_endpoint: ExplicitBootstrapEndpointState::Invalid,
            local_daemon_endpoint: LocalDaemonEndpointState::Present { endpoint_id },
        }) == InviteBootstrapEndpointPlan::RejectInvalidExplicit,
{
}

proof fn local_endpoint_shared_presence_is_required(event_id: nat)
    ensures
        decide_local_endpoint_shared_plan(LocalEndpointSharedDecisionContext {
            local_endpoint_shared: LocalEndpointSharedState::Present { event_id },
        }) == (LocalEndpointSharedPlan::UseLocalEndpointShared { event_id }),
{
}

proof fn missing_local_endpoint_shared_rejects_command_paths()
    ensures
        decide_local_endpoint_shared_plan(LocalEndpointSharedDecisionContext {
            local_endpoint_shared: LocalEndpointSharedState::Missing,
        }) == LocalEndpointSharedPlan::RejectMissingLocalDaemonIdentity,
{
}

proof fn malformed_local_endpoint_shared_rejects_command_paths()
    ensures
        decide_local_endpoint_shared_plan(LocalEndpointSharedDecisionContext {
            local_endpoint_shared: LocalEndpointSharedState::Malformed,
        }) == LocalEndpointSharedPlan::RejectMalformedLocalDaemonIdentity,
{
}

} // verus!
