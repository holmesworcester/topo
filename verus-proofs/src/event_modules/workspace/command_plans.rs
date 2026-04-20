//! Formal verification of workspace command planners that consume local daemon
//! identity query results and decide whether invite/device flows may proceed.
//!
//! Every `pub fn` below is executable Rust consumed by
//! `src/event_modules/workspace/command_plans.rs`. Postconditions (`ensures`) are
//! SMT-checked against the function body by `cargo-verus verify`.
//!
//! Runtime carries `[u8; 32]` / `EventId` inside `Present { .. }` variants; this Verus
//! core reduces each state/plan to a payload-less tag. The runtime wraps the core by
//! projecting its rich variants down to tags, calling the verified dispatcher, then
//! rehydrating the concrete payloads on the `Use*` branches.
//!
//! The mirrored runtime command surface now also carries invite bootstrap history ids
//! and prefers deterministic local endpoint-shared resolution from daemon identity
//! material when that state is present.

use vstd::prelude::*;

verus! {

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExplicitBootstrapEndpointStateCore {
    Absent,
    Present,
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalDaemonEndpointStateCore {
    Missing,
    Present,
    Malformed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InviteBootstrapEndpointDecisionContextCore {
    pub explicit_endpoint: ExplicitBootstrapEndpointStateCore,
    pub local_daemon_endpoint: LocalDaemonEndpointStateCore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteBootstrapEndpointPlanCore {
    UseExplicit,
    UseLocalDaemon,
    RejectInvalidExplicit,
    RejectMissingLocalDaemonIdentity,
    RejectMalformedLocalDaemonIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalEndpointSharedStateCore {
    Missing,
    Present,
    Malformed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalEndpointSharedDecisionContextCore {
    pub local_endpoint_shared: LocalEndpointSharedStateCore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalEndpointSharedPlanCore {
    UseLocalEndpointShared,
    RejectMissingLocalDaemonIdentity,
    RejectMalformedLocalDaemonIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveMemberTargetKindCore {
    User,
    Peer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoveMemberDecisionContextCore {
    pub actor_is_admin: bool,
    pub targets_self: bool,
    pub already_removed: bool,
    pub target_kind: RemoveMemberTargetKindCore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveMemberPlanCore {
    Proceed,
    RejectNotAdmin,
    RejectSelfTarget,
    RejectAlreadyRemoved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantAdminDecisionContextCore {
    pub actor_is_admin: bool,
    pub target_already_admin: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantAdminPlanCore {
    Proceed,
    RejectNotAdmin,
    RejectAlreadyAdmin,
}

pub fn decide_invite_bootstrap_endpoint_plan_core(
    context: InviteBootstrapEndpointDecisionContextCore,
) -> (plan: InviteBootstrapEndpointPlanCore)
    ensures
        context.explicit_endpoint == ExplicitBootstrapEndpointStateCore::Present
            ==> plan == InviteBootstrapEndpointPlanCore::UseExplicit,
        context.explicit_endpoint == ExplicitBootstrapEndpointStateCore::Invalid
            ==> plan == InviteBootstrapEndpointPlanCore::RejectInvalidExplicit,
        (context.explicit_endpoint == ExplicitBootstrapEndpointStateCore::Absent
         && context.local_daemon_endpoint == LocalDaemonEndpointStateCore::Present)
            ==> plan == InviteBootstrapEndpointPlanCore::UseLocalDaemon,
        (context.explicit_endpoint == ExplicitBootstrapEndpointStateCore::Absent
         && context.local_daemon_endpoint == LocalDaemonEndpointStateCore::Missing)
            ==> plan == InviteBootstrapEndpointPlanCore::RejectMissingLocalDaemonIdentity,
        (context.explicit_endpoint == ExplicitBootstrapEndpointStateCore::Absent
         && context.local_daemon_endpoint == LocalDaemonEndpointStateCore::Malformed)
            ==> plan == InviteBootstrapEndpointPlanCore::RejectMalformedLocalDaemonIdentity,
{
    match context.explicit_endpoint {
        ExplicitBootstrapEndpointStateCore::Present => {
            InviteBootstrapEndpointPlanCore::UseExplicit
        }
        ExplicitBootstrapEndpointStateCore::Invalid => {
            InviteBootstrapEndpointPlanCore::RejectInvalidExplicit
        }
        ExplicitBootstrapEndpointStateCore::Absent => match context.local_daemon_endpoint {
            LocalDaemonEndpointStateCore::Present => {
                InviteBootstrapEndpointPlanCore::UseLocalDaemon
            }
            LocalDaemonEndpointStateCore::Missing => {
                InviteBootstrapEndpointPlanCore::RejectMissingLocalDaemonIdentity
            }
            LocalDaemonEndpointStateCore::Malformed => {
                InviteBootstrapEndpointPlanCore::RejectMalformedLocalDaemonIdentity
            }
        },
    }
}

pub fn decide_local_endpoint_shared_plan_core(
    context: LocalEndpointSharedDecisionContextCore,
) -> (plan: LocalEndpointSharedPlanCore)
    ensures
        context.local_endpoint_shared == LocalEndpointSharedStateCore::Present
            ==> plan == LocalEndpointSharedPlanCore::UseLocalEndpointShared,
        context.local_endpoint_shared == LocalEndpointSharedStateCore::Missing
            ==> plan == LocalEndpointSharedPlanCore::RejectMissingLocalDaemonIdentity,
        context.local_endpoint_shared == LocalEndpointSharedStateCore::Malformed
            ==> plan == LocalEndpointSharedPlanCore::RejectMalformedLocalDaemonIdentity,
{
    match context.local_endpoint_shared {
        LocalEndpointSharedStateCore::Present => LocalEndpointSharedPlanCore::UseLocalEndpointShared,
        LocalEndpointSharedStateCore::Missing => LocalEndpointSharedPlanCore::RejectMissingLocalDaemonIdentity,
        LocalEndpointSharedStateCore::Malformed => LocalEndpointSharedPlanCore::RejectMalformedLocalDaemonIdentity,
    }
}

pub fn decide_remove_member_plan_core(
    context: RemoveMemberDecisionContextCore,
) -> (plan: RemoveMemberPlanCore)
    ensures
        !context.actor_is_admin ==> plan == RemoveMemberPlanCore::RejectNotAdmin,
        (context.actor_is_admin && context.targets_self)
            ==> plan == RemoveMemberPlanCore::RejectSelfTarget,
        (context.actor_is_admin && !context.targets_self && context.already_removed)
            ==> plan == RemoveMemberPlanCore::RejectAlreadyRemoved,
        (context.actor_is_admin && !context.targets_self && !context.already_removed)
            ==> plan == RemoveMemberPlanCore::Proceed,
{
    if !context.actor_is_admin {
        RemoveMemberPlanCore::RejectNotAdmin
    } else if context.targets_self {
        RemoveMemberPlanCore::RejectSelfTarget
    } else if context.already_removed {
        RemoveMemberPlanCore::RejectAlreadyRemoved
    } else {
        RemoveMemberPlanCore::Proceed
    }
}

pub fn decide_grant_admin_plan_core(
    context: GrantAdminDecisionContextCore,
) -> (plan: GrantAdminPlanCore)
    ensures
        !context.actor_is_admin ==> plan == GrantAdminPlanCore::RejectNotAdmin,
        (context.actor_is_admin && context.target_already_admin)
            ==> plan == GrantAdminPlanCore::RejectAlreadyAdmin,
        (context.actor_is_admin && !context.target_already_admin)
            ==> plan == GrantAdminPlanCore::Proceed,
{
    if !context.actor_is_admin {
        GrantAdminPlanCore::RejectNotAdmin
    } else if context.target_already_admin {
        GrantAdminPlanCore::RejectAlreadyAdmin
    } else {
        GrantAdminPlanCore::Proceed
    }
}

} // verus!
