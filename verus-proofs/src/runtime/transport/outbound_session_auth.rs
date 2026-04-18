//! Formal verification of outbound session-auth planning.
//!
//! This seam consumes normalized query/runtime facts, builds a
//! `DecisionContext`, and emits a bounded auth plan.
//!
//! Every `pub fn` below is executable Rust consumed by
//! `src/runtime/transport/session_auth.rs`. Postconditions (`ensures`) are
//! SMT-checked against the function body by `cargo-verus verify`.

use vstd::prelude::*;

verus! {

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestedSessionAuthPlan {
    PeerShared,
    InviteBootstrap,
}

/// Primitive core of the bootstrap-fallback-invite raw rows — carries only
/// dedup counts and the boolean workspace flag. The runtime aggregates its
/// `Vec<Candidate>` into this core before calling the verified planner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapFallbackInviteRawRows {
    pub candidate_row_count: u32,
    pub distinct_candidate_count: u32,
    pub unique_distinct_candidate_workspace_already_local_before_candidate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapFallbackInviteDecisionContext {
    MissingCandidate,
    UniqueCandidate {
        workspace_already_local_before_candidate: bool,
    },
    AmbiguousCandidate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapFallbackInvitePlan {
    RejectMissingCandidate,
    UseInvite,
    RejectAmbiguousCandidate,
    RejectAlreadyLocalWorkspaceCandidate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundSessionAuthRawRows {
    pub bootstrap_auth_still_valid: bool,
    pub bound_daemon_matches_remote: bool,
    pub remote_session_peer_authorized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundSessionAuthDecisionContext {
    pub requested_plan: RequestedSessionAuthPlan,
    pub bootstrap_auth_still_valid: bool,
    pub daemon_connection_admits_route: bool,
    pub bound_daemon_matches_remote: bool,
    pub remote_session_peer_authorized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundSessionAuthDecision {
    KeepRequested,
    UpgradeToPeerSharedAfterRouteAdmission,
    UpgradeToPeerSharedAfterBootstrapLapse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedSessionAuthPlan {
    PeerShared,
    InviteBootstrap,
}

pub fn normalize_bootstrap_fallback_invite_decision_context(
    raw_rows: BootstrapFallbackInviteRawRows,
) -> (context: BootstrapFallbackInviteDecisionContext)
    ensures
        raw_rows.distinct_candidate_count == 0
            ==> context == BootstrapFallbackInviteDecisionContext::MissingCandidate,
        raw_rows.distinct_candidate_count == 1
            ==> context == (BootstrapFallbackInviteDecisionContext::UniqueCandidate {
                workspace_already_local_before_candidate:
                    raw_rows.unique_distinct_candidate_workspace_already_local_before_candidate,
            }),
        raw_rows.distinct_candidate_count > 1
            ==> context == BootstrapFallbackInviteDecisionContext::AmbiguousCandidate,
{
    if raw_rows.distinct_candidate_count == 0 {
        BootstrapFallbackInviteDecisionContext::MissingCandidate
    } else if raw_rows.distinct_candidate_count == 1 {
        BootstrapFallbackInviteDecisionContext::UniqueCandidate {
            workspace_already_local_before_candidate:
                raw_rows.unique_distinct_candidate_workspace_already_local_before_candidate,
        }
    } else {
        BootstrapFallbackInviteDecisionContext::AmbiguousCandidate
    }
}

pub fn decide_bootstrap_fallback_invite_plan(
    context: &BootstrapFallbackInviteDecisionContext,
) -> (plan: BootstrapFallbackInvitePlan)
    ensures
        *context == BootstrapFallbackInviteDecisionContext::MissingCandidate
            ==> plan == BootstrapFallbackInvitePlan::RejectMissingCandidate,
        *context == BootstrapFallbackInviteDecisionContext::AmbiguousCandidate
            ==> plan == BootstrapFallbackInvitePlan::RejectAmbiguousCandidate,
        (match context {
            BootstrapFallbackInviteDecisionContext::UniqueCandidate {
                workspace_already_local_before_candidate,
            } => *workspace_already_local_before_candidate,
            _ => false,
        }) ==> plan == BootstrapFallbackInvitePlan::RejectAlreadyLocalWorkspaceCandidate,
        (match context {
            BootstrapFallbackInviteDecisionContext::UniqueCandidate {
                workspace_already_local_before_candidate,
            } => !*workspace_already_local_before_candidate,
            _ => false,
        }) ==> plan == BootstrapFallbackInvitePlan::UseInvite,
{
    match context {
        BootstrapFallbackInviteDecisionContext::MissingCandidate => {
            BootstrapFallbackInvitePlan::RejectMissingCandidate
        }
        BootstrapFallbackInviteDecisionContext::UniqueCandidate {
            workspace_already_local_before_candidate,
        } => {
            if *workspace_already_local_before_candidate {
                BootstrapFallbackInvitePlan::RejectAlreadyLocalWorkspaceCandidate
            } else {
                BootstrapFallbackInvitePlan::UseInvite
            }
        }
        BootstrapFallbackInviteDecisionContext::AmbiguousCandidate => {
            BootstrapFallbackInvitePlan::RejectAmbiguousCandidate
        }
    }
}

pub fn normalize_outbound_session_auth_decision_context(
    raw_rows: OutboundSessionAuthRawRows,
    requested_plan: RequestedSessionAuthPlan,
    daemon_connection_admits_route: bool,
) -> (context: OutboundSessionAuthDecisionContext)
    ensures
        context.requested_plan == requested_plan,
        context.bootstrap_auth_still_valid == raw_rows.bootstrap_auth_still_valid,
        context.daemon_connection_admits_route == daemon_connection_admits_route,
        context.bound_daemon_matches_remote == raw_rows.bound_daemon_matches_remote,
        context.remote_session_peer_authorized == raw_rows.remote_session_peer_authorized,
{
    OutboundSessionAuthDecisionContext {
        requested_plan,
        bootstrap_auth_still_valid: raw_rows.bootstrap_auth_still_valid,
        daemon_connection_admits_route,
        bound_daemon_matches_remote: raw_rows.bound_daemon_matches_remote,
        remote_session_peer_authorized: raw_rows.remote_session_peer_authorized,
    }
}

pub fn decide_outbound_session_auth_decision(
    context: &OutboundSessionAuthDecisionContext,
) -> (decision: OutboundSessionAuthDecision)
    ensures
        // PeerShared requests are always kept as-is.
        context.requested_plan == RequestedSessionAuthPlan::PeerShared
            ==> decision == OutboundSessionAuthDecision::KeepRequested,
        // InviteBootstrap with active bootstrap and authorized steady-state peer
        // with an admitted route upgrades to PeerShared immediately.
        (context.requested_plan == RequestedSessionAuthPlan::InviteBootstrap
            && context.bootstrap_auth_still_valid
            && context.remote_session_peer_authorized
            && (context.bound_daemon_matches_remote || context.daemon_connection_admits_route))
            ==> decision == OutboundSessionAuthDecision::UpgradeToPeerSharedAfterRouteAdmission,
        // InviteBootstrap with active bootstrap but no admitted route keeps the request.
        (context.requested_plan == RequestedSessionAuthPlan::InviteBootstrap
            && context.bootstrap_auth_still_valid
            && !(context.remote_session_peer_authorized
                && (context.bound_daemon_matches_remote || context.daemon_connection_admits_route)))
            ==> decision == OutboundSessionAuthDecision::KeepRequested,
        // InviteBootstrap with lapsed bootstrap, matching daemon binding, and
        // authorized peer upgrades after the bootstrap lapse.
        (context.requested_plan == RequestedSessionAuthPlan::InviteBootstrap
            && !context.bootstrap_auth_still_valid
            && context.bound_daemon_matches_remote
            && context.remote_session_peer_authorized)
            ==> decision == OutboundSessionAuthDecision::UpgradeToPeerSharedAfterBootstrapLapse,
        // InviteBootstrap with lapsed bootstrap and missing binding-or-auth keeps request.
        (context.requested_plan == RequestedSessionAuthPlan::InviteBootstrap
            && !context.bootstrap_auth_still_valid
            && !(context.bound_daemon_matches_remote && context.remote_session_peer_authorized))
            ==> decision == OutboundSessionAuthDecision::KeepRequested,
{
    match context.requested_plan {
        RequestedSessionAuthPlan::PeerShared => OutboundSessionAuthDecision::KeepRequested,
        RequestedSessionAuthPlan::InviteBootstrap => {
            if context.bootstrap_auth_still_valid {
                if context.remote_session_peer_authorized
                    && (context.bound_daemon_matches_remote
                        || context.daemon_connection_admits_route)
                {
                    OutboundSessionAuthDecision::UpgradeToPeerSharedAfterRouteAdmission
                } else {
                    OutboundSessionAuthDecision::KeepRequested
                }
            } else if context.bound_daemon_matches_remote && context.remote_session_peer_authorized {
                OutboundSessionAuthDecision::UpgradeToPeerSharedAfterBootstrapLapse
            } else {
                OutboundSessionAuthDecision::KeepRequested
            }
        }
    }
}

pub fn plan_for_outbound_session_auth_decision(
    requested_plan: RequestedSessionAuthPlan,
    decision: OutboundSessionAuthDecision,
) -> (resolved: ResolvedSessionAuthPlan)
    ensures
        (decision == OutboundSessionAuthDecision::KeepRequested
            && requested_plan == RequestedSessionAuthPlan::PeerShared)
            ==> resolved == ResolvedSessionAuthPlan::PeerShared,
        (decision == OutboundSessionAuthDecision::KeepRequested
            && requested_plan == RequestedSessionAuthPlan::InviteBootstrap)
            ==> resolved == ResolvedSessionAuthPlan::InviteBootstrap,
        decision == OutboundSessionAuthDecision::UpgradeToPeerSharedAfterRouteAdmission
            ==> resolved == ResolvedSessionAuthPlan::PeerShared,
        decision == OutboundSessionAuthDecision::UpgradeToPeerSharedAfterBootstrapLapse
            ==> resolved == ResolvedSessionAuthPlan::PeerShared,
{
    match decision {
        OutboundSessionAuthDecision::KeepRequested => match requested_plan {
            RequestedSessionAuthPlan::PeerShared => ResolvedSessionAuthPlan::PeerShared,
            RequestedSessionAuthPlan::InviteBootstrap => ResolvedSessionAuthPlan::InviteBootstrap,
        },
        OutboundSessionAuthDecision::UpgradeToPeerSharedAfterRouteAdmission
        | OutboundSessionAuthDecision::UpgradeToPeerSharedAfterBootstrapLapse => {
            ResolvedSessionAuthPlan::PeerShared
        }
    }
}

} // verus!
// Mirror maintenance: synced with current transport/session auth runtime changes in this branch.
