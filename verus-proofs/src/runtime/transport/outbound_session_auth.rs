//! Formal verification of outbound session-auth planning.
//!
//! This seam consumes normalized query/runtime facts, builds a
//! `DecisionContext`, and emits a bounded auth plan.

use vstd::prelude::*;

verus! {

pub enum RequestedSessionAuthPlan {
    PeerShared,
    InviteBootstrap,
}

pub struct BootstrapFallbackInviteRawRows {
    pub candidate_row_count: nat,
    pub distinct_candidate_count: nat,
    pub unique_distinct_candidate_workspace_already_local_before_candidate: bool,
}

pub enum BootstrapFallbackInviteDecisionContext {
    MissingCandidate,
    UniqueCandidate {
        workspace_already_local_before_candidate: bool,
    },
    AmbiguousCandidate,
}

pub enum BootstrapFallbackInvitePlan {
    RejectMissingCandidate,
    UseInvite,
    RejectAmbiguousCandidate,
    RejectAlreadyLocalWorkspaceCandidate,
}

pub struct OutboundSessionAuthRawRows {
    pub bootstrap_auth_still_valid: bool,
    pub bound_daemon_matches_remote: bool,
    pub remote_session_peer_authorized: bool,
}

pub struct OutboundSessionAuthDecisionContext {
    pub requested_plan: RequestedSessionAuthPlan,
    pub bootstrap_auth_still_valid: bool,
    pub daemon_connection_admits_route: bool,
    pub bound_daemon_matches_remote: bool,
    pub remote_session_peer_authorized: bool,
}

pub enum OutboundSessionAuthDecision {
    KeepRequested,
    UpgradeToPeerSharedAfterRouteAdmission,
    UpgradeToPeerSharedAfterBootstrapLapse,
}

pub enum ResolvedSessionAuthPlan {
    PeerShared,
    InviteBootstrap,
}

pub open spec fn normalize_bootstrap_fallback_invite_decision_context(
    raw_rows: BootstrapFallbackInviteRawRows,
) -> BootstrapFallbackInviteDecisionContext {
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

pub open spec fn decide_bootstrap_fallback_invite_plan(
    context: BootstrapFallbackInviteDecisionContext,
) -> BootstrapFallbackInvitePlan {
    match context {
        BootstrapFallbackInviteDecisionContext::MissingCandidate => {
            BootstrapFallbackInvitePlan::RejectMissingCandidate
        }
        BootstrapFallbackInviteDecisionContext::UniqueCandidate {
            workspace_already_local_before_candidate,
        } => {
            if workspace_already_local_before_candidate {
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

pub open spec fn normalize_outbound_session_auth_decision_context(
    raw_rows: OutboundSessionAuthRawRows,
    requested_plan: RequestedSessionAuthPlan,
    daemon_connection_admits_route: bool,
) -> OutboundSessionAuthDecisionContext {
    OutboundSessionAuthDecisionContext {
        requested_plan,
        bootstrap_auth_still_valid: raw_rows.bootstrap_auth_still_valid,
        daemon_connection_admits_route,
        bound_daemon_matches_remote: raw_rows.bound_daemon_matches_remote,
        remote_session_peer_authorized: raw_rows.remote_session_peer_authorized,
    }
}

pub open spec fn decide_outbound_session_auth_decision(
    context: OutboundSessionAuthDecisionContext,
) -> OutboundSessionAuthDecision {
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

pub open spec fn plan_for_outbound_session_auth_decision(
    requested_plan: RequestedSessionAuthPlan,
    decision: OutboundSessionAuthDecision,
) -> ResolvedSessionAuthPlan {
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

proof fn outbound_bootstrap_fallback_rejects_same_workspace_candidate()
    ensures
        decide_bootstrap_fallback_invite_plan(
            normalize_bootstrap_fallback_invite_decision_context(BootstrapFallbackInviteRawRows {
                candidate_row_count: 1,
                distinct_candidate_count: 1,
                unique_distinct_candidate_workspace_already_local_before_candidate: true,
            })
        ) == BootstrapFallbackInvitePlan::RejectAlreadyLocalWorkspaceCandidate,
{
}

proof fn outbound_bootstrap_fallback_duplicate_rows_preserve_same_workspace_rejection(
    candidate_row_count: nat,
)
    requires
        candidate_row_count > 1,
    ensures
        normalize_bootstrap_fallback_invite_decision_context(BootstrapFallbackInviteRawRows {
            candidate_row_count,
            distinct_candidate_count: 1,
            unique_distinct_candidate_workspace_already_local_before_candidate: true,
        }) == (BootstrapFallbackInviteDecisionContext::UniqueCandidate {
            workspace_already_local_before_candidate: true,
        }),
        decide_bootstrap_fallback_invite_plan(
            normalize_bootstrap_fallback_invite_decision_context(BootstrapFallbackInviteRawRows {
                candidate_row_count,
                distinct_candidate_count: 1,
                unique_distinct_candidate_workspace_already_local_before_candidate: true,
            })
        ) == BootstrapFallbackInvitePlan::RejectAlreadyLocalWorkspaceCandidate,
{
}

proof fn outbound_bootstrap_fallback_duplicate_row_count_is_noninterfering(
    row_count_a: nat,
    row_count_b: nat,
    distinct_candidate_count: nat,
    workspace_already_local_before_candidate: bool,
)
    ensures
        decide_bootstrap_fallback_invite_plan(
            normalize_bootstrap_fallback_invite_decision_context(BootstrapFallbackInviteRawRows {
                candidate_row_count: row_count_a,
                distinct_candidate_count,
                unique_distinct_candidate_workspace_already_local_before_candidate:
                    workspace_already_local_before_candidate,
            })
        ) == decide_bootstrap_fallback_invite_plan(
            normalize_bootstrap_fallback_invite_decision_context(BootstrapFallbackInviteRawRows {
                candidate_row_count: row_count_b,
                distinct_candidate_count,
                unique_distinct_candidate_workspace_already_local_before_candidate:
                    workspace_already_local_before_candidate,
            })
        ),
{
}

proof fn outbound_bootstrap_fallback_accepts_only_unique_nonlocal_candidate()
    ensures
        decide_bootstrap_fallback_invite_plan(
            normalize_bootstrap_fallback_invite_decision_context(BootstrapFallbackInviteRawRows {
                candidate_row_count: 1,
                distinct_candidate_count: 1,
                unique_distinct_candidate_workspace_already_local_before_candidate: false,
            })
        ) == BootstrapFallbackInvitePlan::UseInvite,
{
}

proof fn outbound_bootstrap_fallback_rejects_ambiguous_candidates(candidate_count: nat)
    requires candidate_count > 1
    ensures
        decide_bootstrap_fallback_invite_plan(
            normalize_bootstrap_fallback_invite_decision_context(BootstrapFallbackInviteRawRows {
                candidate_row_count: candidate_count,
                distinct_candidate_count: candidate_count,
                unique_distinct_candidate_workspace_already_local_before_candidate: false,
            })
        ) == BootstrapFallbackInvitePlan::RejectAmbiguousCandidate,
{
}

proof fn outbound_normalization_preserves_query_facts()
    ensures
        normalize_outbound_session_auth_decision_context(
            OutboundSessionAuthRawRows {
                bootstrap_auth_still_valid: true,
                bound_daemon_matches_remote: false,
                remote_session_peer_authorized: true,
            },
            RequestedSessionAuthPlan::InviteBootstrap,
            false,
        ) == (OutboundSessionAuthDecisionContext {
            requested_plan: RequestedSessionAuthPlan::InviteBootstrap,
            bootstrap_auth_still_valid: true,
            daemon_connection_admits_route: false,
            bound_daemon_matches_remote: false,
            remote_session_peer_authorized: true,
        }),
{
}

proof fn outbound_peer_shared_request_is_preserved(
    bootstrap_auth_still_valid: bool,
    daemon_connection_admits_route: bool,
    bound_daemon_matches_remote: bool,
    remote_session_peer_authorized: bool,
)
    ensures
        plan_for_outbound_session_auth_decision(
            RequestedSessionAuthPlan::PeerShared,
            decide_outbound_session_auth_decision(
                normalize_outbound_session_auth_decision_context(
                    OutboundSessionAuthRawRows {
                        bootstrap_auth_still_valid,
                        bound_daemon_matches_remote,
                        remote_session_peer_authorized,
                    },
                    RequestedSessionAuthPlan::PeerShared,
                    daemon_connection_admits_route,
                ),
            ),
        ) == ResolvedSessionAuthPlan::PeerShared,
{
}

proof fn outbound_bootstrap_upgrades_bound_known_daemon_while_active_when_authorized()
    ensures
        decide_outbound_session_auth_decision(
            normalize_outbound_session_auth_decision_context(
                OutboundSessionAuthRawRows {
                    bootstrap_auth_still_valid: true,
                    bound_daemon_matches_remote: true,
                    remote_session_peer_authorized: true,
                },
                RequestedSessionAuthPlan::InviteBootstrap,
                false,
            ),
        ) == OutboundSessionAuthDecision::UpgradeToPeerSharedAfterRouteAdmission,
        plan_for_outbound_session_auth_decision(
            RequestedSessionAuthPlan::InviteBootstrap,
            decide_outbound_session_auth_decision(
                normalize_outbound_session_auth_decision_context(
                    OutboundSessionAuthRawRows {
                        bootstrap_auth_still_valid: true,
                        bound_daemon_matches_remote: true,
                        remote_session_peer_authorized: true,
                    },
                    RequestedSessionAuthPlan::InviteBootstrap,
                    false,
                ),
            ),
        ) == ResolvedSessionAuthPlan::PeerShared,
{
}

proof fn outbound_bootstrap_keeps_bound_known_daemon_while_active_without_peer_route()
    ensures
        decide_outbound_session_auth_decision(
            normalize_outbound_session_auth_decision_context(
                OutboundSessionAuthRawRows {
                    bootstrap_auth_still_valid: true,
                    bound_daemon_matches_remote: true,
                    remote_session_peer_authorized: false,
                },
                RequestedSessionAuthPlan::InviteBootstrap,
                false,
            ),
        ) == OutboundSessionAuthDecision::KeepRequested,
        plan_for_outbound_session_auth_decision(
            RequestedSessionAuthPlan::InviteBootstrap,
            decide_outbound_session_auth_decision(
                normalize_outbound_session_auth_decision_context(
                    OutboundSessionAuthRawRows {
                        bootstrap_auth_still_valid: true,
                        bound_daemon_matches_remote: true,
                        remote_session_peer_authorized: false,
                    },
                    RequestedSessionAuthPlan::InviteBootstrap,
                    false,
                ),
            ),
        ) == ResolvedSessionAuthPlan::InviteBootstrap,
{
}

proof fn outbound_bootstrap_upgrades_after_admitted_route()
    ensures
        decide_outbound_session_auth_decision(
            normalize_outbound_session_auth_decision_context(
                OutboundSessionAuthRawRows {
                    bootstrap_auth_still_valid: true,
                    bound_daemon_matches_remote: false,
                    remote_session_peer_authorized: true,
                },
                RequestedSessionAuthPlan::InviteBootstrap,
                true,
            ),
        ) == OutboundSessionAuthDecision::UpgradeToPeerSharedAfterRouteAdmission,
        plan_for_outbound_session_auth_decision(
            RequestedSessionAuthPlan::InviteBootstrap,
            decide_outbound_session_auth_decision(
                normalize_outbound_session_auth_decision_context(
                    OutboundSessionAuthRawRows {
                        bootstrap_auth_still_valid: true,
                        bound_daemon_matches_remote: false,
                        remote_session_peer_authorized: true,
                    },
                    RequestedSessionAuthPlan::InviteBootstrap,
                    true,
                ),
            ),
        ) == ResolvedSessionAuthPlan::PeerShared,
{
}

proof fn outbound_bootstrap_upgrades_only_after_bootstrap_lapses_when_binding_and_auth_hold()
    ensures
        decide_outbound_session_auth_decision(
            normalize_outbound_session_auth_decision_context(
                OutboundSessionAuthRawRows {
                    bootstrap_auth_still_valid: false,
                    bound_daemon_matches_remote: true,
                    remote_session_peer_authorized: true,
                },
                RequestedSessionAuthPlan::InviteBootstrap,
                false,
            ),
        ) == OutboundSessionAuthDecision::UpgradeToPeerSharedAfterBootstrapLapse,
        plan_for_outbound_session_auth_decision(
            RequestedSessionAuthPlan::InviteBootstrap,
            decide_outbound_session_auth_decision(
                normalize_outbound_session_auth_decision_context(
                    OutboundSessionAuthRawRows {
                        bootstrap_auth_still_valid: false,
                        bound_daemon_matches_remote: true,
                        remote_session_peer_authorized: true,
                    },
                    RequestedSessionAuthPlan::InviteBootstrap,
                    false,
                ),
            ),
        ) == ResolvedSessionAuthPlan::PeerShared,
        decide_outbound_session_auth_decision(
            normalize_outbound_session_auth_decision_context(
                OutboundSessionAuthRawRows {
                    bootstrap_auth_still_valid: false,
                    bound_daemon_matches_remote: false,
                    remote_session_peer_authorized: true,
                },
                RequestedSessionAuthPlan::InviteBootstrap,
                false,
            ),
        ) == OutboundSessionAuthDecision::KeepRequested,
        plan_for_outbound_session_auth_decision(
            RequestedSessionAuthPlan::InviteBootstrap,
            decide_outbound_session_auth_decision(
                normalize_outbound_session_auth_decision_context(
                    OutboundSessionAuthRawRows {
                        bootstrap_auth_still_valid: false,
                        bound_daemon_matches_remote: false,
                        remote_session_peer_authorized: true,
                    },
                    RequestedSessionAuthPlan::InviteBootstrap,
                    false,
                ),
            ),
        ) == ResolvedSessionAuthPlan::InviteBootstrap,
{
}

} // verus!
