//! Formal verification of active bootstrap fallback selection.

use vstd::prelude::*;

verus! {

pub struct BootstrapFallbackInviteRawRows {
    pub candidate_count: nat,
    pub unique_candidate_workspace_already_local_before_candidate: bool,
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

pub open spec fn normalize_bootstrap_fallback_invite_decision_context(
    raw_rows: BootstrapFallbackInviteRawRows,
) -> BootstrapFallbackInviteDecisionContext {
    if raw_rows.candidate_count == 0 {
        BootstrapFallbackInviteDecisionContext::MissingCandidate
    } else if raw_rows.candidate_count == 1 {
        BootstrapFallbackInviteDecisionContext::UniqueCandidate {
            workspace_already_local_before_candidate:
                raw_rows.unique_candidate_workspace_already_local_before_candidate,
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

proof fn bootstrap_fallback_normalizes_missing_candidates()
    ensures
        normalize_bootstrap_fallback_invite_decision_context(BootstrapFallbackInviteRawRows {
            candidate_count: 0,
            unique_candidate_workspace_already_local_before_candidate: false,
        }) == BootstrapFallbackInviteDecisionContext::MissingCandidate,
        decide_bootstrap_fallback_invite_plan(
            normalize_bootstrap_fallback_invite_decision_context(BootstrapFallbackInviteRawRows {
                candidate_count: 0,
                unique_candidate_workspace_already_local_before_candidate: false,
            })
        ) == BootstrapFallbackInvitePlan::RejectMissingCandidate,
{
}

proof fn bootstrap_fallback_rejects_unique_same_workspace_candidate()
    ensures
        normalize_bootstrap_fallback_invite_decision_context(BootstrapFallbackInviteRawRows {
            candidate_count: 1,
            unique_candidate_workspace_already_local_before_candidate: true,
        }) == (BootstrapFallbackInviteDecisionContext::UniqueCandidate {
            workspace_already_local_before_candidate: true,
        }),
        decide_bootstrap_fallback_invite_plan(
            normalize_bootstrap_fallback_invite_decision_context(BootstrapFallbackInviteRawRows {
                candidate_count: 1,
                unique_candidate_workspace_already_local_before_candidate: true,
            })
        ) == BootstrapFallbackInvitePlan::RejectAlreadyLocalWorkspaceCandidate,
{
}

proof fn bootstrap_fallback_accepts_unique_nonlocal_candidate()
    ensures
        decide_bootstrap_fallback_invite_plan(
            normalize_bootstrap_fallback_invite_decision_context(BootstrapFallbackInviteRawRows {
                candidate_count: 1,
                unique_candidate_workspace_already_local_before_candidate: false,
            })
        ) == BootstrapFallbackInvitePlan::UseInvite,
{
}

proof fn bootstrap_fallback_rejects_ambiguous_candidates(candidate_count: nat)
    requires candidate_count > 1
    ensures
        normalize_bootstrap_fallback_invite_decision_context(BootstrapFallbackInviteRawRows {
            candidate_count,
            unique_candidate_workspace_already_local_before_candidate: false,
        }) == BootstrapFallbackInviteDecisionContext::AmbiguousCandidate,
        decide_bootstrap_fallback_invite_plan(
            normalize_bootstrap_fallback_invite_decision_context(BootstrapFallbackInviteRawRows {
                candidate_count,
                unique_candidate_workspace_already_local_before_candidate: false,
            })
        ) == BootstrapFallbackInvitePlan::RejectAmbiguousCandidate,
{
}

pub struct BootstrapSessionFallbackRawRows {
    pub require_local_bootstrap_phase: bool,
    pub local_bootstrap_phase: bool,
    pub candidate_count: nat,
    pub unique_candidate_workspace_already_local_before_candidate: bool,
}

pub enum BootstrapSessionFallbackDecisionContext {
    RejectRequiresLocalBootstrapPhase,
    MissingCandidate,
    UniqueCandidate {
        workspace_already_local_before_candidate: bool,
    },
    AmbiguousCandidate,
}

pub enum BootstrapSessionFallbackPlan {
    RejectRequiresLocalBootstrapPhase,
    RejectMissingCandidate,
    UseFallback,
    RejectAmbiguousCandidate,
    RejectAlreadyLocalWorkspaceCandidate,
}

pub open spec fn normalize_bootstrap_session_fallback_decision_context(
    raw_rows: BootstrapSessionFallbackRawRows,
) -> BootstrapSessionFallbackDecisionContext {
    if raw_rows.require_local_bootstrap_phase && !raw_rows.local_bootstrap_phase {
        BootstrapSessionFallbackDecisionContext::RejectRequiresLocalBootstrapPhase
    } else if raw_rows.candidate_count == 0 {
        BootstrapSessionFallbackDecisionContext::MissingCandidate
    } else if raw_rows.candidate_count == 1 {
        BootstrapSessionFallbackDecisionContext::UniqueCandidate {
            workspace_already_local_before_candidate:
                raw_rows.unique_candidate_workspace_already_local_before_candidate,
        }
    } else {
        BootstrapSessionFallbackDecisionContext::AmbiguousCandidate
    }
}

pub open spec fn decide_bootstrap_session_fallback_plan(
    context: BootstrapSessionFallbackDecisionContext,
) -> BootstrapSessionFallbackPlan {
    match context {
        BootstrapSessionFallbackDecisionContext::RejectRequiresLocalBootstrapPhase => {
            BootstrapSessionFallbackPlan::RejectRequiresLocalBootstrapPhase
        }
        BootstrapSessionFallbackDecisionContext::MissingCandidate => {
            BootstrapSessionFallbackPlan::RejectMissingCandidate
        }
        BootstrapSessionFallbackDecisionContext::UniqueCandidate {
            workspace_already_local_before_candidate,
        } => {
            if workspace_already_local_before_candidate {
                BootstrapSessionFallbackPlan::RejectAlreadyLocalWorkspaceCandidate
            } else {
                BootstrapSessionFallbackPlan::UseFallback
            }
        }
        BootstrapSessionFallbackDecisionContext::AmbiguousCandidate => {
            BootstrapSessionFallbackPlan::RejectAmbiguousCandidate
        }
    }
}

proof fn bootstrap_session_fallback_rejects_when_local_bootstrap_phase_required_but_missing()
    ensures
        decide_bootstrap_session_fallback_plan(
            normalize_bootstrap_session_fallback_decision_context(
                BootstrapSessionFallbackRawRows {
                    require_local_bootstrap_phase: true,
                    local_bootstrap_phase: false,
                    candidate_count: 1,
                    unique_candidate_workspace_already_local_before_candidate: false,
                },
            )
        ) == BootstrapSessionFallbackPlan::RejectRequiresLocalBootstrapPhase,
{
}

proof fn bootstrap_session_fallback_rejects_unique_same_workspace_candidate()
    ensures
        decide_bootstrap_session_fallback_plan(
            normalize_bootstrap_session_fallback_decision_context(
                BootstrapSessionFallbackRawRows {
                    require_local_bootstrap_phase: false,
                    local_bootstrap_phase: false,
                    candidate_count: 1,
                    unique_candidate_workspace_already_local_before_candidate: true,
                },
            )
        ) == BootstrapSessionFallbackPlan::RejectAlreadyLocalWorkspaceCandidate,
{
}

proof fn bootstrap_session_fallback_accepts_unique_nonlocal_candidate()
    ensures
        decide_bootstrap_session_fallback_plan(
            normalize_bootstrap_session_fallback_decision_context(
                BootstrapSessionFallbackRawRows {
                    require_local_bootstrap_phase: false,
                    local_bootstrap_phase: false,
                    candidate_count: 1,
                    unique_candidate_workspace_already_local_before_candidate: false,
                },
            )
        ) == BootstrapSessionFallbackPlan::UseFallback,
{
}

proof fn bootstrap_session_fallback_rejects_ambiguous_candidates(candidate_count: nat)
    requires candidate_count > 1
    ensures
        decide_bootstrap_session_fallback_plan(
            normalize_bootstrap_session_fallback_decision_context(
                BootstrapSessionFallbackRawRows {
                    require_local_bootstrap_phase: false,
                    local_bootstrap_phase: false,
                    candidate_count,
                    unique_candidate_workspace_already_local_before_candidate: false,
                },
            )
        ) == BootstrapSessionFallbackPlan::RejectAmbiguousCandidate,
{
}

} // verus!
