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

} // verus!
