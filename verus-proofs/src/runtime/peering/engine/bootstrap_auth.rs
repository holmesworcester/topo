//! Bootstrap-auth fallback decision — verified core.
//!
//! Runtime `normalize_bootstrap_session_fallback_decision_context` sorts+dedups
//! `Vec<BootstrapSessionFallbackCandidate>` (String-bearing structs). That sort/dedup logic
//! stays runtime-only — it can't cross into verus-proofs without importing String-heavy types.
//! What we verify here is the *decision* step: given a classified tag (post-normalization),
//! produce the right Plan tag. The runtime adapter carries the `BootstrapSessionFallback`
//! payload through for the UseFallback case.

use vstd::prelude::*;

verus! {

// ───────────── Invite bootstrap fallback (simpler seam) ─────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootstrapFallbackInviteRawRows {
    pub candidate_row_count: u32,
    pub distinct_candidate_count: u32,
    pub unique_distinct_candidate_workspace_already_local_before_candidate: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapFallbackInviteDecisionContext {
    MissingCandidate,
    UniqueCandidate { workspace_already_local_before_candidate: bool },
    AmbiguousCandidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapFallbackInvitePlan {
    RejectMissingCandidate,
    UseInvite,
    RejectAmbiguousCandidate,
    RejectAlreadyLocalWorkspaceCandidate,
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
    context: BootstrapFallbackInviteDecisionContext,
) -> (plan: BootstrapFallbackInvitePlan)
    ensures
        match context {
            BootstrapFallbackInviteDecisionContext::MissingCandidate =>
                plan == BootstrapFallbackInvitePlan::RejectMissingCandidate,
            BootstrapFallbackInviteDecisionContext::UniqueCandidate { workspace_already_local_before_candidate } =>
                if workspace_already_local_before_candidate {
                    plan == BootstrapFallbackInvitePlan::RejectAlreadyLocalWorkspaceCandidate
                } else {
                    plan == BootstrapFallbackInvitePlan::UseInvite
                },
            BootstrapFallbackInviteDecisionContext::AmbiguousCandidate =>
                plan == BootstrapFallbackInvitePlan::RejectAmbiguousCandidate,
        },
{
    match context {
        BootstrapFallbackInviteDecisionContext::MissingCandidate =>
            BootstrapFallbackInvitePlan::RejectMissingCandidate,
        BootstrapFallbackInviteDecisionContext::UniqueCandidate {
            workspace_already_local_before_candidate,
        } => {
            if workspace_already_local_before_candidate {
                BootstrapFallbackInvitePlan::RejectAlreadyLocalWorkspaceCandidate
            } else {
                BootstrapFallbackInvitePlan::UseInvite
            }
        }
        BootstrapFallbackInviteDecisionContext::AmbiguousCandidate =>
            BootstrapFallbackInvitePlan::RejectAmbiguousCandidate,
    }
}

// ───────────── Session-level bootstrap fallback (decision core only) ─────────────
//
// The *normalize* step (sort+dedup Vec<BootstrapSessionFallbackCandidate>) is String-heavy
// and stays in the runtime. Here we verify the post-normalization decision: given a core
// classification tag, produce the right core plan tag. Runtime adapter carries the
// BootstrapSessionFallback payload.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapSessionFallbackCoreContext {
    RejectRequiresLocalBootstrapPhase,
    MissingCandidate,
    UniqueCandidate { workspace_already_local_before_candidate: bool },
    AmbiguousCandidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapSessionFallbackCorePlan {
    RejectRequiresLocalBootstrapPhase,
    RejectMissingCandidate,
    UseFallback,
    RejectAmbiguousCandidate,
    RejectAlreadyLocalWorkspaceCandidate,
}

pub fn decide_bootstrap_session_fallback_core_plan(
    context: BootstrapSessionFallbackCoreContext,
) -> (plan: BootstrapSessionFallbackCorePlan)
    ensures
        match context {
            BootstrapSessionFallbackCoreContext::RejectRequiresLocalBootstrapPhase =>
                plan == BootstrapSessionFallbackCorePlan::RejectRequiresLocalBootstrapPhase,
            BootstrapSessionFallbackCoreContext::MissingCandidate =>
                plan == BootstrapSessionFallbackCorePlan::RejectMissingCandidate,
            BootstrapSessionFallbackCoreContext::UniqueCandidate { workspace_already_local_before_candidate } =>
                if workspace_already_local_before_candidate {
                    plan == BootstrapSessionFallbackCorePlan::RejectAlreadyLocalWorkspaceCandidate
                } else {
                    plan == BootstrapSessionFallbackCorePlan::UseFallback
                },
            BootstrapSessionFallbackCoreContext::AmbiguousCandidate =>
                plan == BootstrapSessionFallbackCorePlan::RejectAmbiguousCandidate,
        },
{
    match context {
        BootstrapSessionFallbackCoreContext::RejectRequiresLocalBootstrapPhase =>
            BootstrapSessionFallbackCorePlan::RejectRequiresLocalBootstrapPhase,
        BootstrapSessionFallbackCoreContext::MissingCandidate =>
            BootstrapSessionFallbackCorePlan::RejectMissingCandidate,
        BootstrapSessionFallbackCoreContext::UniqueCandidate {
            workspace_already_local_before_candidate,
        } => {
            if workspace_already_local_before_candidate {
                BootstrapSessionFallbackCorePlan::RejectAlreadyLocalWorkspaceCandidate
            } else {
                BootstrapSessionFallbackCorePlan::UseFallback
            }
        }
        BootstrapSessionFallbackCoreContext::AmbiguousCandidate =>
            BootstrapSessionFallbackCorePlan::RejectAmbiguousCandidate,
    }
}

} // verus!
