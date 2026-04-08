//! Formal verification of active bootstrap fallback selection.

use vstd::prelude::*;

verus! {

pub enum BootstrapSessionFallbackDecision {
    RejectRequiresLocalBootstrapPhase,
    RejectMissing,
    UseFallback,
    RejectAmbiguous,
    RejectAlreadyLocalWorkspaceCandidate,
}

pub open spec fn decide_bootstrap_session_fallback(
    require_local_bootstrap_phase: bool,
    local_bootstrap_phase: bool,
    candidate_count: nat,
    unique_candidate_workspace_already_local_before_candidate: bool,
) -> BootstrapSessionFallbackDecision {
    if require_local_bootstrap_phase && !local_bootstrap_phase {
        BootstrapSessionFallbackDecision::RejectRequiresLocalBootstrapPhase
    } else if candidate_count == 0 {
        BootstrapSessionFallbackDecision::RejectMissing
    } else if candidate_count == 1 && unique_candidate_workspace_already_local_before_candidate {
        BootstrapSessionFallbackDecision::RejectAlreadyLocalWorkspaceCandidate
    } else if candidate_count == 1 {
        BootstrapSessionFallbackDecision::UseFallback
    } else {
        BootstrapSessionFallbackDecision::RejectAmbiguous
    }
}

proof fn bootstrap_fallback_requires_local_bootstrap_phase()
    ensures
        decide_bootstrap_session_fallback(true, false, 1, false)
            == BootstrapSessionFallbackDecision::RejectRequiresLocalBootstrapPhase,
{
}

proof fn bootstrap_fallback_rejects_unique_same_workspace_candidate()
    ensures
        decide_bootstrap_session_fallback(false, false, 1, true)
            == BootstrapSessionFallbackDecision::RejectAlreadyLocalWorkspaceCandidate,
{
}

proof fn bootstrap_fallback_accepts_unique_nonlocal_candidate(local_bootstrap_phase: bool)
    ensures
        decide_bootstrap_session_fallback(false, local_bootstrap_phase, 1, false)
            == BootstrapSessionFallbackDecision::UseFallback,
{
}

proof fn bootstrap_fallback_rejects_ambiguous_or_missing(local_bootstrap_phase: bool)
    ensures
        decide_bootstrap_session_fallback(false, local_bootstrap_phase, 0, false)
            == BootstrapSessionFallbackDecision::RejectMissing,
        decide_bootstrap_session_fallback(false, local_bootstrap_phase, 2, false)
            == BootstrapSessionFallbackDecision::RejectAmbiguous,
{
}

} // verus!
