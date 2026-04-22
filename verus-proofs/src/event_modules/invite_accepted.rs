//! Verified core of the InviteAccepted projector's acceptance decision.
//!
//! `src/event_modules/invite_accepted.rs::build_projector_context` delegates
//! its single gating check — "does the accepted invite's link point at a
//! workspace consistent with the invite itself?" — to the verified core below.
//!
//! This is the ROOT of the "user cannot read messages unless invited" chain.
//! If an InviteAccepted never becomes Valid, no downstream admin/user/peer_shared
//! row can derive from it, so no peer can acquire authority.

use vstd::prelude::*;

verus! {

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteAcceptedAcceptanceCore {
    Valid,
    RejectLinkWorkspaceMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InviteAcceptedAcceptanceFlags {
    /// `ctx.invite_accepted_link_workspace_mismatch_reason.is_none()` —
    /// the accepted invite's link references a workspace consistent with
    /// the invite's embedded workspace_id. Upstream: decision_context
    /// resolves the link and sets the mismatch reason iff inconsistent.
    pub link_workspace_match_ok: bool,
}

pub open spec fn invite_accepted_accepts_spec(
    flags: InviteAcceptedAcceptanceFlags,
) -> InviteAcceptedAcceptanceCore {
    if !flags.link_workspace_match_ok {
        InviteAcceptedAcceptanceCore::RejectLinkWorkspaceMismatch
    } else {
        InviteAcceptedAcceptanceCore::Valid
    }
}

pub fn decide_invite_accepted_acceptance_core(
    flags: InviteAcceptedAcceptanceFlags,
) -> (out: InviteAcceptedAcceptanceCore)
    ensures out == invite_accepted_accepts_spec(flags),
{
    if !flags.link_workspace_match_ok {
        InviteAcceptedAcceptanceCore::RejectLinkWorkspaceMismatch
    } else {
        InviteAcceptedAcceptanceCore::Valid
    }
}

/// Valid ⟹ link workspace matches. This is the root-layer invariant
/// fragment: an accepted invite's workspace binding is SMT-guaranteed
/// to be consistent with the invite it references.
pub proof fn valid_requires_link_workspace_match(flags: InviteAcceptedAcceptanceFlags)
    ensures
        invite_accepted_accepts_spec(flags) == InviteAcceptedAcceptanceCore::Valid
            ==> flags.link_workspace_match_ok,
{
}

pub proof fn mismatch_rejects(flags: InviteAcceptedAcceptanceFlags)
    ensures
        !flags.link_workspace_match_ok
            ==> invite_accepted_accepts_spec(flags)
                == InviteAcceptedAcceptanceCore::RejectLinkWorkspaceMismatch,
{
}

} // verus!
