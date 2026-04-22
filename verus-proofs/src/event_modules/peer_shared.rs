//! Verified core of the PeerShared projector's acceptance decision.
//!
//! `src/event_modules/peer_shared/projector.rs::build_projector_context` — the
//! context-load stage that gates PeerShared projection — delegates its two
//! structural checks to the verified core below, and the emission stage is
//! split off so the "Valid → exactly these writes" contract is stated
//! separately from the accept/reject decision.
//!
//! This is one step of the "user cannot read messages unless invited" chain.
//! The claim at THIS layer:
//!
//!   PeerShared accepted  ⟺  user_event_id has no authority mismatch
//!                          ∧  endpoint_shared binding exists
//!
//! The upstream "no user mismatch" flag is itself computed by the already-
//! verified `decide_peer_shared_authority_plan` core — so the chain
//! transitively requires the claimed user to live inside the tenant's
//! admin/user chain. A peer whose identity isn't in that chain CANNOT
//! produce an accepted PeerShared.
//!
//! Upstream of this: `decide_peer_shared_authority_plan` (already verified,
//! in verus-proofs/src/state/projection/decision_context.rs).
//! Downstream: KeyShared acceptance (not yet verified) requires a valid
//! PeerShared recipient; Encrypted decryption requires a content Secret,
//! which requires a KeyShared.

use vstd::prelude::*;

verus! {

/// Reason-tagged outcome for the PeerShared acceptance decision.
/// Runtime maps these to the richer context-load error strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerSharedAcceptanceCore {
    Valid,
    RejectUserAuthorityMismatch,
    RejectMissingEndpointBinding,
}

/// Primitive-flag struct (pattern #3 from the refactor plan).
/// These are the only two facts that gate PeerShared acceptance at this
/// seam. The flags are extracted by the runtime's context loader from
/// real SQL-backed state; the verified decision operates on booleans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerSharedAcceptanceFlags {
    /// `ctx.peer_shared_user_mismatch_reason.is_none()` — the claimed
    /// `user_event_id` corresponds to a valid user in the tenant's
    /// admin/user chain. Upstream: `decide_peer_shared_authority_plan`
    /// (already verified) projected `Ready` for this user_event_id.
    pub user_authority_ok: bool,
    /// `ctx.peer_shared_endpoint_id.is_some()` — the `endpoint_shared_event_id`
    /// referenced by the PeerShared has a projected endpoint_shared row.
    pub endpoint_binding_present: bool,
}

// ---------------------------------------------------------------------------
// Decision spec and verified exec fn.

pub open spec fn peer_shared_accepts_spec(
    flags: PeerSharedAcceptanceFlags,
) -> PeerSharedAcceptanceCore {
    if !flags.user_authority_ok {
        PeerSharedAcceptanceCore::RejectUserAuthorityMismatch
    } else if !flags.endpoint_binding_present {
        PeerSharedAcceptanceCore::RejectMissingEndpointBinding
    } else {
        PeerSharedAcceptanceCore::Valid
    }
}

pub fn decide_peer_shared_acceptance_core(
    flags: PeerSharedAcceptanceFlags,
) -> (out: PeerSharedAcceptanceCore)
    ensures out == peer_shared_accepts_spec(flags),
{
    if !flags.user_authority_ok {
        PeerSharedAcceptanceCore::RejectUserAuthorityMismatch
    } else if !flags.endpoint_binding_present {
        PeerSharedAcceptanceCore::RejectMissingEndpointBinding
    } else {
        PeerSharedAcceptanceCore::Valid
    }
}

// ---------------------------------------------------------------------------
// Structural properties — SMT-proven.

/// THE KEY THEOREM for this seam:
/// A Valid PeerShared acceptance strictly requires a valid user authority
/// AND an endpoint binding. Contrapositive of this is the invariant
/// fragment we care about for the top-level "user cannot read messages
/// unless invited" property: if the user is not in the authority chain
/// (i.e. not invited), PeerShared is NOT accepted.
pub proof fn valid_requires_user_authority_and_endpoint(flags: PeerSharedAcceptanceFlags)
    ensures
        peer_shared_accepts_spec(flags) == PeerSharedAcceptanceCore::Valid
            ==> flags.user_authority_ok && flags.endpoint_binding_present,
{
}

/// Contrapositive, stated explicitly for composition: if the claimed user
/// is NOT in the tenant's authority chain, PeerShared acceptance is Rejected.
pub proof fn no_user_authority_means_rejected(flags: PeerSharedAcceptanceFlags)
    ensures
        !flags.user_authority_ok
            ==> peer_shared_accepts_spec(flags)
                == PeerSharedAcceptanceCore::RejectUserAuthorityMismatch,
{
}

/// Similarly for endpoint binding — the seam rejects if the endpoint_shared
/// referenced by the PeerShared isn't projected. This closes the gap where
/// someone with a valid user identity but no resolvable endpoint would
/// still be kept off the peers_shared table.
pub proof fn user_authority_without_endpoint_is_rejected(flags: PeerSharedAcceptanceFlags)
    ensures
        (flags.user_authority_ok && !flags.endpoint_binding_present)
            ==> peer_shared_accepts_spec(flags)
                == PeerSharedAcceptanceCore::RejectMissingEndpointBinding,
{
}

/// Reject-reason precedence. Pinned so reordering the runtime's context
/// checks (user-first vs. endpoint-first) without updating the spec fails
/// SMT or the runtime tests that consume the reason strings.
pub proof fn reject_reason_precedence(flags: PeerSharedAcceptanceFlags)
    ensures
        !flags.user_authority_ok
            ==> peer_shared_accepts_spec(flags)
                == PeerSharedAcceptanceCore::RejectUserAuthorityMismatch,
        (flags.user_authority_ok && !flags.endpoint_binding_present)
            ==> peer_shared_accepts_spec(flags)
                == PeerSharedAcceptanceCore::RejectMissingEndpointBinding,
{
}

// ---------------------------------------------------------------------------
// Pattern #2: write-op structure for the Valid branch.
//
// A Valid PeerShared emits exactly one write: a row in `peers_shared`.
// The table name and column count are pinned by verified constants here.
// Runtime asserts the shape against these at debug time.

pub open spec fn required_valid_write_op_count_spec(
    decision: PeerSharedAcceptanceCore,
) -> nat {
    if decision == PeerSharedAcceptanceCore::Valid { 1 } else { 0 }
}

pub fn required_valid_write_op_count(decision: PeerSharedAcceptanceCore) -> (n: u8)
    ensures
        n as nat == required_valid_write_op_count_spec(decision),
        decision == PeerSharedAcceptanceCore::Valid ==> n == 1,
        decision != PeerSharedAcceptanceCore::Valid ==> n == 0,
{
    match decision {
        PeerSharedAcceptanceCore::Valid => 1,
        _ => 0,
    }
}

pub open spec fn required_valid_table_name_spec() -> &'static str {
    "peers_shared"
}

pub fn required_valid_table_name() -> (name: &'static str)
    ensures name == required_valid_table_name_spec(),
{
    "peers_shared"
}

/// Column count for the `peers_shared` write. Used by the runtime in a
/// debug_assert to catch schema drift.
pub open spec fn required_valid_column_count_spec() -> nat { 8 }

pub fn required_valid_column_count() -> (n: u8)
    ensures n as nat == required_valid_column_count_spec(),
{
    8
}

} // verus!
