//! KeyShared acceptance gate — **retargeted** security theorem.
//!
//! Shape per `docs/planning/ACCESS_CONTROL_PROOF_RETARGETING.md`:
//!
//! > *Content-key material reaches only invited peers.*
//!
//! Rather than proving the runtime's decryption call refuses to run for
//! non-invited peers (which is a lie — a peer holding the key can
//! decrypt with any AES-GCM implementation), we prove a structural
//! property over the event graph:
//!
//! > **Valid KeyShared ⟹ recipient peer is admin-chained to the
//! > workspace.**
//!
//! Combined with the trusted cryptographic primitive "only the
//! recipient's private key can unwrap the wrapped_key" (AES-GCM /
//! X25519 unforgeability — out of scope), this implies: *the only
//! peers who can extract the content key are invited peers.*
//!
//! The unwrap/decryption gate (the current `encrypted.rs` proof) stays
//! in-tree as **operational correctness**, not as a security claim.
//!
//! This module defines the primitive-flag bundle, the verified
//! acceptance spec, the exec-fn decider with `ensures`, and the top-
//! level theorem. Runtime extraction of the flags lives in
//! `src/state/projection/decision_context.rs` as part of the KeyShared
//! DepFacts/GuardFacts migration (follow-up once LocalKeySecret lands
//! — see `docs/planning/LOCAL_KEY_SECRET_MIGRATION.md`).

use crate::state::projection::decision_context::PeerSharedAuthorityPlanCore;
use vstd::prelude::*;

verus! {

/// Primitive-flag bundle for KeyShared acceptance.
///
/// Splits the acceptance criterion into two groups:
///
/// 1. **Structural well-formedness.** Frontier hash matches the parent
///    refs; parent refs are in canonical (sorted, unique) order; the
///    delivery_target_id is a deterministic hash of
///    `(key_event_id, frontier_hash, recipient_event_id,
///    unwrap_key_event_id)`; the `key_event_id` dep resolved to a
///    Valid KeyRotation-kind event.
///
/// 2. **Recipient-side authority.** The claimed `recipient_event_id`
///    resolves to a Valid `peers_shared` row (dep-fact), and that
///    row's user is admin-chained in the workspace via the existing
///    `decide_peer_shared_authority_plan_core`.
///
/// The runtime extracts these booleans from its DepFacts + GuardFacts
/// bundle and passes the struct to `decide_key_shared_accepts_core`.
/// Verus proves acceptance iff all flags hold; the top-level theorem
/// `valid_key_shared_has_invited_recipient` lifts that to a claim
/// about recipient authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeySharedAcceptanceFlags {
    /// Frontier hash matches the canonical-order hash of the frontier
    /// refs carried by the event.
    pub frontier_hash_matches: bool,
    /// Frontier refs are in canonical (sorted, unique) order.
    pub frontier_refs_canonical: bool,
    /// `delivery_target_id` matches the deterministic hash of
    /// `(key_event_id, frontier_hash, recipient_event_id,
    ///   unwrap_key_event_id)`.
    pub delivery_target_matches: bool,
    /// `recipient_event_id` dep resolved to a Valid `peers_shared`
    /// row.
    ///
    /// Note: under the LocalKeySecret migration, `key_event_id` is no
    /// longer a dep — it names the KeySecret the recipient will
    /// derive by unwrapping. The acceptance gate therefore carries no
    /// `has_key_event_dep` / `key_event_kind_ok` flags; the structural
    /// claim is entirely about recipient authority.
    pub recipient_peer_shared_valid: bool,
    /// The recipient `peers_shared` row's user is admin-chained in
    /// the workspace, per the shared PeerSharedAuthority verified
    /// plan. Ready = authority match; Reject = every other case.
    pub recipient_user_authority_plan: PeerSharedAuthorityPlanCore,
}

/// Binary acceptance decision: Valid or Reject. Non-Ready authority
/// plans collapse into Reject — there is no third option at this
/// layer. (Upstream dep-blocking is handled before the acceptance
/// gate runs; this fn assumes the dep facts have resolved.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySharedAcceptanceCore {
    Valid,
    Reject,
}

/// Specification: KeyShared is Valid iff every flag holds and the
/// recipient-user authority plan is `Ready`.
pub open spec fn key_shared_accepts_spec(
    flags: KeySharedAcceptanceFlags,
) -> KeySharedAcceptanceCore {
    if flags.frontier_hash_matches
        && flags.frontier_refs_canonical
        && flags.delivery_target_matches
        && flags.recipient_peer_shared_valid
        && flags.recipient_user_authority_plan == PeerSharedAuthorityPlanCore::Ready
    {
        KeySharedAcceptanceCore::Valid
    } else {
        KeySharedAcceptanceCore::Reject
    }
}

/// Runtime-callable decider. The `ensures` SMT-links the output to
/// `key_shared_accepts_spec`, so any Valid the runtime finalizes
/// corresponds to a flag bundle the spec also accepts.
pub fn decide_key_shared_accepts_core(
    flags: KeySharedAcceptanceFlags,
) -> (out: KeySharedAcceptanceCore)
    ensures out == key_shared_accepts_spec(flags),
{
    let authority_ready = match flags.recipient_user_authority_plan {
        PeerSharedAuthorityPlanCore::Ready => true,
        PeerSharedAuthorityPlanCore::Reject => false,
    };
    if flags.frontier_hash_matches
        && flags.frontier_refs_canonical
        && flags.delivery_target_matches
        && flags.recipient_peer_shared_valid
        && authority_ready
    {
        KeySharedAcceptanceCore::Valid
    } else {
        KeySharedAcceptanceCore::Reject
    }
}

/// THE RETARGETED SECURITY THEOREM.
///
/// `key_shared_accepts_spec(flags) = Valid` implies:
///
///   - the recipient dep resolved to a Valid `peers_shared` row, AND
///   - that row's user is admin-chained in the workspace
///     (`PeerSharedAuthorityPlanCore::Ready`).
///
/// Composing with the existing `decide_peer_shared_authority_plan_core`
/// proof, `Ready` means the signer's peer_shared resolves to a
/// DeviceInvite whose `authority_event_id` matches the claimed user —
/// i.e. the recipient is authority-chained to the workspace.
///
/// Composing further with the trusted cryptographic primitive
/// "X25519/AES-GCM unwrap can only succeed with the recipient's
/// private key," only the admin-chained recipient can extract the
/// content key. That is the full content-key-sharing security
/// invariant in structural form.
pub proof fn valid_key_shared_has_invited_recipient(
    flags: KeySharedAcceptanceFlags,
)
    ensures
        key_shared_accepts_spec(flags) == KeySharedAcceptanceCore::Valid
            ==> flags.recipient_peer_shared_valid
                && flags.recipient_user_authority_plan
                    == PeerSharedAuthorityPlanCore::Ready,
{
    // Follows directly from the definition of `key_shared_accepts_spec`:
    // Valid requires both conjuncts literally.
}

/// Complementary theorem: a Reject verdict from the spec surfaces
/// exactly one of the failure flags. Useful downstream for
/// diagnostic-string mapping; does not affect the security claim.
pub proof fn reject_implies_some_flag_false(flags: KeySharedAcceptanceFlags)
    ensures
        key_shared_accepts_spec(flags) == KeySharedAcceptanceCore::Reject
            ==> !flags.frontier_hash_matches
                || !flags.frontier_refs_canonical
                || !flags.delivery_target_matches
                || !flags.recipient_peer_shared_valid
                || flags.recipient_user_authority_plan
                    != PeerSharedAuthorityPlanCore::Ready,
{
}

} // verus!
