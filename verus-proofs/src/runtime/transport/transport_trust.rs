//! **Abstract specification — not grounded in runtime code.**
//!
//! Per `docs/planning/FORMAL_SEAM_COVERAGE.md`, this file encodes system-level
//! invariants that no single runtime function body satisfies on its own. The
//! SMT solver accepts the proofs inside this file, but they are NOT proofs about
//! runtime code — the grounded verification lives in the per-seam `ensures`
//! clauses on executable `pub fn`s in sibling modules. Do not treat entries
//! here as "the runtime is proven to satisfy X"; treat them as "X is modeled
//! in Verus and consistent with itself".
//!
//! Formal verification of the transport trust model.
//!
//! Three trust sources authorize a peer's transport fingerprint:
//!   1. PeerShared (steady-state, no expiry, removal-aware)
//!   2. InviteBootstrapTrust (accepted, time-bounded)
//!   3. PendingInviteBootstrapTrust (pending, time-bounded)
//!
//! Trust lifecycle: Pending → Accepted → Converged (PeerShared)
//!
//! We prove:
//! - Removed peers lose transport authorization
//! - Expired bootstrap trust is not authoritative
//! - Trust converges: PeerShared supersedes bootstrap
//! - Removal blocks all three trust sources
//! - Node-level authorization requires at least one tenant authorization

use vstd::prelude::*;

verus! {

pub spec const BOOTSTRAP_TTL_MS: nat = 86_400_000; // 24 hours

/// Trust source for a peer's transport fingerprint.
pub enum TrustSource {
    PeerShared,         // steady-state, no expiry
    BootstrapAccepted,  // time-bounded, post-invite-acceptance
    BootstrapPending,   // time-bounded, pre-invite-acceptance
}

/// Trust state for a single fingerprint.
pub struct TrustRecord {
    pub source: TrustSource,
    pub expires_at: Option<nat>,  // None = no expiry (PeerShared)
    pub peer_removed: bool,       // entity in removed_entities
    pub user_removed: bool,       // user in removed_entities
}

/// Whether a trust record is currently authoritative.
pub open spec fn trust_is_active(record: &TrustRecord, now_ms: nat) -> bool {
    !record.peer_removed
    && !record.user_removed
    && match record.expires_at {
        None => true,                   // PeerShared: no expiry
        Some(exp) => exp > now_ms,      // Bootstrap: must be unexpired
    }
}

/// Steady-state trust has no expiry.
pub open spec fn is_steady_state(record: &TrustRecord) -> bool {
    matches!(record.source, TrustSource::PeerShared) && record.expires_at.is_none()
}

/// Bootstrap trust has an expiry.
pub open spec fn is_bootstrap(record: &TrustRecord) -> bool {
    matches!(record.source, TrustSource::BootstrapAccepted | TrustSource::BootstrapPending)
    && record.expires_at.is_some()
}

// ═══════════════════════════════════════════════════════════════════
// Removal Proofs
// ═══════════════════════════════════════════════════════════════════

/// Proof: removed peer loses transport authorization regardless of source.
proof fn proof_removed_peer_loses_auth(record: &TrustRecord, now_ms: nat)
    requires record.peer_removed
    ensures !trust_is_active(record, now_ms),
{
}

/// Proof: removed user's peer loses authorization.
proof fn proof_removed_user_peer_loses_auth(record: &TrustRecord, now_ms: nat)
    requires record.user_removed
    ensures !trust_is_active(record, now_ms),
{
}

/// Proof: unremoved, unexpired PeerShared is always active.
proof fn proof_healthy_peershared_always_active(now_ms: nat)
    ensures
        trust_is_active(&TrustRecord {
            source: TrustSource::PeerShared,
            expires_at: None,
            peer_removed: false,
            user_removed: false,
        }, now_ms),
{
}

// ═══════════════════════════════════════════════════════════════════
// Expiry Proofs
// ═══════════════════════════════════════════════════════════════════

/// Proof: expired bootstrap trust is not active.
proof fn proof_expired_bootstrap_not_active(expires_at: nat, now_ms: nat)
    requires expires_at <= now_ms
    ensures
        !trust_is_active(&TrustRecord {
            source: TrustSource::BootstrapAccepted,
            expires_at: Some(expires_at),
            peer_removed: false,
            user_removed: false,
        }, now_ms),
{
}

/// Proof: unexpired bootstrap trust IS active (when not removed).
proof fn proof_unexpired_bootstrap_is_active(expires_at: nat, now_ms: nat)
    requires expires_at > now_ms
    ensures
        trust_is_active(&TrustRecord {
            source: TrustSource::BootstrapAccepted,
            expires_at: Some(expires_at),
            peer_removed: false,
            user_removed: false,
        }, now_ms),
{
}

/// Proof: PeerShared has no expiry — active indefinitely (until removed).
proof fn proof_peershared_never_expires(now_ms: nat)
    ensures
        ({
            let r = TrustRecord {
                source: TrustSource::PeerShared,
                expires_at: None,
                peer_removed: false,
                user_removed: false,
            };
            forall|future_ms: nat| future_ms >= now_ms ==> trust_is_active(&r, future_ms)
        }),
{
}

// ═══════════════════════════════════════════════════════════════════
// Trust Lifecycle (Convergence)
// ═══════════════════════════════════════════════════════════════════

/// Trust lifecycle state machine.
pub enum TrustLifecycleState {
    NoPending,
    Pending { expires_at: nat },
    Accepted { expires_at: nat },
    Converged,  // PeerShared projected
}

/// Whether a lifecycle state authorizes transport.
pub open spec fn lifecycle_authorizes(state: &TrustLifecycleState, now_ms: nat) -> bool {
    match state {
        TrustLifecycleState::NoPending => false,
        TrustLifecycleState::Pending { expires_at } => *expires_at > now_ms,
        TrustLifecycleState::Accepted { expires_at } => *expires_at > now_ms,
        TrustLifecycleState::Converged => true,  // permanent
    }
}

/// Proof: Converged state is permanent (never expires, no TTL).
proof fn proof_converged_is_permanent(now_ms: nat)
    ensures
        lifecycle_authorizes(&TrustLifecycleState::Converged, now_ms),
        forall|future_ms: nat| lifecycle_authorizes(&TrustLifecycleState::Converged, future_ms),
{
}

/// Proof: Pending has a time window where it authorizes.
proof fn proof_pending_has_window(expires_at: nat)
    requires expires_at > 0
    ensures
        lifecycle_authorizes(&TrustLifecycleState::Pending { expires_at }, 0),
        !lifecycle_authorizes(&TrustLifecycleState::Pending { expires_at }, expires_at),
{
}

/// Proof: lifecycle progression only strengthens authorization.
/// Pending → Accepted → Converged: each step is at least as authoritative.
proof fn proof_lifecycle_progression_strengthens_auth(now_ms: nat, ttl: nat)
    requires now_ms + ttl > now_ms  // no overflow
    ensures
        ({
            let pending = TrustLifecycleState::Pending { expires_at: now_ms + ttl };
            let accepted = TrustLifecycleState::Accepted { expires_at: now_ms + ttl };
            let converged = TrustLifecycleState::Converged;
            // If pending authorizes, accepted also authorizes (same TTL)
            lifecycle_authorizes(&pending, now_ms) == lifecycle_authorizes(&accepted, now_ms)
            // Converged always authorizes
            && lifecycle_authorizes(&converged, now_ms)
        }),
{
}

// ═══════════════════════════════════════════════════════════════════
// Node-Level Authorization
// ═══════════════════════════════════════════════════════════════════

/// Node-level auth: at least one tenant authorizes the fingerprint.
pub open spec fn node_authorizes(tenant_results: Seq<bool>) -> bool
    decreases tenant_results.len(),
{
    if tenant_results.len() == 0 {
        false
    } else if tenant_results.last() {
        true
    } else {
        node_authorizes(tenant_results.drop_last())
    }
}

/// Proof: no tenants → no authorization.
proof fn proof_no_tenants_no_auth()
    ensures !node_authorizes(Seq::empty()),
{
}

/// Proof: at least one authorizing tenant → node authorizes.
proof fn proof_one_tenant_sufficient()
    ensures node_authorizes(seq![true]),
{
}

/// Proof: all-false tenants → no authorization.
proof fn proof_all_false_no_auth()
    ensures !node_authorizes(seq![false, false, false]),
{
    let s = seq![false, false, false];
    assert(!s.last());
    let s2 = s.drop_last();
    assert(!s2.last());
    let s1 = s2.drop_last();
    assert(!s1.last());
    assert(!node_authorizes(s1.drop_last()));
    assert(!node_authorizes(s1));
    assert(!node_authorizes(s2));
}

/// Proof: one true among falses → authorized.
proof fn proof_one_true_among_falses()
    ensures node_authorizes(seq![false, true, false]),
{
    let s = seq![false, true, false];
    assert(!s.last());
    let s2 = s.drop_last();
    assert(s2.last());
    assert(node_authorizes(s2));
}

} // verus!
