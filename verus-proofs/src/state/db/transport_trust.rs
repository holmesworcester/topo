//! Verified core of the transport-trust filter's removal-aware authorization.
//!
//! `src/state/db/transport_trust.rs::is_peer_shared_spki` (and the wider CTE
//! at `tenant_authorized_cte!`) filter out fingerprints belonging to peers
//! that are in `removed_entities`, either directly (their peer_shared
//! event_id is removed) or transitively (their user_event_id is removed
//! with removal_type='user').
//!
//! The verified decision `decide_peer_shared_authz_core` formalizes this
//! filter over three primitive bool flags. A debug assertion in the runtime
//! compares the SQL result to the verified decision computed independently
//! from the three flags; drift (e.g. a regression that drops one of the
//! NOT EXISTS clauses) fires the assert in debug tests.
//!
//! This is step 3 of the "revocation is immediate and monotonic" chain.

use vstd::prelude::*;

verus! {

/// Given the three primitive facts about a peer_shared row, is it
/// currently authorized for the given tenant?
///
/// - `has_matching_row`: a `peers_shared` row exists with the requested
///   `(recorded_by, transport_fingerprint)`.
/// - `peer_in_removed_entities`: that row's event_id appears as a
///   `target_event_id` in `removed_entities` for the same tenant.
/// - `user_in_removed_entities_as_user`: that row's `user_event_id`
///   (if non-null) appears in `removed_entities` with `removal_type='user'`.
pub open spec fn peer_shared_authz_spec(
    has_matching_row: bool,
    peer_in_removed_entities: bool,
    user_in_removed_entities_as_user: bool,
) -> bool {
    has_matching_row
    && !peer_in_removed_entities
    && !user_in_removed_entities_as_user
}

/// Runtime-callable verified decision. The runtime queries the three flags
/// independently (via separate simple presence queries on peers_shared and
/// removed_entities) and calls this to cross-check the fused CTE result.
pub fn decide_peer_shared_authz_core(
    has_matching_row: bool,
    peer_in_removed_entities: bool,
    user_in_removed_entities_as_user: bool,
) -> (ok: bool)
    ensures
        ok == peer_shared_authz_spec(
            has_matching_row,
            peer_in_removed_entities,
            user_in_removed_entities_as_user,
        ),
{
    has_matching_row
        && !peer_in_removed_entities
        && !user_in_removed_entities_as_user
}

// ---------------------------------------------------------------------------
// Structural invariants — SMT-proven.

/// A fingerprint is authorized ONLY if its peer_shared row is not in
/// removed_entities (direct removal). This is "revocation is immediate"
/// at the transport-authorization layer: as soon as the removal row
/// appears, the fingerprint loses authorization.
pub proof fn authz_blocks_direct_removal(
    has_matching_row: bool,
    user_in_removed_entities_as_user: bool,
)
    ensures
        !peer_shared_authz_spec(has_matching_row, true, user_in_removed_entities_as_user),
{
}

/// A fingerprint is authorized ONLY if its user is not removed-as-user
/// (transitive removal). User-level removal cascades to every peer_shared
/// derived from that user.
pub proof fn authz_blocks_user_removal(
    has_matching_row: bool,
    peer_in_removed_entities: bool,
)
    ensures
        !peer_shared_authz_spec(has_matching_row, peer_in_removed_entities, true),
{
}

/// Monotonicity under the primitive flags: if the three flags go from
/// (true, false, false) (authorized) to any state where a removal flag
/// is true, authorization switches to false. Captures the irreversible
/// direction: removal flags flipping true monotonically drives authz false.
pub proof fn authz_monotone_under_removal_flag_increase(
    has_matching_row: bool,
    peer_removed_before: bool,
    peer_removed_after: bool,
    user_removed_before: bool,
    user_removed_after: bool,
)
    requires
        // Removals only accumulate — flag can only go from false to true.
        peer_removed_before ==> peer_removed_after,
        user_removed_before ==> user_removed_after,
    ensures
        // If authorized before became false after a removal flag flipped,
        // authorization stays false.
        !peer_shared_authz_spec(has_matching_row, peer_removed_before, user_removed_before)
            ==> !peer_shared_authz_spec(
                has_matching_row, peer_removed_after, user_removed_after,
            ),
        // And the key direction: authorization can only lose, never gain,
        // under removal-flag monotonicity.
        peer_shared_authz_spec(has_matching_row, peer_removed_after, user_removed_after)
            ==> peer_shared_authz_spec(
                has_matching_row, peer_removed_before, user_removed_before,
            ),
{
}

} // verus!
