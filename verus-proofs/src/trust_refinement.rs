//! Trust refinement — connects abstract state machine to concrete runtime.
//!
//! This module bridges the gap between the abstract `TrustState` model
//! (in `trust_state_machine.rs`) and the verified runtime functions
//! (in `session_auth.rs`, `signer.rs`, `tenant_isolation.rs`, etc.).
//!
//! Structure:
//!   1. **Concrete state types** — model what the runtime DB actually stores.
//!   2. **Abstraction function** — maps concrete → abstract state.
//!   3. **Proved refinement lemmas** — where we CAN prove the correspondence.
//!   4. **Axioms** — where we CANNOT prove but state the assumption clearly.
//!      Each axiom is tagged with `AXIOM:` and a suggested property-based test.
//!   5. **Connection to existing verified functions** — reuses session_auth,
//!      signer, tenant_isolation, writeop_idempotency proofs.

use vstd::prelude::*;
use crate::trust_state_machine::*;
use crate::runtime::transport::session_auth;
use crate::state::projection::signer;
use crate::event_modules::registry::EventTypeCode;

verus! {

// ═══════════════════════════════════════════════════════════════════════════
// 1. Concrete state types (modeling runtime DB rows)
// ═══════════════════════════════════════════════════════════════════════════

/// Trust source tag — mirrors the runtime's trust_source column in
/// the transport_trust table.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TrustSource {
    PeerShared,
    Bootstrap,
    Pending,
}

/// One row in the transport_trust table.
/// Runtime: `src/state/db/transport_trust.rs`
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TransportTrustRow {
    pub spki: nat,
    pub source: TrustSource,
}

/// Concrete per-peer state as the runtime actually stores it.
pub struct ConcretePerPeerState {
    pub trust_rows: Seq<TransportTrustRow>,
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. Abstraction function: Concrete → Abstract
// ═══════════════════════════════════════════════════════════════════════════

/// Extract the set of SPKIs with a given trust source from concrete rows.
pub open spec fn spkis_with_source(rows: Seq<TransportTrustRow>, source: TrustSource) -> Set<nat>
{
    Set::new(|spki: nat| exists|i: int| 0 <= i < rows.len()
        && (#[trigger] rows[i]).spki == spki
        && rows[i].source == source)
}

/// All SPKIs present in any trust row (regardless of source).
pub open spec fn all_spkis(rows: Seq<TransportTrustRow>) -> Set<nat>
{
    Set::new(|spki: nat| exists|i: int| 0 <= i < rows.len()
        && (#[trigger] rows[i]).spki == spki)
}

/// The abstraction function: maps concrete per-peer state to abstract
/// PeerTrustState. This is the core of the refinement.
///
/// NOTE: `invite_derived` is set to `all_spkis(rows)` — every SPKI
/// that appears in any trust row is considered invite-derived.
/// This is sound because of AXIOM_TRUST_WRITES_REQUIRE_INVITE below.
pub open spec fn abstract_from_concrete(c: &ConcretePerPeerState) -> PeerTrustState {
    PeerTrustState {
        peer_shared_trust: spkis_with_source(c.trust_rows, TrustSource::PeerShared),
        bootstrap_trust: spkis_with_source(c.trust_rows, TrustSource::Bootstrap),
        pending_trust: spkis_with_source(c.trust_rows, TrustSource::Pending),
        // Ghost state: all SPKIs in any trust row are invite-derived.
        // This is the key axiom (see below).
        invite_derived: all_spkis(c.trust_rows),
        bootstrap_insert_time: Map::empty(), // not tracked in concrete state
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. Refinement lemma: abstraction preserves the per-peer invariant
// ═══════════════════════════════════════════════════════════════════════════

/// The abstraction function always produces a state satisfying peer_inv.
/// This is because each source-filtered set is a subset of all_spkis.
///
/// This is PROVED, not axiomatized — the subset relationship follows
/// directly from the set definitions.
proof fn lemma_abstraction_satisfies_peer_inv(c: ConcretePerPeerState)
    ensures peer_inv(&abstract_from_concrete(&c)),
{
    let abs = abstract_from_concrete(&c);

    // Prove: peer_shared_trust ⊆ invite_derived
    assert forall|spki: nat| abs.peer_shared_trust.contains(spki)
        implies abs.invite_derived.contains(spki) by {
        // If spki is in peer_shared_trust, there exists a row with
        // source == PeerShared. That same row means spki is in all_spkis.
        let i = choose|i: int| 0 <= i < c.trust_rows.len()
            && c.trust_rows[i].spki == spki
            && c.trust_rows[i].source == TrustSource::PeerShared;
        assert(c.trust_rows[i].spki == spki);
    };

    // Prove: bootstrap_trust ⊆ invite_derived
    assert forall|spki: nat| abs.bootstrap_trust.contains(spki)
        implies abs.invite_derived.contains(spki) by {
        let i = choose|i: int| 0 <= i < c.trust_rows.len()
            && c.trust_rows[i].spki == spki
            && c.trust_rows[i].source == TrustSource::Bootstrap;
        assert(c.trust_rows[i].spki == spki);
    };

    // Prove: pending_trust ⊆ invite_derived
    assert forall|spki: nat| abs.pending_trust.contains(spki)
        implies abs.invite_derived.contains(spki) by {
        let i = choose|i: int| 0 <= i < c.trust_rows.len()
            && c.trust_rows[i].spki == spki
            && c.trust_rows[i].source == TrustSource::Pending;
        assert(c.trust_rows[i].spki == spki);
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Refinement: concrete authorized == abstract authorized
// ═══════════════════════════════════════════════════════════════════════════

/// Concrete authorization check: is the SPKI in any trust row?
pub open spec fn concrete_authorized(c: &ConcretePerPeerState, spki: nat) -> bool {
    exists|i: int| 0 <= i < c.trust_rows.len()
        && (#[trigger] c.trust_rows[i]).spki == spki
}

/// The concrete and abstract auth checks agree.
proof fn lemma_auth_correspondence(c: ConcretePerPeerState, spki: nat)
    ensures concrete_authorized(&c, spki) == authorized(&abstract_from_concrete(&c), spki),
{
    let abs = abstract_from_concrete(&c);
    if concrete_authorized(&c, spki) {
        let i = choose|i: int| 0 <= i < c.trust_rows.len()
            && c.trust_rows[i].spki == spki;
        match c.trust_rows[i].source {
            TrustSource::PeerShared => {
                assert(abs.peer_shared_trust.contains(spki));
            },
            TrustSource::Bootstrap => {
                assert(abs.bootstrap_trust.contains(spki));
            },
            TrustSource::Pending => {
                assert(abs.pending_trust.contains(spki));
            },
        }
    } else {
        // If no concrete row, then no source-filtered set contains it.
        assert forall|i: int| 0 <= i < c.trust_rows.len()
            implies c.trust_rows[i].spki != spki by {};
        // So none of the abstract sets contain it.
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. End-to-end: concrete state → abstract inv → session_auth rejects
// ═══════════════════════════════════════════════════════════════════════════

/// If an SPKI has no concrete trust row, session_auth rejects it.
/// This chains: concrete → abstract → invariant → session_auth_spec.
proof fn lemma_no_concrete_row_means_session_rejects(
    c: ConcretePerPeerState,
    spki: nat,
)
    requires !concrete_authorized(&c, spki),
    ensures
        matches!(
            session_auth::peer_shared_auth_spec(
                authorized(&abstract_from_concrete(&c), spki),
                true, true,
            ),
            session_auth::AuthResult::Rejected
        ),
        matches!(
            session_auth::invite_bootstrap_auth_spec(
                true, true, true,
                authorized(&abstract_from_concrete(&c), spki),
                true,
            ),
            session_auth::AuthResult::Rejected
        ),
{
    lemma_auth_correspondence(c, spki);
    // authorized() is false, so both auth specs reject.
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. Connection to signer.rs: only invite-chain types are valid signers
// ═══════════════════════════════════════════════════════════════════════════

/// The signer type classification ensures that only invite-chain event
/// types (Workspace, UserInvite, DeviceInvite, User, PeerShared, Admin)
/// are valid signers. Non-identity events CANNOT produce trust rows.
///
/// This is PROVED via the spec_is_valid_signer_type spec function.
proof fn lemma_only_identity_types_are_signers()
    ensures
        // Content/envelope types are NOT valid signers
        !signer::spec_is_valid_signer_type(EventTypeCode::Message),
        !signer::spec_is_valid_signer_type(EventTypeCode::Reaction),
        !signer::spec_is_valid_signer_type(EventTypeCode::Encrypted),
        !signer::spec_is_valid_signer_type(EventTypeCode::Signed),
        // Identity types ARE valid signers
        signer::spec_is_valid_signer_type(EventTypeCode::Workspace),
        signer::spec_is_valid_signer_type(EventTypeCode::UserInvite),
        signer::spec_is_valid_signer_type(EventTypeCode::PeerShared),
{
}

// ═══════════════════════════════════════════════════════════════════════════
// 7. AXIOMS — assumptions we cannot prove in Verus
// ═══════════════════════════════════════════════════════════════════════════
//
// Each axiom below is a property we ASSUME but cannot verify in Verus.
// They are stated as spec functions returning bool, with documentation
// explaining what would need to be true and how to test it.

/// AXIOM_TRUST_WRITES_REQUIRE_INVITE:
/// The only allowed production trust-table write families are:
///   1. `src/event_modules/peer_shared/queries.rs` — `PeerShared` projector
///      (steady-state transport trust)
///   2. `src/event_modules/workspace/queries.rs` — `WorkspaceInviteAccepted`
///      projector (bootstrap + `peers_shared` on accept)
///   3. `src/state/db/transport_trust.rs` — DB helper layer called exclusively
///      by the above projectors
///
/// All three write families are inside the projector pipeline, which requires
/// a valid signed invite-chain event.
///
/// `session_auth.rs` has `INSERT INTO peers_shared` inside `#[cfg(test)]` only
/// (test fixtures, not production).
///
/// CI gate: `scripts/check_trust_write_sites.sh` verifies this with
/// Python-based test-block exclusion.
pub open spec fn axiom_trust_writes_require_invite() -> bool { true }

/// AXIOM_DB_FAITHFULNESS:
/// SQLite correctly stores and retrieves transport_trust rows.
/// The rows returned by `authorized_fingerprints_from_db()` exactly
/// match what was previously written by projectors.
///
/// Why we can't prove this: SQLite is an external dependency.
///
/// PROPERTY-BASED TEST: After each projector write, immediately
/// read back the row and assert equality. The existing pipeline
/// integration tests exercise this path.
pub open spec fn axiom_db_faithfulness() -> bool { true }

/// AXIOM_CRYPTO_UNFORGEABILITY:
/// An adversary without the invite private key cannot produce a
/// valid Ed25519 signature that passes the signer verification
/// check in the projection pipeline.
///
/// Why we can't prove this: Ed25519 security is a mathematical
/// hardness assumption, not a code property.
///
/// TEST: This is not property-testable in the traditional sense.
/// The ed25519-dalek crate has its own test suite and is widely
/// audited. The projector signer check is verified by signer.rs.
pub open spec fn axiom_crypto_unforgeability() -> bool { true }

/// AXIOM_SPKI_COLLISION_RESISTANCE:
/// Two distinct Ed25519 public keys produce distinct SPKI fingerprints.
///
/// Why we can't prove this: depends on the hash function's collision
/// resistance (likely BLAKE3 or SHA-256).
///
/// PROPERTY-BASED TEST: Generate N random Ed25519 keypairs, compute
/// SPKI fingerprints, assert all distinct.
pub open spec fn axiom_spki_collision_resistance() -> bool { true }

/// AXIOM_AUTH_CHECK_COMPLETENESS:
/// Every inbound connection attempt passes through either
/// `peer_shared_auth_decide` or `invite_bootstrap_auth_decide`
/// (verified in session_auth.rs). No code path bypasses these.
///
/// Why we can't prove this: whole-program control flow property.
///
/// PROPERTY-BASED TEST: Instrument `inbound_auth_decide` with a
/// counter. After running the full CLI test suite, assert that
/// every accepted connection incremented the counter.
///
/// Architecture-strengthening note:
/// `session_auth.rs` is the single entry point for inbound auth decisions,
/// it delegates decision logic to `topo_verus_proofs` verified functions,
/// and `scripts/check_trust_write_sites.sh` provides a CI gate ensuring the
/// trust-write-site invariant used by AXIOM_TRUST_WRITES_REQUIRE_INVITE.
pub open spec fn axiom_auth_check_completeness() -> bool { true }

// ═══════════════════════════════════════════════════════════════════════════
// 8. Full end-to-end statement
// ═══════════════════════════════════════════════════════════════════════════

/// **THE FULL THEOREM (with all assumptions explicit):**
///
/// Given:
///   - AXIOM_TRUST_WRITES_REQUIRE_INVITE (only projectors write trust rows)
///   - AXIOM_DB_FAITHFULNESS (SQLite stores/retrieves correctly)
///   - AXIOM_CRYPTO_UNFORGEABILITY (Ed25519 is secure)
///   - AXIOM_SPKI_COLLISION_RESISTANCE (fingerprints don't collide)
///   - AXIOM_AUTH_CHECK_COMPLETENESS (all connections go through auth)
///
/// Then:
///   For any concrete per-peer state where an SPKI has no trust row,
///   both the PeerShared and InviteBootstrap auth paths reject it.
///
/// Chain of reasoning:
///   1. No trust row → concrete_authorized == false (by definition)
///   2. concrete_authorized == abstract authorized (lemma_auth_correspondence)
///   3. abstract authorized == false → session_auth_spec rejects
///      (lemma_no_concrete_row_means_session_rejects)
///   4. The abstract model's invariant holds for all reachable states
///      (theorem_no_auth_without_invite in trust_state_machine.rs)
///   5. Axioms 1-5 justify that the abstract model faithfully represents
///      the runtime (this is the refinement gap, stated explicitly).
///
/// Steps 1-4 are machine-checked by Z3. Step 5 is stated as axioms
/// with suggested property-based tests.
proof fn full_end_to_end_theorem(c: ConcretePerPeerState, spki: nat)
    requires
        !concrete_authorized(&c, spki),
        // The axioms are assumed true:
        axiom_trust_writes_require_invite(),
        axiom_db_faithfulness(),
        axiom_crypto_unforgeability(),
        axiom_spki_collision_resistance(),
        axiom_auth_check_completeness(),
    ensures
        // PeerShared auth path rejects
        matches!(
            session_auth::peer_shared_auth_spec(
                authorized(&abstract_from_concrete(&c), spki),
                true, true,
            ),
            session_auth::AuthResult::Rejected
        ),
        // InviteBootstrap auth path rejects
        matches!(
            session_auth::invite_bootstrap_auth_spec(
                true, true, true,
                authorized(&abstract_from_concrete(&c), spki),
                true,
            ),
            session_auth::AuthResult::Rejected
        ),
{
    lemma_no_concrete_row_means_session_rejects(c, spki);
}

} // verus!
