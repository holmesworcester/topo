//! End-to-end transport identity replay tests.
//!
//! These tests verify that `local_transport_targets` (and the underlying
//! `local_transport_creds`) are correctly re-derived by replaying events
//! through the projection pipeline.
//!
//! Two paths are covered:
//! - Bootstrap: InviteSecret + InviteAccepted → MaterializeTransportIdentity(Bootstrap)
//! - PeerShared: create_workspace (peer_secret event) → MaterializeTransportIdentity(PeerShared)

use topo::db::transport_creds::resolve_tenant_transport_target;
use topo::testutil::{Peer, ScenarioHarness};

/// Bootstrap transport target is set on first projection and survives forward replay.
///
/// ScenarioHarness::finish() calls verify_projection_invariants which does:
///   1. Forward replay (clear all tables including local_transport_targets, re-project)
///   2. Fingerprint comparison — local_transport_targets is included in the fingerprint
///   3. Idempotency check
///   4. Reverse-order replay + fingerprint comparison
///   5. Shuffle-order replay + fingerprint comparison
///
/// This test additionally makes an explicit assertion that the transport target
/// is set before harness.finish() so any failure gives a clear, actionable message.
#[test]
fn bootstrap_transport_target_set_and_survives_replay() {
    let alice = Peer::new("alice");
    let harness = ScenarioHarness::new();
    harness.track(&alice);

    // Create invite_secret so InviteAccepted will find key material and emit
    // MaterializeTransportIdentity(InstallBootstrapIdentityFromInviteSecret).
    let invite_private_key = [0x42u8; 32];
    let invite_event_id = [0x42u8; 32];
    alice.create_invite_secret(&invite_event_id, invite_private_key);

    // Create invite_accepted referencing the invite.
    let workspace_id = [0x77u8; 32];
    alice.create_invite_accepted(&invite_event_id, workspace_id);

    // Explicit assertion before replay: bootstrap transport target must be set.
    let db = topo::db::open_connection(&alice.db_path).expect("failed to open db");
    let target = resolve_tenant_transport_target(&db, &alice.identity)
        .expect("failed to query transport target");
    assert!(
        target.is_some(),
        "bootstrap transport target must be set after invite_accepted projection"
    );
    let initial_peer_id = target.unwrap().transport_peer_id;
    assert_eq!(
        initial_peer_id.len(),
        64,
        "transport_peer_id should be 32-byte hex"
    );

    // ScenarioHarness::finish() drives forward/idempotent/reverse/shuffle replay
    // and asserts that local_transport_targets fingerprint matches after each.
    harness.finish();

    // Post-replay assertion: transport target must still be present and identical.
    let db2 = topo::db::open_connection(&alice.db_path).expect("failed to open db after replay");
    let post_target = resolve_tenant_transport_target(&db2, &alice.identity)
        .expect("failed to query transport target after replay");
    assert!(
        post_target.is_some(),
        "bootstrap transport target must still be set after full replay"
    );
    assert_eq!(
        post_target.unwrap().transport_peer_id,
        initial_peer_id,
        "transport_peer_id must be identical after replay (deterministic derivation)"
    );
}

/// PeerShared transport target is set on first projection and survives forward replay.
///
/// create_workspace creates a peer_secret event whose projector emits
/// MaterializeTransportIdentity(InstallPeerSharedIdentityFromSigner).
/// The same replay guarantees verified for bootstrap apply here.
#[test]
fn peershared_transport_target_set_and_survives_replay() {
    let alice = Peer::new_with_identity("alice");
    let harness = ScenarioHarness::new();
    harness.track(&alice);

    // Explicit assertion before replay: peershared transport target must be set.
    let db = topo::db::open_connection(&alice.db_path).expect("failed to open db");
    let target = resolve_tenant_transport_target(&db, &alice.identity)
        .expect("failed to query transport target");
    assert!(
        target.is_some(),
        "peershared transport target must be set after create_workspace"
    );
    let initial_peer_id = target.unwrap().transport_peer_id;
    assert!(!initial_peer_id.is_empty(), "transport_peer_id must be non-empty");
    // PeerShared peer_id should match alice.identity (derived from peer_shared key).
    assert_eq!(
        initial_peer_id, alice.identity,
        "peershared transport_peer_id must match alice.identity"
    );

    // ScenarioHarness::finish() drives forward/idempotent/reverse/shuffle replay.
    harness.finish();

    // Post-replay assertion: transport target must still be present and identical.
    let db2 = topo::db::open_connection(&alice.db_path).expect("failed to open db after replay");
    let post_target = resolve_tenant_transport_target(&db2, &alice.identity)
        .expect("failed to query transport target after replay");
    assert!(
        post_target.is_some(),
        "peershared transport target must still be set after full replay"
    );
    assert_eq!(
        post_target.unwrap().transport_peer_id,
        initial_peer_id,
        "transport_peer_id must be identical after replay (deterministic derivation)"
    );
}
