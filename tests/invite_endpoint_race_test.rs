//! Integration test: invite bootstrap must complete even when mDNS discovery
//! is active on the same network.
//!
//! The root-cause race condition: mDNS discovers the inviter's peer_id and
//! creates a Discovery connect worker before the bootstrap refresher runs.
//! Discovery has higher static precedence, so it can suppress or cancel the
//! Bootstrap connect worker. Only the Bootstrap worker carries the invite
//! fallback TLS cert the inviter will accept during bootstrap, so if it is
//! suppressed the invitee is permanently stuck.
//!
//! This test creates an inviter with mDNS and joins multiple invitees (also
//! with mDNS) to maximize the probability that at least one hits the race.
//! Without the fix the race triggers frequently enough that a 4-invitee run is
//! a stable repro.

mod cli_invite_discovery_common;

use cli_invite_discovery_common::*;

/// Invite multiple peers with mDNS active on all sides and verify every
/// invitee completes bootstrap sync and can exchange events bidirectionally.
#[test]
#[cfg(feature = "discovery")]
fn invite_bootstrap_completes_with_mdns_active() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let timeout_ms = 120_000;

    // --- inviter (alice) ---
    create_workspace(&alice_db);
    let _alice = start_discovery_daemon(&alice_db);
    let bootstrap_eid = send_message(&alice_db, "pre-bootstrap-marker");
    assert_event_visible_on_all(&[&alice_db], &bootstrap_eid, timeout_ms);

    let invite_link = create_invite(&alice_db, &daemon_listen_addr(&alice_db));

    // --- 4 invitees, all with mDNS ---
    let n_invitees = 4;
    let mut peers: Vec<StartedCliPeer> = Vec::with_capacity(n_invitees);
    for i in 0..n_invitees {
        let peer = start_joined_cli_peer_via_discovery(
            &tmpdir,
            &format!("peer{i}.db"),
            &invite_link,
            &format!("user{i}"),
            &format!("device{i}"),
        );
        peers.push(peer);
    }

    // Every invitee must see the marker event that existed before they joined.
    // This proves bootstrap sync completed — the event can only arrive through
    // a successful sync session.
    for (i, peer) in peers.iter().enumerate() {
        assert_event_visible_on_all(&[&peer.db], &bootstrap_eid, timeout_ms);
        assert_identity_eventually_materialized(&peer.db, timeout_ms);

        let reply_eid = send_message(&peer.db, &format!("reply-from-peer{i}"));
        assert_event_visible_on_all(&[&alice_db], &reply_eid, timeout_ms);
    }

    // Send a fresh message from alice and verify all invitees see it.
    let live_eid = send_message(&alice_db, "post-bootstrap-live-message");
    for peer in &peers {
        assert_eventually(
            &peer.db,
            &format!("has_event:{} >= 1", live_eid),
            timeout_ms,
        );
    }
}
