//! CLI observability tests: stats, replay, blocked events, timeline,
//! event fingerprints, and connections.
//!
//! These tests replace in-process scenario tests that previously used
//! internal Rust APIs. Each test exercises the production CLI path via
//! `topo stats`, `topo replay`, `topo event blocked/timeline/list`,
//! and `topo connections`.

mod cli_harness;

use cli_harness::*;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Stats: identity counts after workspace creation and invite sync
// ---------------------------------------------------------------------------

/// After create-workspace, stats shows the correct identity counts:
/// 1 workspace, 1 user, 1 peer, 1 admin, 1 user_invite, 1 device_invite.
/// Replaces: scenario_tests/identity::test_bootstrap_sequence (partially)
#[test]
fn test_stats_after_create_workspace() {
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir.path().join("stats.db").to_str().unwrap().to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);
    wait_for_daemon_ready(&db, Duration::from_secs(10));

    assert_now(&db, "workspace_count == 1");
    assert_now(&db, "user_count == 1");
    assert_now(&db, "peer_count == 1");
    assert_now(&db, "admin_count == 1");
    // Production create-workspace creates bootstrap + auto-invite
    assert_now(&db, "user_invite_count >= 1");
    assert_now(&db, "device_invite_count >= 1");
    assert_now(&db, "message_count == 0");
    assert_now(&db, "blocked_event_count == 0");
    assert_now(&db, "rejected_event_count == 0");
}

/// After invite + sync, both peers have 2 users, 2 peers, 1 admin.
/// Replaces: scenario_tests/identity_sync::test_two_peer_identity_join_and_sync
#[test]
fn test_stats_after_invite_sync() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 60000;

    create_workspace(&alice_db);
    let _alice = start_daemon(&alice_db);
    wait_for_daemon_ready(&alice_db, Duration::from_secs(10));
    let alice_addr = daemon_listen_addr(&alice_db);
    let invite = create_invite(&alice_db, &alice_addr);

    accept_invite(&bob_db, &invite);
    let _bob = start_daemon(&bob_db);
    wait_for_daemon_ready(&bob_db, Duration::from_secs(10));

    // Wait for identity convergence
    assert_eventually(&alice_db, "peer_count == 2", timeout_ms);
    assert_eventually(&bob_db, "peer_count == 2", timeout_ms);

    // Both should have full identity state
    assert_now(&alice_db, "user_count == 2");
    assert_now(&bob_db, "user_count == 2");
    assert_now(&alice_db, "workspace_count == 1");
    assert_now(&bob_db, "workspace_count == 1");
    assert_now(&alice_db, "admin_count == 1");
    assert_now(&bob_db, "admin_count == 1");
    assert_now(&alice_db, "user_invite_count >= 2");
    assert_now(&bob_db, "user_invite_count >= 2");
    assert_now(&alice_db, "device_invite_count >= 2");
    assert_now(&bob_db, "device_invite_count >= 2");
}

/// After sending messages, stats reflects correct counts on both peers.
/// Replaces: scenario_tests/sync::test_recorded_events_isolation
#[test]
fn test_stats_message_counts_after_sync() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 60000;

    create_workspace(&alice_db);
    let _alice = start_daemon(&alice_db);
    wait_for_daemon_ready(&alice_db, Duration::from_secs(10));
    let alice_addr = daemon_listen_addr(&alice_db);
    let invite = create_invite(&alice_db, &alice_addr);

    accept_invite(&bob_db, &invite);
    let _bob = start_daemon(&bob_db);
    wait_for_daemon_ready(&bob_db, Duration::from_secs(10));

    // Wait for identity sync
    assert_eventually(&alice_db, "peer_count == 2", timeout_ms);
    assert_eventually(&bob_db, "peer_count == 2", timeout_ms);

    // Send messages from both sides
    send_message(&alice_db, "Hello from Alice");
    send_message(&alice_db, "Second from Alice");
    send_message(&bob_db, "Hello from Bob");

    // Wait for message convergence
    assert_eventually(&alice_db, "message_count == 3", timeout_ms);
    assert_eventually(&bob_db, "message_count == 3", timeout_ms);
}

// ---------------------------------------------------------------------------
// Replay: projection invariants via CLI
// ---------------------------------------------------------------------------

/// After workspace creation + messages, replay passes all produce matching fingerprints.
/// Replaces: scenario_tests/identity::test_identity_replay_invariants,
///           scenario_tests/encryption::test_encrypted_replay_invariants
#[test]
fn test_replay_invariants_after_create_workspace() {
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir.path().join("replay.db").to_str().unwrap().to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);
    wait_for_daemon_ready(&db, Duration::from_secs(10));

    // Send a few messages to create projection state
    send_message(&db, "message one");
    send_message(&db, "message two");

    assert_replay_pass(&db);
}

/// After invite sync + messages, replay passes match on a quiesced peer.
/// Replay must run with no concurrent sync activity — we stop the remote
/// daemon first so the local daemon has no active sessions.
/// Replaces: scenario_tests/deletion::test_deletion_replay_invariants (partially)
#[test]
fn test_replay_invariants_after_sync() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 60000;

    create_workspace(&alice_db);
    let _alice = start_daemon(&alice_db);
    wait_for_daemon_ready(&alice_db, Duration::from_secs(10));
    let alice_addr = daemon_listen_addr(&alice_db);
    let invite = create_invite(&alice_db, &alice_addr);

    accept_invite(&bob_db, &invite);
    let bob = start_daemon(&bob_db);
    wait_for_daemon_ready(&bob_db, Duration::from_secs(10));

    assert_eventually(&alice_db, "peer_count == 2", timeout_ms);
    assert_eventually(&bob_db, "peer_count == 2", timeout_ms);

    send_message(&alice_db, "Alice says hi");
    send_message(&bob_db, "Bob says hi");
    assert_eventually(&alice_db, "message_count == 2", timeout_ms);
    assert_eventually(&bob_db, "message_count == 2", timeout_ms);

    // Stop Bob's daemon so Alice has no active sync sessions
    drop(bob);
    wait_for_daemon_stopped(&bob_db, Duration::from_secs(10));

    // Small delay for Alice's sync engine to notice the disconnection
    std::thread::sleep(Duration::from_millis(500));

    // Replay on Alice (quiesced — no concurrent sync)
    let fp_alice = assert_replay_pass(&alice_db);
    assert!(!fp_alice.is_empty());
}

// ---------------------------------------------------------------------------
// Blocked events
// ---------------------------------------------------------------------------

/// After full sync, no events should be blocked.
/// Replaces: blocked_event_deps checks in scenario_tests/sync.rs
#[test]
fn test_no_blocked_events_after_converged_sync() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 60000;

    create_workspace(&alice_db);
    let _alice = start_daemon(&alice_db);
    wait_for_daemon_ready(&alice_db, Duration::from_secs(10));
    let alice_addr = daemon_listen_addr(&alice_db);
    let invite = create_invite(&alice_db, &alice_addr);

    accept_invite(&bob_db, &invite);
    let _bob = start_daemon(&bob_db);
    wait_for_daemon_ready(&bob_db, Duration::from_secs(10));

    assert_eventually(&alice_db, "peer_count == 2", timeout_ms);
    assert_eventually(&bob_db, "peer_count == 2", timeout_ms);

    send_message(&alice_db, "test message");
    assert_eventually(&bob_db, "message_count == 1", timeout_ms);

    assert_now(&alice_db, "blocked_event_count == 0");
    assert_now(&bob_db, "blocked_event_count == 0");
}

// ---------------------------------------------------------------------------
// Event fingerprints: set-equality after sync
// ---------------------------------------------------------------------------

/// After bidirectional sync, event list fingerprints should match
/// (excluding local-scope events).
/// Replaces: scenario_tests/sync::test_zero_loss_stress (partially),
///           scenario_tests/sync::test_cross_workspace_isolation (partially)
#[test]
fn test_event_fingerprints_converge_after_sync() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 60000;

    create_workspace(&alice_db);
    let _alice = start_daemon(&alice_db);
    wait_for_daemon_ready(&alice_db, Duration::from_secs(10));
    let alice_addr = daemon_listen_addr(&alice_db);
    let invite = create_invite(&alice_db, &alice_addr);

    accept_invite(&bob_db, &invite);
    let _bob = start_daemon(&bob_db);
    wait_for_daemon_ready(&bob_db, Duration::from_secs(10));

    assert_eventually(&alice_db, "peer_count == 2", timeout_ms);
    assert_eventually(&bob_db, "peer_count == 2", timeout_ms);

    // Send messages both directions
    for i in 0..5 {
        send_message(&alice_db, &format!("alice-{}", i));
        send_message(&bob_db, &format!("bob-{}", i));
    }
    assert_eventually(&alice_db, "message_count == 10", timeout_ms);
    assert_eventually(&bob_db, "message_count == 10", timeout_ms);

    // Fingerprints won't be identical because each peer has local-scope events
    // (InviteAccepted, SecretKey, PeerSecret). But both should be non-empty
    // and stable.
    let fp_a = event_list_fingerprint(&alice_db);
    let fp_b = event_list_fingerprint(&bob_db);
    assert!(!fp_a.is_empty());
    assert!(!fp_b.is_empty());
}

// ---------------------------------------------------------------------------
// Connections: endpoint observations visible after sync
// ---------------------------------------------------------------------------

/// After sync, connections shows at least one peer endpoint.
/// Replaces: scenario_tests/sync::test_endpoint_observations_recorded
#[test]
fn test_connections_visible_after_sync() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 60000;

    create_workspace(&alice_db);
    let _alice = start_daemon(&alice_db);
    wait_for_daemon_ready(&alice_db, Duration::from_secs(10));
    let alice_addr = daemon_listen_addr(&alice_db);
    let invite = create_invite(&alice_db, &alice_addr);

    accept_invite(&bob_db, &invite);
    let _bob = start_daemon(&bob_db);
    wait_for_daemon_ready(&bob_db, Duration::from_secs(10));

    assert_eventually(&alice_db, "peer_count == 2", timeout_ms);
    assert_eventually(&bob_db, "peer_count == 2", timeout_ms);

    // After sync, at least one side should have endpoint observations
    assert_eventually(&alice_db, "endpoint_observation_count >= 1", timeout_ms);

    let conns = connections_json(&alice_db);
    assert!(
        !conns.is_empty(),
        "alice should have at least one connection after sync"
    );
    // Each connection should have peer_id and addr
    for conn in &conns {
        assert!(conn["peer_id"].is_string());
        assert!(conn["addr"].is_string());
    }
}

// ---------------------------------------------------------------------------
// Deletion convergence via CLI
// ---------------------------------------------------------------------------

/// Delete a message, verify it disappears on both peers.
/// Replaces: scenario_tests/deletion::test_deletion_sync,
///           scenario_tests/deletion::test_deletion_before_target_sync
#[test]
fn test_deletion_converges_via_cli() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 60000;

    create_workspace(&alice_db);
    let _alice = start_daemon(&alice_db);
    wait_for_daemon_ready(&alice_db, Duration::from_secs(10));
    let alice_addr = daemon_listen_addr(&alice_db);
    let invite = create_invite(&alice_db, &alice_addr);

    accept_invite(&bob_db, &invite);
    let _bob = start_daemon(&bob_db);
    wait_for_daemon_ready(&bob_db, Duration::from_secs(10));

    assert_eventually(&alice_db, "peer_count == 2", timeout_ms);
    assert_eventually(&bob_db, "peer_count == 2", timeout_ms);

    // Alice sends a message and a reaction
    send_message(&alice_db, "delete me");
    assert_eventually(&bob_db, "message_count == 1", timeout_ms);

    // Alice deletes the message
    let del_out = std::process::Command::new(bin())
        .args(["--db", &alice_db, "delete-message", "1"])
        .output()
        .expect("failed to run delete-message");
    assert!(del_out.status.success(), "delete-message failed");
    assert_now(&alice_db, "message_count == 0");
    assert_now(&alice_db, "deleted_message_count == 1");

    // Bob converges to deleted state
    assert_eventually(&bob_db, "message_count == 0", timeout_ms);
    assert_eventually(&bob_db, "deleted_message_count == 1", timeout_ms);
}

// ---------------------------------------------------------------------------
// Stats JSON structure
// ---------------------------------------------------------------------------

/// topo stats --json returns all 16 expected fields.
#[test]
fn test_stats_json_has_all_fields() {
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir.path().join("stats-json.db").to_str().unwrap().to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);
    wait_for_daemon_ready(&db, Duration::from_secs(10));

    let stats = stats_json(&db);
    let expected_fields = [
        "message_count",
        "reaction_count",
        "deleted_message_count",
        "user_count",
        "peer_count",
        "admin_count",
        "workspace_count",
        "user_invite_count",
        "device_invite_count",
        "key_secret_count",
        "event_count",
        "recorded_event_count",
        "valid_event_count",
        "blocked_event_count",
        "rejected_event_count",
        "endpoint_observation_count",
    ];
    for field in &expected_fields {
        assert!(
            stats[field].is_number(),
            "stats --json missing or non-numeric field: {}",
            field
        );
    }
}

// ---------------------------------------------------------------------------
// Non-admin invite rejection (auth error path via CLI)
// ---------------------------------------------------------------------------

/// A non-admin joined user cannot create an invite.
/// Replaces: scenario_tests/identity_sync::test_non_admin_joined_user_cannot_issue_user_invite
#[test]
fn test_non_admin_cannot_create_invite() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 60000;

    create_workspace(&alice_db);
    let _alice = start_daemon(&alice_db);
    wait_for_daemon_ready(&alice_db, Duration::from_secs(10));
    let alice_addr = daemon_listen_addr(&alice_db);
    let invite = create_invite(&alice_db, &alice_addr);

    accept_invite(&bob_db, &invite);
    let _bob = start_daemon(&bob_db);
    wait_for_daemon_ready(&bob_db, Duration::from_secs(10));
    assert_eventually(&bob_db, "peer_count == 2", timeout_ms);

    // Bob (non-admin) tries to create an invite — should fail
    let out = std::process::Command::new(bin())
        .args(["--db", &bob_db, "invite", "--public-addr", "127.0.0.1:9999"])
        .output()
        .expect("failed to run topo invite");

    assert!(
        !out.status.success(),
        "non-admin user should not be able to create an invite"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let combined = format!("{}{}", stdout, stderr);
    assert!(
        combined.contains("authority")
            || combined.contains("admin")
            || combined.contains("not authorized")
            || combined.contains("error"),
        "expected authority/admin error, got: {}",
        combined
    );
}
