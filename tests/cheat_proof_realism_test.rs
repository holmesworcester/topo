//! Cheat-proof realism tests.
//!
//! These tests enforce an invite-only, daemon-first workflow:
//! - require invite-only autodial behavior,
//! - require daemon CLI invite lifecycle support.

mod cli_harness;

use cli_harness::*;

fn bootstrap_alice_and_invite(tmpdir: &tempfile::TempDir) -> (String, String, String, u16, u16) {
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();

    let alice_port = random_port();
    let bob_port = random_port();

    // Create workspace for Alice (identity chain)
    create_workspace(&alice_db);

    // Start Alice's daemon so we can create invites via RPC
    let _alice_daemon = start_daemon_on_port(&alice_db, alice_port);

    // Create invite via daemon RPC
    let invite_link = topo_create_invite_retry(&alice_db, &format!("127.0.0.1:{}", alice_port));

    // Kill temporary daemon — caller will start their own
    drop(_alice_daemon);

    (alice_db, bob_db, invite_link, alice_port, bob_port)
}

#[test]
fn test_invite_only_daemons_should_autodial_without_manual_connect() {
    let tmpdir = tempfile::tempdir().unwrap();
    let (alice_db, bob_db, invite_link, alice_port, bob_port) = bootstrap_alice_and_invite(&tmpdir);

    let _alice = start_daemon_on_port(&alice_db, alice_port);
    accept_invite_lightweight(&bob_db, &invite_link);
    let _bob = start_daemon_on_port(&bob_db, bob_port);

    // Desired behavior: after invite acceptance, daemons should autodial based on
    // persisted bootstrap/discovery state, with no manual connect flag.
    let bob_event_id = topo_send_retry(&bob_db, "invite-only-autodial-required");
    let out = topo_assert_eventually(
        &alice_db,
        &format!("has_event:{} >= 1", bob_event_id),
        8_000,
    );
    assert!(
        out.status.success(),
        "invite-only autodial realism gap: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn test_daemon_cli_invite_lifecycle_works_without_restart() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();

    let alice_port = random_port();
    let bob_port = random_port();

    // Create workspace for Alice and start her daemon.
    create_workspace(&alice_db);
    let _alice = start_daemon_on_port(&alice_db, alice_port);

    // Create invite while Alice's daemon is running (via RPC).
    let invite_link = topo_create_invite_retry(&alice_db, &format!("127.0.0.1:{}", alice_port));

    // Bob accepts invite before starting daemon (daemon-routed CLI command).
    accept_invite_lightweight(&bob_db, &invite_link);

    // Bob starts daemon after accept-invite — auto-selects the shared workspace peer.
    let _bob = start_daemon_on_port(&bob_db, bob_port);

    // Bob sends a message in the shared workspace via daemon RPC.
    let bob_event_id = topo_send_retry(&bob_db, "runtime-accept-invite-no-restart");
    let out = topo_assert_eventually(
        &alice_db,
        &format!("has_event:{} >= 1", bob_event_id),
        20_000,
    );
    assert!(
        out.status.success(),
        "daemon CLI invite lifecycle behavior gap: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
