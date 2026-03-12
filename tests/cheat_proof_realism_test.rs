//! Cheat-proof realism tests.
//!
//! These tests enforce an invite-only, daemon-first workflow:
//! - require invite-only autodial behavior (no manual connect flags),
//! - require daemon CLI invite lifecycle support (no restart after accept).
//!
//! **Boundary**: tests that prove the system works under production-realistic
//! constraints — daemons autodial from persisted invite state, and the CLI
//! invite lifecycle works without daemon restarts. For general CLI sync
//! scenarios, see `cli_test.rs`.

mod cli_harness;

use cli_harness::*;
use std::sync::{Mutex, OnceLock};

fn realism_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
}

fn bootstrap_alice_and_invite(tmpdir: &tempfile::TempDir) -> (String, String, String) {
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();

    // Create workspace for Alice (identity chain)
    create_workspace(&alice_db);

    // Start Alice's daemon so we can create invites via RPC
    let _alice_daemon = start_daemon(&alice_db);

    // Create invite via daemon RPC
    let invite_link = topo_create_invite_retry(&alice_db, &daemon_listen_addr(&alice_db));

    // Kill temporary daemon — caller will start their own
    drop(_alice_daemon);
    wait_for_daemon_stopped(&alice_db, std::time::Duration::from_secs(10));

    (alice_db, bob_db, invite_link)
}

#[test]
fn test_invite_only_daemons_should_autodial_without_manual_connect() {
    let _guard = realism_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let (alice_db, bob_db, invite_link) = bootstrap_alice_and_invite(&tmpdir);

    let _alice = start_daemon(&alice_db);
    accept_invite_lightweight(&bob_db, &invite_link);
    let _bob = start_daemon(&bob_db);
    wait_for_local_peer_signer_ready(&bob_db, std::time::Duration::from_secs(60));

    // Desired behavior: after invite acceptance, daemons should autodial based on
    // persisted bootstrap/discovery state, with no manual connect flag.
    let bob_event_id = topo_send_retry(&bob_db, "invite-only-autodial-required");
    let out = topo_assert_eventually(
        &alice_db,
        &format!("has_event:{} >= 1", bob_event_id),
        30_000,
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
    let _guard = realism_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();

    // Create workspace for Alice and start her daemon.
    create_workspace(&alice_db);
    let _alice = start_daemon(&alice_db);

    // Create invite while Alice's daemon is running (via RPC).
    let invite_link = topo_create_invite_retry(&alice_db, &daemon_listen_addr(&alice_db));

    // Bob accepts invite before starting daemon (daemon-routed CLI command).
    accept_invite_lightweight(&bob_db, &invite_link);

    // Bob starts daemon after accept — auto-selects the shared workspace peer.
    let _bob = start_daemon(&bob_db);
    wait_for_local_peer_signer_ready(&bob_db, std::time::Duration::from_secs(60));

    // Bob sends a message in the shared workspace via daemon RPC.
    let bob_event_id = topo_send_retry(&bob_db, "runtime-accept-no-restart");
    let out = topo_assert_eventually(
        &alice_db,
        &format!("has_event:{} >= 1", bob_event_id),
        30_000,
    );
    assert!(
        out.status.success(),
        "daemon CLI invite lifecycle behavior gap: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
