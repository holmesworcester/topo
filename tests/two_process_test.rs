//! Two-process integration test: real QUIC sync between separate daemon invocations.
//!
//! This test validates the full invite + bootstrap sync + ongoing sync flow
//! using real separate processes, just like a user would run from the command line.

mod cli_harness;

use cli_harness::*;

/// Full two-process invite + bootstrap sync + ongoing sync test.
///
/// 1. Alice creates workspace and starts daemon
/// 2. Alice creates an invite
/// 3. Bob accepts the invite (real QUIC bootstrap sync from Alice)
/// 4. Both run daemons, exchange messages, verify convergence
#[test]
fn test_two_process_invite_and_sync() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 30000;

    // Step 1: Alice creates workspace and starts daemon.
    create_workspace(&alice_db);
    let _alice_daemon = start_daemon_with_options(
        &alice_db,
        &DaemonOptions {
            inherit_stdio: true,
            ..Default::default()
        },
    );

    // Step 2: Alice creates an invite pointing to her sync address (via daemon RPC).
    let invite_link = create_invite_with_spki(
        &alice_db,
        &daemon_listen_addr(&alice_db),
        Some(&daemon_transport_fingerprint(&alice_db)),
    );
    assert!(
        invite_link.starts_with("topo://invite/"),
        "Expected topo://invite/ link, got: {}",
        invite_link
    );

    // Step 3: Bob accepts the invite. This connects to Alice's sync endpoint
    // via real QUIC, fetches prerequisite events, then creates Bob's identity chain.
    accept_invite_with_identity(&bob_db, &invite_link, "bob", "laptop");

    // Bob's daemon handles bootstrap sync via autodial: the runtime discovers
    // bootstrap trust from projected SQL state and dials Alice's sync address.
    let _bob_daemon = start_daemon_with_options(
        &bob_db,
        &DaemonOptions {
            inherit_stdio: true,
            ..Default::default()
        },
    );

    // Step 4: Exchange messages and verify convergence.
    let alice_eid = send_message(&alice_db, "Hello from alice");
    let bob_eid = send_message(&bob_db, "Hello from bob");

    // Wait for sync convergence: each peer should have the other's last message event
    assert_eventually(
        &alice_db,
        &format!("has_event:{} >= 1", bob_eid),
        timeout_ms,
    );
    assert_eventually(
        &bob_db,
        &format!("has_event:{} >= 1", alice_eid),
        timeout_ms,
    );

    // Wait for cross-peer message projection.
    assert_eventually(&alice_db, "message_count >= 2", timeout_ms);
    assert_eventually(&bob_db, "message_count >= 2", timeout_ms);

    // Verify Alice's messages.
    let alice_msgs = get_messages(&alice_db);
    assert!(
        alice_msgs.contains(&"Hello from alice".to_string()),
        "Alice should have her message, got: {:?}",
        alice_msgs
    );
    assert!(
        alice_msgs.contains(&"Hello from bob".to_string()),
        "Alice should see Bob's message (shared workspace), got: {:?}",
        alice_msgs
    );

    // Verify Bob's messages.
    let bob_msgs = get_messages(&bob_db);
    assert!(
        bob_msgs.contains(&"Hello from bob".to_string()),
        "Bob should have his message, got: {:?}",
        bob_msgs
    );
    assert!(
        bob_msgs.contains(&"Hello from alice".to_string()),
        "Bob should see Alice's message (shared workspace), got: {:?}",
        bob_msgs
    );
}
