//! End-to-end validation for the rateless spray sync mode using real daemons.

mod cli_harness;

use std::time::Duration;

use cli_harness::*;

fn rateless_daemon_options() -> DaemonOptions {
    DaemonOptions {
        extra_env: vec![("TOPO_SYNC_MODE".to_string(), "rateless-spray".to_string())],
        ..Default::default()
    }
}

#[test]
fn rateless_spray_invite_and_message_sync_converges() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 30_000;

    create_workspace(&alice_db);
    let _alice_daemon = start_daemon_with_options(&alice_db, &rateless_daemon_options());
    let _bob_daemon = start_daemon_with_options(&bob_db, &rateless_daemon_options());

    let invite_link = topo_create_invite_retry(&alice_db, &daemon_listen_addr(&alice_db));
    accept_invite_with_identity_on_running_daemon(
        &bob_db,
        &invite_link,
        "bob",
        "laptop",
        Duration::from_secs(30),
    );
    wait_for_active_tenant_transport_converged(&bob_db, Duration::from_secs(30));

    let alice_eid = send_message(&alice_db, "rateless hello from alice");
    let bob_eid = send_message(&bob_db, "rateless hello from bob");

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
    assert_eventually(&alice_db, "message_count >= 2", timeout_ms);
    assert_eventually(&bob_db, "message_count >= 2", timeout_ms);

    let alice_msgs = get_messages(&alice_db);
    let bob_msgs = get_messages(&bob_db);
    assert!(
        alice_msgs.contains(&"rateless hello from alice".to_string())
            && alice_msgs.contains(&"rateless hello from bob".to_string()),
        "alice should project both rateless-sync messages, got {alice_msgs:?}"
    );
    assert!(
        bob_msgs.contains(&"rateless hello from alice".to_string())
            && bob_msgs.contains(&"rateless hello from bob".to_string()),
        "bob should project both rateless-sync messages, got {bob_msgs:?}"
    );
}
