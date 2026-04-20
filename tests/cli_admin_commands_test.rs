mod cli_harness;

use cli_harness::*;
use serde_json::Value;
use std::time::Duration;

fn rpc_data(response: &Value) -> &Value {
    assert!(
        response["ok"].as_bool().unwrap_or(false),
        "rpc response should be ok=true, got: {response}"
    );
    &response["data"]
}

fn count_event_type(db: &str, event_type: &str) -> usize {
    let response = rpc_method_json(db, r#"{"type":"EventList"}"#);
    rpc_data(&response)["events"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter(|event| event["event_type"].as_str() == Some(event_type))
                .count()
        })
        .unwrap_or(0)
}

fn user_event_id_by_username(db: &str, username: &str) -> String {
    let response = rpc_method_json(db, r#"{"type":"Users"}"#);
    rpc_data(&response)
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .find(|item| item["username"].as_str() == Some(username))
                .and_then(|item| item["event_id"].as_str())
        })
        .unwrap_or_else(|| panic!("missing user {username} in Users RPC: {response}"))
        .to_string()
}

#[test]
fn test_cli_admin_add_requires_admin_and_rejects_existing_admin() {
    let tmpdir = tempfile::tempdir().unwrap();
    let timeout = Duration::from_secs(60);
    let timeout_ms = timeout.as_millis() as u64;
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();

    create_workspace_with_details(&alice_db, "admin-grant", "alice", "alice-phone");
    let mut alice = start_daemon(&alice_db);
    wait_for_active_tenant_ready(&alice_db, Duration::from_secs(30));
    let alice_addr = daemon_listen_addr(&alice_db);

    let invite = create_invite(&alice_db, &alice_addr);
    accept_invite_with_identity(&bob_db, &invite, "bob", "bob-phone");
    let mut bob = start_daemon(&bob_db);
    wait_for_active_tenant_ready(&bob_db, Duration::from_secs(30));

    for db in [&alice_db, &bob_db] {
        wait_for_live_sync_session(db, timeout);
    }
    assert_eventually(&alice_db, "user_count == 2", timeout_ms);
    assert_eventually(&bob_db, "user_count == 2", timeout_ms);

    let alice_user_event_id = user_event_id_by_username(&bob_db, "alice");
    let bob_user_event_id = user_event_id_by_username(&alice_db, "bob");

    let non_admin_grant = topo_cmd(&bob_db, &["admin", "add", &alice_user_event_id]);
    assert!(
        !non_admin_grant.status.success(),
        "non-admin admin-add should fail: stdout={} stderr={}",
        String::from_utf8_lossy(&non_admin_grant.stdout),
        String::from_utf8_lossy(&non_admin_grant.stderr)
    );
    assert!(
        String::from_utf8_lossy(&non_admin_grant.stderr).contains("not admin"),
        "non-admin admin-add should explain the admin requirement: stderr={}",
        String::from_utf8_lossy(&non_admin_grant.stderr)
    );

    let grant = topo_cmd(&alice_db, &["admin", "add", &bob_user_event_id]);
    assert!(
        grant.status.success(),
        "admin add should succeed: stdout={} stderr={}",
        String::from_utf8_lossy(&grant.stdout),
        String::from_utf8_lossy(&grant.stderr)
    );
    assert!(
        count_event_type(&alice_db, "admin") >= 2,
        "successful admin add should emit a real admin event"
    );
    assert_eventually(&bob_db, "admin_count == 2", timeout_ms);

    let duplicate = topo_cmd(&alice_db, &["admin", "add", &bob_user_event_id]);
    assert!(
        !duplicate.status.success(),
        "duplicate admin add should fail: stdout={} stderr={}",
        String::from_utf8_lossy(&duplicate.stdout),
        String::from_utf8_lossy(&duplicate.stderr)
    );
    assert!(
        String::from_utf8_lossy(&duplicate.stderr).contains("already admin"),
        "duplicate admin add should explain the conflict: stderr={}",
        String::from_utf8_lossy(&duplicate.stderr)
    );

    stop_daemon(&alice_db, &mut alice);
    stop_daemon(&bob_db, &mut bob);
    wait_for_daemon_stopped(&alice_db, Duration::from_secs(10));
    wait_for_daemon_stopped(&bob_db, Duration::from_secs(10));
}

#[test]
fn test_cli_admin_add_promotes_user_and_grantee_can_create_invite() {
    let tmpdir = tempfile::tempdir().unwrap();
    let timeout = Duration::from_secs(60);
    let timeout_ms = timeout.as_millis() as u64;
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let carol_db = tmpdir.path().join("carol.db").to_str().unwrap().to_string();

    create_workspace_with_details(&alice_db, "admin-promotion", "alice", "alice-phone");
    let mut alice = start_daemon(&alice_db);
    wait_for_active_tenant_ready(&alice_db, Duration::from_secs(30));
    let alice_addr = daemon_listen_addr(&alice_db);

    let invite = create_invite(&alice_db, &alice_addr);
    accept_invite_with_identity(&bob_db, &invite, "bob", "bob-phone");
    let mut bob = start_daemon(&bob_db);
    wait_for_active_tenant_ready(&bob_db, Duration::from_secs(30));

    for db in [&alice_db, &bob_db] {
        wait_for_live_sync_session(db, timeout);
    }
    assert_eventually(&alice_db, "user_count == 2", timeout_ms);
    assert_eventually(&bob_db, "user_count == 2", timeout_ms);

    let bob_addr = daemon_listen_addr(&bob_db);
    let invite_before_grant = topo_cmd(&bob_db, &["invite", "--public-addr", &bob_addr]);
    assert!(
        !invite_before_grant.status.success(),
        "non-admin invite should fail before promotion: stdout={} stderr={}",
        String::from_utf8_lossy(&invite_before_grant.stdout),
        String::from_utf8_lossy(&invite_before_grant.stderr)
    );

    let bob_user_event_id = user_event_id_by_username(&alice_db, "bob");
    let grant = topo_cmd(&alice_db, &["admin", "add", &bob_user_event_id]);
    assert!(
        grant.status.success(),
        "admin add should succeed: stdout={} stderr={}",
        String::from_utf8_lossy(&grant.stdout),
        String::from_utf8_lossy(&grant.stderr)
    );

    assert_eventually(&bob_db, "admin_count == 2", timeout_ms);
    let bob_invite = create_invite(&bob_db, &bob_addr);
    accept_invite_with_identity(&carol_db, &bob_invite, "carol", "carol-phone");
    let mut carol = start_daemon(&carol_db);
    wait_for_active_tenant_ready(&carol_db, Duration::from_secs(30));

    for db in [&alice_db, &bob_db, &carol_db] {
        wait_for_live_sync_session(db, timeout);
    }
    assert_eventually(&alice_db, "user_count == 3", timeout_ms);
    assert_eventually(&bob_db, "user_count == 3", timeout_ms);
    assert_eventually(&carol_db, "user_count == 3", timeout_ms);

    stop_daemon(&alice_db, &mut alice);
    stop_daemon(&bob_db, &mut bob);
    stop_daemon(&carol_db, &mut carol);
    wait_for_daemon_stopped(&alice_db, Duration::from_secs(10));
    wait_for_daemon_stopped(&bob_db, Duration::from_secs(10));
    wait_for_daemon_stopped(&carol_db, Duration::from_secs(10));
}
