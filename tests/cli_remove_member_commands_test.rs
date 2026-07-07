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

fn peer_event_id_by_device_name(db: &str, device_name: &str) -> String {
    let response = rpc_method_json(db, r#"{"type":"Peers"}"#);
    rpc_data(&response)
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .find(|item| item["device_name"].as_str() == Some(device_name))
                .and_then(|item| item["peer_id"].as_str())
        })
        .unwrap_or_else(|| panic!("missing device {device_name} in Peers RPC: {response}"))
        .to_string()
}

fn message_visible(db: &str, content: &str) -> bool {
    get_messages_raw(db).contains(content)
}

#[test]
fn test_cli_unlink_admin_rotates_and_removed_device_cannot_decrypt() {
    let tmpdir = tempfile::tempdir().unwrap();
    let timeout = Duration::from_secs(60);
    let timeout_ms = timeout.as_millis() as u64;
    let phone_db = tmpdir
        .path()
        .join("alice-phone.db")
        .to_str()
        .unwrap()
        .to_string();
    let laptop_db = tmpdir
        .path()
        .join("alice-laptop.db")
        .to_str()
        .unwrap()
        .to_string();
    let content = "unlink/live-removed-device-cannot-decrypt";

    create_workspace_with_details(&phone_db, "unlink-live", "alice", "alice-phone");
    let mut phone = start_daemon(&phone_db);
    wait_for_active_tenant_ready(&phone_db, Duration::from_secs(30));
    let phone_addr = daemon_listen_addr(&phone_db);

    let link = create_device_link(&phone_db, &phone_addr);
    accept_device_link_with_name(&laptop_db, &link, "alice-laptop");
    let mut laptop = start_daemon(&laptop_db);
    wait_for_active_tenant_ready(&laptop_db, Duration::from_secs(30));

    for db in [&phone_db, &laptop_db] {
        wait_for_live_sync_session(db, timeout);
    }
    assert_eventually(&phone_db, "peer_count == 2", timeout_ms);
    assert_eventually(&laptop_db, "peer_count == 2", timeout_ms);
    let laptop_peer_event_id = peer_event_id_by_device_name(&phone_db, "alice-laptop");

    let unlink = topo_cmd(&phone_db, &["unlink", &laptop_peer_event_id]);
    assert!(
        unlink.status.success(),
        "topo unlink failed: stdout={} stderr={}",
        String::from_utf8_lossy(&unlink.stdout),
        String::from_utf8_lossy(&unlink.stderr)
    );
    assert!(
        count_event_type(&phone_db, "removal") >= 1,
        "unlink should emit a real removal event"
    );

    let message_event_id = send_message(&phone_db, content);
    assert_eventually(
        &laptop_db,
        &format!("has_event:{} >= 1", message_event_id),
        timeout_ms,
    );
    assert_condition_holds_for(
        Duration::from_secs(5),
        Duration::from_millis(250),
        "unlinked device must remain unable to decrypt post-unlink messages",
        || !message_visible(&laptop_db, content),
    );

    stop_daemon(&phone_db, &mut phone);
    stop_daemon(&laptop_db, &mut laptop);
    wait_for_daemon_stopped(&phone_db, Duration::from_secs(10));
    wait_for_daemon_stopped(&laptop_db, Duration::from_secs(10));
}

#[test]
fn test_cli_ban_and_unlink_require_admin() {
    let tmpdir = tempfile::tempdir().unwrap();
    let timeout = Duration::from_secs(60);
    let timeout_ms = timeout.as_millis() as u64;
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let content = "remove/admin-guard-still-allows-sync";

    create_workspace_with_details(&alice_db, "admin-guard", "alice", "alice-phone");
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
    assert_eventually(&alice_db, "peer_count == 2", timeout_ms);
    assert_eventually(&alice_db, "user_count == 2", timeout_ms);

    let alice_user_event_id = user_event_id_by_username(&bob_db, "alice");
    let alice_peer_event_id = peer_event_id_by_device_name(&bob_db, "alice-phone");

    let ban = topo_cmd(&bob_db, &["ban", &alice_user_event_id]);
    assert!(
        !ban.status.success(),
        "non-admin topo ban should fail: stdout={} stderr={}",
        String::from_utf8_lossy(&ban.stdout),
        String::from_utf8_lossy(&ban.stderr)
    );
    assert!(
        String::from_utf8_lossy(&ban.stderr).contains("not admin"),
        "non-admin ban should explain the admin requirement: stderr={}",
        String::from_utf8_lossy(&ban.stderr)
    );

    let unlink = topo_cmd(&bob_db, &["unlink", &alice_peer_event_id]);
    assert!(
        !unlink.status.success(),
        "non-admin topo unlink should fail: stdout={} stderr={}",
        String::from_utf8_lossy(&unlink.stdout),
        String::from_utf8_lossy(&unlink.stderr)
    );
    assert!(
        String::from_utf8_lossy(&unlink.stderr).contains("not admin"),
        "non-admin unlink should explain the admin requirement: stderr={}",
        String::from_utf8_lossy(&unlink.stderr)
    );
    assert_eq!(
        count_event_type(&bob_db, "removal"),
        0,
        "failed non-admin removal commands must not emit removal events"
    );

    let message_event_id = send_message(&alice_db, content);
    assert_eventually(
        &bob_db,
        &format!("has_event:{} >= 1", message_event_id),
        timeout_ms,
    );
    assert_value_eventually(
        timeout,
        Duration::from_millis(200),
        "workspace must continue syncing after failed non-admin removal commands",
        || get_messages_raw(&bob_db),
        |messages| messages.contains(content),
    );

    stop_daemon(&alice_db, &mut alice);
    stop_daemon(&bob_db, &mut bob);
    wait_for_daemon_stopped(&alice_db, Duration::from_secs(10));
    wait_for_daemon_stopped(&bob_db, Duration::from_secs(10));
}
