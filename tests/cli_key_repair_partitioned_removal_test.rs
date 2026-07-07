mod cli_harness;

use cli_harness::*;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn rpc_data(response: &Value) -> &Value {
    assert!(
        response["ok"].as_bool().unwrap_or(false),
        "rpc response should be ok=true, got: {response}"
    );
    &response["data"]
}

fn event_list_items(data: &Value) -> &[Value] {
    data["events"].as_array().map(Vec::as_slice).unwrap_or(&[])
}

fn count_event_type(db: &str, event_type: &str) -> usize {
    let response = rpc_method_json(db, r#"{"type":"EventList"}"#);
    event_list_items(rpc_data(&response))
        .iter()
        .filter(|event| event["event_type"].as_str() == Some(event_type))
        .count()
}

fn message_visible(db: &str, content: &str) -> bool {
    get_messages_raw(db).contains(content)
}

fn user_event_id_by_username(db: &str, username: &str) -> String {
    let response = rpc_method_json(db, r#"{"type":"Users"}"#);
    let Some(items) = rpc_data(&response).as_array() else {
        panic!("Users RPC returned non-array: {response}");
    };
    items
        .iter()
        .find(|item| item["username"].as_str() == Some(username))
        .and_then(|item| item["event_id"].as_str())
        .unwrap_or_else(|| panic!("missing user {username} in Users RPC: {response}"))
        .to_string()
}

#[allow(dead_code)]
#[derive(Debug)]
struct RepairObservation {
    key_request_count: usize,
    key_history_count: usize,
    key_rotation_count: usize,
    removal_count: usize,
    key_shared_count: usize,
    message_visible: bool,
}

enum TestDir {
    Temp(tempfile::TempDir),
    Persistent(PathBuf),
}

impl TestDir {
    fn path(&self) -> &Path {
        match self {
            TestDir::Temp(dir) => dir.path(),
            TestDir::Persistent(path) => path.as_path(),
        }
    }
}

fn scenario_dir() -> TestDir {
    if let Some(path) = std::env::var_os("TOPO_KEEP_KEY_REPAIR_DEBUG_DIR") {
        let path = PathBuf::from(path);
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create persistent debug dir");
        eprintln!("key repair debug dir: {}", path.display());
        TestDir::Persistent(path)
    } else {
        TestDir::Temp(tempfile::tempdir().unwrap())
    }
}

#[test]
fn test_cli_key_request_heals_partitioned_removal_for_unknown_joiner() {
    let tmpdir = scenario_dir();
    let timeout = Duration::from_secs(90);
    let timeout_ms = timeout.as_millis() as u64;
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let mallory_db = tmpdir
        .path()
        .join("mallory.db")
        .to_str()
        .unwrap()
        .to_string();
    let carol_db = tmpdir.path().join("carol.db").to_str().unwrap().to_string();
    let content = "partitioned-removal/key-repair-marker";

    create_workspace_with_details(&bob_db, "partitioned-removal", "bob", "bob-root");
    let bob = start_daemon(&bob_db);
    wait_for_active_tenant_ready(&bob_db, Duration::from_secs(30));
    let invite_addr = daemon_listen_addr(&bob_db);

    let alice_invite = create_invite(&bob_db, &invite_addr);
    accept_invite_with_identity(&alice_db, &alice_invite, "alice", "alice-phone");
    let alice = start_daemon(&alice_db);
    wait_for_active_tenant_ready(&alice_db, Duration::from_secs(30));

    let mallory_invite = create_invite(&bob_db, &invite_addr);
    accept_invite_with_identity(&mallory_db, &mallory_invite, "mallory", "mallory-phone");
    let mut mallory = start_daemon(&mallory_db);
    wait_for_active_tenant_ready(&mallory_db, Duration::from_secs(30));

    for db in [&alice_db, &bob_db, &mallory_db] {
        wait_for_live_sync_session(db, timeout);
    }
    assert_eventually(&bob_db, "peer_count == 3", timeout_ms);
    assert_eventually(&bob_db, "user_count == 3", timeout_ms);
    assert_eventually(&alice_db, "user_count == 3", timeout_ms);
    assert_eventually(&mallory_db, "user_count == 3", timeout_ms);
    let alice_user_event_id = user_event_id_by_username(&bob_db, "alice");
    let mallory_user_event_id = user_event_id_by_username(&alice_db, "mallory");

    let grant_alice = topo_cmd(&bob_db, &["admin", "add", &alice_user_event_id]);
    assert!(
        grant_alice.status.success(),
        "granting Alice admin should succeed: stdout={} stderr={}",
        String::from_utf8_lossy(&grant_alice.stdout),
        String::from_utf8_lossy(&grant_alice.stderr)
    );
    assert_eventually(&alice_db, "admin_count == 2", timeout_ms);

    drop(alice);
    wait_for_daemon_stopped(&alice_db, Duration::from_secs(10));

    let bob_partition_addr = daemon_listen_addr(&bob_db);
    let carol_invite = create_invite(&bob_db, &bob_partition_addr);
    accept_invite_with_identity(&carol_db, &carol_invite, "carol", "carol-phone");
    let mut carol = start_daemon(&carol_db);
    wait_for_active_tenant_ready(&carol_db, Duration::from_secs(30));
    wait_for_live_sync_session(&bob_db, timeout);
    wait_for_live_sync_session(&mallory_db, timeout);
    wait_for_live_sync_session(&carol_db, timeout);
    assert_eventually(&bob_db, "user_count == 4", timeout_ms);
    assert_eventually(&carol_db, "user_count == 4", timeout_ms);

    let mallory_request_baseline = count_event_type(&mallory_db, "key_request");
    assert_eq!(
        mallory_request_baseline, 0,
        "Mallory should have no key_request events before Alice's removal frontier exists"
    );
    assert_condition_holds_for(
        Duration::from_secs(2),
        Duration::from_millis(200),
        "Mallory should not emit key requests while Bob's partition lacks Alice's removal frontier",
        || count_event_type(&mallory_db, "key_request") == mallory_request_baseline,
    );

    let remove_mallory = topo_cmd(&alice_db, &["ban", &mallory_user_event_id]);
    assert!(
        remove_mallory.status.success(),
        "offline Alice removal should succeed through real CLI flow: stdout={} stderr={}",
        String::from_utf8_lossy(&remove_mallory.stdout),
        String::from_utf8_lossy(&remove_mallory.stderr)
    );

    let alice = start_daemon(&alice_db);
    wait_for_active_tenant_ready(&alice_db, Duration::from_secs(30));
    wait_for_live_sync_session(&bob_db, timeout);

    let alice_message_event_id = send_message(&alice_db, content);

    assert_eventually(
        &bob_db,
        &format!("has_event:{} >= 1", alice_message_event_id),
        timeout_ms,
    );
    assert_value_eventually(
        timeout,
        Duration::from_millis(200),
        "Bob decrypts Alice's post-removal message from the new frontier-bound key_rotation",
        || get_messages_raw(&bob_db),
        |messages| messages.contains(content),
    );

    assert_eventually(
        &carol_db,
        &format!("has_event:{} >= 1", alice_message_event_id),
        timeout_ms,
    );
    let _repair = assert_value_eventually(
        timeout,
        Duration::from_millis(300),
        "Carol emits a real daemon key_request after receiving Alice's message without a key",
        || RepairObservation {
            key_request_count: count_event_type(&carol_db, "key_request"),
            key_history_count: count_event_type(&carol_db, "key_history"),
            key_rotation_count: count_event_type(&carol_db, "key_rotation"),
            removal_count: count_event_type(&carol_db, "removal"),
            key_shared_count: count_event_type(&carol_db, "key_shared"),
            message_visible: message_visible(&carol_db, content),
        },
        |state| state.key_request_count >= 1,
    );
    assert_value_eventually(
        timeout,
        Duration::from_millis(200),
        "Carol decrypts Alice's message after Bob responds to the key_request",
        || get_messages_raw(&carol_db),
        |messages| messages.contains(content),
    );

    assert_eventually(
        &mallory_db,
        &format!("has_event:{} >= 1", alice_message_event_id),
        timeout_ms,
    );
    assert_condition_holds_for(
        Duration::from_secs(5),
        Duration::from_millis(250),
        "Mallory must remain unable to decrypt Alice's post-removal message",
        || !message_visible(&mallory_db, content),
    );

    drop(alice);
    drop(bob);
    stop_daemon(&mallory_db, &mut mallory);
    stop_daemon(&carol_db, &mut carol);
    wait_for_daemon_stopped(&mallory_db, Duration::from_secs(10));
    wait_for_daemon_stopped(&carol_db, Duration::from_secs(10));
}
