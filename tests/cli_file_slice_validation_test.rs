mod cli_harness;

use cli_harness::*;
use serde_json::Value;
use std::io::Write;
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

fn encrypted_file_events_using_key<'a>(events: &'a [Value], expected_key: &str) -> Vec<&'a Value> {
    events
        .iter()
        .filter(|event| event["event_type"].as_str() == Some("encrypted"))
        .filter(|event| {
            matches!(
                event["decrypted_inner"]["inner_type"].as_str(),
                Some("file") | Some("file_slice")
            )
        })
        .filter(|event| {
            event["deps"].as_array().into_iter().flatten().any(|dep| {
                dep[0].as_str() == Some("key_event_id") && dep[1].as_str() == Some(expected_key)
            })
        })
        .collect()
}

fn count_encrypted_inner_type(events: &[Value], inner_type: &str) -> usize {
    events
        .iter()
        .filter(|event| event["event_type"].as_str() == Some("encrypted"))
        .filter(|event| event["decrypted_inner"]["inner_type"].as_str() == Some(inner_type))
        .count()
}

#[test]
fn test_cli_file_and_file_slices_are_encrypted_with_latest_content_key() {
    hold_network_test_lock_for_binary();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice_file_key.db");
    let alice_db = alice_db.to_str().unwrap().to_string();
    let source_path = tmpdir.path().join("payload.bin");
    let mut source = std::fs::File::create(&source_path).unwrap();
    source.write_all(&vec![0x5Au8; 300_000]).unwrap();
    source.flush().unwrap();

    create_workspace(&alice_db);
    let _alice = start_daemon(&alice_db);
    wait_for_active_tenant_ready(&alice_db, Duration::from_secs(30));

    send_file(
        &alice_db,
        "encrypted payload",
        source_path.to_str().unwrap(),
    );

    let content_keys = rpc_method_json(&alice_db, r#"{"type":"ContentKeys","summary":false}"#);
    let latest_key = rpc_data(&content_keys)["latest_key_event_id"]
        .as_str()
        .expect("latest content key")
        .to_string();

    let event_list = assert_value_eventually(
        Duration::from_secs(20),
        Duration::from_millis(200),
        "encrypted file and file_slice events appear in event list",
        || rpc_method_json(&alice_db, r#"{"type":"EventList"}"#),
        |response| {
            let events = event_list_items(rpc_data(response));
            count_encrypted_inner_type(events, "file") >= 1
                && count_encrypted_inner_type(events, "file_slice") >= 1
        },
    );
    let events = event_list_items(rpc_data(&event_list));
    let matching = encrypted_file_events_using_key(events, &latest_key);
    assert!(
        !matching.is_empty(),
        "expected encrypted file/file_slice events using latest content key {}; got {:?}",
        latest_key,
        events
    );
    assert!(
        count_encrypted_inner_type(events, "file") >= 1,
        "expected at least one encrypted file event"
    );
    assert!(
        count_encrypted_inner_type(events, "file_slice") >= 1,
        "expected at least one encrypted file_slice event"
    );
    assert_eq!(
        matching.len(),
        count_encrypted_inner_type(events, "file")
            + count_encrypted_inner_type(events, "file_slice"),
        "every encrypted file/file_slice event should use the latest content key"
    );
}

#[test]
fn test_cli_bad_extra_slices_do_not_change_visible_progress_or_break_save() {
    hold_network_test_lock_for_binary();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice_bad_slices.db");
    let alice_db = alice_db.to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob_bad_slices.db");
    let bob_db = bob_db.to_str().unwrap().to_string();
    let source_path = tmpdir.path().join("tiny.bin");
    let payload = b"slice-proof-payload".to_vec();
    let mut source = std::fs::File::create(&source_path).unwrap();
    source.write_all(&payload).unwrap();
    source.flush().unwrap();

    create_workspace(&alice_db);
    let _alice = start_daemon(&alice_db);

    let invite_link = create_invite_with_public_addr(&alice_db, &daemon_listen_addr(&alice_db));
    accept_invite(&bob_db, &invite_link);
    let _bob = start_daemon(&bob_db);

    wait_for_active_tenant_ready(&bob_db, Duration::from_secs(60));
    wait_for_live_sync_session(&alice_db, Duration::from_secs(60));
    wait_for_live_sync_session(&bob_db, Duration::from_secs(60));

    let bad_slice_count = 12usize;
    send_file_with_bad_slices(
        &alice_db,
        "tiny payload with junk slices",
        source_path.to_str().unwrap(),
        bad_slice_count,
    );

    let bob_events = assert_value_eventually(
        Duration::from_secs(30),
        Duration::from_millis(250),
        "bob receives all real and bogus encrypted file_slice events",
        || rpc_method_json(&bob_db, r#"{"type":"EventList"}"#),
        |response| {
            count_encrypted_inner_type(event_list_items(rpc_data(response)), "file_slice")
                >= 1 + bad_slice_count
        },
    );
    let bob_event_items = event_list_items(rpc_data(&bob_events));
    assert!(
        count_encrypted_inner_type(bob_event_items, "file_slice") >= 1 + bad_slice_count,
        "expected bad extra slices to replicate as encrypted file_slice events"
    );

    let bob_files = assert_value_eventually(
        Duration::from_secs(20),
        Duration::from_millis(200),
        "visible file progress ignores bogus extra slices",
        || rpc_method_json(&bob_db, r#"{"type":"Files","limit":10}"#),
        |response| {
            let files = rpc_data(response)["files"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            files.first().is_some_and(|file| {
                file["total_slices"].as_i64() == Some(1)
                    && file["slices_received"].as_i64() == Some(1)
                    && file["downloaded_bytes"].as_i64() == Some(payload.len() as i64)
                    && file["complete"].as_bool() == Some(true)
            })
        },
    );
    let files = rpc_data(&bob_files)["files"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let file = files.first().expect("one file on bob");
    assert_eq!(file["total_slices"].as_i64(), Some(1));
    assert_eq!(
        file["slices_received"].as_i64(),
        Some(1),
        "bogus extra slices must not increase visible progress"
    );
    assert_eq!(
        file["downloaded_bytes"].as_i64(),
        Some(payload.len() as i64)
    );
    assert_eq!(file["complete"].as_bool(), Some(true));

    let saved_path = tmpdir.path().join("saved.bin");
    save_file_eventually(
        &bob_db,
        "1",
        saved_path.to_str().unwrap(),
        Duration::from_secs(20),
    );
    assert_eq!(std::fs::read(saved_path).unwrap(), payload);
}
