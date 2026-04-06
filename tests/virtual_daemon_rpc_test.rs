use topo::rpc::protocol::RpcMethod;
use topo::sim::VirtualDaemon;

fn temp_db_path() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("virtual-daemon.db");
    (dir, db_path.to_string_lossy().into_owned())
}

#[test]
fn in_process_rpc_path_can_create_seed_send_and_query_state() {
    let (_dir, db_path) = temp_db_path();
    let daemon = VirtualDaemon::new(&db_path);

    let create = daemon.call(RpcMethod::CreateWorkspace {
        workspace_name: "sim-workspace".into(),
        username: "alice".into(),
        device_name: "laptop".into(),
        message_count: 3,
        network_age: Some("1d".into()),
    });
    assert!(create.ok, "workspace creation failed: {:?}", create.error);
    assert!(create.data.is_some(), "create workspace should return data");

    let send = daemon.call(RpcMethod::Send {
        content: "hello from in-process rpc".into(),
        client_op_id: None,
    });
    assert!(send.ok, "send failed: {:?}", send.error);

    let messages = daemon.call(RpcMethod::Messages { limit: 20 });
    assert!(messages.ok, "messages query failed: {:?}", messages.error);
    let messages_data = messages.data.expect("messages data");
    let total = messages_data["total"].as_i64().expect("messages total");
    assert!(total >= 4, "expected send + seeded messages, got {total}");
    let items = messages_data["messages"]
        .as_array()
        .expect("messages array");
    assert!(
        items
            .iter()
            .any(|msg| msg["content"] == "hello from in-process rpc"),
        "sent message should be visible through real RPC query"
    );

    let stats = daemon.call(RpcMethod::Stats);
    assert!(stats.ok, "stats query failed: {:?}", stats.error);
    let stats_data = stats.data.expect("stats data");
    assert!(
        stats_data["message_count"].as_i64().unwrap_or(0) >= 4,
        "expected stats to reflect created messages"
    );
    assert!(
        stats_data["recorded_event_count"].as_i64().unwrap_or(0) >= 4,
        "expected stats to reflect recorded events"
    );
}

#[test]
fn create_workspace_caps_created_events_oldest_first() {
    let (_dir, db_path) = temp_db_path();
    let daemon = VirtualDaemon::new(&db_path);

    let create = daemon.call(RpcMethod::CreateWorkspace {
        workspace_name: "seeded-workspace".into(),
        username: "alice".into(),
        device_name: "laptop".into(),
        message_count: 128,
        network_age: Some("30d".into()),
    });
    assert!(create.ok, "workspace creation failed: {:?}", create.error);

    let data = create.data.expect("create workspace data");
    let created_events = data["created_events"]
        .as_array()
        .expect("created_events array");
    let cap = data["created_events_cap"]
        .as_u64()
        .expect("created_events_cap") as usize;
    assert_eq!(cap, 32);
    assert_eq!(created_events.len(), cap);
    assert_eq!(data["seeded_message_count"].as_u64(), Some(128));

    let mut previous_created_at = None;
    for event in created_events {
        let created_at_ms = event["created_at_ms"].as_u64().expect("created_at_ms");
        if let Some(previous) = previous_created_at {
            assert!(
                previous <= created_at_ms,
                "created_events should be oldest-first: previous={} current={}",
                previous,
                created_at_ms
            );
        }
        previous_created_at = Some(created_at_ms);
    }
}
