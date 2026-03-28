use topo::rpc::protocol::RpcMethod;
use topo::sim::VirtualDaemon;

fn temp_db_path() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("virtual-daemon.db");
    (dir, db_path.to_string_lossy().into_owned())
}

#[test]
fn in_process_rpc_path_can_create_send_generate_and_query_state() {
    let (_dir, db_path) = temp_db_path();
    let daemon = VirtualDaemon::new(&db_path);

    let create = daemon.call(RpcMethod::CreateWorkspace {
        workspace_name: "sim-workspace".into(),
        username: "alice".into(),
        device_name: "laptop".into(),
    });
    assert!(create.ok, "workspace creation failed: {:?}", create.error);
    assert!(create.data.is_some(), "create workspace should return data");

    let send = daemon.call(RpcMethod::Send {
        content: "hello from in-process rpc".into(),
        client_op_id: None,
    });
    assert!(send.ok, "send failed: {:?}", send.error);

    let generate = daemon.call(RpcMethod::Generate {
        count: 3,
        history_span: Some("1d".into()),
    });
    assert!(generate.ok, "generate failed: {:?}", generate.error);

    let messages = daemon.call(RpcMethod::Messages { limit: 20 });
    assert!(messages.ok, "messages query failed: {:?}", messages.error);
    let messages_data = messages.data.expect("messages data");
    let total = messages_data["total"].as_i64().expect("messages total");
    assert!(total >= 4, "expected send + generate messages, got {total}");
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
