use topo::rpc::protocol::RpcMethod;
use topo::sim::VirtualDaemon;

fn main() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let db_path = tmp.path().join("virtual-daemon-smoke.db");
    let daemon = VirtualDaemon::new(db_path.to_str().expect("db path utf8"));

    let create = daemon.call(RpcMethod::CreateWorkspace {
        workspace_name: "smoke-workspace".into(),
        username: "alice".into(),
        device_name: "laptop".into(),
    });
    assert!(create.ok, "workspace creation failed: {:?}", create.error);

    let send = daemon.call(RpcMethod::Send {
        content: "hello from smoke".into(),
        client_op_id: None,
    });
    assert!(send.ok, "send failed: {:?}", send.error);

    let stats = daemon.call(RpcMethod::Stats);
    assert!(stats.ok, "stats failed: {:?}", stats.error);

    let messages = daemon.call(RpcMethod::Messages { limit: 20 });
    assert!(messages.ok, "messages failed: {:?}", messages.error);

    let summary = serde_json::json!({
        "workspace_created": create.ok,
        "send_ok": send.ok,
        "message_count": stats.data.as_ref().and_then(|v| v["message_count"].as_i64()).unwrap_or(0),
        "recorded_event_count": stats.data.as_ref().and_then(|v| v["recorded_event_count"].as_i64()).unwrap_or(0),
        "messages_total": messages.data.as_ref().and_then(|v| v["total"].as_i64()).unwrap_or(0),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&summary).expect("summary json")
    );
}
