//! RPC tests: protocol roundtrip, daemon+CLI integration, command regression.

use std::path::PathBuf;
use std::process::Command;

fn bin() -> String {
    env!("CARGO_BIN_EXE_topo").to_string()
}

fn temp_db() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db").to_str().unwrap().to_string();
    (dir, db)
}

fn socket_path_for_db(db: &str) -> PathBuf {
    topo::service::socket_path_for_db(db)
}

// ---------------------------------------------------------------------------
// 1. RPC protocol unit tests
// ---------------------------------------------------------------------------

#[test]
fn rpc_request_encode_decode_roundtrip() {
    use topo::rpc::protocol::*;

    let req = RpcRequest {
        version: PROTOCOL_VERSION,
        method: RpcMethod::Status,
    };
    let frame = encode_frame(&req).unwrap();
    let decoded: RpcRequest = decode_frame(&mut &frame[..]).unwrap();
    assert_eq!(decoded.version, PROTOCOL_VERSION);
    match decoded.method {
        RpcMethod::Status => {}
        other => panic!("expected Status, got {:?}", other),
    }
}

#[test]
fn rpc_request_send_roundtrip() {
    use topo::rpc::protocol::*;

    let req = RpcRequest {
        version: PROTOCOL_VERSION,
        method: RpcMethod::Send {
            workspace: "abc123".into(),
            content: "hello world".into(),
        },
    };
    let frame = encode_frame(&req).unwrap();
    let decoded: RpcRequest = decode_frame(&mut &frame[..]).unwrap();
    match decoded.method {
        RpcMethod::Send { workspace, content } => {
            assert_eq!(workspace, "abc123");
            assert_eq!(content, "hello world");
        }
        other => panic!("expected Send, got {:?}", other),
    }
}

#[test]
fn rpc_response_success_roundtrip() {
    use topo::rpc::protocol::*;
    use topo::service::StatusResponse;

    let data = StatusResponse {
        events_count: 42,
        messages_count: 10,
        reactions_count: 3,
        recorded_events_count: 42,
        neg_items_count: 42,
    };
    let resp = RpcResponse::success(data);
    let frame = encode_frame(&resp).unwrap();
    let decoded: RpcResponse = decode_frame(&mut &frame[..]).unwrap();
    assert!(decoded.ok);
    assert!(decoded.error.is_none());
    let d = decoded.data.unwrap();
    assert_eq!(d["events_count"], 42);
    assert_eq!(d["messages_count"], 10);
}

#[test]
fn rpc_response_error_roundtrip() {
    use topo::rpc::protocol::*;

    let resp = RpcResponse::error("something went wrong");
    let frame = encode_frame(&resp).unwrap();
    let decoded: RpcResponse = decode_frame(&mut &frame[..]).unwrap();
    assert!(!decoded.ok);
    assert_eq!(decoded.error.as_deref(), Some("something went wrong"));
    assert!(decoded.data.is_none());
}

#[test]
fn rpc_all_methods_serialize() {
    use topo::rpc::protocol::*;

    let methods = vec![
        RpcMethod::Status,
        RpcMethod::Messages { limit: 50 },
        RpcMethod::Send {
            workspace: "ws".into(),
            content: "msg".into(),
        },
        RpcMethod::Generate {
            count: 10,
            workspace: "ws".into(),
        },
        RpcMethod::AssertNow {
            predicate: "message_count == 0".into(),
        },
        RpcMethod::AssertEventually {
            predicate: "message_count == 5".into(),
            timeout_ms: 10000,
            interval_ms: 200,
        },
        RpcMethod::TransportIdentity,
        RpcMethod::React {
            target: "abc".into(),
            emoji: "thumbs_up".into(),
        },
        RpcMethod::DeleteMessage {
            target: "def".into(),
        },
        RpcMethod::Reactions,
        RpcMethod::Users,
        RpcMethod::Keys { summary: true },
        RpcMethod::Workspaces,
        RpcMethod::IntroAttempts {
            peer: Some("peer1".into()),
        },
        RpcMethod::Shutdown,
    ];

    for method in methods {
        let req = RpcRequest {
            version: PROTOCOL_VERSION,
            method,
        };
        let frame = encode_frame(&req).unwrap();
        let decoded: RpcRequest = decode_frame(&mut &frame[..]).unwrap();
        assert_eq!(decoded.version, PROTOCOL_VERSION);
    }
}

// ---------------------------------------------------------------------------
// 2. Integration: daemon via `topo start` + CLI commands
// ---------------------------------------------------------------------------

#[test]
fn daemon_and_cli_status() {
    let (_dir, db) = temp_db();
    let socket = socket_path_for_db(&db);

    // Bootstrap identity chain (workspace + PeerShared) so daemon can start sync.
    let out = Command::new(bin())
        .args(["send", "bootstrap", "--db", &db])
        .output()
        .unwrap();
    assert!(out.status.success(), "bootstrap failed: {:?}", out);

    // Start daemon in background.
    let mut daemon = Command::new(bin())
        .args(["--db", &db, "start", "--bind", "127.0.0.1:0"])
        .spawn()
        .unwrap();

    // Wait for socket to appear.
    let start = std::time::Instant::now();
    while !socket.exists() && start.elapsed().as_secs() < 5 {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(socket.exists(), "daemon socket did not appear");

    // Query status via unified CLI (routes through daemon via RPC).
    let out = Command::new(bin())
        .args(["--db", &db, "status"])
        .output()
        .unwrap();

    // Kill daemon.
    let _ = daemon.kill();
    let _ = daemon.wait();

    assert!(out.status.success(), "status failed: {:?}", out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("STATUS"), "status output should contain STATUS header");
    assert!(stdout.contains("Events:"), "status output should contain Events count");
}

#[test]
fn daemon_and_cli_send_and_messages() {
    let (_dir, db) = temp_db();
    let socket = socket_path_for_db(&db);

    // Bootstrap identity chain so daemon can start sync.
    let out = Command::new(bin())
        .args(["send", "bootstrap", "--db", &db])
        .output()
        .unwrap();
    assert!(out.status.success());

    // Start daemon.
    let mut daemon = Command::new(bin())
        .args(["--db", &db, "start", "--bind", "127.0.0.1:0"])
        .spawn()
        .unwrap();

    let start = std::time::Instant::now();
    while !socket.exists() && start.elapsed().as_secs() < 5 {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // Send a message via unified CLI (routes through daemon via RPC).
    let out = Command::new(bin())
        .args(["--db", &db, "send", "hello from topo"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "send failed: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Sent: hello from topo"));

    // Query messages.
    let out = Command::new(bin())
        .args(["--db", &db, "messages"])
        .output()
        .unwrap();

    // Kill daemon.
    let _ = daemon.kill();
    let _ = daemon.wait();

    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("hello from topo"),
        "should find message in list, got: {}",
        stdout
    );
}

#[test]
fn daemon_and_cli_assert_now() {
    let (_dir, db) = temp_db();
    let socket = socket_path_for_db(&db);

    // Bootstrap identity chain so daemon can start sync.
    Command::new(bin())
        .args(["send", "bootstrap", "--db", &db])
        .output()
        .unwrap();

    // Start daemon.
    let mut daemon = Command::new(bin())
        .args(["--db", &db, "start", "--bind", "127.0.0.1:0"])
        .spawn()
        .unwrap();

    let start = std::time::Instant::now();
    while !socket.exists() && start.elapsed().as_secs() < 5 {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // Assert message_count == 1 (bootstrap message; should pass).
    let out = Command::new(bin())
        .args(["--db", &db, "assert-now", "message_count == 1"])
        .output()
        .unwrap();

    assert!(out.status.success(), "assert-now should pass");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("PASS"));

    // Assert message_count == 99 (should fail with exit 1).
    let out = Command::new(bin())
        .args(["--db", &db, "assert-now", "message_count == 99"])
        .output()
        .unwrap();

    // Kill daemon.
    let _ = daemon.kill();
    let _ = daemon.wait();

    assert_eq!(out.status.code(), Some(1), "assert-now should fail with exit 1");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("FAIL"));
}

#[test]
fn direct_fallback_when_daemon_not_running() {
    let (_dir, db) = temp_db();

    // Send without daemon — should fall back to direct DB access.
    let out = Command::new(bin())
        .args(["send", "direct msg", "--db", &db])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "direct send failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Sent: direct msg"));

    // Status without daemon — should fall back to direct DB access.
    let out = Command::new(bin())
        .args(["status", "--db", &db])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Messages:"));
}

// ---------------------------------------------------------------------------
// 3. Direct CLI commands (single-process mode, no daemon)
// ---------------------------------------------------------------------------

#[test]
fn cli_direct_send_and_status() {
    let (_dir, db) = temp_db();

    // Send a message via direct CLI.
    let out = Command::new(bin())
        .args(["send", "direct msg", "--db", &db])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "direct send failed: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Sent: direct msg"));

    // Check status.
    let out = Command::new(bin())
        .args(["status", "--db", &db])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Messages:"));
}

#[test]
fn cli_direct_assert_now() {
    let (_dir, db) = temp_db();

    // Bootstrap with a send.
    Command::new(bin())
        .args(["send", "test", "--db", &db])
        .output()
        .unwrap();

    // assert-now message_count == 1.
    let out = Command::new(bin())
        .args(["assert-now", "message_count == 1", "--db", &db])
        .output()
        .unwrap();
    assert!(out.status.success(), "assert-now should pass");

    // assert-now message_count == 0 (should fail).
    let out = Command::new(bin())
        .args(["assert-now", "message_count == 0", "--db", &db])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
}

// ---------------------------------------------------------------------------
// 4. Service function unit tests
// ---------------------------------------------------------------------------

#[test]
fn service_socket_path_derivation() {
    let path = topo::service::socket_path_for_db("server.db");
    assert!(path.to_str().unwrap().ends_with("server.topo.sock"));

    let path = topo::service::socket_path_for_db("/tmp/mydb.db");
    assert_eq!(path.to_str().unwrap(), "/tmp/mydb.topo.sock");
}

#[test]
fn service_predicate_parsing() {
    use topo::service::parse_predicate;

    let (field, op, val) = parse_predicate("message_count == 10").unwrap();
    assert_eq!(field, "message_count");
    assert_eq!(op.symbol(), "==");
    assert_eq!(val, 10);

    let (field, op, val) = parse_predicate("store_count >= 0").unwrap();
    assert_eq!(field, "store_count");
    assert_eq!(op.symbol(), ">=");
    assert_eq!(val, 0);

    assert!(parse_predicate("bad").is_err());
    assert!(parse_predicate("x ?? 1").is_err());
}
