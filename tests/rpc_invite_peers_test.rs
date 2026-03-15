mod cli_harness;

use cli_harness::*;
use std::process::Command;
use std::time::Duration;
use topo::testutil::DaemonGuard;

#[test]
fn peers_shows_remote_after_invite_accept() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();

    let alice_socket = socket_path_for_db(&alice_db);
    let bob_socket = socket_path_for_db(&bob_db);

    let mut alice_daemon = DaemonGuard::new(
        Command::new(bin())
            .args(["--db", &alice_db, "start", "--bind", "127.0.0.1:0"])
            .spawn()
            .unwrap(),
    );
    wait_for_socket(&alice_socket);
    let _ = wait_for_runtime_state(&alice_socket, "IdleNoTenants", Duration::from_secs(10));
    let create = Command::new(bin())
        .args(["create-workspace", "--db", &alice_db, "--username", "alice"])
        .output()
        .unwrap();
    assert!(create.status.success(), "alice create-workspace failed");
    let alice_status = wait_for_runtime_state(&alice_socket, "Active", Duration::from_secs(10));
    let alice_listen = alice_status["runtime"]["listen_addr"]
        .as_str()
        .expect("alice runtime.listen_addr")
        .to_string();

    let invite_out = Command::new(bin())
        .args(["--db", &alice_db, "invite", "--public-addr", &alice_listen])
        .output()
        .unwrap();
    assert!(invite_out.status.success(), "invite failed");
    let invite_link = String::from_utf8_lossy(&invite_out.stdout)
        .lines()
        .find(|line| line.starts_with("topo://"))
        .expect("missing invite link")
        .to_string();

    let mut bob_daemon = DaemonGuard::new(
        Command::new(bin())
            .args(["--db", &bob_db, "start", "--bind", "127.0.0.1:0"])
            .spawn()
            .unwrap(),
    );
    wait_for_socket(&bob_socket);
    accept_invite_with_identity_on_running_daemon(
        &bob_db,
        &invite_link,
        "bob",
        "device",
        Duration::from_secs(10),
    );
    let _ = wait_for_runtime_state(&bob_socket, "Active", Duration::from_secs(10));

    let start = std::time::Instant::now();
    loop {
        let resp = topo::rpc::client::rpc_call(&bob_socket, topo::rpc::protocol::RpcMethod::Peers)
            .unwrap();
        if resp.ok {
            if let Some(data) = &resp.data {
                if let Some(items) = data.as_array() {
                    if items.len() >= 2 {
                        let local_count = items
                            .iter()
                            .filter(|p| p["local"].as_bool().unwrap_or(false))
                            .count();
                        let remote_count = items
                            .iter()
                            .filter(|p| !p["local"].as_bool().unwrap_or(false))
                            .count();
                        assert_eq!(local_count, 1, "bob should see exactly one local peer");
                        assert!(
                            remote_count >= 1,
                            "bob should see at least one remote peer (alice)"
                        );

                        let has_endpoint = items.iter().any(|p| {
                            !p["local"].as_bool().unwrap_or(false) && p["endpoint"].is_string()
                        });
                        assert!(
                            has_endpoint,
                            "remote peer should have endpoint from sync, got: {:?}",
                            items
                        );
                        break;
                    }
                }
            }
        }
        if start.elapsed() > Duration::from_secs(30) {
            let resp =
                topo::rpc::client::rpc_call(&bob_socket, topo::rpc::protocol::RpcMethod::Peers)
                    .unwrap();
            panic!(
                "bob did not see 2 peers within 30s, last response: {:?}",
                resp.data
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    stop_daemon(&alice_db, &mut alice_daemon);
    stop_daemon(&bob_db, &mut bob_daemon);
}
