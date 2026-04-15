//! Live Tor smoke test for the Arti/onion transport backend.
//!
//! Run explicitly:
//! `cargo test --no-default-features --features tor-transport --test tor_live_smoke_test -- --ignored --nocapture --test-threads=1`

mod cli_harness;

use cli_harness::*;
use std::process::Command;
use std::thread;
use std::time::Duration;

#[cfg(feature = "tor-transport")]
fn wait_for_onion_published_addr(db: &str, timeout: Duration) -> String {
    let socket = socket_path_for_db(db);
    let status = assert_value_eventually(
        timeout,
        Duration::from_secs(1),
        "Tor onion address publication",
        || status_via_rpc(&socket),
        |data| {
            data["runtime"]["published_addrs"]
                .as_array()
                .map(|addrs| {
                    addrs.iter().any(|addr| {
                        addr.as_str()
                            .map(|addr| addr.ends_with(".onion:17691"))
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false)
        },
    );
    status["runtime"]["published_addrs"]
        .as_array()
        .and_then(|addrs| {
            addrs.iter().find_map(|addr| {
                let addr = addr.as_str()?;
                addr.ends_with(".onion:17691").then(|| addr.to_string())
            })
        })
        .expect("status should contain a published onion address")
}

#[cfg(feature = "tor-transport")]
#[test]
#[ignore = "live Tor smoke test; requires real Tor bootstrap and can take minutes"]
fn tor_live_invite_and_message_smoke() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();

    let alice_socket = socket_path_for_db(&alice_db);
    let bob_socket = socket_path_for_db(&bob_db);

    let mut alice_daemon = start_daemon(&alice_db);
    let _ = wait_for_runtime_state(&alice_socket, "IdleNoTenants", Duration::from_secs(30));

    let create = Command::new(bin())
        .args([
            "create-workspace",
            "--db",
            &alice_db,
            "--workspace-name",
            "tor-live",
            "--username",
            "alice",
            "--device-name",
            "alice-laptop",
        ])
        .output()
        .expect("alice create-workspace");
    assert!(
        create.status.success(),
        "alice create-workspace failed: stdout={} stderr={}",
        String::from_utf8_lossy(&create.stdout),
        String::from_utf8_lossy(&create.stderr)
    );

    let _ = wait_for_runtime_state(&alice_socket, "Active", Duration::from_secs(30));
    let alice_onion_addr = wait_for_onion_published_addr(&alice_db, Duration::from_secs(300));

    // Onion publication can lag behind first appearance in local status.
    thread::sleep(Duration::from_secs(20));

    let invite_link = create_invite(&alice_db, &alice_onion_addr);
    assert!(
        invite_link.starts_with("topo://invite/"),
        "expected invite link, got: {}",
        invite_link
    );

    let mut bob_daemon = start_daemon(&bob_db);
    let _ = wait_for_runtime_state(&bob_socket, "IdleNoTenants", Duration::from_secs(30));

    accept_invite_with_identity_on_running_daemon(
        &bob_db,
        &invite_link,
        "bob",
        "bob-laptop",
        Duration::from_secs(180),
    );
    let _ = wait_for_runtime_state(&bob_socket, "Active", Duration::from_secs(30));

    wait_for_active_tenant_bootstrap_ready(&bob_db, Duration::from_secs(180));
    wait_for_active_tenant_ready(&bob_db, Duration::from_secs(300));
    wait_for_active_tenant_transport_converged(&bob_db, Duration::from_secs(300));

    let message = "hello-over-live-tor";
    let _event_id = send_message(&alice_db, message);

    let bob_messages = assert_value_eventually(
        Duration::from_secs(300),
        Duration::from_secs(1),
        "Bob receiving Alice's live Tor message",
        || get_messages(&bob_db),
        |messages| messages.iter().any(|item| item == message),
    );
    assert!(
        bob_messages.iter().any(|item| item == message),
        "Bob should project Alice's live Tor message, got: {:?}",
        bob_messages
    );

    stop_daemon(&alice_db, &mut alice_daemon);
    stop_daemon(&bob_db, &mut bob_daemon);
}
