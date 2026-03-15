mod cli_harness;

use cli_harness::*;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use topo::event_modules::workspace::invite_link::{
    parse_bootstrap_address, parse_invite_link, rewrite_bootstrap_addrs,
};
use topo::testutil::DaemonGuard;

fn cli_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let guard = LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    cleanup_test_daemons();
    guard
}

fn reserve_wrong_bootstrap_addr() -> (std::net::UdpSocket, String) {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind reserved wrong udp port");
    let addr = socket
        .local_addr()
        .expect("read reserved wrong udp port")
        .to_string();
    (socket, addr)
}

fn rewrite_invite_addrs(invite_link: &str, addrs: &[&str]) -> String {
    let parsed = addrs
        .iter()
        .map(|addr| parse_bootstrap_address(addr).expect("parse bootstrap address"))
        .collect::<Vec<_>>();
    rewrite_bootstrap_addrs(invite_link, &parsed).expect("rewrite invite bootstrap addrs")
}

fn active_tenant_peer_id(db_path: &str) -> Option<String> {
    let output = topo_cmd(db_path, &["tenant", "active"]);
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let active = stdout.trim();
    if active.is_empty() || active == "(none)" {
        None
    } else {
        Some(active.to_string())
    }
}

fn assert_event_visible_on_all(db_paths: &[&str], event_id: &str, timeout_ms: u64) {
    for db_path in db_paths {
        assert_eventually(db_path, &format!("has_event:{} >= 1", event_id), timeout_ms);
    }
}

fn assert_identity_eventually_materialized(db_path: &str, timeout_ms: u64) {
    let start = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    loop {
        let identity = topo_cmd(db_path, &["identity"]);
        let stdout = String::from_utf8_lossy(&identity.stdout);
        if identity.status.success()
            && stdout.contains("Transport:")
            && !stdout.contains("User:      (none)")
            && !stdout.contains("Peer:      (none)")
        {
            return;
        }
        if start.elapsed() >= timeout {
            panic!(
                "identity did not materialize within {}ms for {}:\nstdout:\n{}\nstderr:\n{}",
                timeout_ms,
                db_path,
                stdout,
                String::from_utf8_lossy(&identity.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn wait_for_bootstrap_supersession_and_endpoint_observation(
    db_path: &str,
    remote_peer_id: &str,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    loop {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_millis() as i64;
        let conn = topo::db::open_connection(db_path).expect("open db");
        let bootstrap_rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM invite_bootstrap_trust", [], |row| {
                row.get(0)
            })
            .expect("count invite_bootstrap_trust");
        let pending_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pending_invite_bootstrap_trust",
                [],
                |row| row.get(0),
            )
            .expect("count pending_invite_bootstrap_trust");
        let observed_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*)
                 FROM peer_endpoint_observations
                 WHERE via_peer_id = ?1
                   AND expires_at > ?2",
                rusqlite::params![remote_peer_id, now_ms],
                |row| row.get(0),
            )
            .expect("count peer_endpoint_observations");
        drop(conn);

        if bootstrap_rows == 0 && pending_rows == 0 && observed_rows > 0 {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "bootstrap supersession + endpoint observation did not converge for peer {} in {}ms",
            remote_peer_id,
            timeout.as_millis()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

struct StartedCliPeer {
    db: String,
    _daemon: DaemonGuard,
}

fn start_joined_cli_peer_via_discovery(
    tmpdir: &tempfile::TempDir,
    db_name: &str,
    invite_link: &str,
    username: &str,
    device_name: &str,
) -> StartedCliPeer {
    let db = tmpdir.path().join(db_name).to_str().unwrap().to_string();
    accept_invite_with_identity(&db, invite_link, username, device_name);
    let daemon = start_discovery_daemon(&db);
    StartedCliPeer {
        db,
        _daemon: daemon,
    }
}

/// Two separate local daemons should recover endpoint state via mDNS and then
/// sync successfully even when the invite carries no bootstrap addresses.
#[test]
#[cfg(feature = "discovery")]
fn test_cli_local_mdns_discovery_without_bootstrap_addresses() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let timeout_ms = 90000;

    create_workspace(&alice_db);
    let _alice = start_discovery_daemon(&alice_db);
    let bootstrap_eid = send_message(&alice_db, "bootstrap");
    assert_event_visible_on_all(&[&alice_db], &bootstrap_eid, timeout_ms);

    let invite_link = rewrite_invite_addrs(
        &create_invite(&alice_db, &daemon_listen_addr(&alice_db)),
        &[],
    );
    assert!(
        parse_invite_link(&invite_link)
            .expect("parse empty-address invite")
            .bootstrap_addrs
            .is_empty(),
        "invite should carry no bootstrap addresses"
    );

    let mut bob =
        start_joined_cli_peer_via_discovery(&tmpdir, "bob.db", &invite_link, "user", "device");
    let alice_peer_id = active_tenant_peer_id(&alice_db).expect("alice active tenant");
    wait_for_bootstrap_supersession_and_endpoint_observation(
        &bob.db,
        &alice_peer_id,
        Duration::from_millis(timeout_ms),
    );
    stop_daemon(&bob.db, &mut bob._daemon);
    bob._daemon = start_daemon(&bob.db);

    assert_event_visible_on_all(&[&bob.db], &bootstrap_eid, timeout_ms);
    assert_identity_eventually_materialized(&bob.db, timeout_ms);

    let alice_live_eid = send_message(&alice_db, "alice-via-mdns-empty-bootstrap");
    assert_eventually(
        &bob.db,
        &format!("has_event:{} >= 1", alice_live_eid),
        timeout_ms,
    );

    let bob_msg_eid = send_message(&bob.db, "bob-via-mdns-empty-bootstrap");
    assert_eventually(
        &alice_db,
        &format!("has_event:{} >= 1", bob_msg_eid),
        timeout_ms,
    );
}

/// A rewritten invite with only wrong bootstrap addresses should still recover
/// via mDNS once both daemons are running.
#[test]
#[cfg(feature = "discovery")]
fn test_cli_local_mdns_discovery_with_wrong_bootstrap_address_only() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let timeout_ms = 90000;

    create_workspace(&alice_db);
    let _alice = start_discovery_daemon(&alice_db);
    let (_wrong_addr_guard, wrong_addr) = reserve_wrong_bootstrap_addr();
    let invite_link = rewrite_invite_addrs(
        &create_invite(&alice_db, &daemon_listen_addr(&alice_db)),
        &[&wrong_addr],
    );
    assert_eq!(
        parse_invite_link(&invite_link)
            .expect("parse wrong-address invite")
            .bootstrap_addr_strings(),
        vec![wrong_addr.clone()],
        "invite should carry only the wrong bootstrap address"
    );

    let bob =
        start_joined_cli_peer_via_discovery(&tmpdir, "bob.db", &invite_link, "bob", "bob-box");

    let alice_live_eid = send_message(&alice_db, "alice-via-mdns-wrong-bootstrap");
    assert_eventually(
        &bob.db,
        &format!("has_event:{} >= 1", alice_live_eid),
        timeout_ms,
    );

    let bob_live_eid = send_message(&bob.db, "bob-via-mdns-wrong-bootstrap");
    assert_eventually(
        &alice_db,
        &format!("has_event:{} >= 1", bob_live_eid),
        timeout_ms,
    );
}
