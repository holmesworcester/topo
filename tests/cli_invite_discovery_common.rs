#![allow(dead_code, unused_imports)]

#[path = "cli_harness/mod.rs"]
mod cli_harness;

use self::cli_harness::*;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use topo::event_modules::workspace::invite_link::{
    parse_bootstrap_address, parse_invite_link, rewrite_bootstrap_addrs,
};

pub fn cli_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    hold_network_test_lock_for_binary();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub fn reserve_wrong_bootstrap_addr() -> (std::net::UdpSocket, String) {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind reserved wrong udp port");
    let addr = socket
        .local_addr()
        .expect("read reserved wrong udp port")
        .to_string();
    (socket, addr)
}

pub fn rewrite_invite_addrs(invite_link: &str, addrs: &[&str]) -> String {
    let parsed = addrs
        .iter()
        .map(|addr| parse_bootstrap_address(addr).expect("parse bootstrap address"))
        .collect::<Vec<_>>();
    rewrite_bootstrap_addrs(invite_link, &parsed).expect("rewrite invite bootstrap addrs")
}

pub fn active_tenant_peer_id(db_path: &str) -> Option<String> {
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

pub fn assert_event_visible_on_all(db_paths: &[&str], event_id: &str, timeout_ms: u64) {
    for db_path in db_paths {
        assert_eventually(db_path, &format!("has_event:{} >= 1", event_id), timeout_ms);
    }
}

pub fn assert_identity_eventually_materialized(db_path: &str, timeout_ms: u64) {
    let start = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    loop {
        let identity = topo_cmd(db_path, &["identity"]);
        let stdout = String::from_utf8_lossy(&identity.stdout);
        if identity.status.success()
            && stdout.contains("Transport:")
            && !stdout.contains("User:      (none)")
            && !stdout.contains("Account:   (none)")
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

pub fn wait_for_endpoint_observation(db_path: &str, remote_peer_id: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_millis() as i64;
        let conn = topo::db::open_connection(db_path).expect("open db");
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

        if observed_rows > 0 {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "endpoint observation did not appear for peer {} in {}ms",
            remote_peer_id,
            timeout.as_millis()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub struct StartedCliPeer {
    pub db: String,
    pub daemon: HarnessDaemon,
}

pub fn start_joined_cli_peer_via_discovery(
    tmpdir: &tempfile::TempDir,
    db_name: &str,
    invite_link: &str,
    username: &str,
    device_name: &str,
) -> StartedCliPeer {
    let db = tmpdir.path().join(db_name).to_str().unwrap().to_string();
    let daemon = start_discovery_daemon(&db);
    accept_invite_with_identity_on_running_daemon(
        &db,
        invite_link,
        username,
        device_name,
        Duration::from_secs(20),
    );
    StartedCliPeer { db, daemon }
}

pub use cli_harness::{
    accept_invite_with_identity_on_running_daemon, assert_eventually, create_invite,
    create_workspace, daemon_listen_addr, send_message, start_daemon, start_discovery_daemon,
    stop_daemon,
};
