//! Cheat-proof realism tests.
//!
//! These tests enforce an invite-only, daemon-first workflow:
//! - require invite-only autodial behavior,
//! - require daemon CLI invite lifecycle support.

use std::collections::HashSet;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

fn bin() -> String {
    env!("CARGO_BIN_EXE_topo").to_string()
}

fn random_port() -> u16 {
    static USED_PORTS: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();
    let used_ports = USED_PORTS.get_or_init(|| Mutex::new(HashSet::new()));
    loop {
        // Daemon QUIC bind is UDP, so reserve from UDP ephemeral space.
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        if used_ports.lock().unwrap().insert(port) {
            return port;
        }
    }
}

fn is_transient_rpc_startup_error(stderr: &str) -> bool {
    stderr.contains("daemon not running")
        || stderr.contains("Connection reset by peer")
        || stderr.contains("no identity — run `topo create-workspace` first")
        || stderr.contains("no active peer — run `topo use-peer <N>`")
}

fn wait_for_daemon_ready(db: &str, path: &Path, child: &mut Child, timeout: Duration) {
    let start = Instant::now();
    let mut last_status_err = String::new();
    while start.elapsed() < timeout {
        if let Some(status) = child
            .try_wait()
            .expect("failed to check daemon child status")
        {
            panic!(
                "daemon exited before becoming ready (status: {}) for db {}",
                status, db
            );
        }
        if path.exists() {
            let out = topo_rpc(db, &["status"]);
            if out.status.success() {
                return;
            }
            last_status_err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        path.exists(),
        "daemon socket did not appear at {} within {:?}",
        path.display(),
        timeout
    );
    panic!(
        "daemon socket appeared but daemon did not become RPC-ready within {:?} (db={}, last status error={})",
        timeout,
        db,
        last_status_err
    );
}

fn socket_path_for_db(db: &str) -> PathBuf {
    topo::service::socket_path_for_db(db)
}

fn run_topo(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("failed to run topo")
}

fn create_workspace(db: &str) {
    let out = run_topo(&["create-workspace", "--db", db]);
    assert!(
        out.status.success(),
        "create-workspace failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // create-workspace auto-starts daemon; tests start daemons explicitly.
    let _ = run_topo(&["--db", db, "stop"]);
}

fn accept_invite(db: &str, invite_link: &str) {
    let out = run_topo(&[
        "accept-invite",
        "--db",
        db,
        "--invite",
        invite_link,
        "--username",
        "user",
        "--devicename",
        "device",
    ]);
    assert!(
        out.status.success(),
        "accept-invite failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // accept-invite auto-starts daemon; tests start daemons explicitly.
    let _ = run_topo(&["--db", db, "stop"]);
}

/// Run a topo subcommand that routes through the daemon via RPC (daemon-preferred commands).
fn topo_rpc(db: &str, args: &[&str]) -> Output {
    Command::new(bin())
        .arg("--db")
        .arg(db)
        .args(args)
        .output()
        .expect("failed to run topo")
}

fn topo_rpc_retry(db: &str, args: &[&str], timeout: Duration) -> Output {
    let start = Instant::now();
    let mut attempt = 0u32;
    loop {
        let out = topo_rpc(db, args);
        if out.status.success() {
            return out;
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.contains("no active peer") {
            let _ = topo_rpc(db, &["use-peer", "1"]);
        }
        if start.elapsed() >= timeout || !is_transient_rpc_startup_error(&stderr) {
            return out;
        }
        attempt += 1;
        let delay_ms = 25u64 * (1u64 << attempt.min(5));
        std::thread::sleep(Duration::from_millis(delay_ms));
    }
}

fn topo_send(db: &str, content: &str) -> String {
    let out = topo_rpc_retry(db, &["send", content], Duration::from_secs(4));
    assert!(
        out.status.success(),
        "topo send failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("event_id:"))
        .expect("send output missing event_id: line")
        .to_string()
}

fn topo_create_invite(db: &str, bootstrap_addr: &str) -> String {
    let out = topo_rpc_retry(
        db,
        &["create-invite", "--public-addr", bootstrap_addr],
        Duration::from_secs(3),
    );
    assert!(
        out.status.success(),
        "topo create-invite failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .lines()
        .find(|line| line.starts_with("quiet://"))
        .expect("create-invite output missing quiet:// link")
        .to_string()
}

fn topo_accept_invite(db: &str, invite_link: &str) {
    let out = run_topo(&[
        "accept-invite",
        "--db",
        db,
        "--invite",
        invite_link,
        "--username",
        "user",
        "--devicename",
        "device",
    ]);
    assert!(
        out.status.success(),
        "topo accept-invite failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // accept-invite auto-starts daemon; tests start daemons explicitly.
    let _ = run_topo(&["--db", db, "stop"]);
}

fn topo_assert_eventually(db: &str, predicate: &str, timeout_ms: u64) -> Output {
    topo_rpc(
        db,
        &[
            "assert-eventually",
            predicate,
            "--timeout-ms",
            &timeout_ms.to_string(),
        ],
    )
}

struct Daemon {
    child: Option<Child>,
}

impl Daemon {
    fn start(db: &str, bind_port: u16) -> Self {
        let socket = socket_path_for_db(db);
        let mut cmd = Command::new(bin());
        cmd.arg("--db")
            .arg(db)
            .arg("start")
            .arg("--bind")
            .arg(format!("127.0.0.1:{}", bind_port))
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let mut child = cmd.spawn().expect("failed to start topo daemon");
        wait_for_daemon_ready(db, &socket, &mut child, Duration::from_secs(5));
        Self { child: Some(child) }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn bootstrap_alice_and_invite(tmpdir: &tempfile::TempDir) -> (String, String, String, u16, u16) {
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();

    let alice_port = random_port();
    let bob_port = random_port();

    // Create workspace for Alice (identity chain)
    create_workspace(&alice_db);

    // Start Alice's daemon so we can create invites via RPC
    // (Daemon is returned via the test — caller will hold it)
    // We need the daemon running to create invites, so we start it here
    // and return the invite link. Caller will start their own Daemon.
    let _alice_daemon = Daemon::start(&alice_db, alice_port);

    // Create invite via daemon RPC
    let invite_link = topo_create_invite(&alice_db, &format!("127.0.0.1:{}", alice_port));

    // Kill temporary daemon — caller will start their own
    drop(_alice_daemon);

    (alice_db, bob_db, invite_link, alice_port, bob_port)
}

#[test]
fn test_invite_only_daemons_should_autodial_without_manual_connect() {
    let tmpdir = tempfile::tempdir().unwrap();
    let (alice_db, bob_db, invite_link, alice_port, bob_port) = bootstrap_alice_and_invite(&tmpdir);

    let _alice = Daemon::start(&alice_db, alice_port);
    accept_invite(&bob_db, &invite_link);
    let _bob = Daemon::start(&bob_db, bob_port);

    // Desired behavior: after invite acceptance, daemons should autodial based on
    // persisted bootstrap/discovery state, with no manual connect flag.
    let bob_event_id = topo_send(&bob_db, "invite-only-autodial-required");
    let out = topo_assert_eventually(
        &alice_db,
        &format!("has_event:{} >= 1", bob_event_id),
        8_000,
    );
    assert!(
        out.status.success(),
        "invite-only autodial realism gap: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn test_daemon_cli_invite_lifecycle_works_without_restart() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();

    let alice_port = random_port();
    let bob_port = random_port();

    // Create workspace for Alice and start her daemon.
    create_workspace(&alice_db);
    let _alice = Daemon::start(&alice_db, alice_port);

    // Create invite while Alice's daemon is running (via RPC).
    let invite_link = topo_create_invite(
        &alice_db,
        &format!("127.0.0.1:{}", alice_port),
    );

    // Bob accepts invite before starting daemon (daemon-routed CLI command).
    topo_accept_invite(&bob_db, &invite_link);

    // Bob starts daemon after accept-invite — auto-selects the shared workspace peer.
    let _bob = Daemon::start(&bob_db, bob_port);

    // Bob sends a message in the shared workspace via daemon RPC.
    let bob_event_id = topo_send(&bob_db, "runtime-accept-invite-no-restart");
    let out = topo_assert_eventually(
        &alice_db,
        &format!("has_event:{} >= 1", bob_event_id),
        20_000,
    );
    assert!(
        out.status.success(),
        "daemon CLI invite lifecycle behavior gap: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
