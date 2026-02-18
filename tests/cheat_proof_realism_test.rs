//! Cheat-proof realism tests.
//!
//! These tests enforce an invite-only, daemon-first workflow:
//! - require invite-only autodial behavior,
//! - require daemon CLI invite lifecycle support.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

fn bin() -> String {
    env!("CARGO_BIN_EXE_topo").to_string()
}

fn random_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn wait_for_socket(path: &Path, timeout: Duration) {
    let start = Instant::now();
    while !path.exists() && start.elapsed() < timeout {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        path.exists(),
        "daemon socket did not appear at {} within {:?}",
        path.display(),
        timeout
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

fn create_invite(db: &str, bootstrap_addr: &str) -> String {
    let out = run_topo(&["create-invite", "--db", db, "--bootstrap", bootstrap_addr]);
    assert!(
        out.status.success(),
        "create-invite failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
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

fn topo_send(db: &str, content: &str) -> String {
    let out = topo_rpc(db, &["send", content]);
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
    let out = topo_rpc(db, &["create-invite", "--bootstrap", bootstrap_addr]);
    assert!(
        out.status.success(),
        "topo create-invite failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
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

        let child = cmd.spawn().expect("failed to start topo daemon");
        wait_for_socket(&socket, Duration::from_secs(5));
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

    let alice_bootstrap = run_topo(&["send", "alice-bootstrap", "--db", &alice_db]);
    assert!(
        alice_bootstrap.status.success(),
        "alice bootstrap send failed: stdout={} stderr={}",
        String::from_utf8_lossy(&alice_bootstrap.stdout),
        String::from_utf8_lossy(&alice_bootstrap.stderr)
    );

    let alice_port = random_port();
    let bob_port = random_port();
    let invite_link = create_invite(&alice_db, &format!("127.0.0.1:{}", alice_port));
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

    // Both peers already have local identities so daemons can start immediately.
    let alice_bootstrap = run_topo(&["send", "alice-bootstrap", "--db", &alice_db]);
    assert!(alice_bootstrap.status.success(), "alice bootstrap send failed");
    let bob_bootstrap = run_topo(&["send", "bob-bootstrap", "--db", &bob_db]);
    assert!(bob_bootstrap.status.success(), "bob bootstrap send failed");

    let alice_port = random_port();
    let bob_port = random_port();

    let _alice = Daemon::start(&alice_db, alice_port);
    let _bob = Daemon::start(&bob_db, bob_port);

    // Create/accept invite entirely via unified CLI while Bob is already running.
    let invite_link = topo_create_invite(
        &alice_db,
        &format!("127.0.0.1:{}", alice_port),
    );
    topo_accept_invite(&bob_db, &invite_link);

    // If runtime autodial refresh works, Bob reaches Alice without daemon restart.
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
