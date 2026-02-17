//! Cheat-proof realism tests.
//!
//! These tests enforce an invite-only, daemon-first workflow:
//! - prove transport path works today (manual `--connect` baseline),
//! - require invite-only autodial behavior,
//! - require daemon CLI invite lifecycle support.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

fn bin_poc7() -> String {
    env!("CARGO_BIN_EXE_poc-7").to_string()
}

fn bin_p7d() -> String {
    env!("CARGO_BIN_EXE_p7d").to_string()
}

fn bin_p7ctl() -> String {
    env!("CARGO_BIN_EXE_p7ctl").to_string()
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

fn run_poc7(args: &[&str]) -> Output {
    Command::new(bin_poc7())
        .args(args)
        .output()
        .expect("failed to run poc-7")
}

fn create_invite(db: &str, bootstrap_addr: &str) -> String {
    let out = run_poc7(&["create-invite", "--db", db, "--bootstrap", bootstrap_addr]);
    assert!(
        out.status.success(),
        "create-invite failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn accept_invite(db: &str, invite_link: &str) {
    let out = run_poc7(&[
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

fn p7ctl_output(db: &str, socket: &Path, args: &[&str]) -> Output {
    Command::new(bin_p7ctl())
        .arg("--db")
        .arg(db)
        .arg("--socket")
        .arg(socket)
        .args(args)
        .output()
        .expect("failed to run p7ctl")
}

fn p7ctl_send(db: &str, socket: &Path, content: &str) -> String {
    let out = p7ctl_output(db, socket, &["send", content]);
    assert!(
        out.status.success(),
        "p7ctl send failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("p7ctl send stdout should be JSON");
    v["data"]["event_id"]
        .as_str()
        .expect("p7ctl send response missing data.event_id")
        .to_string()
}

fn p7ctl_assert_eventually(db: &str, socket: &Path, predicate: &str, timeout_ms: u64) -> Output {
    p7ctl_output(
        db,
        socket,
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
    fn start(db: &str, socket: &Path, bind_port: u16, connect_port: Option<u16>) -> Self {
        let mut cmd = Command::new(bin_p7d());
        cmd.arg("--db")
            .arg(db)
            .arg("--socket")
            .arg(socket)
            .arg("--bind")
            .arg(format!("127.0.0.1:{}", bind_port))
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        if let Some(port) = connect_port {
            cmd.arg("--connect").arg(format!("127.0.0.1:{}", port));
        }

        let child = cmd.spawn().expect("failed to start p7d");
        wait_for_socket(socket, Duration::from_secs(5));
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

    let alice_bootstrap = run_poc7(&["send", "alice-bootstrap", "--db", &alice_db]);
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
fn test_manual_connect_proves_transport_path_after_invite_bootstrap() {
    let tmpdir = tempfile::tempdir().unwrap();
    let (alice_db, bob_db, invite_link, alice_port, bob_port) = bootstrap_alice_and_invite(&tmpdir);

    let alice_socket: PathBuf = tmpdir.path().join("alice.sock");
    let bob_socket: PathBuf = tmpdir.path().join("bob.sock");

    let _alice = Daemon::start(&alice_db, &alice_socket, alice_port, None);
    accept_invite(&bob_db, &invite_link);
    let _bob = Daemon::start(&bob_db, &bob_socket, bob_port, Some(alice_port));

    let bob_event_id = p7ctl_send(&bob_db, &bob_socket, "manual-connect-proof");
    let out = p7ctl_assert_eventually(
        &alice_db,
        &alice_socket,
        &format!("has_event:{} >= 1", bob_event_id),
        12_000,
    );
    assert!(
        out.status.success(),
        "manual-connect baseline failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn test_invite_only_daemons_should_autodial_without_manual_connect() {
    let tmpdir = tempfile::tempdir().unwrap();
    let (alice_db, bob_db, invite_link, alice_port, bob_port) = bootstrap_alice_and_invite(&tmpdir);

    let alice_socket: PathBuf = tmpdir.path().join("alice.sock");
    let bob_socket: PathBuf = tmpdir.path().join("bob.sock");

    let _alice = Daemon::start(&alice_db, &alice_socket, alice_port, None);
    accept_invite(&bob_db, &invite_link);
    let _bob = Daemon::start(&bob_db, &bob_socket, bob_port, None);

    // Desired behavior: after invite acceptance, daemons should autodial based on
    // persisted bootstrap/discovery state, with no manual --connect.
    let bob_event_id = p7ctl_send(&bob_db, &bob_socket, "invite-only-autodial-required");
    let out = p7ctl_assert_eventually(
        &alice_db,
        &alice_socket,
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
fn test_daemon_cli_contract_exposes_invite_lifecycle_commands() {
    let out = Command::new(bin_p7ctl())
        .arg("--help")
        .output()
        .expect("failed to run p7ctl --help");
    assert!(out.status.success(), "p7ctl --help failed");
    let text = String::from_utf8_lossy(&out.stdout);

    // Desired daemon-first realism: setup should be possible via daemon CLI only.
    assert!(
        text.contains("create-invite"),
        "p7ctl missing create-invite (daemon-first invite realism not met)"
    );
    assert!(
        text.contains("accept-invite"),
        "p7ctl missing accept-invite (daemon-first invite realism not met)"
    );
}
