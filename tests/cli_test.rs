use std::process::{Child, Command, Stdio};
use std::time::Duration;
use rusqlite::Connection;

fn bin() -> String {
    env!("CARGO_BIN_EXE_poc-7").to_string()
}

/// Pick a random port in the ephemeral range to avoid conflicts between
/// parallel test runs and other services.
fn random_port() -> u16 {
    // Bind to :0, read the assigned port, close immediately
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn start_sync_with_options(db: &str, bind_port: u16, disable_placeholder_autodial: bool) -> Child {
    let mut cmd = Command::new(bin());
    cmd.arg("sync")
        .arg("--bind")
        .arg(format!("127.0.0.1:{}", bind_port))
        .arg("--db")
        .arg(db)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if disable_placeholder_autodial {
        cmd.env("P7_DISABLE_PLACEHOLDER_AUTODIAL", "1");
    }

    cmd.spawn().expect("failed to start sync process")
}

fn start_sync(db: &str, bind_port: u16) -> Child {
    start_sync_with_options(db, bind_port, false)
}

fn send_message(db: &str, content: &str) -> String {
    let output = Command::new(bin())
        .arg("send")
        .arg(content)
        .arg("--db")
        .arg(db)
        .output()
        .expect("failed to run send");
    assert!(
        output.status.success(),
        "send failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("event_id:"))
        .expect("send output missing event_id: line")
        .to_string()
}

fn assert_now(db: &str, predicate: &str) {
    let output = Command::new(bin())
        .arg("assert-now")
        .arg(predicate)
        .arg("--db")
        .arg(db)
        .output()
        .expect("failed to run assert-now");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "assert-now failed: {} ({})",
        predicate,
        text.trim()
    );
}

fn assert_eventually(db: &str, predicate: &str, timeout_ms: u64) {
    let output = Command::new(bin())
        .arg("assert-eventually")
        .arg(predicate)
        .arg("--db")
        .arg(db)
        .arg("--timeout-ms")
        .arg(timeout_ms.to_string())
        .output()
        .expect("failed to run assert-eventually");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "assert-eventually timed out: {} ({})",
        predicate,
        text.trim()
    );
}

fn get_messages(db: &str) -> Vec<String> {
    let output = Command::new(bin())
        .arg("messages")
        .arg("--db")
        .arg(db)
        .output()
        .expect("failed to run messages");
    let text = String::from_utf8_lossy(&output.stdout);
    // Parse numbered lines like "    1. Hello from Alice"
    text.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            // Match "N. content" pattern
            let dot_pos = trimmed.find(". ")?;
            let prefix = &trimmed[..dot_pos];
            if prefix.chars().all(|c| c.is_ascii_digit()) {
                Some(trimmed[dot_pos + 2..].to_string())
            } else {
                None
            }
        })
        .collect()
}

/// Helper: run create-invite CLI command. Returns the invite link printed to stdout.
fn create_invite(db: &str, bootstrap_addr: &str) -> String {
    let output = Command::new(bin())
        .arg("create-invite")
        .arg("--db")
        .arg(db)
        .arg("--bootstrap")
        .arg(bootstrap_addr)
        .output()
        .expect("failed to run create-invite");
    assert!(
        output.status.success(),
        "create-invite failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// Helper: run accept-invite CLI command. Installs deterministic transport cert,
/// does bootstrap sync, creates identity chain, and records bootstrap trust.
fn accept_invite(db: &str, invite_link: &str) {
    let output = Command::new(bin())
        .arg("accept-invite")
        .arg("--db")
        .arg(db)
        .arg("--invite")
        .arg(invite_link)
        .output()
        .expect("failed to run accept-invite");
    assert!(
        output.status.success(),
        "accept-invite failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn count_rows(db: &str, table: &str) -> i64 {
    let conn = Connection::open(db).expect("failed to open db");
    let sql = format!("SELECT COUNT(*) FROM {}", table);
    conn.query_row(&sql, [], |row| row.get(0))
        .expect("failed to query row count")
}

/// Functional sync test using invite-based shared workspace flow.
/// Alice bootstraps identity, creates invite, starts sync.
/// Bob accepts invite (bootstrap sync), starts sync with invite-seeded autodial.
/// Both send messages in the shared workspace.
#[test]
fn test_cli_bidirectional_sync() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 15000;

    let alice_port = random_port();
    let bob_port = random_port();

    // Alice bootstraps identity chain (workspace + keys)
    send_message(&alice_db, "Hello from Alice");
    let alice_eid = send_message(&alice_db, "How are you?");

    // Alice creates invite
    let invite_link = create_invite(&alice_db, &format!("127.0.0.1:{}", alice_port));

    // Alice starts sync
    let mut alice = start_sync(&alice_db, alice_port);
    std::thread::sleep(Duration::from_millis(500));

    // Bob accepts invite (bootstrap sync from Alice)
    accept_invite(&bob_db, &invite_link);

    // Bob starts sync; daemon uses invite-seeded autodial to reach Alice.
    let mut bob = start_sync(&bob_db, bob_port);
    std::thread::sleep(Duration::from_secs(1));

    // Bob sends a message in the shared workspace
    let bob_eid = send_message(&bob_db, "Hey Alice!");
    assert_eventually(&alice_db, &format!("has_event:{} >= 1", bob_eid), timeout_ms);
    assert_eventually(&bob_db, &format!("has_event:{} >= 1", alice_eid), timeout_ms);

    // Verify specific message content arrived on both sides
    let alice_msgs = get_messages(&alice_db);
    assert!(alice_msgs.len() >= 3, "Alice should see at least 3 messages, got {}", alice_msgs.len());
    assert!(alice_msgs.contains(&"Hello from Alice".to_string()));
    assert!(alice_msgs.contains(&"How are you?".to_string()));
    assert!(alice_msgs.contains(&"Hey Alice!".to_string()));

    let bob_msgs = get_messages(&bob_db);
    assert!(bob_msgs.len() >= 3, "Bob should see at least 3 messages, got {}", bob_msgs.len());
    assert!(bob_msgs.contains(&"Hello from Alice".to_string()));
    assert!(bob_msgs.contains(&"How are you?".to_string()));
    assert!(bob_msgs.contains(&"Hey Alice!".to_string()));

    // Cleanup
    let _ = alice.kill();
    let _ = bob.kill();
    let _ = alice.wait();
    let _ = bob.wait();
}

/// Functional sync test using invite-based flow.
/// Verifies sync picks up new messages over time (ongoing sync).
#[test]
fn test_cli_ongoing_sync() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 15000;

    let alice_port = random_port();
    let bob_port = random_port();

    // Alice bootstraps identity
    send_message(&alice_db, "bootstrap");

    // Alice creates invite and starts sync
    let invite_link = create_invite(&alice_db, &format!("127.0.0.1:{}", alice_port));
    let mut alice = start_sync(&alice_db, alice_port);
    std::thread::sleep(Duration::from_millis(500));

    // Bob accepts invite and starts sync
    accept_invite(&bob_db, &invite_link);
    let mut bob = start_sync(&bob_db, bob_port);
    std::thread::sleep(Duration::from_secs(1));

    // Both send messages over time
    send_message(&alice_db, "Round 1");
    send_message(&bob_db, "Round 2");
    send_message(&alice_db, "Round 3a");
    let bob_last_eid = send_message(&bob_db, "Round 3b");
    std::thread::sleep(Duration::from_secs(1));
    let alice_last_eid = send_message(&alice_db, "Round 4");

    assert_eventually(&alice_db, &format!("has_event:{} >= 1", bob_last_eid), timeout_ms);
    assert_eventually(&bob_db, &format!("has_event:{} >= 1", alice_last_eid), timeout_ms);

    let _ = alice.kill();
    let _ = bob.kill();
    let _ = alice.wait();
    let _ = bob.wait();
}

/// Two separate local daemons should discover and sync on the same machine
/// even when invite-seeded placeholder autodial is disabled.
#[test]
fn test_cli_local_mdns_discovery_without_placeholder_autodial() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 20000;

    let alice_port = random_port();
    let bob_port = random_port();

    // Bootstrap Alice and produce an invite Bob can accept.
    let alice_seed_eid = send_message(&alice_db, "alice-seed");
    let invite_link = create_invite(&alice_db, &format!("127.0.0.1:{}", alice_port));

    // Start both daemons with placeholder invite-autodial disabled so this test
    // exercises LAN discovery + trust gating for ongoing sync.
    let mut alice = start_sync_with_options(&alice_db, alice_port, true);
    std::thread::sleep(Duration::from_millis(700));

    accept_invite(&bob_db, &invite_link);
    let mut bob = start_sync_with_options(&bob_db, bob_port, true);
    std::thread::sleep(Duration::from_secs(2));

    // Validate bidirectional convergence.
    let bob_msg_eid = send_message(&bob_db, "bob-via-mdns-localhost");
    assert_eventually(&alice_db, &format!("has_event:{} >= 1", bob_msg_eid), timeout_ms);
    assert_eventually(&bob_db, &format!("has_event:{} >= 1", alice_seed_eid), timeout_ms);

    let _ = alice.kill();
    let _ = bob.kill();
    let _ = alice.wait();
    let _ = bob.wait();
}

#[test]
fn test_cli_send_and_messages() {
    // Basic test: send/messages work without sync running
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir.path().join("test.db").to_str().unwrap().to_string();

    let _first_eid = send_message(&db, "First message");
    let second_eid = send_message(&db, "Second message");

    assert_now(&db, "message_count == 2");
    assert_now(&db, &format!("has_event:{} >= 1", second_eid));

    let messages = get_messages(&db);
    assert_eq!(messages.len(), 2);
    assert!(messages.contains(&"First message".to_string()));
    assert!(messages.contains(&"Second message".to_string()));
}

/// TRUST POLICY TEST: untrusted peer is rejected.
/// Alice bootstraps identity (PeerShared self-trust makes has_any_trusted_peer true).
/// Bob has independent identity (not in Alice's workspace). Alice should reject Bob.
#[test]
fn test_cli_unpinned_peer_rejected() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();

    let alice_port = random_port();
    let bob_port = random_port();

    // Alice bootstraps identity (creates workspace, identity chain, TransportKey)
    send_message(&alice_db, "alice bootstrap");

    // Bob bootstraps his own independent identity
    send_message(&bob_db, "bob bootstrap");

    // Alice starts sync (has PeerShared self-trust from identity chain)
    let mut alice = start_sync(&alice_db, alice_port);
    std::thread::sleep(Duration::from_millis(500));

    // Bob starts sync; with independent identity/workspace he should still be rejected.
    let mut bob = start_sync(&bob_db, bob_port);
    std::thread::sleep(Duration::from_secs(1));

    // Bob sends a message
    let bob_eid = send_message(&bob_db, "Should not arrive");
    // Give some time for sync to try
    std::thread::sleep(Duration::from_secs(3));

    assert_now(&alice_db, &format!("has_event:{} == 0", bob_eid));

    let _ = alice.kill();
    let _ = bob.kill();
    let _ = alice.wait();
    let _ = bob.wait();
}

/// TRUST POLICY TEST: sync with no trusted peers is rejected at startup.
#[test]
fn test_cli_sync_without_trust_fails() {
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("no_trust.db")
        .to_str()
        .unwrap()
        .to_string();
    let port = random_port();

    // Start sync with no identity chain (no trusted peers) — should fail immediately
    let output = Command::new(bin())
        .arg("sync")
        .arg("--bind")
        .arg(format!("127.0.0.1:{}", port))
        .arg("--db")
        .arg(&db)
        .output()
        .expect("failed to run sync");

    assert!(
        !output.status.success(),
        "sync with no trusted peers should fail, but exited with {:?}",
        output.status.code()
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No local identities"),
        "error should mention missing identities, got: {}",
        stderr
    );
}

/// Bootstrap trust test using production create-invite / accept-invite CLI flow.
/// No direct SQL trust seeding — trust is materialized through CLI commands.
/// accept-invite does bootstrap sync (fetches workspace events from Alice),
/// then creates the full identity chain and records transport trust.
#[test]
fn test_cli_sync_bootstrap_from_accepted_invite_data() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir
        .path()
        .join("alice_bootstrap.db")
        .to_str()
        .unwrap()
        .to_string();
    let bob_db = tmpdir
        .path()
        .join("bob_bootstrap.db")
        .to_str()
        .unwrap()
        .to_string();
    let timeout_ms = 15000;

    let alice_port = random_port();
    let bob_port = random_port();

    // Bootstrap Alice's identity chain (workspace + keys) so create-invite
    // can find the workspace key. send triggers ensure_identity_chain.
    send_message(&alice_db, "bootstrap");

    // Alice creates invite (records pending trust with derived invitee SPKI).
    let invite_link = create_invite(
        &alice_db,
        &format!("127.0.0.1:{}", alice_port),
    );

    // Alice must be running sync before Bob accepts (accept-invite does
    // bootstrap sync to fetch prerequisite workspace events from Alice).
    let mut alice = start_sync(&alice_db, alice_port);
    std::thread::sleep(Duration::from_millis(500));

    // Bob accepts invite: installs deterministic cert, bootstrap-syncs from
    // Alice, creates identity chain, records bootstrap trust.
    accept_invite(&bob_db, &invite_link);
    assert!(
        count_rows(&alice_db, "secret_shared") >= 1,
        "inviter should emit at least one secret_shared key-wrap during invite creation"
    );
    assert!(
        count_rows(&bob_db, "secret_keys") >= 1,
        "invitee should materialize local secret_key after unwrap"
    );
    assert!(
        count_rows(&bob_db, "secret_shared") >= 1,
        "invitee should eventually project inviter secret_shared after local key materialization"
    );

    // Bob starts ongoing sync; invite bootstrap trust seeds daemon autodial.
    let mut bob = start_sync(&bob_db, bob_port);
    std::thread::sleep(Duration::from_secs(1));

    let bob_eid = send_message(&bob_db, "bootstrap trust from invite data");
    assert_eventually(&alice_db, &format!("has_event:{} >= 1", bob_eid), timeout_ms);

    let _ = alice.kill();
    let _ = bob.kill();
    let _ = alice.wait();
    let _ = bob.wait();
}
