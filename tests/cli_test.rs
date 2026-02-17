use std::process::{Child, Command, Stdio};
use std::time::Duration;

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

fn start_sync(db: &str, bind_port: u16, connect_port: Option<u16>) -> Child {
    let mut cmd = Command::new(bin());
    cmd.arg("sync")
        .arg("--bind")
        .arg(format!("127.0.0.1:{}", bind_port))
        .arg("--db")
        .arg(db)
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    if let Some(port) = connect_port {
        cmd.arg("--connect").arg(format!("127.0.0.1:{}", port));
    }

    cmd.spawn().expect("failed to start sync process")
}

fn send_message(db: &str, content: &str) {
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

/// Functional sync test using invite-based shared workspace flow.
/// Alice bootstraps identity, creates invite, starts sync.
/// Bob accepts invite (bootstrap sync), starts sync connecting to Alice.
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
    send_message(&alice_db, "How are you?");

    // Alice creates invite
    let invite_link = create_invite(&alice_db, &format!("127.0.0.1:{}", alice_port));

    // Alice starts sync
    let mut alice = start_sync(&alice_db, alice_port, None);
    std::thread::sleep(Duration::from_millis(500));

    // Bob accepts invite (bootstrap sync from Alice)
    accept_invite(&bob_db, &invite_link);

    // Bob starts sync connecting to Alice
    let mut bob = start_sync(&bob_db, bob_port, Some(alice_port));
    std::thread::sleep(Duration::from_secs(1));

    // Bob sends a message in the shared workspace
    send_message(&bob_db, "Hey Alice!");

    // Wait for convergence on actual message data:
    // Alice sent 2 messages, Bob sent 1 = 3 total per peer
    assert_eventually(&alice_db, "message_count >= 3", timeout_ms);
    assert_eventually(&bob_db, "message_count >= 3", timeout_ms);

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
    let mut alice = start_sync(&alice_db, alice_port, None);
    std::thread::sleep(Duration::from_millis(500));

    // Bob accepts invite and starts sync
    accept_invite(&bob_db, &invite_link);
    let mut bob = start_sync(&bob_db, bob_port, Some(alice_port));
    std::thread::sleep(Duration::from_secs(1));

    // Both send messages over time
    send_message(&alice_db, "Round 1");
    send_message(&bob_db, "Round 2");
    send_message(&alice_db, "Round 3a");
    send_message(&bob_db, "Round 3b");
    std::thread::sleep(Duration::from_secs(1));
    send_message(&alice_db, "Round 4");

    // Wait for convergence on actual message data:
    // Alice sent 4 messages (bootstrap, Round 1, Round 3a, Round 4)
    // Bob sent 2 messages (Round 2, Round 3b) = 6 total per peer
    assert_eventually(&alice_db, "message_count >= 6", timeout_ms);
    assert_eventually(&bob_db, "message_count >= 6", timeout_ms);

    // Verify bidirectional message propagation
    let alice_msgs = get_messages(&alice_db);
    assert!(alice_msgs.len() >= 6, "Alice should see at least 6 messages, got {}", alice_msgs.len());
    assert!(alice_msgs.contains(&"Round 1".to_string()));
    assert!(alice_msgs.contains(&"Round 2".to_string()));
    assert!(alice_msgs.contains(&"Round 4".to_string()));

    let bob_msgs = get_messages(&bob_db);
    assert!(bob_msgs.len() >= 6, "Bob should see at least 6 messages, got {}", bob_msgs.len());
    assert!(bob_msgs.contains(&"Round 1".to_string()));
    assert!(bob_msgs.contains(&"Round 2".to_string()));
    assert!(bob_msgs.contains(&"Round 4".to_string()));

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

    send_message(&db, "First message");
    send_message(&db, "Second message");

    // 6 identity chain events + 2 messages = 8
    assert_now(&db, "store_count == 8");
    assert_now(&db, "message_count == 2");
    assert_now(&db, "recorded_events_count == 8");

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
    let mut alice = start_sync(&alice_db, alice_port, None);
    std::thread::sleep(Duration::from_millis(500));

    // Bob starts sync connecting to Alice (but Alice doesn't trust Bob)
    let mut bob = start_sync(&bob_db, bob_port, Some(alice_port));
    std::thread::sleep(Duration::from_secs(1));

    // Bob sends a message
    send_message(&bob_db, "Should not arrive");
    // Give some time for sync to try
    std::thread::sleep(Duration::from_secs(3));

    // Alice should have her own events but NOT Bob's (Bob's cert is not trusted by Alice)
    // Alice has 8 events (6 identity + 1 bootstrap msg + 1 transport key from ensure_identity_chain)
    // Bob's message should NOT arrive
    let alice_store = Command::new(bin())
        .arg("assert-now")
        .arg("message_count == 1")
        .arg("--db")
        .arg(&alice_db)
        .output()
        .expect("failed to run assert");
    assert!(alice_store.status.success(), "Alice should only have her own message");

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
        stderr.contains("No trusted peers") || stderr.contains("invite"),
        "error should mention trusted peers or invite, got: {}",
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
    let mut alice = start_sync(&alice_db, alice_port, None);
    std::thread::sleep(Duration::from_millis(500));

    // Bob accepts invite: installs deterministic cert, bootstrap-syncs from
    // Alice, creates identity chain, records bootstrap trust.
    accept_invite(&bob_db, &invite_link);

    // Bob starts ongoing sync (connects to Alice for continued sync).
    let mut bob = start_sync(&bob_db, bob_port, Some(alice_port));
    std::thread::sleep(Duration::from_secs(1));

    send_message(&bob_db, "bootstrap trust from invite data");

    // Wait for convergence: Alice has "bootstrap", Bob has "bootstrap trust from invite data"
    // Both should see both messages after sync
    assert_eventually(&alice_db, "message_count >= 2", timeout_ms);
    assert_eventually(&bob_db, "message_count >= 2", timeout_ms);

    let alice_msgs = get_messages(&alice_db);
    assert!(alice_msgs.contains(&"bootstrap".to_string()));
    assert!(alice_msgs.contains(&"bootstrap trust from invite data".to_string()));

    let _ = alice.kill();
    let _ = bob.kill();
    let _ = alice.wait();
    let _ = bob.wait();
}
