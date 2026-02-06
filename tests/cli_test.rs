use std::process::{Command, Child, Stdio};
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

/// Get the SPKI fingerprint for a given DB path (generates cert if needed).
fn get_identity(db: &str) -> String {
    let output = Command::new(bin())
        .arg("identity")
        .arg("--db")
        .arg(db)
        .output()
        .expect("failed to run identity");
    assert!(output.status.success(), "identity failed: {}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn start_sync(db: &str, bind_port: u16, connect_port: Option<u16>, pin_peers: &[&str]) -> Child {
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

    for fp in pin_peers {
        cmd.arg("--pin-peer").arg(fp);
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
    assert!(output.status.success(), "send failed: {}", String::from_utf8_lossy(&output.stderr));
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


#[test]
fn test_cli_bidirectional_sync() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 15000;

    let alice_port = random_port();
    let bob_port = random_port();

    // Get fingerprints for mutual pinning
    let alice_fp = get_identity(&alice_db);
    let bob_fp = get_identity(&bob_db);

    // Start Alice (just listens, pins Bob)
    let mut alice = start_sync(&alice_db, alice_port, None, &[&bob_fp]);
    std::thread::sleep(Duration::from_millis(500));

    // Start Bob (listens + connects to Alice, pins Alice)
    let mut bob = start_sync(&bob_db, bob_port, Some(alice_port), &[&alice_fp]);
    std::thread::sleep(Duration::from_secs(1));

    // Alice sends a message
    send_message(&alice_db, "Hello from Alice");
    assert_eventually(&bob_db, "store_count >= 1", timeout_ms);

    // Bob sends a message
    send_message(&bob_db, "Hey Alice!");
    assert_eventually(&alice_db, "store_count >= 2", timeout_ms);

    // Alice sends another
    send_message(&alice_db, "How are you?");
    assert_eventually(&bob_db, "store_count >= 3", timeout_ms);
    assert_eventually(&alice_db, "store_count >= 3", timeout_ms);

    // Verify both peers have all 3 messages
    assert_now(&alice_db, "store_count == 3");
    assert_now(&alice_db, "message_count == 3");
    assert_now(&bob_db, "store_count == 3");
    assert_now(&bob_db, "message_count == 3");

    // Verify message content
    let alice_messages = get_messages(&alice_db);
    let bob_messages = get_messages(&bob_db);
    assert!(alice_messages.contains(&"Hello from Alice".to_string()));
    assert!(alice_messages.contains(&"Hey Alice!".to_string()));
    assert!(alice_messages.contains(&"How are you?".to_string()));
    assert_eq!(alice_messages.len(), 3);
    assert_eq!(bob_messages.len(), 3);
    // Bob should have the same messages (order may differ by timestamp)
    for msg in &alice_messages {
        assert!(bob_messages.contains(msg), "bob missing: {}", msg);
    }

    // Cleanup
    let _ = alice.kill();
    let _ = bob.kill();
    let _ = alice.wait();
    let _ = bob.wait();
}

#[test]
fn test_cli_ongoing_sync() {
    // Verify sync picks up new messages over time (not just initial state)
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 15000;

    let alice_port = random_port();
    let bob_port = random_port();

    // Get fingerprints for mutual pinning
    let alice_fp = get_identity(&alice_db);
    let bob_fp = get_identity(&bob_db);

    // Start both peers with no initial messages
    let mut alice = start_sync(&alice_db, alice_port, None, &[&bob_fp]);
    std::thread::sleep(Duration::from_millis(500));
    let mut bob = start_sync(&bob_db, bob_port, Some(alice_port), &[&alice_fp]);
    std::thread::sleep(Duration::from_secs(1));

    // Round 1: Alice sends
    send_message(&alice_db, "Round 1");
    assert_eventually(&bob_db, "store_count >= 1", timeout_ms);

    // Round 2: Bob sends while sync runs
    send_message(&bob_db, "Round 2");
    assert_eventually(&alice_db, "store_count >= 2", timeout_ms);

    // Round 3: Both send
    send_message(&alice_db, "Round 3a");
    send_message(&bob_db, "Round 3b");
    assert_eventually(&alice_db, "store_count >= 4", timeout_ms);
    assert_eventually(&bob_db, "store_count >= 4", timeout_ms);

    // Round 4: One more after a pause
    std::thread::sleep(Duration::from_secs(1));
    send_message(&alice_db, "Round 4");
    assert_eventually(&bob_db, "store_count >= 5", timeout_ms);

    assert_now(&alice_db, "store_count == 5");
    assert_now(&bob_db, "store_count == 5");

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

    assert_now(&db, "store_count == 2");
    assert_now(&db, "message_count == 2");

    let messages = get_messages(&db);
    assert_eq!(messages.len(), 2);
    assert!(messages.contains(&"First message".to_string()));
    assert!(messages.contains(&"Second message".to_string()));
}

#[test]
fn test_cli_unpinned_peer_rejected() {
    // Alice starts without pinning Bob's fingerprint.
    // Bob connects but should not be able to sync.
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();

    let alice_port = random_port();
    let bob_port = random_port();

    // Get fingerprints
    let alice_fp = get_identity(&alice_db);
    let _bob_fp = get_identity(&bob_db);

    // Alice starts with a bogus pin (does NOT pin Bob)
    let bogus_fp = "0000000000000000000000000000000000000000000000000000000000000000";
    let mut alice = start_sync(&alice_db, alice_port, None, &[bogus_fp]);
    std::thread::sleep(Duration::from_millis(500));

    // Bob pins Alice correctly and connects
    let mut bob = start_sync(&bob_db, bob_port, Some(alice_port), &[&alice_fp]);
    std::thread::sleep(Duration::from_secs(1));

    // Bob sends a message
    send_message(&bob_db, "Should not arrive");
    // Give some time for sync to try
    std::thread::sleep(Duration::from_secs(3));

    // Alice should NOT have received Bob's message (Bob's cert is not pinned by Alice)
    assert_now(&alice_db, "store_count == 0");

    let _ = alice.kill();
    let _ = bob.kill();
    let _ = alice.wait();
    let _ = bob.wait();
}
