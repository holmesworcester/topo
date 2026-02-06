use std::process::{Command, Child, Stdio};
use std::time::{Duration, Instant};

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
    assert!(output.status.success(), "send failed: {}", String::from_utf8_lossy(&output.stderr));
}

fn get_status(db: &str) -> (i64, i64) {
    let output = Command::new(bin())
        .arg("status")
        .arg("--db")
        .arg(db)
        .output()
        .expect("failed to run status");
    let text = String::from_utf8_lossy(&output.stdout);
    let store = parse_status_line(&text, "Store:");
    let messages = parse_status_line(&text, "Messages:");
    (store, messages)
}

fn parse_status_line(text: &str, label: &str) -> i64 {
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix(label) {
            // "  3 events" -> 3
            let num_str = rest.trim().split_whitespace().next().unwrap_or("0");
            return num_str.parse().unwrap_or(0);
        }
    }
    0
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

/// Wait until a peer has the expected store count, polling status.
fn wait_for_count(db: &str, expected: i64, timeout: Duration) {
    let start = Instant::now();
    loop {
        let (store, _) = get_status(db);
        if store >= expected {
            return;
        }
        if start.elapsed() >= timeout {
            let (store, messages) = get_status(db);
            panic!(
                "Timed out waiting for {} to have {} events (has store={}, messages={})",
                db, expected, store, messages
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn test_cli_bidirectional_sync() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout = Duration::from_secs(15);

    let alice_port = random_port();
    let bob_port = random_port();

    // Start Alice (just listens)
    let mut alice = start_sync(&alice_db, alice_port, None);
    std::thread::sleep(Duration::from_millis(500));

    // Start Bob (listens + connects to Alice)
    let mut bob = start_sync(&bob_db, bob_port, Some(alice_port));
    std::thread::sleep(Duration::from_secs(1));

    // Alice sends a message
    send_message(&alice_db, "Hello from Alice");
    wait_for_count(&bob_db, 1, timeout);

    // Bob sends a message
    send_message(&bob_db, "Hey Alice!");
    wait_for_count(&alice_db, 2, timeout);

    // Alice sends another
    send_message(&alice_db, "How are you?");
    wait_for_count(&bob_db, 3, timeout);
    wait_for_count(&alice_db, 3, timeout);

    // Verify both peers have all 3 messages
    let (alice_store, alice_msgs) = get_status(&alice_db);
    let (bob_store, bob_msgs) = get_status(&bob_db);
    assert_eq!(alice_store, 3, "alice store count");
    assert_eq!(alice_msgs, 3, "alice message count");
    assert_eq!(bob_store, 3, "bob store count");
    assert_eq!(bob_msgs, 3, "bob message count");

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
    let timeout = Duration::from_secs(15);

    let alice_port = random_port();
    let bob_port = random_port();

    // Start both peers with no initial messages
    let mut alice = start_sync(&alice_db, alice_port, None);
    std::thread::sleep(Duration::from_millis(500));
    let mut bob = start_sync(&bob_db, bob_port, Some(alice_port));
    std::thread::sleep(Duration::from_secs(1));

    // Round 1: Alice sends
    send_message(&alice_db, "Round 1");
    wait_for_count(&bob_db, 1, timeout);

    // Round 2: Bob sends while sync runs
    send_message(&bob_db, "Round 2");
    wait_for_count(&alice_db, 2, timeout);

    // Round 3: Both send
    send_message(&alice_db, "Round 3a");
    send_message(&bob_db, "Round 3b");
    wait_for_count(&alice_db, 4, timeout);
    wait_for_count(&bob_db, 4, timeout);

    // Round 4: One more after a pause
    std::thread::sleep(Duration::from_secs(1));
    send_message(&alice_db, "Round 4");
    wait_for_count(&bob_db, 5, timeout);

    let (alice_store, _) = get_status(&alice_db);
    let (bob_store, _) = get_status(&bob_db);
    assert_eq!(alice_store, 5);
    assert_eq!(bob_store, 5);

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

    let (store, msgs) = get_status(&db);
    assert_eq!(store, 2);
    assert_eq!(msgs, 2);

    let messages = get_messages(&db);
    assert_eq!(messages.len(), 2);
    assert!(messages.contains(&"First message".to_string()));
    assert!(messages.contains(&"Second message".to_string()));
}
