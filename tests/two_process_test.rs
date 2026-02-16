//! Two-process integration test: real QUIC sync between separate CLI invocations.
//!
//! This test validates the full invite + bootstrap sync + ongoing sync flow
//! using real separate processes, just like a user would run from the command line.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

fn bin() -> String {
    env!("CARGO_BIN_EXE_poc-7").to_string()
}

fn random_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
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

fn accept_invite(db: &str, invite_link: &str, username: &str, devicename: &str) {
    let output = Command::new(bin())
        .arg("accept-invite")
        .arg("--db")
        .arg(db)
        .arg("--invite")
        .arg(invite_link)
        .arg("--username")
        .arg(username)
        .arg("--devicename")
        .arg(devicename)
        .output()
        .expect("failed to run accept-invite");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "accept-invite failed:\n  stdout: {}\n  stderr: {}",
        stdout.trim(),
        stderr.trim()
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

fn get_messages(db: &str) -> Vec<String> {
    let output = Command::new(bin())
        .arg("messages")
        .arg("--db")
        .arg(db)
        .output()
        .expect("failed to run messages");
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
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

/// Full two-process invite + bootstrap sync + ongoing sync test.
///
/// 1. Alice bootstraps a workspace (via `send`)
/// 2. Alice creates an invite
/// 3. Alice runs sync
/// 4. Bob accepts the invite (real QUIC bootstrap sync from Alice)
/// 5. Both run sync, exchange messages, verify convergence
#[test]
fn test_two_process_invite_and_sync() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 15000;

    let alice_port = random_port();
    let bob_port = random_port();

    // Step 1: Alice bootstraps her workspace by sending an initial message.
    // This creates: Network, InviteAccepted, UserInviteBoot, UserBoot,
    // DeviceInviteFirst, PeerSharedFirst, AdminBoot + the message itself.
    send_message(&alice_db, "Hello world from alice");

    // Step 2: Alice creates an invite pointing to her sync address.
    let invite_link = create_invite(&alice_db, &format!("127.0.0.1:{}", alice_port));
    assert!(
        invite_link.starts_with("quiet://invite/"),
        "Expected quiet://invite/ link, got: {}",
        invite_link
    );

    // Step 3: Start Alice's sync. The pending_invite_bootstrap_trust from
    // create-invite means Alice will accept Bob's bootstrap cert.
    let mut alice_sync = start_sync(&alice_db, alice_port, None);
    std::thread::sleep(Duration::from_millis(500));

    // Step 4: Bob accepts the invite. This connects to Alice's sync endpoint
    // via real QUIC, fetches prerequisite events, then creates Bob's identity chain.
    accept_invite(&bob_db, &invite_link, "bob", "laptop");

    // Verify Bob has events from bootstrap sync + his own identity chain.
    // Alice has: 7 identity events + 1 message + 1 user_invite = 9 shared events
    // Bob receives those shared events, plus creates his own identity chain.
    assert_now(&bob_db, "store_count >= 5");

    // Step 5: Start Bob's sync. Both now have invite_bootstrap_trust entries
    // so they can connect without --pin-peer.
    let mut bob_sync = start_sync(&bob_db, bob_port, Some(alice_port));
    std::thread::sleep(Duration::from_secs(1));

    // Step 6: Exchange messages and verify convergence.
    send_message(&alice_db, "Second message from alice");
    send_message(&bob_db, "Hello from bob");

    // Wait for sync convergence. Both should see all events from both peers.
    // Alice creates: Network + InviteAccepted + UserInviteBoot + UserBoot +
    //   DeviceInviteFirst + PeerSharedFirst = 6 identity + 1 msg + 1 user_invite = 8
    // Bob creates: InviteAccepted + UserBoot + DeviceInviteFirst + PeerSharedFirst = 4 identity + 1 msg = 5
    // Shared events synced between them: alice's 7 shared + bob's 4 shared = 11+
    // Each peer stores: own events + remote shared events
    assert_eventually(&alice_db, "store_count >= 12", timeout_ms);
    assert_eventually(&bob_db, "store_count >= 12", timeout_ms);

    // Verify Alice's locally-projected messages (her own + bob's if signer resolved)
    let alice_msgs = get_messages(&alice_db);
    assert!(
        alice_msgs.contains(&"Hello world from alice".to_string()),
        "Alice should have her first message, got: {:?}",
        alice_msgs
    );
    assert!(
        alice_msgs.contains(&"Second message from alice".to_string()),
        "Alice should have her second message, got: {:?}",
        alice_msgs
    );

    // Verify Bob's locally-projected messages
    let bob_msgs = get_messages(&bob_db);
    assert!(
        bob_msgs.contains(&"Hello from bob".to_string()),
        "Bob should have his message, got: {:?}",
        bob_msgs
    );

    // Cleanup
    let _ = alice_sync.kill();
    let _ = bob_sync.kill();
    let _ = alice_sync.wait();
    let _ = bob_sync.wait();
}
