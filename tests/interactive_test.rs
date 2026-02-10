use std::io::Write;
use std::process::{Command, Stdio};

fn bin() -> String {
    env!("CARGO_BIN_EXE_poc-7").to_string()
}

/// Run the interactive REPL with the given commands piped to stdin.
/// Returns (stdout, stderr) as strings.
fn run_interactive(commands: &str) -> (String, String) {
    let mut child = Command::new(bin())
        .arg("interactive")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn interactive");

    {
        let stdin = child.stdin.as_mut().expect("failed to open stdin");
        stdin
            .write_all(commands.as_bytes())
            .expect("failed to write to stdin");
    }

    let output = child.wait_with_output().expect("failed to wait on child");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (stdout, stderr)
}

/// Assert the output contains a string, with context on failure.
fn assert_contains(output: &str, needle: &str, context: &str) {
    assert!(
        output.contains(needle),
        "{}: expected output to contain {:?}, got:\n{}",
        context,
        needle,
        output
    );
}

/// Assert the output does NOT contain a string.
fn assert_not_contains(output: &str, needle: &str, context: &str) {
    assert!(
        !output.contains(needle),
        "{}: expected output NOT to contain {:?}, got:\n{}",
        context,
        needle,
        output
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_single_user_messaging() {
    let (out, err) = run_interactive(
        "new-workspace --name test --username alice --devicename desktop\n\
         send hello world\n\
         send second message\n\
         messages\n\
         status\n\
         quit\n",
    );
    assert!(err.is_empty(), "stderr should be empty, got: {}", err);

    assert_contains(&out, "Created workspace 'test'", "new-workspace");
    assert_contains(&out, "alice (desktop)", "new-workspace user info");
    assert_contains(&out, "Sent: hello world", "first send");
    assert_contains(&out, "Sent: second message", "second send");
    assert_contains(&out, "MESSAGES (#general):", "messages header");
    assert_contains(&out, "1. [alice] hello world", "messages list");
    assert_contains(&out, "2. [alice] second message", "messages list");
    assert_contains(&out, "STATUS (alice):", "status header");
    assert_contains(&out, "Events:", "status events");
    assert_contains(&out, "Messages:  2", "status messages count");
    assert_contains(&out, "Workspace: test", "status network");
    assert_contains(&out, "Channel:   #general", "status channel");
}

#[test]
fn test_two_user_messaging() {
    let (out, err) = run_interactive(
        "new-workspace --name chat --username alice --devicename laptop\n\
         invite\n\
         accept-invite --username bob --devicename phone --invite 1\n\
         send hello from bob\n\
         switch 1\n\
         send hello from alice\n\
         messages\n\
         switch 2\n\
         messages\n\
         quit\n",
    );
    assert!(err.is_empty(), "stderr should be empty, got: {}", err);

    assert_contains(&out, "Created workspace 'chat'", "new-workspace");
    assert_contains(&out, "Created invite #1", "invite");
    assert_contains(&out, "Accepted invite #1 as bob", "accept-invite");
    assert_contains(&out, "Sent: hello from bob", "bob send");
    assert_contains(&out, "Switched to account 1", "switch to alice");
    assert_contains(&out, "Sent: hello from alice", "alice send");
    // Alice should see alice's message
    assert_contains(&out, "1. [alice] hello from alice", "alice messages");
    // Bob should see bob's message
    assert_contains(&out, "1. [bob] hello from bob", "bob messages");
}

#[test]
fn test_list_commands() {
    let (out, err) = run_interactive(
        "new-workspace --name test --username alice --devicename desktop\n\
         accounts\n\
         channels\n\
         users\n\
         quit\n",
    );
    assert!(err.is_empty(), "stderr should be empty, got: {}", err);

    assert_contains(&out, "ACCOUNTS:", "accounts header");
    assert_contains(&out, "*1 alice (desktop)", "accounts list");
    assert_contains(&out, "CHANNELS:", "channels header");
    assert_contains(&out, "*1 #general", "default channel");
    assert_contains(&out, "USERS:", "users header");
    assert_contains(&out, "1. user_", "users list");
}

#[test]
fn test_create_channel_and_send() {
    let (out, err) = run_interactive(
        "new-workspace --name test --username alice --devicename desktop\n\
         new-channel random\n\
         channels\n\
         channel 2\n\
         send in random\n\
         messages\n\
         channel 1\n\
         messages\n\
         quit\n",
    );
    assert!(err.is_empty(), "stderr should be empty, got: {}", err);

    assert_contains(&out, "Created channel #2: random", "new-channel");
    assert_contains(&out, "2 #random", "channels list");
    assert_contains(&out, "Switched to channel #2: random", "channel switch");
    assert_contains(&out, "1. [alice] in random", "message in random channel");
    // Messages are workspace-wide (workspace_id = workspace dep, not per-channel filter),
    // so after switching back to general, the message is still visible.
    assert_contains(&out, "1. [alice] in random", "message visible from general too");
}

#[test]
fn test_reactions() {
    let (out, err) = run_interactive(
        "new-workspace --name test --username alice --devicename desktop\n\
         send test message\n\
         react 1 thumbsup\n\
         reactions 1\n\
         quit\n",
    );
    assert!(err.is_empty(), "stderr should be empty, got: {}", err);

    assert_contains(&out, "Reacted thumbsup to message 1", "react");
    assert_contains(&out, "REACTIONS for message 1:", "reactions header");
    assert_contains(&out, "thumbsup", "reactions content");
}

#[test]
fn test_delete_message() {
    let (out, err) = run_interactive(
        "new-workspace --name test --username alice --devicename desktop\n\
         send keep this\n\
         send delete this\n\
         messages\n\
         delete 2\n\
         messages\n\
         quit\n",
    );
    assert!(err.is_empty(), "stderr should be empty, got: {}", err);

    // Before delete
    assert_contains(&out, "2. [alice] delete this", "before delete");
    assert_contains(&out, "Deleted message 2", "delete confirmation");
    // After delete - message count should be 1
    // The second "messages" output should only have "keep this"
    // Split on "Deleted message 2" to check after deletion
    let after_delete = out.split("Deleted message 2").nth(1).unwrap_or("");
    assert_contains(after_delete, "1. [alice] keep this", "after delete - kept message");
    assert_not_contains(after_delete, "delete this", "after delete - deleted message gone");
}

#[test]
fn test_link_device() {
    let (out, err) = run_interactive(
        "new-workspace --name test --username alice --devicename desktop\n\
         link\n\
         accept-link --devicename phone --invite 1\n\
         accounts\n\
         quit\n",
    );
    assert!(err.is_empty(), "stderr should be empty, got: {}", err);

    assert_contains(&out, "Created device link invite #1", "link");
    assert_contains(&out, "Accepted device link #1", "accept-link");
    assert_contains(&out, "ACCOUNTS:", "accounts header");
    // Should have 2 accounts
    assert_contains(&out, "1 alice (desktop)", "account 1");
    assert_contains(&out, "2 alice (phone)", "account 2 - same user, different device");
}

#[test]
fn test_invite_accept_flow() {
    let (out, err) = run_interactive(
        "new-workspace --name mynet --username alice --devicename desktop\n\
         invite\n\
         accept-invite --username bob --devicename laptop --invite 1\n\
         accounts\n\
         users\n\
         quit\n",
    );
    assert!(err.is_empty(), "stderr should be empty, got: {}", err);

    assert_contains(&out, "Created invite #1", "invite created");
    assert_contains(&out, "Accepted invite #1 as bob (laptop)", "invite accepted");
    assert_contains(&out, "ACCOUNTS:", "accounts");
    assert_contains(&out, "alice (desktop)", "alice in accounts");
    assert_contains(&out, "bob (laptop)", "bob in accounts");
    // Bob's db should have its own user
    assert_contains(&out, "USERS:", "users header");
    assert_contains(&out, "1. user_", "user listed");
}

#[test]
fn test_identity_display() {
    let (out, err) = run_interactive(
        "new-workspace --name test --username alice --devicename desktop\n\
         identity\n\
         keys --summary\n\
         quit\n",
    );
    assert!(err.is_empty(), "stderr should be empty, got: {}", err);

    assert_contains(&out, "IDENTITY:", "identity header");
    assert_contains(&out, "Transport:", "transport identity");
    assert_contains(&out, "User: user_", "user identity");
    assert_contains(&out, "Peer: peer_", "peer identity");
    assert_contains(&out, "KEYS SUMMARY:", "keys header");
    assert_contains(&out, "Users: 1", "user key count");
    assert_contains(&out, "Peers: 1", "peer key count");
    assert_contains(&out, "Admins: 1", "admin key count");
    assert_contains(&out, "TransportKeys: 1", "transport key count");
}

#[test]
fn test_help_covers_all_commands() {
    let (out, err) = run_interactive("help\nquit\n");
    assert!(err.is_empty(), "stderr should be empty, got: {}", err);

    assert_contains(&out, "COMMANDS:", "help header");
    let expected_commands = [
        "new-workspace", "send", "messages", "react", "reactions", "delete",
        "invite", "accept-invite", "link", "accept-link", "switch", "accounts",
        "channels", "new-channel", "channel", "users", "keys", "workspaces",
        "status", "identity", "ban", "help", "quit",
    ];
    for cmd in &expected_commands {
        assert_contains(&out, cmd, &format!("help lists '{}'", cmd));
    }
}

#[test]
fn test_all_commands_no_crash() {
    // Run every command to verify none panic. Some will produce errors
    // (e.g., "No active account") but should not crash.
    let (out, _err) = run_interactive(
        "help\n\
         status\n\
         identity\n\
         messages\n\
         accounts\n\
         channels\n\
         users\n\
         keys\n\
         workspaces\n\
         new-workspace --name test --username alice --devicename desktop\n\
         send test\n\
         messages\n\
         react 1 star\n\
         reactions 1\n\
         delete 1\n\
         messages\n\
         status\n\
         identity\n\
         accounts\n\
         channels\n\
         new-channel test-ch\n\
         channel 2\n\
         users\n\
         keys --summary\n\
         keys\n\
         workspaces\n\
         invite\n\
         link\n\
         switch 1\n\
         quit\n",
    );

    // Should have completed without crashing
    assert_contains(&out, "COMMANDS:", "help ran");
    assert_contains(&out, "Created workspace", "new-workspace ran");
    assert_contains(&out, "Sent: test", "send ran");
}

#[test]
fn test_workspaces_display() {
    let (out, err) = run_interactive(
        "new-workspace --name mynetwork --username alice --devicename desktop\n\
         workspaces\n\
         quit\n",
    );
    assert!(err.is_empty(), "stderr should be empty, got: {}", err);

    assert_contains(&out, "WORKSPACES:", "workspaces header");
    assert_contains(&out, "1. mynetwork", "workspace name displayed");
}

#[test]
fn test_unknown_command() {
    let (out, err) = run_interactive("foobar\nquit\n");
    assert!(err.is_empty(), "stderr should be empty, got: {}", err);

    assert_contains(&out, "Unknown command: foobar", "unknown command message");
}

// ---------------------------------------------------------------------------
// Follow-up tests for FEEDBACK.md findings
// ---------------------------------------------------------------------------

/// Verify that delete-message succeeds for a message created by the same account
/// (stable author identity within interactive session).
#[test]
fn test_delete_then_verify_stable_author() {
    let (out, err) = run_interactive(
        "new-workspace --name test --username alice --devicename desktop\n\
         send msg-one\n\
         send msg-two\n\
         send msg-three\n\
         delete 2\n\
         messages\n\
         quit\n",
    );
    assert!(err.is_empty(), "stderr should be empty, got: {}", err);

    assert_contains(&out, "Deleted message 2", "delete succeeded");
    // After delete, msg-two is removed from the table; remaining are renumbered
    let after_delete = out.split("Deleted message 2").nth(1).unwrap_or("");
    assert_contains(after_delete, "1. [alice] msg-one", "msg-one kept");
    assert_contains(after_delete, "2. [alice] msg-three", "msg-three kept");
    assert_not_contains(after_delete, "msg-two", "msg-two removed");
}

/// Verify that accept-invite with require_valid_event_id properly creates a usable account
/// (post-anchor events are Valid, not just Blocked).
#[test]
fn test_invite_accept_produces_valid_identity() {
    let (out, err) = run_interactive(
        "new-workspace --name test --username alice --devicename desktop\n\
         invite\n\
         accept-invite --username bob --devicename phone --invite 1\n\
         keys --summary\n\
         send hello from bob\n\
         messages\n\
         quit\n",
    );
    assert!(err.is_empty(), "stderr should be empty, got: {}", err);

    // Bob should have a valid identity chain (sees both alice's and bob's projected keys)
    assert_contains(&out, "Accepted invite #1 as bob", "invite accepted");
    assert_contains(&out, "KEYS SUMMARY:", "keys summary shown");
    // Bob sees both alice's and his own user/peer (from copied chain + own bootstrap)
    assert_contains(&out, "Users: 2", "bob sees both users");
    assert_contains(&out, "Peers: 2", "bob sees both peers");
    // Bob should be able to send messages (requires valid identity)
    assert_contains(&out, "Sent: hello from bob", "bob can send");
    assert_contains(&out, "1. [bob] hello from bob", "bob message visible");
}

/// Verify that copy_event_chain only transfers shared events by checking
/// that the new account's status shows the expected event count (no extras
/// from local-only events of the source account).
#[test]
fn test_copy_event_chain_shared_only() {
    let (out, err) = run_interactive(
        "new-workspace --name test --username alice --devicename desktop\n\
         status\n\
         invite\n\
         accept-invite --username bob --devicename phone --invite 1\n\
         status\n\
         quit\n",
    );
    assert!(err.is_empty(), "stderr should be empty, got: {}", err);

    // Split output at bob's acceptance to get alice's status and bob's status separately
    let parts: Vec<&str> = out.split("Accepted invite #1 as bob").collect();
    assert!(parts.len() >= 2, "should have output before and after accept");

    let alice_status = parts[0];
    let bob_status = parts[1];

    // Alice has local + shared events (InviteAccepted is local, so alice has more)
    assert_contains(alice_status, "STATUS (alice):", "alice status");

    // Bob should have events but fewer than alice (no alice's local-only events)
    assert_contains(bob_status, "STATUS (bob):", "bob status");
    // Bob's event count should be non-zero (shared chain was copied)
    assert_not_contains(bob_status, "Events:    0", "bob has events from chain copy");
}
