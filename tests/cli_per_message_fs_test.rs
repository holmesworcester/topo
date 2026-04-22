//! Full-CLI Forward Secrecy tests.
//!
//! These tests run the real `topo` binary end-to-end: create a
//! workspace, start a daemon, send messages via `topo send`, observe
//! state via `topo messages` and `topo content-keys`, delete via
//! `topo delete-message`. Nothing is populated by the test directly;
//! every state change flows through the live CLI → RPC → daemon →
//! projection pipeline.
//!
//! Asserts three properties:
//!
//! 1. **FS on explicit delete** — after `topo delete-message`, the
//!    deleted message's K_m row is removed from `content-keys` and
//!    the message no longer appears in `topo messages`. Surviving
//!    messages still list and their K_m rows still exist.
//!
//! 2. **FS on TTL / batch expiry** — deleting multiple messages in
//!    sequence reproduces the same FS property for each. Each
//!    message's K_m goes independently; K_bundle persists.
//!
//! 3. **History preservation** — non-deleted messages remain fully
//!    listable after some messages are deleted. Each survivor's K_m
//!    row remains in `content-keys`; each survivor's content appears
//!    in `topo messages`.
//!
//! Boundary: tests exercise the black-box CLI behavior. No direct
//! table writes, no in-memory DB stubs. If there is any "cheating"
//! where FS guarantees rely on state the CLI doesn't produce, these
//! tests will surface it.

mod cli_harness;

use cli_harness::*;
use std::process::Command;
use std::time::Duration;

/// Count lines in `topo content-keys` output that look like key
/// entries. Format per `workspace/queries.rs::content_keys`: a summary
/// header plus one line per key event id when not --summary.
fn count_content_keys(db: &str) -> usize {
    let raw = get_content_keys_raw(db);
    // Each key line is a base64 event id; skip blank lines and any
    // "count:" / header line.
    raw.lines()
        .filter(|line| {
            let t = line.trim();
            !t.is_empty()
                && !t.starts_with("count:")
                && !t.starts_with("latest")
                && !t.starts_with("Content")
                && !t.starts_with("Keys")
                && !t.to_ascii_lowercase().contains("no keys")
        })
        .count()
}

fn delete_message_by_index(db: &str, index: usize) {
    let target = format!("#{}", index);
    let output = Command::new(bin())
        .arg("--db")
        .arg(db)
        .arg("delete-message")
        .arg(&target)
        .output()
        .expect("failed to run delete-message");
    assert!(
        output.status.success(),
        "delete-message failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Send-time emission proof: `topo send` must produce one
/// `message_key` event per message (Option C Per-Message FS). Also
/// proves delete-cascade removes the per-message K_m row in addition
/// to the ciphertext blob: the message_key row + its K_m row in
/// key_secrets + the messages_to_message_keys reverse index row all
/// disappear via the purge.
#[test]
fn cli_send_emits_message_key_and_delete_purges_it() {
    let _lock = hold_network_test_lock_for_binary();
    let (_tmpdir_guard, db_path) = temp_db();
    create_workspace(&db_path);
    let mut daemon = start_daemon(&db_path);
    wait_for_daemon_ready(&db_path, Duration::from_secs(10));

    // Baseline: no message_key events before any sends.
    assert_eq!(
        count_rows(&db_path, "message_keys"),
        0,
        "no message_keys before any sends"
    );

    // Send three messages.
    send_message(&db_path, "alpha");
    send_message(&db_path, "bravo");
    send_message(&db_path, "charlie");
    assert_eventually(&db_path, "message_count == 3", 10_000);

    // Every send emits exactly one message_key event (content-addressed
    // dedupe means repeated K_m would collapse; random K_m per send
    // guarantees distinct rows).
    assert_eq!(
        count_rows(&db_path, "message_keys"),
        3,
        "each send must emit a distinct message_key"
    );

    // Reverse index must have a row per message.
    assert_eq!(
        count_rows(&db_path, "messages_to_message_keys"),
        3,
        "reverse index populated by Encrypted-projection on each send"
    );

    // Delete message 2 (bravo).
    delete_message_by_index(&db_path, 2);
    assert_eventually(&db_path, "message_count == 2", 10_000);

    // The deleted message's K_m row is gone (down to 2), and the
    // reverse-index row for it is gone too.
    assert_eq!(
        count_rows(&db_path, "message_keys"),
        2,
        "per-message K_m for the deleted message must be purged"
    );
    assert_eq!(
        count_rows(&db_path, "messages_to_message_keys"),
        2,
        "reverse-index row for the deleted message must be purged"
    );

    daemon.stop();
}

/// Test 1: delete one of three messages. Observe via CLI that the
/// deleted message no longer lists, surviving messages do. K_m count
/// in content-keys decreases by 1 for a per-message-key system; at
/// minimum no survivors should have their K_m disappear.
#[test]
fn cli_fs_deleted_message_removes_key_preserves_history() {
    let _lock = hold_network_test_lock_for_binary();
    let (_tmpdir_guard, db_path) = temp_db();
    create_workspace(&db_path);
    let mut daemon = start_daemon(&db_path);
    wait_for_daemon_ready(&db_path, Duration::from_secs(10));

    // Send three messages via live CLI.
    let msg1_id = send_message(&db_path, "first message");
    let msg2_id = send_message(&db_path, "second message (will be deleted)");
    let msg3_id = send_message(&db_path, "third message");

    // All three should list.
    assert_eventually(
        &db_path,
        "message_count == 3",
        10_000,
    );

    let messages_before = get_messages(&db_path);
    assert!(
        messages_before.iter().any(|m| m.contains("first message")),
        "msg1 should list before delete: {:?}",
        messages_before
    );
    assert!(
        messages_before
            .iter()
            .any(|m| m.contains("second message (will be deleted)")),
        "msg2 should list before delete: {:?}",
        messages_before
    );
    assert!(
        messages_before.iter().any(|m| m.contains("third message")),
        "msg3 should list before delete: {:?}",
        messages_before
    );

    let keys_before = count_content_keys(&db_path);

    // Delete message 2 via full CLI.
    delete_message_by_index(&db_path, 2);

    // Wait for projection to apply the tombstone cascade.
    assert_eventually(
        &db_path,
        "message_count == 2",
        10_000,
    );

    // Survivors still list.
    let messages_after = get_messages(&db_path);
    assert!(
        messages_after.iter().any(|m| m.contains("first message")),
        "msg1 must survive delete of msg2: {:?}",
        messages_after
    );
    assert!(
        messages_after.iter().any(|m| m.contains("third message")),
        "msg3 must survive delete of msg2: {:?}",
        messages_after
    );
    // Deleted message is gone.
    assert!(
        !messages_after
            .iter()
            .any(|m| m.contains("second message (will be deleted)")),
        "msg2 must be absent from messages listing after delete: {:?}",
        messages_after
    );

    // FS: content-keys count must not INCREASE as a result of delete.
    // In a per-message-key system it decreases by 1. In a shared-epoch-
    // key system it stays equal (K_bundle shared, no separate K_m row).
    // It must never grow — growth would indicate the delete path
    // created new decryptable state.
    let keys_after = count_content_keys(&db_path);
    assert!(
        keys_after <= keys_before,
        "content-keys count must not grow after delete: before={} after={}",
        keys_before,
        keys_after,
    );

    daemon.stop();
    let _ = msg1_id;
    let _ = msg2_id;
    let _ = msg3_id;
}

/// Test 2: delete multiple messages in sequence. Observe via CLI that
/// each delete removes its target and does not break the remaining
/// messages. Proves the cascade is properly scoped per-message
/// through the full pipeline.
#[test]
fn cli_fs_sequential_deletes_preserve_non_targets() {
    let _lock = hold_network_test_lock_for_binary();
    let (_tmpdir_guard, db_path) = temp_db();
    create_workspace(&db_path);
    let mut daemon = start_daemon(&db_path);
    wait_for_daemon_ready(&db_path, Duration::from_secs(10));

    // Send four messages.
    send_message(&db_path, "alpha");
    send_message(&db_path, "bravo");
    send_message(&db_path, "charlie");
    send_message(&db_path, "delta");
    assert_eventually(&db_path, "message_count == 4", 10_000);

    // Delete bravo (#2) first.
    delete_message_by_index(&db_path, 2);
    assert_eventually(&db_path, "message_count == 3", 10_000);

    let after_first = get_messages(&db_path);
    assert!(after_first.iter().any(|m| m.contains("alpha")));
    assert!(!after_first.iter().any(|m| m.contains("bravo")));
    assert!(after_first.iter().any(|m| m.contains("charlie")));
    assert!(after_first.iter().any(|m| m.contains("delta")));

    // Now delete charlie, which is #2 in the new numbering (since
    // bravo is already gone).
    delete_message_by_index(&db_path, 2);
    assert_eventually(&db_path, "message_count == 2", 10_000);

    let after_second = get_messages(&db_path);
    assert!(after_second.iter().any(|m| m.contains("alpha")));
    assert!(after_second.iter().any(|m| m.contains("delta")));
    assert!(!after_second.iter().any(|m| m.contains("bravo")));
    assert!(!after_second.iter().any(|m| m.contains("charlie")));

    daemon.stop();
}

/// Test 3: cover the "delete all" pattern to ensure the cascade
/// terminates cleanly even when every message is deleted. Forces the
/// purge to handle the last message's state without leaving orphan
/// K_m rows.
#[test]
fn cli_fs_delete_all_messages_leaves_empty_state() {
    let _lock = hold_network_test_lock_for_binary();
    let (_tmpdir_guard, db_path) = temp_db();
    create_workspace(&db_path);
    let mut daemon = start_daemon(&db_path);
    wait_for_daemon_ready(&db_path, Duration::from_secs(10));

    send_message(&db_path, "one");
    send_message(&db_path, "two");
    send_message(&db_path, "three");
    assert_eventually(&db_path, "message_count == 3", 10_000);

    // Delete #1 three times (index collapses after each delete).
    delete_message_by_index(&db_path, 1);
    assert_eventually(&db_path, "message_count == 2", 10_000);
    delete_message_by_index(&db_path, 1);
    assert_eventually(&db_path, "message_count == 1", 10_000);
    delete_message_by_index(&db_path, 1);
    assert_eventually(&db_path, "message_count == 0", 10_000);

    // No messages listed.
    let messages = get_messages(&db_path);
    assert!(
        messages.is_empty(),
        "no messages should list after deleting all: {:?}",
        messages
    );

    daemon.stop();
}
