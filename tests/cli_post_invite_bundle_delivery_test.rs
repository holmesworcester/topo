//! Full-CLI black-box test for post-invite bundle delivery under
//! strong forward secrecy.
//!
//! Scenario: Alice creates a workspace, creates an invite, then rotates
//! to a new K_bundle by triggering a deletion on her existing bundle.
//! Alice sends a fresh message under the new (post-invite) K_bundle.
//! Bob accepts the invite, syncs, and must be able to see the fresh
//! message.
//!
//! This is the end-to-end contract for the "bundle made AFTER invite"
//! path sketched in `docs/DESIGN.md` §9.6.5 and tracked in
//! `docs/PLAN.md` §22.3.3. The preferred delivery mechanism is
//! including each still-active invite pubkey as an additional
//! recipient slot in every `key_broadcast`; a reactive heal via
//! `key_request` / `key_bundle_share` covers concurrency edges.
//!
//! This test is intentionally agnostic to the delivery mechanism:
//! it asserts the user-observable outcome (Bob's `topo messages`
//! includes the post-invite-bundle message). If the delivery path
//! isn't yet wired up, this test will fail — that is the correct
//! signal. Flip the `#[ignore]` attribute once delivery is
//! implemented.

mod cli_harness;

use cli_harness::*;
use std::time::Duration;

/// Send a message, then delete it. The delete triggers the strong-FS
/// bundle-purge cascade; Alice's next send will auto-rotate to a
/// fresh K_bundle via the existing `ensure_content_key_for_peer_at`
/// logic (the `key_rotations JOIN key_secrets` INNER JOIN sees no
/// match and falls through to rotate).
fn delete_latest_message(db: &str) {
    let output = std::process::Command::new(bin())
        .arg("--db")
        .arg(db)
        .arg("delete-message")
        .arg("#1")
        .output()
        .expect("failed to run delete-message");
    assert!(
        output.status.success(),
        "delete-message failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "requires post-invite bundle delivery to be wired up \
           (active_rotation_recipients_for_frontier must include \
           active invite pubkeys, or a reactive heal path must \
           deliver new K_bundles to joiners). Tracked in \
           docs/PLAN.md §22.3.3."]
fn cli_joiner_sees_messages_encrypted_under_post_invite_bundle() {
    let _lock = hold_network_test_lock_for_binary();
    let tmpdir = tempfile::tempdir().unwrap();
    let timeout_ms: u64 = 60_000;

    let alice_db = tmpdir
        .path()
        .join("alice.db")
        .to_str()
        .unwrap()
        .to_string();
    let bob_db = tmpdir
        .path()
        .join("bob.db")
        .to_str()
        .unwrap()
        .to_string();

    // 1. Alice creates a workspace and starts her daemon.
    create_workspace_with_details(&alice_db, "post-invite-fs", "alice", "alice-laptop");
    let mut alice_daemon = start_daemon_with_options(
        &alice_db,
        &DaemonOptions {
            disable_discovery: true,
            ..Default::default()
        },
    );
    wait_for_daemon_ready(&alice_db, Duration::from_secs(10));

    // 2. Alice creates an invite. This snapshots her CURRENT K_bundle
    // into whatever invite-time delivery mechanism exists (today:
    // `key_history_bundle` with live K_bundle slots; tomorrow: also
    // active-invite-pubkey slots in future `key_broadcast`s).
    let invite_link = create_invite_with_public_addr(&alice_db, &daemon_listen_addr(&alice_db));

    // 3. Alice sends a pre-rotation message, then deletes it. The
    // delete cascade retires the current K_bundle on Alice's side
    // (strong-FS Phase A). Alice's NEXT send auto-rotates to a
    // fresh K_bundle — that is the "post-invite bundle" under test.
    let pre_rot = send_message(&alice_db, "pre-rotation-will-be-deleted");
    assert_eventually(&alice_db, "message_count == 1", timeout_ms);
    let _ = pre_rot;

    delete_latest_message(&alice_db);
    assert_eventually(&alice_db, "message_count == 0", timeout_ms);

    // 4. Alice sends a message under the freshly-rotated bundle.
    // Under the future delivery design, this `key_broadcast` should
    // include Bob's invite pubkey as a recipient so Bob can unwrap
    // K_bundle when he syncs.
    let post_rot = send_message(&alice_db, "post-rotation-should-reach-bob");
    assert_eventually(&alice_db, "message_count == 1", timeout_ms);

    // 5. Bob accepts the invite and starts his daemon.
    accept_invite_with_identity(&bob_db, &invite_link, "bob", "bob-phone");
    let mut bob_daemon = start_daemon_with_options(
        &bob_db,
        &DaemonOptions {
            disable_discovery: true,
            ..Default::default()
        },
    );
    wait_for_daemon_ready(&bob_db, Duration::from_secs(10));

    // 6. Bob waits for sync convergence and the post-rotation message
    // must be visible + decryptable in his `topo messages`.
    assert_eventually(&bob_db, &format!("has_event:{} >= 1", post_rot), timeout_ms);
    assert_eventually(&bob_db, "message_count >= 1", timeout_ms);

    let bob_messages = get_messages(&bob_db);
    assert!(
        bob_messages
            .iter()
            .any(|m| m.contains("post-rotation-should-reach-bob")),
        "Bob must see the post-invite-bundle message in his `topo \
         messages` output. Contents: {:?}",
        bob_messages
    );

    alice_daemon.stop();
    bob_daemon.stop();
}
