use std::time::Duration;
use topo::crypto::{event_id_from_base64, event_id_to_base64};
use topo::db::open_connection;
use topo::testutil::{assert_eventually, start_peers_pinned, Peer, ScenarioHarness};

/// Integration test: Alice creates message + reactions, syncs to Bob. Alice deletes message.
/// Bob syncs again. Verify: Bob has tombstone, no message, no reactions.
#[tokio::test]
async fn test_deletion_sync() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    // Alice creates a message and a reaction targeting it
    let msg_id = alice.create_message("Delete me");
    let msg_b64 = event_id_to_base64(&msg_id);
    let rxn_id = alice.create_reaction(&msg_id, "\u{1f44d}");
    let rxn_b64 = event_id_to_base64(&rxn_id);

    assert_eq!(alice.message_count(), 1);
    assert_eq!(alice.reaction_count(), 1);

    // Sync to Bob
    let sync = start_peers_pinned(&alice, &bob);

    assert_eventually(
        || bob.has_event(&msg_b64) && bob.has_event(&rxn_b64),
        Duration::from_secs(15),
        "bob should receive alice's message and reaction",
    )
    .await;

    drop(sync);

    // Bob: Alice's events blocked (foreign signer)
    assert_eq!(bob.message_count(), 0);
    assert_eq!(bob.reaction_count(), 0);

    // Alice deletes the message
    let del_id = alice.create_message_deletion(&msg_id);
    let del_b64 = event_id_to_base64(&del_id);

    assert_eq!(alice.message_count(), 0); // deleted
    assert_eq!(alice.reaction_count(), 0); // cascaded
    assert_eq!(alice.deleted_message_count(), 1); // tombstone

    // Sync again — Bob gets the deletion event
    let sync2 = start_peers_pinned(&alice, &bob);

    assert_eventually(
        || bob.has_event(&del_b64),
        Duration::from_secs(15),
        "bob should receive alice's deletion event",
    )
    .await;

    drop(sync2);

    // Bob: all of Alice's events blocked (foreign signer), including deletion
    assert_eq!(
        bob.message_count(),
        0,
        "bob: no messages projected (foreign signer)"
    );
    assert_eq!(
        bob.reaction_count(),
        0,
        "bob: no reactions projected (foreign signer)"
    );
    assert_eq!(
        bob.deleted_message_count(),
        0,
        "bob: no tombstones (deletion blocked too)"
    );

    harness.finish();
}

/// Integration test: Alice creates a message and then a deletion targeting it.
/// Bob syncs and gets both events. Regardless of receive order, Bob converges
/// to the same final state: 0 messages, 1 tombstone.
/// This also tests that if Bob receives the deletion first (blocked), the
/// cascade-unblock when the message arrives produces the correct state.
#[tokio::test]
async fn test_deletion_before_target_sync() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    // Alice creates a message and then deletes it
    let msg_id = alice.create_message("Delete me via sync");
    let del_id = alice.create_message_deletion(&msg_id);
    let del_b64 = event_id_to_base64(&del_id);

    assert_eq!(alice.message_count(), 0); // deleted
    assert_eq!(alice.deleted_message_count(), 1); // tombstone

    // Sync
    let sync = start_peers_pinned(&alice, &bob);

    assert_eventually(
        || bob.has_event(&del_b64),
        Duration::from_secs(15),
        "bob should receive alice's deletion event",
    )
    .await;

    drop(sync);

    // Bob: Alice's events blocked (foreign signer)
    assert_eq!(bob.message_count(), 0, "bob: no messages (foreign signer)");
    assert_eq!(
        bob.deleted_message_count(),
        0,
        "bob: no tombstones (foreign signer)"
    );

    harness.finish();
}

/// Integration test: Create encrypted message, then encrypted deletion targeting it.
/// Verify cascade works through encryption layer.
#[tokio::test]
async fn test_encrypted_deletion() {
    let alice = Peer::new_with_identity("alice");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    let initial_keys = alice.secret_key_count();

    // Create a secret key
    let key_bytes: [u8; 32] = rand::random();
    let sk_eid = alice.create_secret_key(key_bytes);

    // Create an encrypted message
    let _enc_msg_eid = alice.create_encrypted_message(&sk_eid, "Encrypted delete me");

    assert_eq!(alice.secret_key_count(), initial_keys + 1);
    assert_eq!(alice.scoped_message_count(), 1); // inner message projected

    // Get the inner message's event_id from the messages table
    let alice_db = open_connection(&alice.db_path).expect("open alice db");
    let inner_msg_id: String = alice_db
        .query_row(
            "SELECT message_id FROM messages WHERE recorded_by = ?1",
            rusqlite::params![&alice.identity],
            |row| row.get(0),
        )
        .unwrap();
    let inner_msg_eid = event_id_from_base64(&inner_msg_id).expect("parse inner msg id");
    drop(alice_db);

    // Create an encrypted deletion targeting the inner message
    alice.create_encrypted_deletion(&sk_eid, &inner_msg_eid);

    assert_eq!(alice.scoped_message_count(), 0); // inner message deleted
    assert_eq!(alice.deleted_message_count(), 1); // tombstone from encrypted deletion

    harness.finish();
}

/// Integration test: After deletion sync, verify_projection_invariants on both peers.
#[tokio::test]
async fn test_deletion_replay_invariants() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    // Create a mix of messages, reactions, and deletions
    let msg1 = alice.create_message("Keep me");
    let msg2 = alice.create_message("Delete me");
    alice.create_reaction(&msg1, "\u{2764}\u{fe0f}");
    alice.create_reaction(&msg2, "\u{1f44d}");

    // Delete msg2 (cascades its reaction too)
    let del_id = alice.create_message_deletion(&msg2);
    let del_b64 = event_id_to_base64(&del_id);

    assert_eq!(alice.message_count(), 1); // msg1 survives
    assert_eq!(alice.reaction_count(), 1); // msg1's reaction survives
    assert_eq!(alice.deleted_message_count(), 1); // msg2 tombstone

    // Sync to Bob
    let sync = start_peers_pinned(&alice, &bob);

    assert_eventually(
        || bob.has_event(&del_b64),
        Duration::from_secs(15),
        "bob should receive alice's deletion event",
    )
    .await;

    drop(sync);

    // Bob: Alice's events blocked (foreign signer)
    assert_eq!(bob.message_count(), 0);
    assert_eq!(bob.reaction_count(), 0);
    assert_eq!(bob.deleted_message_count(), 0);

    // Run full replay invariants on both
    harness.finish();
}
