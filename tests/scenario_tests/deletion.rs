use topo::crypto::event_id_from_base64;
use topo::db::open_connection;
use topo::testutil::{Peer, ScenarioHarness};

/// Integration test: Create encrypted message, then encrypted deletion targeting it.
/// Verify cascade works through encryption layer.
#[tokio::test]
async fn test_encrypted_deletion() {
    let alice = Peer::new_with_identity("alice");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    let initial_keys = alice.key_secret_count();

    // Create a secret key
    let key_bytes: [u8; 32] = rand::random();
    let sk_eid = alice.create_key_secret(key_bytes);

    // Create an encrypted message
    let _enc_msg_eid = alice.create_encrypted_message(&sk_eid, "Encrypted delete me");

    assert_eq!(alice.key_secret_count(), initial_keys + 1);
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

