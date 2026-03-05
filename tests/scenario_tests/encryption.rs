use std::time::Duration;
use topo::crypto::event_id_to_base64;
use topo::db::open_connection;
use topo::testutil::{assert_eventually, start_peers_pinned, Peer, ScenarioHarness};

/// Integration test: Alice creates a PSK + encrypted message → syncs to Bob → Bob projects.
#[tokio::test]
async fn test_encrypted_event_sync() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);
    let alice_initial_keys = alice.secret_key_count();
    let bob_initial_keys = bob.secret_key_count();

    // Materialize the same PSK locally on both peers (local-only key event, not synced).
    let key_bytes: [u8; 32] = rand::random();
    let fixed_ts = 4_000_000u64;
    let sk_eid_alice = alice.create_secret_key_deterministic(key_bytes, fixed_ts);
    let sk_eid_bob = bob.create_secret_key_deterministic(key_bytes, fixed_ts);
    assert_eq!(
        sk_eid_alice, sk_eid_bob,
        "deterministic PSK materialization should match"
    );

    let enc_eid = alice.create_encrypted_message(&sk_eid_alice, "Hello encrypted world");
    let enc_b64 = event_id_to_base64(&enc_eid);

    assert_eq!(alice.secret_key_count(), alice_initial_keys + 1);
    assert_eq!(bob.secret_key_count(), bob_initial_keys + 1);
    // The encrypted event projects into messages table
    assert_eq!(alice.scoped_message_count(), 1);

    // Sync to Bob
    let sync = start_peers_pinned(&alice, &bob);

    assert_eventually(
        || bob.has_event(&enc_b64),
        Duration::from_secs(15),
        "bob should receive alice's encrypted event",
    )
    .await;

    drop(sync);

    // Bob has his local secret key. The encrypted wrapper decrypts to a Message
    // with signed_by = Alice's PeerShared (foreign signer -> inner message rejected).
    assert_eq!(bob.secret_key_count(), bob_initial_keys + 1);
    // Encrypted inner message is rejected because its signer (Alice's PeerShared)
    // is not valid on Bob's side (foreign network)
    assert_eq!(bob.scoped_message_count(), 0);

    harness.finish();
}

/// Integration test: Encrypted event syncs before key → blocks → key syncs → cascade unblocks.
#[tokio::test]
async fn test_encrypted_out_of_order_sync() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);
    let bob_initial_keys = bob.secret_key_count();

    // Alice creates key + encrypted message.
    let key_bytes: [u8; 32] = rand::random();
    let fixed_ts = 5_000_000u64;
    let sk_eid = alice.create_secret_key_deterministic(key_bytes, fixed_ts);
    let enc_eid = alice.create_encrypted_message(&sk_eid, "Out of order encrypted");
    let enc_b64 = event_id_to_base64(&enc_eid);

    // Also create a normal message to verify mixed events work
    let alice_msg = alice.create_message("Normal message");
    let alice_msg_b64 = event_id_to_base64(&alice_msg);

    // Bob creates a message too, but does NOT have the key yet.
    let bob_msg = bob.create_message("Bob's message");
    let bob_msg_b64 = event_id_to_base64(&bob_msg);

    // Sync phase 1: ciphertext arrives before key materialization on Bob.
    // Note: alice's SK is local scope, not synced
    let sync1 = start_peers_pinned(&alice, &bob);

    assert_eventually(
        || {
            bob.has_event(&enc_b64)
                && bob.has_event(&alice_msg_b64)
                && alice.has_event(&bob_msg_b64)
        },
        Duration::from_secs(15),
        "phase 1: both peers should have synced shared events",
    )
    .await;

    drop(sync1);

    // Bob should be blocked on missing key after phase 1.
    assert_eq!(bob.secret_key_count(), bob_initial_keys);
    // Bob: only his own message projected (Alice's normal message blocked by foreign signer)
    assert_eq!(bob.scoped_message_count(), 1);
    let bob_db = open_connection(&bob.db_path).expect("open bob db");
    let blocked_before: i64 = bob_db
        .query_row(
            "SELECT COUNT(*) FROM blocked_event_deps WHERE peer_id = ?1",
            rusqlite::params![&bob.identity],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        blocked_before >= 1,
        "encrypted wrapper should be blocked until key appears"
    );

    // Materialize the matching key locally on Bob; this should unblock encrypted wrapper.
    let sk_eid_bob = bob.create_secret_key_deterministic(key_bytes, fixed_ts);
    assert_eq!(
        sk_eid_bob, sk_eid,
        "bob key materialization should match alice key event id"
    );

    // After key materialization, the encrypted wrapper unblocks. But the inner message
    // has signed_by = Alice's PeerShared (foreign signer), so it gets rejected.
    assert_eq!(bob.secret_key_count(), bob_initial_keys + 1);
    // Bob still only sees his own message (encrypted inner rejected due to foreign signer)
    assert_eq!(bob.scoped_message_count(), 1);

    // Alice sees all her own messages
    assert_eq!(alice.scoped_message_count(), 2); // encrypted inner + normal message

    harness.finish();
}

/// Integration test: mixed cleartext + encrypted events → verify_projection_invariants.
#[tokio::test]
async fn test_encrypted_replay_invariants() {
    let alice = Peer::new_with_identity("alice");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    let initial_keys = alice.secret_key_count();

    // Create a mix of cleartext and encrypted events
    let key_bytes: [u8; 32] = rand::random();
    let sk_eid = alice.create_secret_key(key_bytes);

    alice.create_message("Cleartext 1");
    alice.create_encrypted_message(&sk_eid, "Encrypted 1");
    alice.create_message("Cleartext 2");
    alice.create_encrypted_message(&sk_eid, "Encrypted 2");

    assert_eq!(alice.secret_key_count(), initial_keys + 1);
    assert_eq!(alice.scoped_message_count(), 4); // 2 cleartext + 2 encrypted inner messages

    // Run invariant checks (forward, double, reverse)
    harness.finish();
}

#[tokio::test]
async fn test_encrypted_inner_unsupported_signer_rejects_durably() {
    use topo::crypto::hash_event;
    use topo::event_modules::{
        encode_event, EncryptedEvent, MessageEvent, ParsedEvent, EVENT_TYPE_MESSAGE,
    };
    use topo::projection::apply::project_one;
    use topo::projection::encrypted::encrypt_event_blob;

    let alice = Peer::new_with_identity("alice");
    let harness = ScenarioHarness::new();
    harness.track(&alice);

    // Create and project a secret key
    let key_bytes: [u8; 32] = rand::random();
    let sk_eid = alice.create_secret_key(key_bytes);

    // Create an inner Message with signer_type=255 (unsupported)
    // signed_by references an existing PeerShared signer event, but signer_type is invalid
    let inner = ParsedEvent::Message(MessageEvent {
        created_at_ms: 999999u64,
        workspace_id: [0u8; 32],
        author_id: alice.peer_shared_event_id.unwrap(),
        content: "bad signer type".to_string(),
        signed_by: alice.peer_shared_event_id.unwrap(),
        signer_type: 255, // unsupported
        signature: [0u8; 64],
    });
    let inner_blob = encode_event(&inner).unwrap();

    // Encrypt it
    let (nonce, ciphertext, auth_tag) = encrypt_event_blob(&key_bytes, &inner_blob).unwrap();
    let wrapper = ParsedEvent::Encrypted(EncryptedEvent {
        created_at_ms: 999999u64,
        key_event_id: sk_eid,
        inner_type_code: EVENT_TYPE_MESSAGE,
        nonce,
        ciphertext,
        auth_tag,
    });
    let wrapper_blob = encode_event(&wrapper).unwrap();

    // Insert the encrypted event manually
    let db = open_connection(&alice.db_path).expect("open db");
    let enc_eid = hash_event(&wrapper_blob);
    let enc_b64 = event_id_to_base64(&enc_eid);
    let ts = 999999i64;
    db.execute(
        "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
         VALUES (?1, ?2, ?3, 'shared', ?4, ?5)",
        rusqlite::params![&enc_b64, "encrypted", &wrapper_blob, ts, ts],
    )
    .unwrap();
    db.execute(
        "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source)
         VALUES (?1, ?2, ?3, 'test')",
        rusqlite::params![&alice.identity, &enc_b64, ts],
    )
    .unwrap();

    // Project: should get Reject (not hard Err) because signer_type=255 is invalid
    let result = project_one(&db, &alice.identity, &enc_eid).unwrap();
    match result {
        topo::projection::decision::ProjectionDecision::Reject { reason } => {
            assert!(
                reason.contains("unsupported signer_type")
                    || reason.contains("signer resolution failed"),
                "unexpected rejection reason: {}",
                reason
            );
        }
        other => panic!("expected Reject, got {:?}", other),
    }

    // Verify rejected_events table has a row
    let rej_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM rejected_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&alice.identity, &enc_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rej_count, 1, "rejected event should be recorded durably");

    // Second call should return AlreadyProcessed (not re-Reject)
    let result2 = project_one(&db, &alice.identity, &enc_eid).unwrap();
    assert_eq!(
        result2,
        topo::projection::decision::ProjectionDecision::AlreadyProcessed,
        "rejected event should not be re-processed"
    );

    harness.finish();
}
