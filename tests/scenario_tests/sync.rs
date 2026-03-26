use std::time::Duration;
use topo::crypto::event_id_to_base64;
use topo::db::open_connection;
use topo::testutil::{assert_eventually, start_peers, Peer, ScenarioHarness};

/// Two-set PSK isolation: mismatched PSKs cannot decrypt each other's messages.
/// This requires internal APIs (create_key_secret, create_encrypted_message)
/// because the CLI send command auto-encrypts with the shared workspace key.
#[tokio::test]
async fn test_psk_two_set_isolation() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_in_workspace("bob", &alice).await;
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    // Alice and Bob use DIFFERENT PSKs
    let key_a: [u8; 32] = rand::random();
    let key_b: [u8; 32] = rand::random();
    let sk_eid_alice = alice.create_key_secret(key_a);
    let _sk_eid_bob = bob.create_key_secret(key_b);

    // Alice encrypts with her key
    let enc_eid = alice.create_encrypted_message(&sk_eid_alice, "Alice secret");
    let enc_b64 = event_id_to_base64(&enc_eid);

    // Alice also creates a normal message
    let alice_msg = alice.create_message("Alice cleartext");
    let alice_msg_b64 = event_id_to_base64(&alice_msg);

    // Sync
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || bob.has_event(&enc_b64) && bob.has_event(&alice_msg_b64),
        Duration::from_secs(15),
        "bob should receive alice's encrypted and cleartext events",
    )
    .await;

    drop(sync);

    assert_eq!(
        bob.scoped_message_count(),
        1,
        "bob should project Alice's cleartext message while the encrypted one stays blocked"
    );

    // Verify the encrypted event is blocked
    let bob_db = open_connection(&bob.db_path).expect("open bob db");
    let blocked: i64 = bob_db
        .query_row(
            "SELECT COUNT(*) FROM blocked_event_deps WHERE peer_id = ?1",
            rusqlite::params![&bob.identity],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        blocked >= 1,
        "events should be blocked (foreign signer + missing key dep)"
    );

    harness.finish();
}
