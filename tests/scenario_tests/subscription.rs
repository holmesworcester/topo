use topo::db::open_connection;
use topo::state::subscriptions as subscription;
use topo::state::subscriptions::types::*;
use topo::testutil::{Peer, ScenarioHarness};

fn spec_no_filters() -> SubscriptionSpec {
    SubscriptionSpec {
        event_type: "message".to_string(),
        since: None,
        filters: vec![],
    }
}

/// Encrypted message projection triggers subscription on inner event.
/// This test requires internal APIs (create_encrypted_message, subscription::poll_feed)
/// because the CLI send command does not expose encrypted event creation directly.
#[test]
fn test_encrypted_message_triggers_subscription() {
    let harness = ScenarioHarness::skip("subscription tests are local-only, no sync");
    let alice = Peer::new_with_identity("alice");

    let db = open_connection(&alice.db_path).unwrap();
    subscription::schema::ensure_schema(&db).unwrap();

    let sub = subscription::create_subscription(
        &db,
        &alice.identity,
        "encrypted_inbox",
        "message",
        DeliveryMode::Full,
        &spec_no_filters(),
    )
    .unwrap();
    drop(db);

    // Create a secret key and encrypted message
    let key_eid = alice.create_key_secret([0x42u8; 32]);
    let _enc_eid = alice.create_encrypted_message(&key_eid, "secret hello");

    let db = open_connection(&alice.db_path).unwrap();
    let items =
        subscription::poll_feed(&db, &alice.identity, &sub.subscription_id, 0, 100).unwrap();
    assert_eq!(
        items.len(),
        1,
        "encrypted message should trigger subscription"
    );

    // Payload should contain the decrypted content
    assert_eq!(items[0].payload["content"], "secret hello");

    harness.finish();
}
