//! Integration tests for the subscription engine.
//!
//! Tests the full lifecycle: subscription creation → message projection →
//! feed population → poll → ack, using real identity chains and the
//! production projection pipeline.

use topo::crypto::event_id_to_base64;
use topo::db::open_connection;
use topo::state::subscriptions as subscription;
use topo::state::subscriptions::types::*;
use topo::testutil::{Peer, ScenarioHarness};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn spec_no_filters() -> SubscriptionSpec {
    SubscriptionSpec {
        event_type: "message".to_string(),
        since: None,
        filters: vec![],
    }
}

fn spec_with_since_event(event_id_b64: &str, created_at_ms: u64) -> SubscriptionSpec {
    SubscriptionSpec {
        event_type: "message".to_string(),
        since: Some(SinceCursor {
            created_at_ms,
            event_id: event_id_b64.to_string(),
        }),
        filters: vec![],
    }
}

fn spec_with_author_filter(author_b64: &str) -> SubscriptionSpec {
    SubscriptionSpec {
        event_type: "message".to_string(),
        since: None,
        filters: vec![FilterClause {
            field: "author_id".to_string(),
            op: FilterOp::Eq,
            value: serde_json::Value::String(author_b64.to_string()),
        }],
    }
}

// ---------------------------------------------------------------------------
// 1. Basic lifecycle: create sub → send message → poll feed → ack
// ---------------------------------------------------------------------------

#[test]
fn test_subscription_full_lifecycle() {
    let harness = ScenarioHarness::skip("subscription tests are local-only, no sync");
    let alice = Peer::new_with_identity("alice");

    let db = open_connection(&alice.db_path).unwrap();
    subscription::schema::ensure_schema(&db).unwrap();

    // Create subscription before any messages
    let sub = subscription::create_subscription(
        &db,
        &alice.identity,
        "inbox",
        "message",
        DeliveryMode::Full,
        &spec_no_filters(),
    )
    .unwrap();
    drop(db);

    // Send 3 messages (projection fires subscription hook)
    let _m1 = alice.create_message("hello");
    let _m2 = alice.create_message("world");
    let _m3 = alice.create_message("test");

    // Poll feed
    let db = open_connection(&alice.db_path).unwrap();
    let items =
        subscription::poll_feed(&db, &alice.identity, &sub.subscription_id, 0, 100).unwrap();
    assert_eq!(items.len(), 3, "expected 3 feed items, got {}", items.len());
    assert_eq!(items[0].seq, 1);
    assert_eq!(items[1].seq, 2);
    assert_eq!(items[2].seq, 3);

    // Verify full payload contains content
    assert!(items[0].payload["content"].is_string());
    assert!(items[0].payload["author_id"].is_string());
    assert!(items[0].payload["event_id"].is_string());

    // Check state
    let state = subscription::get_state(&db, &alice.identity, &sub.subscription_id).unwrap();
    assert_eq!(state.pending_count, 3);
    assert!(state.dirty);

    // Ack through seq 2
    subscription::ack_feed(&db, &alice.identity, &sub.subscription_id, 2).unwrap();

    let state = subscription::get_state(&db, &alice.identity, &sub.subscription_id).unwrap();
    assert_eq!(state.pending_count, 1);

    // Only seq 3 remains
    let items =
        subscription::poll_feed(&db, &alice.identity, &sub.subscription_id, 0, 100).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].seq, 3);

    // Ack the rest
    subscription::ack_feed(&db, &alice.identity, &sub.subscription_id, 3).unwrap();
    let state = subscription::get_state(&db, &alice.identity, &sub.subscription_id).unwrap();
    assert_eq!(state.pending_count, 0);
    assert!(!state.dirty);

    harness.finish();
}

// ---------------------------------------------------------------------------
// 3. Since-event-id cursor: cursor event excluded, concurrent events at
//    same ms allowed
// ---------------------------------------------------------------------------

#[test]
fn test_subscription_since_event_id() {
    let harness = ScenarioHarness::skip("subscription tests are local-only, no sync");
    let alice = Peer::new_with_identity("alice");

    // Create a cursor event
    let cursor_eid = alice.create_message("cursor");
    let cursor_b64 = event_id_to_base64(&cursor_eid);

    // Resolve its timestamp
    let db = open_connection(&alice.db_path).unwrap();
    subscription::schema::ensure_schema(&db).unwrap();
    let cursor_ts = subscription::queries::resolve_event_created_at(&db, &cursor_b64).unwrap();

    let sub = subscription::create_subscription(
        &db,
        &alice.identity,
        "from_cursor",
        "message",
        DeliveryMode::Full,
        &spec_with_since_event(&cursor_b64, cursor_ts),
    )
    .unwrap();
    drop(db);

    // Send new messages
    let _m1 = alice.create_message("after_cursor_1");
    let _m2 = alice.create_message("after_cursor_2");

    let db = open_connection(&alice.db_path).unwrap();
    let items =
        subscription::poll_feed(&db, &alice.identity, &sub.subscription_id, 0, 100).unwrap();
    assert_eq!(
        items.len(),
        2,
        "expected 2 items after cursor, got {}",
        items.len()
    );

    harness.finish();
}

// ---------------------------------------------------------------------------
// 4. Has_changed delivery mode: no feed rows, just state updates
// ---------------------------------------------------------------------------

#[test]
fn test_subscription_has_changed_mode() {
    let harness = ScenarioHarness::skip("subscription tests are local-only, no sync");
    let alice = Peer::new_with_identity("alice");

    let db = open_connection(&alice.db_path).unwrap();
    subscription::schema::ensure_schema(&db).unwrap();

    let sub = subscription::create_subscription(
        &db,
        &alice.identity,
        "changed",
        "message",
        DeliveryMode::HasChanged,
        &spec_no_filters(),
    )
    .unwrap();
    drop(db);

    // Send several messages
    for i in 0..5 {
        alice.create_message(&format!("msg_{}", i));
    }

    let db = open_connection(&alice.db_path).unwrap();

    // No feed rows for has_changed mode
    let items =
        subscription::poll_feed(&db, &alice.identity, &sub.subscription_id, 0, 100).unwrap();
    assert_eq!(items.len(), 0);

    // But state should show pending changes
    let state = subscription::get_state(&db, &alice.identity, &sub.subscription_id).unwrap();
    assert_eq!(state.pending_count, 5);
    assert!(state.dirty);

    // Ack resets
    subscription::ack_feed(&db, &alice.identity, &sub.subscription_id, 0).unwrap();
    let state = subscription::get_state(&db, &alice.identity, &sub.subscription_id).unwrap();
    assert_eq!(state.pending_count, 0);
    assert!(!state.dirty);

    harness.finish();
}

// ---------------------------------------------------------------------------
// 5. Filter by author_id
// ---------------------------------------------------------------------------

#[test]
fn test_subscription_filter_by_author() {
    let harness = ScenarioHarness::skip("subscription tests are local-only, no sync");
    let alice = Peer::new_with_identity("alice");

    let author_b64 = event_id_to_base64(&alice.author_id);

    let db = open_connection(&alice.db_path).unwrap();
    subscription::schema::ensure_schema(&db).unwrap();

    // Subscribe only to alice's messages (which is all of them in this test,
    // but validates the filter path)
    let sub = subscription::create_subscription(
        &db,
        &alice.identity,
        "alice_only",
        "message",
        DeliveryMode::Full,
        &spec_with_author_filter(&author_b64),
    )
    .unwrap();
    drop(db);

    alice.create_message("from alice");

    let db = open_connection(&alice.db_path).unwrap();
    let items =
        subscription::poll_feed(&db, &alice.identity, &sub.subscription_id, 0, 100).unwrap();
    assert_eq!(items.len(), 1);

    harness.finish();
}

#[test]
fn test_subscription_filter_rejects_non_matching_author() {
    let harness = ScenarioHarness::skip("subscription tests are local-only, no sync");
    let alice = Peer::new_with_identity("alice");

    // Subscribe with a filter for a different author
    let fake_author = event_id_to_base64(&[0xFFu8; 32]);

    let db = open_connection(&alice.db_path).unwrap();
    subscription::schema::ensure_schema(&db).unwrap();

    let sub = subscription::create_subscription(
        &db,
        &alice.identity,
        "nobody",
        "message",
        DeliveryMode::Full,
        &spec_with_author_filter(&fake_author),
    )
    .unwrap();
    drop(db);

    alice.create_message("from alice, but sub filters for someone else");

    let db = open_connection(&alice.db_path).unwrap();
    let items =
        subscription::poll_feed(&db, &alice.identity, &sub.subscription_id, 0, 100).unwrap();
    assert_eq!(
        items.len(),
        0,
        "filter should have excluded alice's message"
    );

    harness.finish();
}

// ---------------------------------------------------------------------------
// 6. Id delivery mode: payload contains only event_id + timestamp
// ---------------------------------------------------------------------------

#[test]
fn test_subscription_id_delivery_mode() {
    let harness = ScenarioHarness::skip("subscription tests are local-only, no sync");
    let alice = Peer::new_with_identity("alice");

    let db = open_connection(&alice.db_path).unwrap();
    subscription::schema::ensure_schema(&db).unwrap();

    let sub = subscription::create_subscription(
        &db,
        &alice.identity,
        "ids",
        "message",
        DeliveryMode::Id,
        &spec_no_filters(),
    )
    .unwrap();
    drop(db);

    alice.create_message("hello");

    let db = open_connection(&alice.db_path).unwrap();
    let items =
        subscription::poll_feed(&db, &alice.identity, &sub.subscription_id, 0, 100).unwrap();
    assert_eq!(items.len(), 1);

    // Id mode: has event_id and created_at_ms, but no content
    assert!(items[0].payload["event_id"].is_string());
    assert!(items[0].payload["created_at_ms"].is_number());
    assert!(items[0].payload.get("content").is_none());

    harness.finish();
}

// ---------------------------------------------------------------------------
// 7. Disabled subscription does not receive new events
// ---------------------------------------------------------------------------

#[test]
fn test_disabled_subscription_skipped() {
    let harness = ScenarioHarness::skip("subscription tests are local-only, no sync");
    let alice = Peer::new_with_identity("alice");

    let db = open_connection(&alice.db_path).unwrap();
    subscription::schema::ensure_schema(&db).unwrap();

    let sub = subscription::create_subscription(
        &db,
        &alice.identity,
        "inbox",
        "message",
        DeliveryMode::Full,
        &spec_no_filters(),
    )
    .unwrap();
    subscription::set_enabled(&db, &alice.identity, &sub.subscription_id, false).unwrap();
    drop(db);

    alice.create_message("should not be delivered");

    let db = open_connection(&alice.db_path).unwrap();
    let items =
        subscription::poll_feed(&db, &alice.identity, &sub.subscription_id, 0, 100).unwrap();
    assert_eq!(items.len(), 0, "disabled sub should not receive events");

    // Re-enable and send another
    subscription::set_enabled(&db, &alice.identity, &sub.subscription_id, true).unwrap();
    drop(db);

    alice.create_message("should be delivered");

    let db = open_connection(&alice.db_path).unwrap();
    let items =
        subscription::poll_feed(&db, &alice.identity, &sub.subscription_id, 0, 100).unwrap();
    assert_eq!(items.len(), 1, "re-enabled sub should receive events");

    harness.finish();
}

// ---------------------------------------------------------------------------
// 8. Multiple subscriptions: each gets independent feeds
// ---------------------------------------------------------------------------

#[test]
fn test_multiple_subscriptions_independent() {
    let harness = ScenarioHarness::skip("subscription tests are local-only, no sync");
    let alice = Peer::new_with_identity("alice");

    let db = open_connection(&alice.db_path).unwrap();
    subscription::schema::ensure_schema(&db).unwrap();

    let sub_full = subscription::create_subscription(
        &db,
        &alice.identity,
        "full_sub",
        "message",
        DeliveryMode::Full,
        &spec_no_filters(),
    )
    .unwrap();
    let sub_id = subscription::create_subscription(
        &db,
        &alice.identity,
        "id_sub",
        "message",
        DeliveryMode::Id,
        &spec_no_filters(),
    )
    .unwrap();
    let sub_changed = subscription::create_subscription(
        &db,
        &alice.identity,
        "changed_sub",
        "message",
        DeliveryMode::HasChanged,
        &spec_no_filters(),
    )
    .unwrap();
    drop(db);

    alice.create_message("shared event");

    let db = open_connection(&alice.db_path).unwrap();

    // Full: 1 feed item with content
    let full_items =
        subscription::poll_feed(&db, &alice.identity, &sub_full.subscription_id, 0, 100).unwrap();
    assert_eq!(full_items.len(), 1);
    assert!(full_items[0].payload["content"].is_string());

    // Id: 1 feed item without content
    let id_items =
        subscription::poll_feed(&db, &alice.identity, &sub_id.subscription_id, 0, 100).unwrap();
    assert_eq!(id_items.len(), 1);
    assert!(id_items[0].payload.get("content").is_none());

    // HasChanged: no feed items, but state updated
    let changed_items =
        subscription::poll_feed(&db, &alice.identity, &sub_changed.subscription_id, 0, 100)
            .unwrap();
    assert_eq!(changed_items.len(), 0);
    let state =
        subscription::get_state(&db, &alice.identity, &sub_changed.subscription_id).unwrap();
    assert_eq!(state.pending_count, 1);

    harness.finish();
}

// ---------------------------------------------------------------------------
// 9. Feed order is deterministic (ascending seq)
// ---------------------------------------------------------------------------

#[test]
fn test_feed_ordering_deterministic() {
    let harness = ScenarioHarness::skip("subscription tests are local-only, no sync");
    let alice = Peer::new_with_identity("alice");

    let db = open_connection(&alice.db_path).unwrap();
    subscription::schema::ensure_schema(&db).unwrap();

    let sub = subscription::create_subscription(
        &db,
        &alice.identity,
        "ordered",
        "message",
        DeliveryMode::Full,
        &spec_no_filters(),
    )
    .unwrap();
    drop(db);

    for i in 0..10 {
        alice.create_message(&format!("msg_{}", i));
    }

    let db = open_connection(&alice.db_path).unwrap();
    let items =
        subscription::poll_feed(&db, &alice.identity, &sub.subscription_id, 0, 100).unwrap();
    assert_eq!(items.len(), 10);

    // Verify seq is strictly ascending
    for i in 1..items.len() {
        assert!(
            items[i].seq > items[i - 1].seq,
            "seq not ascending at index {}: {} vs {}",
            i,
            items[i - 1].seq,
            items[i].seq,
        );
    }

    harness.finish();
}

// ---------------------------------------------------------------------------
// 10. Non-message events do not trigger message subscription
// ---------------------------------------------------------------------------

#[test]
fn test_non_message_events_ignored() {
    let harness = ScenarioHarness::skip("subscription tests are local-only, no sync");
    let alice = Peer::new_with_identity("alice");

    let db = open_connection(&alice.db_path).unwrap();
    subscription::schema::ensure_schema(&db).unwrap();

    let sub = subscription::create_subscription(
        &db,
        &alice.identity,
        "messages_only",
        "message",
        DeliveryMode::Full,
        &spec_no_filters(),
    )
    .unwrap();
    drop(db);

    // Create a message then a reaction — only message should appear in feed
    let msg_eid = alice.create_message("hello");
    let _rxn_eid = alice.create_reaction(&msg_eid, "thumbs_up");

    let db = open_connection(&alice.db_path).unwrap();
    let items =
        subscription::poll_feed(&db, &alice.identity, &sub.subscription_id, 0, 100).unwrap();
    assert_eq!(items.len(), 1, "only message should appear, not reaction");
    assert_eq!(items[0].event_type, "message");

    harness.finish();
}

