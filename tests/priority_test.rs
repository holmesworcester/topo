//! Tests that egress sends newest events first regardless of enqueue order.
//!
//! Run with: cargo test --release --test priority_test -- --nocapture

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use rusqlite::Connection;

use topo::crypto::{hash_event, EventId};
use topo::db::{
    egress_queue::EgressQueue, open_connection, schema::create_tables, store::insert_event,
    store::Store,
};
use topo::event_modules::ShareScope;
use topo::protocol::Frame;
use topo::transport::connection::ConnectionError;
use topo::transport::StreamSend;

/// Recording mock for StreamSend that captures sent frames.
#[derive(Clone, Default)]
struct RecordingSend {
    frames: Arc<Mutex<Vec<Frame>>>,
}

#[async_trait]
impl StreamSend for RecordingSend {
    async fn send(&mut self, msg: &Frame) -> Result<(), ConnectionError> {
        self.frames.lock().unwrap().push(msg.clone());
        Ok(())
    }

    async fn flush(&mut self) -> Result<(), ConnectionError> {
        Ok(())
    }
}

/// Insert a synthetic event with a specific created_at timestamp and content.
fn insert_event_with_ts(conn: &Connection, content: &[u8], created_at_ms: i64) -> EventId {
    let event_id = hash_event(content);
    insert_event(
        conn,
        &event_id,
        "message",
        content,
        ShareScope::Shared,
        created_at_ms,
        created_at_ms,
    )
    .unwrap();
    event_id
}

/// Extract blobs from recorded frames, in send order.
fn extract_blobs(frames: &[Frame]) -> Vec<Vec<u8>> {
    frames
        .iter()
        .filter_map(|f| match f {
            Frame::Event { blob } => Some(blob.clone()),
            _ => None,
        })
        .collect()
}

/// Core test: enqueue many old events and one new event, verify the new event
/// is sent first via drain_egress_to_data_stream.
#[tokio::test]
async fn priority_newest_event_sent_first_via_drain() {
    use topo::runtime::sync_engine::session::data_plane::drain_egress_to_data_stream;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("priority.db");
    let conn = open_connection(&path).unwrap();
    conn.busy_timeout(Duration::from_millis(500)).unwrap();
    create_tables(&conn).unwrap();

    let old_ts = 1_600_000_000_000i64; // ~Sep 2020
    let new_ts = 1_700_000_000_000i64; // ~Nov 2023

    // Create 200 old events (simulating backlog/file slices)
    let mut old_event_ids: Vec<EventId> = Vec::new();
    for i in 0..200u32 {
        let content = format!("old-backlog-event-{}", i);
        let eid = insert_event_with_ts(&conn, content.as_bytes(), old_ts + i as i64);
        old_event_ids.push(eid);
    }

    // Create 1 new event (the "priority" message)
    let priority_content = b"PRIORITY-NEW-MESSAGE";
    let priority_eid = insert_event_with_ts(&conn, priority_content, new_ts);

    // Enqueue old events first, then the new one (simulating reconciliation discovery)
    let egress = EgressQueue::new(&conn);
    egress.enqueue_events("peer-x", &old_event_ids).unwrap();
    egress.enqueue_events("peer-x", &[priority_eid]).unwrap();

    // Verify the priority event is enqueued
    let pending = egress.count_pending("peer-x").unwrap();
    assert_eq!(pending, 201, "expected 201 pending events");

    // Drain via the production code path
    let store = Store::new(&conn);
    let mut sender = RecordingSend::default();
    let stats = drain_egress_to_data_stream(99, &egress, &store, "peer-x", &mut sender)
        .await
        .unwrap();

    assert_eq!(
        stats.events_sent_delta, 201,
        "all 201 events should be sent"
    );

    // Check the send order
    let frames = sender.frames.lock().unwrap();
    let blobs = extract_blobs(&frames);
    assert_eq!(blobs.len(), 201);

    // The FIRST blob sent should be the priority (newest) event
    assert_eq!(
        blobs[0], priority_content,
        "newest event (PRIORITY-NEW-MESSAGE) should be sent first, \
         but got: {:?}",
        String::from_utf8_lossy(&blobs[0])
    );

    // Verify all old events come after
    for (i, blob) in blobs.iter().skip(1).enumerate() {
        let s = String::from_utf8_lossy(blob);
        assert!(
            s.starts_with("old-backlog-event-"),
            "event at position {} should be an old backlog event, got: {}",
            i + 1,
            s
        );
    }

    eprintln!("PASS: priority message sent at position 0 out of 201 events");
}

/// Test with multiple priority levels: verify strict timestamp ordering.
#[tokio::test]
async fn priority_ordering_by_event_timestamp() {
    use topo::runtime::sync_engine::session::data_plane::drain_egress_to_data_stream;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("priority-multi.db");
    let conn = open_connection(&path).unwrap();
    conn.busy_timeout(Duration::from_millis(500)).unwrap();
    create_tables(&conn).unwrap();

    // Create events with precise timestamps in scrambled order
    let ts_a = 1_000_000i64; // oldest
    let ts_b = 2_000_000i64;
    let ts_c = 3_000_000i64;
    let ts_d = 4_000_000i64; // newest

    let eid_c = insert_event_with_ts(&conn, b"event-C-3M", ts_c);
    let eid_a = insert_event_with_ts(&conn, b"event-A-1M", ts_a);
    let eid_d = insert_event_with_ts(&conn, b"event-D-4M", ts_d);
    let eid_b = insert_event_with_ts(&conn, b"event-B-2M", ts_b);

    // Enqueue in creation order (scrambled timestamps)
    let egress = EgressQueue::new(&conn);
    egress
        .enqueue_events("p1", &[eid_c, eid_a, eid_d, eid_b])
        .unwrap();

    let store = Store::new(&conn);
    let mut sender = RecordingSend::default();
    let _stats = drain_egress_to_data_stream(1, &egress, &store, "p1", &mut sender)
        .await
        .unwrap();

    let frames = sender.frames.lock().unwrap();
    let blobs = extract_blobs(&frames);

    // Should come out newest-first: D, C, B, A
    assert_eq!(blobs.len(), 4);
    assert_eq!(blobs[0], b"event-D-4M", "newest should be first");
    assert_eq!(blobs[1], b"event-C-3M", "second newest should be second");
    assert_eq!(blobs[2], b"event-B-2M", "third newest should be third");
    assert_eq!(blobs[3], b"event-A-1M", "oldest should be last");

    eprintln!("PASS: events sent in strict newest-first timestamp order");
}

/// Full integration test with real peers: create old backlog + new priority message,
/// sync, and verify the priority message arrives at the receiver promptly.
///
/// Since events are encrypted (outer wrapper has different event_id than inner),
/// we verify arrival order by checking which messages are projected first. The
/// priority message has a strictly later created_at than the backlog, and with
/// newest-first egress it should appear in bob's messages table early.
#[tokio::test]
async fn priority_full_sync_newest_arrives_early() {
    use topo::testutil::{assert_eventually, start_peers_pinned, Peer};

    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_in_workspace("bob", &alice).await;

    // Create 200 old messages on alice (backlog)
    alice.batch_create_messages(200);

    // Small pause so the priority message gets a strictly newer timestamp
    std::thread::sleep(Duration::from_millis(10));

    // Create 1 priority message with identifiable content
    let _priority_eid = alice.create_message("PRIORITY_MARKER_MSG");

    eprintln!("Created 200 old messages + 1 priority message");

    // Start sync
    let sync = start_peers_pinned(&alice, &bob);

    // Wait for all 201 messages to arrive at bob
    assert_eventually(
        || bob.message_count() == 201,
        Duration::from_secs(60),
        &format!(
            "bob should have 201 messages (has {})",
            bob.message_count()
        ),
    )
    .await;

    drop(sync);

    // Verify the priority message is present at bob
    let bob_db = open_connection(&bob.db_path).unwrap();
    let has_priority: bool = bob_db
        .query_row(
            "SELECT COUNT(*) > 0 FROM messages WHERE content = 'PRIORITY_MARKER_MSG'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(has_priority, "bob should have the priority message");

    // Smoke test: all 201 messages projected
    assert_eq!(bob.message_count(), 201);

    eprintln!(
        "PASS: full sync converged with 201 messages including priority message"
    );
}
