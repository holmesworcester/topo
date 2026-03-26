use topo::db::open_connection;
use topo::testutil::{Peer, ScenarioHarness};

/// Integration test: verify project_queue drain works end-to-end with create_event_synchronous events.
#[tokio::test]
async fn test_project_queue_drain_after_batch() {
    let harness = ScenarioHarness::skip("tests queue dedup guard, not projection invariants");
    use topo::crypto::event_id_from_base64;
    use topo::db::project_queue::ProjectQueue;
    use topo::projection::apply::project_one;

    let alice = Peer::new_with_identity("alice");

    // Create events (projected inline by create_event_synchronous)
    alice.batch_create_messages(5);
    assert_eq!(alice.scoped_message_count(), 5);

    // Enqueue to project_queue — guard should prevent re-enqueue (already valid)
    let db = open_connection(&alice.db_path).expect("open db");
    let pq = ProjectQueue::new(&db);

    let event_ids: Vec<String> = db
        .prepare("SELECT event_id FROM events")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let refs: Vec<&str> = event_ids.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        pq.count_pending(&alice.identity).unwrap(),
        0,
        "inline bootstrap and message projection should leave project_queue empty"
    );
    let inserted = pq.enqueue_batch(&alice.identity, &refs).unwrap();
    assert_eq!(
        inserted, 0,
        "guard should prevent re-enqueue of already-valid events"
    );

    // Drain should process nothing (queue empty)
    let drained = pq
        .drain(&alice.identity, |conn, eid_b64| {
            if let Some(eid) = event_id_from_base64(eid_b64) {
                project_one(conn, &alice.identity, &eid)
                    .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(drained, 0);

    // State unchanged
    assert_eq!(alice.scoped_message_count(), 5);

    harness.finish();
}
