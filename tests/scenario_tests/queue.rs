use topo::db::open_connection;
use topo::testutil::{Peer, ScenarioHarness};

/// Integration test: simulate crash recovery by manually enqueuing events into project_queue,
/// then calling recovery (recover_expired + drain). All events should be projected.
#[tokio::test]
async fn test_project_queue_crash_recovery() {
    let harness = ScenarioHarness::skip("manually destroys/rebuilds projection as test mechanism");
    use topo::crypto::event_id_from_base64;
    use topo::db::project_queue::ProjectQueue;
    use topo::projection::apply::project_one;

    let alice = Peer::new_with_identity("alice");

    // Create messages via create_event_synchronous (bypasses queue, projects inline)
    let _msg1 = alice.create_message("Recovery message 1");
    let _msg2 = alice.create_message("Recovery message 2");
    let _msg3 = alice.create_message("Recovery message 3");

    assert_eq!(alice.scoped_message_count(), 3);

    // Now simulate a crash scenario: clear ALL projection state and re-enqueue ALL events
    let db = open_connection(&alice.db_path).expect("open db");
    db.execute(
        "DELETE FROM messages WHERE recorded_by = ?1",
        rusqlite::params![&alice.identity],
    )
    .unwrap();
    db.execute(
        "DELETE FROM workspaces WHERE recorded_by = ?1",
        rusqlite::params![&alice.identity],
    )
    .unwrap();
    db.execute(
        "DELETE FROM user_invites WHERE recorded_by = ?1",
        rusqlite::params![&alice.identity],
    )
    .unwrap();
    db.execute(
        "DELETE FROM users WHERE recorded_by = ?1",
        rusqlite::params![&alice.identity],
    )
    .unwrap();
    db.execute(
        "DELETE FROM device_invites WHERE recorded_by = ?1",
        rusqlite::params![&alice.identity],
    )
    .unwrap();
    db.execute(
        "DELETE FROM peers_shared WHERE recorded_by = ?1",
        rusqlite::params![&alice.identity],
    )
    .unwrap();
    db.execute(
        "DELETE FROM invites_accepted WHERE recorded_by = ?1",
        rusqlite::params![&alice.identity],
    )
    .unwrap();
    db.execute(
        "DELETE FROM valid_events WHERE peer_id = ?1",
        rusqlite::params![&alice.identity],
    )
    .unwrap();
    db.execute(
        "DELETE FROM blocked_event_deps WHERE peer_id = ?1",
        rusqlite::params![&alice.identity],
    )
    .unwrap();
    db.execute(
        "DELETE FROM rejected_events WHERE peer_id = ?1",
        rusqlite::params![&alice.identity],
    )
    .unwrap();

    // Enqueue ALL recorded events into project_queue (simulating full crash recovery)
    let pq = ProjectQueue::new(&db);
    let all_eids: Vec<String> = {
        let mut stmt = db
            .prepare("SELECT event_id FROM recorded_events WHERE peer_id = ?1")
            .unwrap();
        stmt.query_map(rusqlite::params![&alice.identity], |row| {
            row.get::<_, String>(0)
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
    };
    for eid_b64 in &all_eids {
        pq.enqueue(&alice.identity, eid_b64).unwrap();
    }
    assert!(
        all_eids.len() >= 3 + 1,
        "should have identity events + 3 messages, got {}",
        all_eids.len()
    );

    // Verify nothing projected yet
    let msg_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
            rusqlite::params![&alice.identity],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(msg_count, 0);

    // Run recovery: recover expired leases + drain
    let recovered = pq.recover_expired().unwrap();
    assert_eq!(recovered, 0);

    let drained = pq
        .drain(&alice.identity, |conn, eid_b64| {
            if let Some(eid) = event_id_from_base64(eid_b64) {
                project_one(conn, &alice.identity, &eid)
                    .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(
        drained,
        all_eids.len(),
        "all enqueued events should be drained"
    );

    // Verify all messages projected
    let msg_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
            rusqlite::params![&alice.identity],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(msg_count, 3);

    // Verify valid_events: at least identity + messages should be valid
    let valid_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM valid_events WHERE peer_id = ?1",
            rusqlite::params![&alice.identity],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        valid_count >= 3,
        "at least the 3 messages should be valid, got {}",
        valid_count
    );

    // Queue should be empty
    assert_eq!(pq.count_pending(&alice.identity).unwrap(), 0);

    harness.finish();
}

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
