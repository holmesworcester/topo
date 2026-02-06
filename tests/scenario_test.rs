use std::time::{Duration, Instant};
use poc_7::testutil::{Peer, start_peers, assert_eventually, sync_until_converged};
use poc_7::db::open_connection;

fn test_channel() -> [u8; 32] {
    let mut ch = [0u8; 32];
    ch[0..4].copy_from_slice(b"test");
    ch
}

#[tokio::test]
async fn test_two_peer_bidirectional_sync() {
    let channel = test_channel();
    let alice = Peer::new("alice", channel);
    let bob = Peer::new("bob", channel);

    alice.batch_create_messages(2);
    bob.batch_create_messages(1);

    assert_eq!(alice.store_count(), 2);
    assert_eq!(bob.store_count(), 1);

    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || alice.store_count() == 3 && bob.store_count() == 3,
        Duration::from_secs(15),
        "both peers should have 3 events",
    ).await;

    assert_eq!(alice.message_count(), 3);
    assert_eq!(bob.message_count(), 3);

    drop(sync);
}

#[tokio::test]
async fn test_one_way_sync() {
    let channel = test_channel();
    let alice = Peer::new("alice", channel);
    let bob = Peer::new("bob", channel);

    alice.batch_create_messages(10);
    assert_eq!(alice.store_count(), 10);
    assert_eq!(bob.store_count(), 0);

    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || bob.store_count() == 10,
        Duration::from_secs(15),
        "bob should have all 10 events",
    ).await;

    drop(sync);
}

#[tokio::test]
async fn test_concurrent_create_and_sync() {
    let channel = test_channel();
    let alice = Peer::new("alice", channel);
    let bob = Peer::new("bob", channel);

    let sync = start_peers(&alice, &bob);

    // Give sync loop a moment to connect
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Create messages while sync runs
    alice.create_message("Hello from Alice");
    bob.create_message("Hi from Bob");

    assert_eventually(
        || alice.store_count() == 2 && bob.store_count() == 2,
        Duration::from_secs(15),
        "both peers converge to 2 events",
    ).await;

    // Create more messages — sync loop picks them up
    alice.create_message("Another from Alice");

    assert_eventually(
        || bob.store_count() == 3,
        Duration::from_secs(15),
        "bob gets the new message",
    ).await;

    drop(sync);
}

#[tokio::test]
async fn test_sync_10k() {
    let channel = test_channel();
    let alice = Peer::new("alice", channel);
    let bob = Peer::new("bob", channel);

    let gen_start = Instant::now();
    alice.batch_create_messages(10_000);
    let gen_secs = gen_start.elapsed().as_secs_f64();
    eprintln!("Generated 10k events in {:.2}s", gen_secs);

    let metrics = sync_until_converged(
        &alice, &bob, 10_000, Duration::from_secs(120),
    ).await;

    eprintln!("10k sync: {}", metrics);

    assert_eq!(alice.store_count(), 10_000);
    assert_eq!(bob.store_count(), 10_000);
    assert_eq!(alice.message_count(), 10_000);
    assert_eq!(bob.message_count(), 10_000);
}

#[tokio::test]
async fn test_recorded_events_isolation() {
    let channel = test_channel();
    let alice = Peer::new("alice", channel);
    let bob = Peer::new("bob", channel);

    // Create messages locally
    alice.batch_create_messages(3);
    bob.batch_create_messages(2);

    // Verify local recorded_events before sync
    assert_eq!(alice.recorded_events_count(), 3);
    assert_eq!(bob.recorded_events_count(), 2);
    assert_eq!(alice.scoped_message_count(), 3);
    assert_eq!(bob.scoped_message_count(), 2);

    // Sync
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || alice.store_count() == 5 && bob.store_count() == 5,
        Duration::from_secs(15),
        "both peers should have 5 events",
    ).await;

    drop(sync);

    // After sync: store has all events, messages has all events
    assert_eq!(alice.store_count(), 5);
    assert_eq!(bob.store_count(), 5);
    assert_eq!(alice.message_count(), 5);
    assert_eq!(bob.message_count(), 5);

    // recorded_events: local creates + received via sync
    // Alice created 3 locally, received 2 via sync = 5
    // Bob created 2 locally, received 3 via sync = 5
    assert_eq!(alice.recorded_events_count(), 5);
    assert_eq!(bob.recorded_events_count(), 5);

    // scoped_message_count matches total (all recorded by this peer)
    assert_eq!(alice.scoped_message_count(), 5);
    assert_eq!(bob.scoped_message_count(), 5);
}

#[tokio::test]
async fn test_recorded_at_monotonicity() {
    let channel = test_channel();
    let alice = Peer::new("alice", channel);
    let bob = Peer::new("bob", channel);

    // Alice creates messages with small delays to ensure different created_at
    alice.create_message("first");
    std::thread::sleep(Duration::from_millis(10));
    alice.create_message("second");
    std::thread::sleep(Duration::from_millis(10));
    alice.create_message("third");

    // Sync to Bob — Bob's recorded_at should use local wall clock, not event created_at
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || bob.store_count() == 3,
        Duration::from_secs(15),
        "bob should have 3 events",
    ).await;

    drop(sync);

    // Verify recorded_at is monotonically non-decreasing for each peer
    for peer in [&alice, &bob] {
        let db = open_connection(&peer.db_path).expect("open db");
        let timestamps: Vec<i64> = db
            .prepare("SELECT recorded_at FROM recorded_events WHERE peer_id = ?1 ORDER BY id")
            .unwrap()
            .query_map(rusqlite::params![&peer.identity], |row| row.get(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert!(timestamps.len() >= 3, "expected >= 3 recorded events for {}", peer.name);

        for window in timestamps.windows(2) {
            assert!(
                window[1] >= window[0],
                "recorded_at not monotonic for {}: {} < {}",
                peer.name,
                window[1],
                window[0],
            );
        }
    }

    // Bob's recorded_at for received events should be >= Alice's local create times
    // (since Bob received them after Alice created them)
    let alice_db = open_connection(&alice.db_path).expect("open alice db");
    let alice_max_recorded: i64 = alice_db
        .query_row(
            "SELECT MAX(recorded_at) FROM recorded_events WHERE peer_id = ?1",
            rusqlite::params![&alice.identity],
            |row| row.get(0),
        )
        .unwrap();

    let bob_db = open_connection(&bob.db_path).expect("open bob db");
    let bob_min_recv: i64 = bob_db
        .query_row(
            "SELECT MIN(recorded_at) FROM recorded_events WHERE peer_id = ?1 AND source = 'quic_recv'",
            rusqlite::params![&bob.identity],
            |row| row.get(0),
        )
        .unwrap();

    assert!(
        bob_min_recv >= alice_max_recorded,
        "Bob's earliest receive recorded_at ({}) should be >= Alice's latest create recorded_at ({})",
        bob_min_recv,
        alice_max_recorded,
    );
}

#[tokio::test]
async fn test_cross_workspace_isolation() {
    // Two independent workspace sets:
    // Set A: peerA1 + peerA2 (sync with each other)
    // Set B: peerB1 + peerB2 (sync with each other)
    // Verify no cross-set contamination.
    let mut channel_a = [0u8; 32];
    channel_a[0..6].copy_from_slice(b"workA\0");
    let mut channel_b = [0u8; 32];
    channel_b[0..6].copy_from_slice(b"workB\0");

    let peer_a1 = Peer::new("peerA1", channel_a);
    let peer_a2 = Peer::new("peerA2", channel_a);
    let peer_b1 = Peer::new("peerB1", channel_b);
    let peer_b2 = Peer::new("peerB2", channel_b);

    // Create messages in each workspace
    peer_a1.batch_create_messages(5);
    peer_a2.batch_create_messages(3);
    peer_b1.batch_create_messages(4);
    peer_b2.batch_create_messages(2);

    // Sync workspace A peers
    let sync_a = start_peers(&peer_a1, &peer_a2);
    assert_eventually(
        || peer_a1.store_count() == 8 && peer_a2.store_count() == 8,
        Duration::from_secs(15),
        "workspace A peers should converge to 8 events",
    ).await;
    drop(sync_a);

    // Sync workspace B peers
    let sync_b = start_peers(&peer_b1, &peer_b2);
    assert_eventually(
        || peer_b1.store_count() == 6 && peer_b2.store_count() == 6,
        Duration::from_secs(15),
        "workspace B peers should converge to 6 events",
    ).await;
    drop(sync_b);

    // Verify store counts: each workspace has its own events only
    assert_eq!(peer_a1.store_count(), 8);
    assert_eq!(peer_a2.store_count(), 8);
    assert_eq!(peer_b1.store_count(), 6);
    assert_eq!(peer_b2.store_count(), 6);

    // Verify recorded_events scoping: no cross-workspace rows
    // A peers should have 8 recorded_events each (5 local + 3 from sync, or 3 local + 5 from sync)
    assert_eq!(peer_a1.recorded_events_count(), 8);
    assert_eq!(peer_a2.recorded_events_count(), 8);
    assert_eq!(peer_b1.recorded_events_count(), 6);
    assert_eq!(peer_b2.recorded_events_count(), 6);

    // Verify scoped messages: each peer sees only its workspace's messages
    assert_eq!(peer_a1.scoped_message_count(), 8);
    assert_eq!(peer_a2.scoped_message_count(), 8);
    assert_eq!(peer_b1.scoped_message_count(), 6);
    assert_eq!(peer_b2.scoped_message_count(), 6);

    // Cross-check: A peers have zero B events in their recorded_events
    let a1_db = open_connection(&peer_a1.db_path).expect("open a1 db");
    let a1_has_b_events: i64 = a1_db.query_row(
        "SELECT COUNT(*) FROM recorded_events WHERE peer_id IN (?1, ?2)",
        rusqlite::params![&peer_b1.identity, &peer_b2.identity],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(a1_has_b_events, 0, "peerA1 should have no events from workspace B");

    let b1_db = open_connection(&peer_b1.db_path).expect("open b1 db");
    let b1_has_a_events: i64 = b1_db.query_row(
        "SELECT COUNT(*) FROM recorded_events WHERE peer_id IN (?1, ?2)",
        rusqlite::params![&peer_a1.identity, &peer_a2.identity],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(b1_has_a_events, 0, "peerB1 should have no events from workspace A");
}

#[tokio::test]
async fn test_sync_50k() {
    let channel = test_channel();
    let alice = Peer::new("alice", channel);
    let bob = Peer::new("bob", channel);

    let gen_start = Instant::now();
    alice.batch_create_messages(50_000);
    let gen_secs = gen_start.elapsed().as_secs_f64();
    eprintln!("Generated 50k events in {:.2}s", gen_secs);

    let metrics = sync_until_converged(
        &alice, &bob, 50_000, Duration::from_secs(300),
    ).await;

    eprintln!("50k sync: {}", metrics);

    assert_eq!(alice.store_count(), 50_000);
    assert_eq!(bob.store_count(), 50_000);
}
