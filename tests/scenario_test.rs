use std::sync::Arc;
use std::time::{Duration, Instant};
use poc_7::testutil::{Peer, start_peers, assert_eventually, sync_until_converged, verify_projection_invariants};
use poc_7::transport::{
    AllowedPeers, create_client_endpoint, create_server_endpoint,
    extract_spki_fingerprint, load_or_generate_cert, peer_identity_from_connection,
};
use poc_7::identity::cert_paths_from_db;
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

    verify_projection_invariants(&alice);
    verify_projection_invariants(&bob);
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
    assert_eq!(alice.recorded_events_count(), 5);
    assert_eq!(bob.recorded_events_count(), 5);

    // scoped_message_count matches total (all recorded by this peer)
    assert_eq!(alice.scoped_message_count(), 5);
    assert_eq!(bob.scoped_message_count(), 5);

    verify_projection_invariants(&alice);
    verify_projection_invariants(&bob);
}

#[tokio::test]
async fn test_reaction_sync() {
    let channel = test_channel();
    let alice = Peer::new("alice", channel);
    let bob = Peer::new("bob", channel);

    // Alice creates messages, Bob adds reactions
    let msg1 = alice.create_message("Hello!");
    let msg2 = alice.create_message("World!");
    bob.create_reaction(&msg1, "\u{1f44d}");
    bob.create_reaction(&msg2, "\u{2764}\u{fe0f}");

    // Alice: 2 messages, 0 reactions; Bob: 0 messages, 2 reactions
    assert_eq!(alice.store_count(), 2);
    assert_eq!(bob.store_count(), 2);
    assert_eq!(alice.message_count(), 2);
    assert_eq!(bob.reaction_count(), 2);

    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || alice.store_count() == 4 && bob.store_count() == 4,
        Duration::from_secs(15),
        "both peers should have 4 events (2 messages + 2 reactions)",
    ).await;

    drop(sync);

    // Both should have 2 messages and 2 reactions projected
    assert_eq!(alice.message_count(), 2);
    assert_eq!(bob.message_count(), 2);
    assert_eq!(alice.reaction_count(), 2);
    assert_eq!(bob.reaction_count(), 2);

    verify_projection_invariants(&alice);
    verify_projection_invariants(&bob);
}

/// Stress test: high-volume bidirectional sync verifying exact event ID equality.
/// This checks the Done/DoneAck handshake prevents data loss at scale.
#[tokio::test]
async fn test_zero_loss_stress() {
    let channel = test_channel();
    let alice = Peer::new("alice", channel);
    let bob = Peer::new("bob", channel);

    alice.batch_create_messages(5_000);
    bob.batch_create_messages(5_000);

    let alice_ids_before = alice.store_ids();
    let bob_ids_before = bob.store_ids();
    assert_eq!(alice_ids_before.len(), 5_000);
    assert_eq!(bob_ids_before.len(), 5_000);

    let metrics = sync_until_converged(
        &alice, &bob, 10_000, Duration::from_secs(120),
    ).await;

    eprintln!("zero-loss stress: {}", metrics);

    let alice_ids = alice.store_ids();
    let bob_ids = bob.store_ids();

    // Exact set equality, not just counts
    assert_eq!(alice_ids.len(), 10_000, "alice store count mismatch");
    assert_eq!(bob_ids.len(), 10_000, "bob store count mismatch");
    assert_eq!(alice_ids, bob_ids, "event ID sets differ between peers");

    // Verify all original events survived
    for id in &alice_ids_before {
        assert!(alice_ids.contains(id), "alice lost own event {}", id);
        assert!(bob_ids.contains(id), "bob missing alice event {}", id);
    }
    for id in &bob_ids_before {
        assert!(alice_ids.contains(id), "alice missing bob event {}", id);
        assert!(bob_ids.contains(id), "bob lost own event {}", id);
    }
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

    // Cross-check: assert zero overlap in event IDs between workspace A and B events.
    // This is a stronger isolation proof than checking peer_id (which is always local).
    use std::collections::HashSet;

    let a1_db = open_connection(&peer_a1.db_path).expect("open a1 db");
    let a_event_ids: HashSet<String> = a1_db
        .prepare("SELECT event_id FROM events")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<HashSet<_>, _>>()
        .unwrap();

    let b1_db = open_connection(&peer_b1.db_path).expect("open b1 db");
    let b_event_ids: HashSet<String> = b1_db
        .prepare("SELECT event_id FROM events")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<HashSet<_>, _>>()
        .unwrap();

    let overlap: Vec<&String> = a_event_ids.intersection(&b_event_ids).collect();
    assert!(
        overlap.is_empty(),
        "workspace A and B should have zero overlapping event IDs, found {} shared: {:?}",
        overlap.len(),
        &overlap[..overlap.len().min(5)],
    );

    // Also verify message_ids don't overlap across workspaces
    let a_msg_ids: HashSet<String> = a1_db
        .prepare("SELECT message_id FROM messages")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<HashSet<_>, _>>()
        .unwrap();

    let b_msg_ids: HashSet<String> = b1_db
        .prepare("SELECT message_id FROM messages")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<HashSet<_>, _>>()
        .unwrap();

    let msg_overlap: Vec<&String> = a_msg_ids.intersection(&b_msg_ids).collect();
    assert!(
        msg_overlap.is_empty(),
        "workspace A and B should have zero overlapping message IDs, found {} shared",
        msg_overlap.len(),
    );
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

/// Integration test: verify peer_identity_from_connection returns the correct
/// SPKI fingerprint across a live QUIC mTLS handshake.
#[tokio::test]
async fn test_peer_identity_extraction_live_handshake() {
    let channel = test_channel();
    let alice = Peer::new("alice", channel);
    let bob = Peer::new("bob", channel);

    let (cert_path_a, key_path_a) = cert_paths_from_db(&alice.db_path);
    let (cert_a, key_a) = load_or_generate_cert(&cert_path_a, &key_path_a).unwrap();
    let (cert_path_b, key_path_b) = cert_paths_from_db(&bob.db_path);
    let (cert_b, key_b) = load_or_generate_cert(&cert_path_b, &key_path_b).unwrap();

    let fp_a = extract_spki_fingerprint(cert_a.as_ref()).unwrap();
    let fp_b = extract_spki_fingerprint(cert_b.as_ref()).unwrap();
    let expected_a = hex::encode(fp_a);
    let expected_b = hex::encode(fp_b);

    let allowed_for_a = Arc::new(AllowedPeers::from_fingerprints(vec![fp_b]));
    let allowed_for_b = Arc::new(AllowedPeers::from_fingerprints(vec![fp_a]));

    let server_ep = create_server_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        cert_a, key_a, allowed_for_a,
    ).unwrap();
    let addr = server_ep.local_addr().unwrap();

    let client_ep = create_client_endpoint(
        "0.0.0.0:0".parse().unwrap(),
        cert_b, key_b, allowed_for_b,
    ).unwrap();

    // Client connects, server accepts
    let (client_conn, server_conn) = tokio::join!(
        async {
            client_ep.connect(addr, "localhost").unwrap().await.unwrap()
        },
        async {
            server_ep.accept().await.unwrap().await.unwrap()
        }
    );

    // Extract identities from live connections
    let client_sees_server = peer_identity_from_connection(&client_conn);
    let server_sees_client = peer_identity_from_connection(&server_conn);

    assert_eq!(
        client_sees_server.as_deref(), Some(expected_a.as_str()),
        "client should see server's (Alice's) fingerprint"
    );
    assert_eq!(
        server_sees_client.as_deref(), Some(expected_b.as_str()),
        "server should see client's (Bob's) fingerprint"
    );

    // Verify they match the Peer identities computed from DB
    assert_eq!(client_sees_server.unwrap(), alice.identity);
    assert_eq!(server_sees_client.unwrap(), bob.identity);
}
