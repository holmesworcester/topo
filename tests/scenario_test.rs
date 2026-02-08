use std::sync::Arc;
use std::time::{Duration, Instant};
use poc_7::testutil::{Peer, start_peers, assert_eventually, sync_until_converged, verify_projection_invariants};
use poc_7::crypto::{event_id_to_base64, event_id_from_base64};
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

    // Wait for projection queue to drain (batch_writer projects asynchronously via project_queue)
    assert_eventually(
        || bob.message_count() == 10_000,
        Duration::from_secs(30),
        &format!("bob projection to complete (bob.message_count={})", bob.message_count()),
    ).await;
    assert_eq!(alice.message_count(), 10_000);
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

    // Alice: 2 messages, 0 reactions; Bob: 2 events stored but reactions blocked
    // (Bob doesn't have Alice's messages yet, so reactions can't project)
    assert_eq!(alice.store_count(), 2);
    assert_eq!(bob.store_count(), 2);
    assert_eq!(alice.message_count(), 2);
    assert_eq!(bob.reaction_count(), 0); // blocked until targets arrive

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

    // Wait for projection queue to drain
    assert_eventually(
        || bob.message_count() == 50_000,
        Duration::from_secs(120),
        &format!("bob projection to complete (bob.message_count={})", bob.message_count()),
    ).await;
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

/// Test out-of-order reaction sync: Bob creates a reaction targeting Alice's message,
/// then syncs. The reaction arrives blocked, and auto-projects once the message arrives.
#[tokio::test]
async fn test_out_of_order_reaction_sync() {
    let channel = test_channel();
    let alice = Peer::new("alice", channel);
    let bob = Peer::new("bob", channel);

    // Alice creates a message
    let msg_id = alice.create_message("Hello from Alice");

    // Bob creates a reaction targeting Alice's message (Bob doesn't have the message yet)
    bob.create_reaction(&msg_id, "\u{1f44d}");

    // Bob: reaction is stored but blocked (target not in his DB)
    assert_eq!(bob.store_count(), 1);
    assert_eq!(bob.reaction_count(), 0); // blocked

    // Alice has the message
    assert_eq!(alice.store_count(), 1);
    assert_eq!(alice.message_count(), 1);

    // Sync — both get each other's events
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || alice.store_count() == 2 && bob.store_count() == 2,
        Duration::from_secs(15),
        "both peers should have 2 events",
    ).await;

    drop(sync);

    // After sync: Bob now has the message, so the reaction should be auto-projected
    assert_eq!(bob.message_count(), 1);
    assert_eq!(bob.reaction_count(), 1); // auto-unblocked

    // Alice received the reaction and has the message, so she can project it too
    assert_eq!(alice.message_count(), 1);
    assert_eq!(alice.reaction_count(), 1);

    // Verify valid_events counts
    let bob_db = open_connection(&bob.db_path).expect("open bob db");
    let bob_valid: i64 = bob_db.query_row(
        "SELECT COUNT(*) FROM valid_events WHERE peer_id = ?1",
        rusqlite::params![&bob.identity],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(bob_valid, 2, "Bob should have 2 valid events");

    verify_projection_invariants(&alice);
    verify_projection_invariants(&bob);
}

/// Test that multiple reactions targeting different messages all resolve correctly
/// when the messages arrive via sync.
#[tokio::test]
async fn test_multi_dep_blocking_sync() {
    let channel = test_channel();
    let alice = Peer::new("alice", channel);
    let bob = Peer::new("bob", channel);

    // Alice creates 3 messages
    let msg1 = alice.create_message("First");
    let msg2 = alice.create_message("Second");
    let msg3 = alice.create_message("Third");

    // Bob creates reactions targeting all 3 (none of which are in his DB)
    bob.create_reaction(&msg1, "\u{1f44d}");
    bob.create_reaction(&msg2, "\u{2764}\u{fe0f}");
    bob.create_reaction(&msg3, "\u{1f525}");

    // Bob: 3 events stored but all blocked
    assert_eq!(bob.store_count(), 3);
    assert_eq!(bob.reaction_count(), 0);

    // Sync
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || alice.store_count() == 6 && bob.store_count() == 6,
        Duration::from_secs(15),
        "both peers should have 6 events (3 messages + 3 reactions)",
    ).await;

    drop(sync);

    // All reactions should be unblocked and projected
    assert_eq!(alice.message_count(), 3);
    assert_eq!(bob.message_count(), 3);
    assert_eq!(alice.reaction_count(), 3);
    assert_eq!(bob.reaction_count(), 3);

    // Verify no remaining blocked deps
    let bob_db = open_connection(&bob.db_path).expect("open bob db");
    let blocked: i64 = bob_db.query_row(
        "SELECT COUNT(*) FROM blocked_event_deps WHERE peer_id = ?1",
        rusqlite::params![&bob.identity],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(blocked, 0, "no remaining blocked deps after sync");

    verify_projection_invariants(&alice);
    verify_projection_invariants(&bob);
}

/// Integration test: Alice creates a PeerKey + SignedMemo, Bob syncs, both valid.
#[tokio::test]
async fn test_signed_event_sync() {
    use ed25519_dalek::SigningKey;

    let channel = test_channel();
    let alice = Peer::new("alice", channel);
    let bob = Peer::new("bob", channel);

    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let public_key = signing_key.verifying_key().to_bytes();

    // Alice creates PeerKey + SignedMemo
    let pk_eid = alice.create_peer_key(public_key);
    let _memo_eid = alice.create_signed_memo(&pk_eid, &signing_key, "Hello signed world");

    assert_eq!(alice.store_count(), 2);
    assert_eq!(alice.peer_key_count(), 1);
    assert_eq!(alice.signed_memo_count(), 1);

    // Sync to Bob
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || bob.store_count() == 2,
        Duration::from_secs(15),
        "bob should have 2 events (PeerKey + SignedMemo)",
    ).await;

    drop(sync);

    // Both should have valid projections
    assert_eq!(bob.peer_key_count(), 1);
    assert_eq!(bob.signed_memo_count(), 1);

    verify_projection_invariants(&alice);
    verify_projection_invariants(&bob);
}

/// Integration test: Bob gets signed memo before signer key, auto-unblocks after sync.
#[tokio::test]
async fn test_signed_event_out_of_order_sync() {
    use ed25519_dalek::SigningKey;

    let channel = test_channel();
    let alice = Peer::new("alice", channel);
    let bob = Peer::new("bob", channel);

    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let public_key = signing_key.verifying_key().to_bytes();

    // Alice creates PeerKey + SignedMemo + a message
    let pk_eid = alice.create_peer_key(public_key);
    let _memo_eid = alice.create_signed_memo(&pk_eid, &signing_key, "Out of order memo");
    alice.create_message("Normal message");

    // Bob creates a message too
    bob.create_message("Bob's message");

    assert_eq!(alice.store_count(), 3); // pk, memo, msg
    assert_eq!(bob.store_count(), 1);

    // Sync
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || alice.store_count() == 4 && bob.store_count() == 4,
        Duration::from_secs(15),
        "both peers should have 4 events",
    ).await;

    drop(sync);

    // Bob should have auto-unblocked the signed memo
    assert_eq!(bob.peer_key_count(), 1);
    assert_eq!(bob.signed_memo_count(), 1);
    assert_eq!(bob.message_count(), 2);

    // No remaining blocked deps
    let bob_db = open_connection(&bob.db_path).expect("open bob db");
    let blocked: i64 = bob_db.query_row(
        "SELECT COUNT(*) FROM blocked_event_deps WHERE peer_id = ?1",
        rusqlite::params![&bob.identity],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(blocked, 0, "no remaining blocked deps after sync");

    verify_projection_invariants(&alice);
    verify_projection_invariants(&bob);
}

/// Integration test: wrong-key memo rejected on remote peer.
#[tokio::test]
async fn test_invalid_signature_rejected_after_sync() {
    use ed25519_dalek::SigningKey;
    use poc_7::crypto::event_id_to_base64;

    let channel = test_channel();
    let alice = Peer::new("alice", channel);
    let bob = Peer::new("bob", channel);

    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let wrong_key = SigningKey::generate(&mut rng);
    let public_key = signing_key.verifying_key().to_bytes();

    // Alice creates a PeerKey with signing_key's public key
    let pk_eid = alice.create_peer_key(public_key);

    // Alice creates a signed memo but signs with the WRONG key (simulating corruption)
    // We need to do this manually since create_signed_memo uses proper signing
    {
        use poc_7::events::{SignedMemoEvent, ParsedEvent, encode_event};
        use poc_7::projection::signer::sign_event_bytes;
        use poc_7::crypto::hash_event;

        let db = open_connection(&alice.db_path).expect("open alice db");
        let memo = ParsedEvent::SignedMemo(SignedMemoEvent {
            created_at_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64,
            signed_by: pk_eid,
            signer_type: 0,
            content: "bad signature memo".to_string(),
            signature: [0u8; 64],
        });
        let mut blob = encode_event(&memo).unwrap();

        // Sign with wrong key
        let sig_len = 64;
        let blob_len = blob.len();
        let signing_bytes = &blob[..blob_len - sig_len];
        let sig = sign_event_bytes(&wrong_key, signing_bytes);
        blob[blob_len - sig_len..].copy_from_slice(&sig);

        // Store directly (bypassing create_signed_event_sync validation)
        let event_id = hash_event(&blob);
        let event_id_b64 = event_id_to_base64(&event_id);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;

        db.execute(
            "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, ?2, ?3, 'shared', ?4, ?5)",
            rusqlite::params![&event_id_b64, "signed_memo", &blob, now_ms, now_ms],
        ).unwrap();
        db.execute(
            "INSERT OR IGNORE INTO neg_items (ts, id) VALUES (?1, ?2)",
            rusqlite::params![now_ms, event_id.as_slice()],
        ).unwrap();
        db.execute(
            "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source)
             VALUES (?1, ?2, ?3, 'local_create')",
            rusqlite::params![&alice.identity, &event_id_b64, now_ms],
        ).unwrap();
        // Don't project — it would be rejected. The blob will sync via negentropy.
    }

    // Alice has 2 events: PeerKey + the bad-sig memo
    assert_eq!(alice.store_count(), 2);

    // Sync to Bob
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || bob.store_count() == 2,
        Duration::from_secs(15),
        "bob should have 2 events (PeerKey + bad-sig memo) in store",
    ).await;

    drop(sync);

    // Bob should have the PeerKey projected but NOT the bad-sig memo
    assert_eq!(bob.peer_key_count(), 1);
    assert_eq!(bob.signed_memo_count(), 0, "bad-signature memo should be rejected, not projected");
}

/// Integration test: verify valid_events are tenant-scoped after sync.
/// Alice creates message + reaction, syncs to Bob. Both converge to 2 events.
/// valid_events are per-tenant, and projection invariants hold.
#[tokio::test]
async fn test_cross_tenant_dep_scoping_after_sync() {
    let channel = test_channel();
    let alice = Peer::new("alice", channel);
    let bob = Peer::new("bob", channel);

    // Alice creates a message and a reaction targeting it
    let msg_id = alice.create_message("Cross-tenant scoping test");
    alice.create_reaction(&msg_id, "\u{2705}");

    assert_eq!(alice.store_count(), 2);
    assert_eq!(alice.message_count(), 1);
    assert_eq!(alice.reaction_count(), 1);

    // Sync to Bob
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || alice.store_count() == 2 && bob.store_count() == 2,
        Duration::from_secs(15),
        "both peers should have 2 events (message + reaction)",
    ).await;

    drop(sync);

    // Both have projected correctly
    assert_eq!(bob.message_count(), 1);
    assert_eq!(bob.reaction_count(), 1);

    // Verify valid_events are tenant-scoped: each peer has its own valid_events rows
    let alice_db = open_connection(&alice.db_path).expect("open alice db");
    let bob_db = open_connection(&bob.db_path).expect("open bob db");

    let alice_valid: i64 = alice_db.query_row(
        "SELECT COUNT(*) FROM valid_events WHERE peer_id = ?1",
        rusqlite::params![&alice.identity],
        |row| row.get(0),
    ).unwrap();
    let bob_valid: i64 = bob_db.query_row(
        "SELECT COUNT(*) FROM valid_events WHERE peer_id = ?1",
        rusqlite::params![&bob.identity],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(alice_valid, 2, "Alice should have 2 valid_events");
    assert_eq!(bob_valid, 2, "Bob should have 2 valid_events");

    // Run projection invariants for both
    verify_projection_invariants(&alice);
    verify_projection_invariants(&bob);
}

/// Integration test: PSK encrypted message sync. Both peers share the same key event
/// (out-of-band distribution). SecretKey events are local-only (share_scope=Local)
/// and do NOT sync via negentropy.
#[tokio::test]
async fn test_encrypted_event_sync() {
    use poc_7::projection::pipeline::project_one;

    let channel = test_channel();
    let alice = Peer::new("alice", channel);
    let bob = Peer::new("bob", channel);

    // Alice creates a secret key + encrypted message
    let key_bytes: [u8; 32] = rand::random();
    let sk_eid = alice.create_secret_key(key_bytes);
    let _enc_eid = alice.create_encrypted_message(&sk_eid, "Hello encrypted world");

    assert_eq!(alice.store_count(), 2);
    assert_eq!(alice.secret_key_count(), 1);
    assert_eq!(alice.scoped_message_count(), 1);

    // Simulate out-of-band PSK distribution: copy Alice's SecretKey event to Bob
    {
        let alice_db = open_connection(&alice.db_path).expect("open alice db");
        let bob_db = open_connection(&bob.db_path).expect("open bob db");
        let sk_b64 = event_id_to_base64(&sk_eid);
        let blob: Vec<u8> = alice_db.query_row(
            "SELECT blob FROM events WHERE event_id = ?1", rusqlite::params![&sk_b64], |row| row.get(0),
        ).unwrap();
        let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
        bob_db.execute(
            "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, ?2, ?3, 'local', ?4, ?5)",
            rusqlite::params![&sk_b64, "secret_key", &blob, now_ms, now_ms],
        ).unwrap();
        bob_db.execute(
            "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source)
             VALUES (?1, ?2, ?3, 'psk_import')",
            rusqlite::params![&bob.identity, &sk_b64, now_ms],
        ).unwrap();
        let _ = project_one(&bob_db, &bob.identity, &sk_eid);
    }
    assert_eq!(bob.store_count(), 1); // just the PSK
    assert_eq!(bob.secret_key_count(), 1);

    // Sync — only the encrypted event (shared) syncs
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || bob.store_count() == 2,
        Duration::from_secs(15),
        "bob should have 2 events (imported SecretKey + synced Encrypted)",
    ).await;

    drop(sync);

    // Bob should have projected the decrypted inner message
    assert_eq!(bob.secret_key_count(), 1);
    assert_eq!(bob.scoped_message_count(), 1);

    verify_projection_invariants(&alice);
    verify_projection_invariants(&bob);
}

/// Integration test: PSK encrypted event sync with mixed event types.
/// SecretKey is local-only — distributed out-of-band to Bob.
#[tokio::test]
async fn test_encrypted_out_of_order_sync() {
    use poc_7::projection::pipeline::project_one;

    let channel = test_channel();
    let alice = Peer::new("alice", channel);
    let bob = Peer::new("bob", channel);

    // Alice creates the key + encrypted message + normal message
    let key_bytes: [u8; 32] = rand::random();
    let sk_eid = alice.create_secret_key(key_bytes);
    let _enc_eid = alice.create_encrypted_message(&sk_eid, "Out of order encrypted");
    alice.create_message("Normal message");

    // Bob creates a message too
    bob.create_message("Bob's message");

    // Simulate out-of-band PSK distribution: copy Alice's SecretKey event to Bob
    {
        let alice_db = open_connection(&alice.db_path).expect("open alice db");
        let bob_db = open_connection(&bob.db_path).expect("open bob db");
        let sk_b64 = event_id_to_base64(&sk_eid);
        let blob: Vec<u8> = alice_db.query_row(
            "SELECT blob FROM events WHERE event_id = ?1", rusqlite::params![&sk_b64], |row| row.get(0),
        ).unwrap();
        let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
        bob_db.execute(
            "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, ?2, ?3, 'local', ?4, ?5)",
            rusqlite::params![&sk_b64, "secret_key", &blob, now_ms, now_ms],
        ).unwrap();
        bob_db.execute(
            "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source)
             VALUES (?1, ?2, ?3, 'psk_import')",
            rusqlite::params![&bob.identity, &sk_b64, now_ms],
        ).unwrap();
        let _ = project_one(&bob_db, &bob.identity, &sk_eid);
    }

    // Alice: 3 (sk, encrypted, message), Bob: 2 (imported sk, own message)
    assert_eq!(alice.store_count(), 3);
    assert_eq!(bob.store_count(), 2);

    // Sync — only shared events sync (encrypted + messages), not secret keys
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || alice.store_count() == 4 && bob.store_count() == 4,
        Duration::from_secs(15),
        "both peers should have 4 events (local sk + synced shared events)",
    ).await;

    drop(sync);

    // Both should have decrypted the encrypted message
    assert_eq!(bob.secret_key_count(), 1);
    assert_eq!(bob.scoped_message_count(), 3); // encrypted inner + normal + bob's
    assert_eq!(alice.scoped_message_count(), 3);

    // No remaining blocked deps
    let bob_db = open_connection(&bob.db_path).expect("open bob db");
    let blocked: i64 = bob_db.query_row(
        "SELECT COUNT(*) FROM blocked_event_deps WHERE peer_id = ?1",
        rusqlite::params![&bob.identity],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(blocked, 0, "no remaining blocked deps after sync");

    verify_projection_invariants(&alice);
    verify_projection_invariants(&bob);
}

/// Integration test: mixed cleartext + encrypted events → verify_projection_invariants.
#[tokio::test]
async fn test_encrypted_replay_invariants() {
    let channel = test_channel();
    let alice = Peer::new("alice", channel);

    // Create a mix of cleartext and encrypted events
    let key_bytes: [u8; 32] = rand::random();
    let sk_eid = alice.create_secret_key(key_bytes);

    alice.create_message("Cleartext 1");
    alice.create_encrypted_message(&sk_eid, "Encrypted 1");
    alice.create_message("Cleartext 2");
    alice.create_encrypted_message(&sk_eid, "Encrypted 2");

    // Verify counts
    assert_eq!(alice.store_count(), 5); // sk + 2 cleartext + 2 encrypted
    assert_eq!(alice.secret_key_count(), 1);
    assert_eq!(alice.scoped_message_count(), 4); // 2 cleartext + 2 encrypted inner messages

    // Run invariant checks (forward, double, reverse)
    verify_projection_invariants(&alice);
}

/// Integration test: simulate crash recovery by manually enqueuing events into project_queue,
/// then calling recovery (recover_expired + drain). All events should be projected.
#[tokio::test]
async fn test_project_queue_crash_recovery() {
    use poc_7::db::project_queue::ProjectQueue;
    use poc_7::projection::pipeline::project_one;

    let channel = test_channel();
    let alice = Peer::new("alice", channel);

    // Create messages via create_event_sync (bypasses queue, projects inline)
    let msg1 = alice.create_message("Recovery message 1");
    let msg2 = alice.create_message("Recovery message 2");
    let msg3 = alice.create_message("Recovery message 3");

    assert_eq!(alice.store_count(), 3);
    assert_eq!(alice.scoped_message_count(), 3);

    // Now simulate a crash scenario: clear projection state and re-enqueue to project_queue
    let db = open_connection(&alice.db_path).expect("open db");
    db.execute("DELETE FROM messages WHERE recorded_by = ?1", rusqlite::params![&alice.identity]).unwrap();
    db.execute("DELETE FROM valid_events WHERE peer_id = ?1", rusqlite::params![&alice.identity]).unwrap();
    db.execute("DELETE FROM blocked_event_deps WHERE peer_id = ?1", rusqlite::params![&alice.identity]).unwrap();
    db.execute("DELETE FROM rejected_events WHERE peer_id = ?1", rusqlite::params![&alice.identity]).unwrap();

    // Enqueue the events into project_queue (simulating what batch_writer does)
    let pq = ProjectQueue::new(&db);
    for eid in &[msg1, msg2, msg3] {
        let eid_b64 = event_id_to_base64(eid);
        pq.enqueue(&alice.identity, &eid_b64).unwrap();
    }

    // Verify nothing projected yet
    let msg_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
        rusqlite::params![&alice.identity], |row| row.get(0),
    ).unwrap();
    assert_eq!(msg_count, 0);

    // Run recovery: recover expired leases + drain
    let recovered = pq.recover_expired().unwrap();
    // Items were just enqueued (no lease set), so nothing to recover
    assert_eq!(recovered, 0);

    let drained = pq.drain(&alice.identity, |conn, eid_b64| {
        if let Some(eid) = event_id_from_base64(eid_b64) {
            project_one(conn, &alice.identity, &eid)
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        }
        Ok(())
    }).unwrap();
    assert_eq!(drained, 3);

    // Verify all messages projected
    let msg_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
        rusqlite::params![&alice.identity], |row| row.get(0),
    ).unwrap();
    assert_eq!(msg_count, 3);

    // Verify valid_events
    let valid_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM valid_events WHERE peer_id = ?1",
        rusqlite::params![&alice.identity], |row| row.get(0),
    ).unwrap();
    assert_eq!(valid_count, 3);

    // Queue should be empty
    assert_eq!(pq.count_pending(&alice.identity).unwrap(), 0);
}

/// Integration test: verify project_queue drain works end-to-end with create_event_sync events.
#[tokio::test]
async fn test_project_queue_drain_after_batch() {
    use poc_7::db::project_queue::ProjectQueue;
    use poc_7::projection::pipeline::project_one;

    let channel = test_channel();
    let alice = Peer::new("alice", channel);

    // Create events (projected inline by create_event_sync)
    alice.batch_create_messages(5);
    assert_eq!(alice.store_count(), 5);
    assert_eq!(alice.scoped_message_count(), 5);

    // Enqueue to project_queue — guard should prevent re-enqueue (already valid)
    let db = open_connection(&alice.db_path).expect("open db");
    let pq = ProjectQueue::new(&db);

    let event_ids: Vec<String> = db.prepare("SELECT event_id FROM events")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let refs: Vec<&str> = event_ids.iter().map(|s| s.as_str()).collect();
    let inserted = pq.enqueue_batch(&alice.identity, &refs).unwrap();
    assert_eq!(inserted, 0, "guard should prevent re-enqueue of already-valid events");

    // Drain should process nothing (queue empty)
    let drained = pq.drain(&alice.identity, |conn, eid_b64| {
        if let Some(eid) = event_id_from_base64(eid_b64) {
            project_one(conn, &alice.identity, &eid)
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        }
        Ok(())
    }).unwrap();
    assert_eq!(drained, 0);

    // State unchanged
    assert_eq!(alice.scoped_message_count(), 5);
}

/// Integration test: egress_queue lifecycle — enqueue, claim, send, cleanup.
#[tokio::test]
async fn test_egress_queue_lifecycle() {
    use poc_7::db::egress_queue::EgressQueue;

    let channel = test_channel();
    let alice = Peer::new("alice", channel);

    // Create some events to get event IDs
    let msg1 = alice.create_message("Egress msg 1");
    let msg2 = alice.create_message("Egress msg 2");
    let msg3 = alice.create_message("Egress msg 3");

    let db = open_connection(&alice.db_path).expect("open db");
    let eq = EgressQueue::new(&db);

    let conn_id = "test-connection-1";

    // Enqueue events
    let enqueued = eq.enqueue_events(conn_id, &[msg1, msg2, msg3]).unwrap();
    assert_eq!(enqueued, 3);

    // Count pending
    let pending = eq.count_pending(conn_id).unwrap();
    assert_eq!(pending, 3);

    // Claim batch
    let claimed = eq.claim_batch(conn_id, 10, 30_000).unwrap();
    assert_eq!(claimed.len(), 3);

    // Mark sent
    let rowids: Vec<i64> = claimed.iter().map(|(rowid, _)| *rowid).collect();
    eq.mark_sent(&rowids).unwrap();

    // Count pending after sending
    let pending = eq.count_pending(conn_id).unwrap();
    assert_eq!(pending, 0);

    // Cleanup sent with large threshold — recent items should NOT be purged
    let purged = eq.cleanup_sent(300_000).unwrap();
    assert_eq!(purged, 0);

    // Backdate and cleanup with smaller threshold
    db.execute("UPDATE egress_queue SET sent_at = sent_at - 600000", []).unwrap();
    let purged = eq.cleanup_sent(300_000).unwrap();
    assert_eq!(purged, 3);

    // Re-enqueue should work (dedup index only blocks unsent)
    let enqueued = eq.enqueue_events(conn_id, &[msg1, msg2]).unwrap();
    assert_eq!(enqueued, 2);

    // Clear connection
    eq.clear_connection(conn_id).unwrap();
    let pending = eq.count_pending(conn_id).unwrap();
    assert_eq!(pending, 0);
}

/// Test gap 1: Local-only events (e.g. SecretKey with share_scope=Local) must NOT appear
/// in neg_items and must NOT be sent to peers via the egress send path.
#[tokio::test]
async fn test_local_only_events_excluded_from_neg_items() {
    use poc_7::db::store::Store;

    let channel = test_channel();
    let alice = Peer::new("alice", channel);

    // Create a shared message and a local-only secret key
    let _msg_eid = alice.create_message("Shared message");
    let key_bytes: [u8; 32] = rand::random();
    let sk_eid = alice.create_secret_key(key_bytes);

    // Both events should be in the events table
    assert_eq!(alice.store_count(), 2);

    // Verify the secret key is stored with share_scope=local
    let db = open_connection(&alice.db_path).expect("open db");
    let sk_eid_b64 = event_id_to_base64(&sk_eid);
    let share_scope: String = db.query_row(
        "SELECT share_scope FROM events WHERE event_id = ?1",
        rusqlite::params![&sk_eid_b64],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(share_scope, "local", "secret key should have local share_scope");

    // Verify neg_items does NOT contain the secret key's event_id
    let sk_in_neg: i64 = db.query_row(
        "SELECT COUNT(*) FROM neg_items WHERE id = ?1",
        rusqlite::params![sk_eid.as_slice()],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(sk_in_neg, 0, "local-only event should not be in neg_items");

    // Verify the shared message IS in neg_items
    let total_neg: i64 = db.query_row(
        "SELECT COUNT(*) FROM neg_items",
        [],
        |row| row.get(0),
    ).unwrap();
    assert!(total_neg >= 1, "shared events should be in neg_items");

    // Verify get_shared returns None for local-only events (defense-in-depth on send path)
    let store = Store::new(&db);
    assert!(
        store.get_shared(&sk_eid).unwrap().is_none(),
        "get_shared should return None for local-only events"
    );
}

/// Test gap 2: Verify local-only events don't leak through sync to a peer.
#[tokio::test]
async fn test_local_only_events_not_synced_to_peer() {
    let channel = test_channel();
    let alice = Peer::new("alice", channel);
    let bob = Peer::new("bob", channel);

    // Alice creates a message (shared) + secret key (local)
    alice.create_message("Hello from Alice");
    let key_bytes: [u8; 32] = rand::random();
    alice.create_secret_key(key_bytes);

    assert_eq!(alice.store_count(), 2);

    // Sync
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || bob.store_count() >= 1,
        Duration::from_secs(15),
        "bob should receive at least the shared message",
    ).await;

    // Give extra time for any potential secret key to sync (it shouldn't)
    tokio::time::sleep(Duration::from_secs(2)).await;

    drop(sync);

    // Bob should only have the shared message, not the secret key
    assert_eq!(bob.store_count(), 1, "bob should only have the shared message, not the local-only secret key");
    assert_eq!(bob.secret_key_count(), 0, "bob should not have any secret keys from alice");
}

/// Test gap 3: project_queue drain callback error → item remains queued/retriable.
/// (Integration-level test complementing the unit test in project_queue.rs)
#[tokio::test]
async fn test_project_queue_drain_retries_on_failure() {
    use poc_7::db::project_queue::ProjectQueue;

    let channel = test_channel();
    let alice = Peer::new("alice", channel);

    // Create events to get valid event IDs in the events table
    let msg1 = alice.create_message("Recovery msg 1");
    let msg2 = alice.create_message("Recovery msg 2");
    let msg3 = alice.create_message("Recovery msg 3");
    let msg1_b64 = event_id_to_base64(&msg1);
    let msg2_b64 = event_id_to_base64(&msg2);
    let msg3_b64 = event_id_to_base64(&msg3);

    // Directly test the queue retry mechanism (not projection)
    let db = open_connection(&alice.db_path).expect("open db");
    let pq = ProjectQueue::new(&db);

    // Enqueue items directly (guard allows since they aren't already in project_queue)
    // First remove from valid_events so the enqueue guard doesn't block
    db.execute("DELETE FROM valid_events WHERE peer_id = ?1", rusqlite::params![&alice.identity]).unwrap();
    pq.enqueue(&alice.identity, &msg1_b64).unwrap();
    pq.enqueue(&alice.identity, &msg2_b64).unwrap();
    pq.enqueue(&alice.identity, &msg3_b64).unwrap();

    // Drain with a callback that fails for msg2 (without calling project_one to avoid cascade)
    let mut succeeded_items = Vec::new();
    let count = pq.drain(&alice.identity, |_conn, eid_b64| {
        if eid_b64 == msg2_b64 {
            return Err("simulated projection failure".into());
        }
        succeeded_items.push(eid_b64.to_string());
        Ok(())
    }).unwrap();

    // msg1 and msg3 should have succeeded, msg2 failed
    assert_eq!(count, 2, "two items should have been successfully drained");
    assert!(succeeded_items.contains(&msg1_b64));
    assert!(succeeded_items.contains(&msg3_b64));

    // msg2 should still be in project_queue with incremented attempts
    let remaining: i64 = db.query_row(
        "SELECT COUNT(*) FROM project_queue WHERE peer_id = ?1",
        rusqlite::params![&alice.identity], |row| row.get(0),
    ).unwrap();
    assert_eq!(remaining, 1, "only the failed item should remain in queue");

    let remaining_eid: String = db.query_row(
        "SELECT event_id FROM project_queue WHERE peer_id = ?1",
        rusqlite::params![&alice.identity], |row| row.get(0),
    ).unwrap();
    assert_eq!(remaining_eid, msg2_b64, "the remaining item should be msg2");

    let attempts: i64 = db.query_row(
        "SELECT attempts FROM project_queue WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![&alice.identity, &msg2_b64], |row| row.get(0),
    ).unwrap();
    assert!(attempts >= 1, "failed item should have retry attempts incremented");
}
