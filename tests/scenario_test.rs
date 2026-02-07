use std::sync::Arc;
use std::time::{Duration, Instant};
use poc_7::testutil::{Peer, start_peers, assert_eventually, sync_until_converged, verify_projection_invariants};
use poc_7::crypto::event_id_to_base64;
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

/// Integration test: Alice creates PSK + encrypted message, both peers materialize PSK locally.
/// Only the encrypted event syncs; SecretKey (ShareScope::Local) does not.
#[tokio::test]
async fn test_encrypted_event_sync() {
    let channel = test_channel();
    let alice = Peer::new("alice", channel);
    let bob = Peer::new("bob", channel);

    // Both peers materialize the same PSK locally (deterministic)
    let key_bytes: [u8; 32] = rand::random();
    let fixed_ts = 1000000u64;
    let sk_eid = alice.create_secret_key_deterministic(key_bytes, fixed_ts);
    let _sk_eid_bob = bob.create_secret_key_deterministic(key_bytes, fixed_ts);

    // Alice creates an encrypted message using the shared PSK
    let _enc_eid = alice.create_encrypted_message(&sk_eid, "Hello encrypted world");

    // Alice: 2 events (SK + encrypted), Bob: 1 event (SK)
    assert_eq!(alice.store_count(), 2);
    assert_eq!(alice.secret_key_count(), 1);
    assert_eq!(alice.scoped_message_count(), 1);
    assert_eq!(bob.store_count(), 1);
    assert_eq!(bob.secret_key_count(), 1);

    // Sync: only encrypted event syncs (SK is local-only)
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || bob.store_count() == 2,
        Duration::from_secs(15),
        "bob should have 2 events (his own SK + synced encrypted)",
    ).await;

    drop(sync);

    // Bob should have projected: his own secret key + decrypted inner message
    assert_eq!(bob.secret_key_count(), 1);
    assert_eq!(bob.scoped_message_count(), 1);

    verify_projection_invariants(&alice);
    verify_projection_invariants(&bob);
}

/// Integration test: Both peers materialize PSK locally, encrypted event syncs, mixed with normal msgs.
#[tokio::test]
async fn test_encrypted_out_of_order_sync() {
    let channel = test_channel();
    let alice = Peer::new("alice", channel);
    let bob = Peer::new("bob", channel);

    // Both peers materialize the same PSK locally (deterministic)
    let key_bytes: [u8; 32] = rand::random();
    let fixed_ts = 2000000u64;
    let sk_eid = alice.create_secret_key_deterministic(key_bytes, fixed_ts);
    let _sk_eid_bob = bob.create_secret_key_deterministic(key_bytes, fixed_ts);

    // Alice creates encrypted message + normal message
    let _enc_eid = alice.create_encrypted_message(&sk_eid, "Out of order encrypted");
    alice.create_message("Normal message");

    // Bob creates a message too
    bob.create_message("Bob's message");

    // Alice: 3 events (SK + encrypted + msg), Bob: 2 events (SK + msg)
    assert_eq!(alice.store_count(), 3);
    assert_eq!(bob.store_count(), 2);

    // Sync: SK is local-only, only encrypted + normal messages sync
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || alice.store_count() == 4 && bob.store_count() == 4,
        Duration::from_secs(15),
        "both peers should have 4 events (SK + encrypted + 2 messages each)",
    ).await;

    drop(sync);

    // Bob should have projected the encrypted inner message
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

/// Gap 1: Verify SecretKey events (ShareScope::Local) are never sent to remote peers.
#[tokio::test]
async fn test_local_only_events_not_synced() {
    let channel = test_channel();
    let alice = Peer::new("alice", channel);
    let bob = Peer::new("bob", channel);

    // Both peers materialize the same PSK locally
    let key_bytes: [u8; 32] = rand::random();
    let fixed_ts = 3000000u64;
    let sk_eid = alice.create_secret_key_deterministic(key_bytes, fixed_ts);
    let sk_eid_bob = bob.create_secret_key_deterministic(key_bytes, fixed_ts);
    assert_eq!(sk_eid, sk_eid_bob, "deterministic PSK should produce same event_id");

    // Alice creates encrypted message + normal message
    let _enc_eid = alice.create_encrypted_message(&sk_eid, "Encrypted for local-only test");
    alice.create_message("Normal message from Alice");

    // Alice: 3 events (SK + encrypted + msg), Bob: 1 event (SK)
    assert_eq!(alice.store_count(), 3);
    assert_eq!(bob.store_count(), 1);

    // Alice's SK should NOT be in neg_items (local-only)
    assert_eq!(alice.neg_items_count(), 2, "Alice should have 2 neg_items (encrypted + msg, not SK)");
    assert_eq!(bob.neg_items_count(), 0, "Bob should have 0 neg_items (SK is local-only)");

    // Sync
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || bob.store_count() == 3,
        Duration::from_secs(15),
        "bob should have 3 events (his SK + synced encrypted + synced msg)",
    ).await;

    drop(sync);

    // Bob should NOT have received Alice's SK event — his store has his own SK
    // (both have same event_id since deterministic, so store_count is 3 not 4)
    assert_eq!(bob.secret_key_count(), 1);
    assert_eq!(bob.scoped_message_count(), 2); // encrypted inner + normal msg

    // Verify Alice's SK event_id IS in bob's events (because bob created his own copy)
    let sk_b64 = event_id_to_base64(&sk_eid);
    assert!(bob.has_event(&sk_b64), "bob should have the SK event (his own local copy)");

    verify_projection_invariants(&alice);
    verify_projection_invariants(&bob);
}

/// Gap 2: Two-set PSK isolation — mismatched PSKs cannot decrypt each other's messages.
#[tokio::test]
async fn test_psk_two_set_isolation() {
    let channel = test_channel();
    let alice = Peer::new("alice", channel);
    let bob = Peer::new("bob", channel);

    // Alice and Bob use DIFFERENT PSKs
    let key_a: [u8; 32] = rand::random();
    let key_b: [u8; 32] = rand::random();
    let sk_eid_alice = alice.create_secret_key(key_a);
    let _sk_eid_bob = bob.create_secret_key(key_b);

    // Alice encrypts with her key
    let _enc_eid = alice.create_encrypted_message(&sk_eid_alice, "Alice secret");

    // Alice also creates a normal message
    alice.create_message("Alice cleartext");

    // Alice: 3 events (SK + encrypted + msg), Bob: 1 event (SK)
    assert_eq!(alice.store_count(), 3);
    assert_eq!(bob.store_count(), 1);

    // Sync: encrypted event and normal msg sync to Bob
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || bob.store_count() == 3,
        Duration::from_secs(15),
        "bob should have 3 events (his SK + synced encrypted + synced msg)",
    ).await;

    drop(sync);

    // Bob should have the cleartext message projected
    // But the encrypted message should be REJECTED (wrong key) or blocked
    // Since Bob's SK has different key_bytes, the encrypted event references
    // Alice's SK event_id which Bob doesn't have locally → blocks on missing dep
    assert_eq!(bob.scoped_message_count(), 1, "bob should only see the cleartext message");

    // Verify the encrypted event is blocked (not projected into messages)
    let bob_db = open_connection(&bob.db_path).expect("open bob db");
    let blocked: i64 = bob_db.query_row(
        "SELECT COUNT(*) FROM blocked_event_deps WHERE peer_id = ?1",
        rusqlite::params![&bob.identity],
        |row| row.get(0),
    ).unwrap();
    assert!(blocked >= 1, "encrypted event should be blocked on missing key dep");
}

/// Gap 3: Encrypted inner event with unsupported signer_type rejects durably (not hard error).
#[tokio::test]
async fn test_encrypted_inner_unsupported_signer_rejects_durably() {
    use poc_7::events::{
        SignedMemoEvent, EncryptedEvent, ParsedEvent,
        encode_event, EVENT_TYPE_SIGNED_MEMO,
    };
    use poc_7::projection::encrypted::encrypt_event_blob;
    use poc_7::crypto::hash_event;
    use poc_7::projection::pipeline::project_one;

    let channel = test_channel();
    let alice = Peer::new("alice", channel);

    // Create and project a secret key
    let key_bytes: [u8; 32] = rand::random();
    let sk_eid = alice.create_secret_key(key_bytes);

    // Create a PeerKey so it can satisfy the signed_by dep check
    let dummy_pk = alice.create_peer_key([99u8; 32]);

    // Create an inner SignedMemo with signer_type=255 (unsupported)
    // signed_by references the PeerKey (so dep check passes), but signer_type is invalid
    let inner = ParsedEvent::SignedMemo(SignedMemoEvent {
        created_at_ms: 999999u64,
        signed_by: dummy_pk,
        signer_type: 255, // unsupported
        content: "bad signer type".to_string(),
        signature: [0u8; 64],
    });
    let inner_blob = encode_event(&inner).unwrap();

    // Encrypt it
    let (nonce, ciphertext, auth_tag) = encrypt_event_blob(&key_bytes, &inner_blob).unwrap();
    let wrapper = ParsedEvent::Encrypted(EncryptedEvent {
        created_at_ms: 999999u64,
        key_event_id: sk_eid,
        inner_type_code: EVENT_TYPE_SIGNED_MEMO,
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
    ).unwrap();
    db.execute(
        "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source)
         VALUES (?1, ?2, ?3, 'test')",
        rusqlite::params![&alice.identity, &enc_b64, ts],
    ).unwrap();

    // Project: should get Reject (not hard Err) because signer_type=255 is invalid
    let result = project_one(&db, &alice.identity, &enc_eid).unwrap();
    match result {
        poc_7::projection::decision::ProjectionDecision::Reject { reason } => {
            assert!(
                reason.contains("unsupported signer_type") || reason.contains("signer resolution invalid"),
                "unexpected rejection reason: {}",
                reason
            );
        }
        other => panic!("expected Reject, got {:?}", other),
    }

    // Verify rejected_events table has a row
    let rej_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM rejected_events WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![&alice.identity, &enc_b64],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(rej_count, 1, "rejected event should be recorded durably");

    // Second call should return AlreadyProcessed (not re-Reject)
    let result2 = project_one(&db, &alice.identity, &enc_eid).unwrap();
    assert_eq!(
        result2,
        poc_7::projection::decision::ProjectionDecision::AlreadyProcessed,
        "rejected event should not be re-processed"
    );
}
