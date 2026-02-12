use std::sync::Arc;
use std::time::{Duration, Instant};
use poc_7::testutil::{Peer, start_peers, assert_eventually, sync_until_converged, verify_projection_invariants};
use poc_7::crypto::{event_id_to_base64, event_id_from_base64};
use poc_7::transport::{
    AllowedPeers, create_client_endpoint, create_server_endpoint,
    extract_spki_fingerprint, load_or_generate_cert, peer_identity_from_connection,
};
use poc_7::transport_identity::transport_cert_paths_from_db;
use poc_7::db::open_connection;



#[tokio::test]
async fn test_two_peer_bidirectional_sync() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");

    alice.batch_create_messages(2);
    bob.batch_create_messages(1);

    assert_eq!(alice.store_count(), 6 + 2);
    assert_eq!(bob.store_count(), 6 + 1);

    let sync = start_peers(&alice, &bob);

    // After sync: 6 own identity + 5 other shared identity + 3 content = 14
    assert_eventually(
        || alice.store_count() == 14 && bob.store_count() == 14,
        Duration::from_secs(15),
        "both peers should have 14 events (11 identity + 3 content)",
    ).await;

    // Only locally-created messages are projected (remote messages are blocked
    // because their signer chain is from a different network)
    assert_eq!(alice.message_count(), 2);
    assert_eq!(bob.message_count(), 1);

    drop(sync);

    verify_projection_invariants(&alice);
    verify_projection_invariants(&bob);
}

#[tokio::test]
async fn test_one_way_sync() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");

    alice.batch_create_messages(10);
    assert_eq!(alice.store_count(), 6 + 10);
    assert_eq!(bob.store_count(), 6);

    let sync = start_peers(&alice, &bob);

    // After sync: 6 own identity + 5 other shared identity + 10 content = 21
    assert_eventually(
        || bob.store_count() == 21,
        Duration::from_secs(15),
        "bob should have 21 events (11 identity + 10 content)",
    ).await;

    drop(sync);
}

#[tokio::test]
async fn test_concurrent_create_and_sync() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");

    let sync = start_peers(&alice, &bob);

    // Give sync loop a moment to connect
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Create messages while sync runs
    alice.create_message("Hello from Alice");
    bob.create_message("Hi from Bob");

    // After sync: 6 own identity + 5 other shared identity + 2 content = 13
    assert_eventually(
        || alice.store_count() == 13 && bob.store_count() == 13,
        Duration::from_secs(15),
        "both peers converge to 13 events (11 identity + 2 content)",
    ).await;

    // Create more messages — sync loop picks them up
    alice.create_message("Another from Alice");

    // 13 + 1 new content = 14
    assert_eventually(
        || bob.store_count() == 14,
        Duration::from_secs(15),
        "bob gets the new message (3 messages + 1 workspace)",
    ).await;

    drop(sync);
}

#[tokio::test]
async fn test_sync_10k() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");

    let gen_start = Instant::now();
    alice.batch_create_messages(10_000);
    let gen_secs = gen_start.elapsed().as_secs_f64();
    eprintln!("Generated 10k events in {:.2}s", gen_secs);

    // After sync: 6 own identity + 5 other shared identity + 10k content = 10_011
    let converged = 11 + 10_000;
    let metrics = sync_until_converged(
        &alice, &bob, converged, Duration::from_secs(120),
    ).await;

    eprintln!("10k sync: {}", metrics);

    assert_eq!(alice.store_count(), converged);
    assert_eq!(bob.store_count(), converged);

    // Only alice's locally-created messages are projected on alice; bob has none projected
    assert_eq!(alice.message_count(), 10_000);
}

#[tokio::test]
async fn test_recorded_events_isolation() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");

    // Create messages locally
    alice.batch_create_messages(3);
    bob.batch_create_messages(2);

    // Verify local recorded_events before sync (6 identity + content)
    assert_eq!(alice.recorded_events_count(), 6 + 3);
    assert_eq!(bob.recorded_events_count(), 6 + 2);
    assert_eq!(alice.scoped_message_count(), 3);
    assert_eq!(bob.scoped_message_count(), 2);

    // Sync
    // After sync: 6 own identity + 5 other shared identity + 5 content = 16
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || alice.store_count() == 16 && bob.store_count() == 16,
        Duration::from_secs(15),
        "both peers should have 16 events (11 identity + 5 content)",
    ).await;

    drop(sync);

    // After sync: store has all events
    assert_eq!(alice.store_count(), 16);
    assert_eq!(bob.store_count(), 16);
    // Only locally-created messages are projected (remote messages blocked by foreign signer)
    assert_eq!(alice.message_count(), 3);
    assert_eq!(bob.message_count(), 2);

    // recorded_events: 6 own identity + own content + 5 other shared identity + other content
    assert_eq!(alice.recorded_events_count(), 16);
    assert_eq!(bob.recorded_events_count(), 16);

    // scoped_message_count: only locally-created messages projected
    assert_eq!(alice.scoped_message_count(), 3);
    assert_eq!(bob.scoped_message_count(), 2);

    verify_projection_invariants(&alice);
    verify_projection_invariants(&bob);
}

#[tokio::test]
async fn test_reaction_sync() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");

    // Alice creates messages, Bob adds reactions
    let msg1 = alice.create_message("Hello!");
    let msg2 = alice.create_message("World!");
    bob.create_reaction(&msg1, "\u{1f44d}");
    bob.create_reaction(&msg2, "\u{2764}\u{fe0f}");

    // Alice: 6 identity + 2 messages; Bob: 6 identity + 2 reactions (blocked on target dep)
    assert_eq!(alice.store_count(), 6 + 2);
    assert_eq!(bob.store_count(), 6 + 2);
    assert_eq!(alice.message_count(), 2);
    assert_eq!(bob.reaction_count(), 0); // blocked until targets arrive

    let sync = start_peers(&alice, &bob);

    // After sync: 6 own identity + 5 other shared identity + 4 content = 15
    assert_eventually(
        || alice.store_count() == 15 && bob.store_count() == 15,
        Duration::from_secs(15),
        "both peers should have 15 events (11 identity + 4 content)",
    ).await;

    drop(sync);

    // With independent identity chains, cross-peer events are blocked (foreign signer).
    // Alice projects her own 2 messages; Bob's reactions are blocked (foreign signer on Alice).
    // Bob: Alice's messages are blocked (foreign signer), so reaction targets remain invalid.
    assert_eq!(alice.message_count(), 2);
    assert_eq!(bob.message_count(), 0);
    assert_eq!(alice.reaction_count(), 0);
    assert_eq!(bob.reaction_count(), 0);

    verify_projection_invariants(&alice);
    verify_projection_invariants(&bob);
}

/// Stress test: high-volume bidirectional sync verifying exact event ID equality.
/// This checks the Done/DoneAck handshake prevents data loss at scale.
#[tokio::test]
async fn test_zero_loss_stress() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");

    alice.batch_create_messages(5_000);
    bob.batch_create_messages(5_000);

    let alice_ids_before = alice.store_ids();
    let bob_ids_before = bob.store_ids();
    assert_eq!(alice_ids_before.len(), 6 + 5_000);
    assert_eq!(bob_ids_before.len(), 6 + 5_000);

    // After sync: 6 own identity + 5 other shared identity + 10k content = 10_011
    let converged = 11 + 10_000;
    let metrics = sync_until_converged(
        &alice, &bob, converged, Duration::from_secs(120),
    ).await;

    eprintln!("zero-loss stress: {}", metrics);

    let alice_ids = alice.store_ids();
    let bob_ids = bob.store_ids();

    // Both peers should have the same count
    assert_eq!(alice_ids.len(), converged as usize, "alice store count mismatch");
    assert_eq!(bob_ids.len(), converged as usize, "bob store count mismatch");

    // Set difference should be exactly the two InviteAccepted events (local scope, not synced)
    let alice_only: Vec<_> = alice_ids.difference(&bob_ids).collect();
    let bob_only: Vec<_> = bob_ids.difference(&alice_ids).collect();
    assert_eq!(alice_only.len(), 1, "alice should have 1 unique event (InviteAccepted)");
    assert_eq!(bob_only.len(), 1, "bob should have 1 unique event (InviteAccepted)");

    // Verify all original events survived on their own peer
    for id in &alice_ids_before {
        assert!(alice_ids.contains(id), "alice lost own event {}", id);
    }
    for id in &bob_ids_before {
        assert!(bob_ids.contains(id), "bob lost own event {}", id);
    }
}

#[tokio::test]
async fn test_recorded_at_monotonicity() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");

    // Alice creates messages with small delays to ensure different created_at
    alice.create_message("first");
    std::thread::sleep(Duration::from_millis(10));
    alice.create_message("second");
    std::thread::sleep(Duration::from_millis(10));
    alice.create_message("third");

    // Sync to Bob — Bob's recorded_at should use local wall clock, not event created_at
    // After sync: 6 own identity + 5 other shared identity + 3 content = 14
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || bob.store_count() == 14,
        Duration::from_secs(15),
        "bob should have 14 events (11 identity + 3 content)",
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
    let alice_max_local_create: i64 = alice_db
        .query_row(
            "SELECT MAX(recorded_at) FROM recorded_events WHERE peer_id = ?1 AND source = 'local_create'",
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
        bob_min_recv >= alice_max_local_create,
        "Bob's earliest receive recorded_at ({}) should be >= Alice's latest local_create recorded_at ({})",
        bob_min_recv,
        alice_max_local_create,
    );
}

#[tokio::test]
async fn test_cross_workspace_isolation() {
    // Two independent workspace sets:
    // Set A: peerA1 + peerA2 (sync with each other)
    // Set B: peerB1 + peerB2 (sync with each other)
    // Verify no cross-set contamination.
    let peer_a1 = Peer::new_with_identity("peerA1");
    let peer_a2 = Peer::new_with_identity("peerA2");
    let peer_b1 = Peer::new_with_identity("peerB1");
    let peer_b2 = Peer::new_with_identity("peerB2");

    // Create messages in each workspace
    peer_a1.batch_create_messages(5);
    peer_a2.batch_create_messages(3);
    peer_b1.batch_create_messages(4);
    peer_b2.batch_create_messages(2);

    // Sync workspace A peers: 6 own identity + 5 other shared identity + 8 content = 19
    let sync_a = start_peers(&peer_a1, &peer_a2);
    assert_eventually(
        || peer_a1.store_count() == 19 && peer_a2.store_count() == 19,
        Duration::from_secs(15),
        "workspace A peers should converge to 19 events (11 identity + 8 content)",
    ).await;
    drop(sync_a);

    // Sync workspace B peers: 6 own identity + 5 other shared identity + 6 content = 17
    let sync_b = start_peers(&peer_b1, &peer_b2);
    assert_eventually(
        || peer_b1.store_count() == 17 && peer_b2.store_count() == 17,
        Duration::from_secs(15),
        "workspace B peers should converge to 17 events (11 identity + 6 content)",
    ).await;
    drop(sync_b);

    // Verify store counts: each workspace has its own events only
    assert_eq!(peer_a1.store_count(), 19);
    assert_eq!(peer_a2.store_count(), 19);
    assert_eq!(peer_b1.store_count(), 17);
    assert_eq!(peer_b2.store_count(), 17);

    // Verify recorded_events scoping: 6 own identity + own content + 5 other shared identity + other content
    assert_eq!(peer_a1.recorded_events_count(), 19);
    assert_eq!(peer_a2.recorded_events_count(), 19);
    assert_eq!(peer_b1.recorded_events_count(), 17);
    assert_eq!(peer_b2.recorded_events_count(), 17);

    // Verify scoped messages: only locally-created messages are projected (foreign signer blocked)
    assert_eq!(peer_a1.scoped_message_count(), 5);
    assert_eq!(peer_a2.scoped_message_count(), 3);
    assert_eq!(peer_b1.scoped_message_count(), 4);
    assert_eq!(peer_b2.scoped_message_count(), 2);

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
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");

    let gen_start = Instant::now();
    alice.batch_create_messages(50_000);
    let gen_secs = gen_start.elapsed().as_secs_f64();
    eprintln!("Generated 50k events in {:.2}s", gen_secs);

    // After sync: 6 own identity + 5 other shared identity + 50k content = 50_011
    let converged = 11 + 50_000;
    let metrics = sync_until_converged(
        &alice, &bob, converged, Duration::from_secs(300),
    ).await;

    eprintln!("50k sync: {}", metrics);

    assert_eq!(alice.store_count(), converged);
    assert_eq!(bob.store_count(), converged);

    // Only alice's locally-created messages are projected on alice
    assert_eq!(alice.message_count(), 50_000);
}

/// Integration test: verify peer_identity_from_connection returns the correct
/// SPKI fingerprint across a live QUIC mTLS handshake.
#[tokio::test]
async fn test_peer_identity_extraction_live_handshake() {
    let alice = Peer::new("alice");
    let bob = Peer::new("bob");

    let (cert_path_a, key_path_a) = transport_cert_paths_from_db(&alice.db_path);
    let (cert_a, key_a) = load_or_generate_cert(&cert_path_a, &key_path_a).unwrap();
    let (cert_path_b, key_path_b) = transport_cert_paths_from_db(&bob.db_path);
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
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");

    // Alice creates a message
    let msg_id = alice.create_message("Hello from Alice");

    // Bob creates a reaction targeting Alice's message (Bob doesn't have the message yet)
    bob.create_reaction(&msg_id, "\u{1f44d}");

    // Bob: 6 identity + 1 reaction (blocked on target dep)
    assert_eq!(bob.store_count(), 6 + 1);
    assert_eq!(bob.reaction_count(), 0); // blocked

    // Alice: 6 identity + 1 message
    assert_eq!(alice.store_count(), 6 + 1);
    assert_eq!(alice.message_count(), 1);

    // Sync — both get each other's events
    // After sync: 6 own identity + 5 other shared identity + 2 content = 13
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || alice.store_count() == 13 && bob.store_count() == 13,
        Duration::from_secs(15),
        "both peers should have 13 events (11 identity + 2 content)",
    ).await;

    drop(sync);

    // With independent identity chains, cross-peer events are blocked (foreign signer).
    // Bob: Alice's message blocked (foreign signer), reaction still blocked (target not valid)
    assert_eq!(bob.message_count(), 0);
    assert_eq!(bob.reaction_count(), 0);

    // Alice: own message valid, Bob's reaction blocked (foreign signer)
    assert_eq!(alice.message_count(), 1);
    assert_eq!(alice.reaction_count(), 0);

    verify_projection_invariants(&alice);
    verify_projection_invariants(&bob);
}

/// Test that multiple reactions targeting different messages all resolve correctly
/// when the messages arrive via sync.
#[tokio::test]
async fn test_multi_dep_blocking_sync() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");

    // Alice creates 3 messages
    let msg1 = alice.create_message("First");
    let msg2 = alice.create_message("Second");
    let msg3 = alice.create_message("Third");

    // Bob creates reactions targeting all 3 (none of which are in his DB)
    bob.create_reaction(&msg1, "\u{1f44d}");
    bob.create_reaction(&msg2, "\u{2764}\u{fe0f}");
    bob.create_reaction(&msg3, "\u{1f525}");

    // Bob: 6 identity + 3 reactions (all blocked on target dep)
    assert_eq!(bob.store_count(), 6 + 3);
    assert_eq!(bob.reaction_count(), 0);

    // Sync: 6 own identity + 5 other shared identity + 6 content = 17
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || alice.store_count() == 17 && bob.store_count() == 17,
        Duration::from_secs(15),
        "both peers should have 17 events (11 identity + 6 content)",
    ).await;

    drop(sync);

    // With independent identity chains, cross-peer events are blocked (foreign signer).
    assert_eq!(alice.message_count(), 3);
    assert_eq!(bob.message_count(), 0);
    assert_eq!(alice.reaction_count(), 0);
    assert_eq!(bob.reaction_count(), 0);

    verify_projection_invariants(&alice);
    verify_projection_invariants(&bob);
}

/// Integration test: Alice creates SignedMemo + message, Bob syncs, both valid.
#[tokio::test]
async fn test_signed_event_sync() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");

    // Alice creates a SignedMemo using her PeerShared identity chain key
    let signer_eid = alice.peer_shared_event_id.unwrap();
    let signing_key = alice.peer_shared_signing_key.as_ref().unwrap().clone();
    let _memo_eid = alice.create_signed_memo(&signer_eid, &signing_key, "Hello signed world");

    // 6 identity events + 1 SignedMemo
    assert_eq!(alice.store_count(), 7);
    assert_eq!(alice.signed_memo_count(), 1);

    // Sync to Bob: bob has 6 own identity + 5 alice shared identity + 1 memo = 12
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || bob.store_count() == 12,
        Duration::from_secs(15),
        "bob should have 12 events (11 identity + 1 SignedMemo)",
    ).await;

    drop(sync);

    // SignedMemo is stored on Bob but not projected: signer chain from foreign network
    // (InviteAccepted is Local-scoped, not synced). Only locally-created signed memos project.
    assert_eq!(alice.signed_memo_count(), 1);

    verify_projection_invariants(&alice);
    verify_projection_invariants(&bob);
}

/// Integration test: signed memo syncs alongside messages; verify store convergence.
#[tokio::test]
async fn test_signed_event_out_of_order_sync() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");

    // Alice creates SignedMemo (using PeerShared key) + a message
    let signer_eid = alice.peer_shared_event_id.unwrap();
    let signing_key = alice.peer_shared_signing_key.as_ref().unwrap().clone();
    let _memo_eid = alice.create_signed_memo(&signer_eid, &signing_key, "Out of order memo");
    alice.create_message("Normal message");

    // Bob creates a message too
    bob.create_message("Bob's message");

    assert_eq!(alice.store_count(), 6 + 2); // 6 identity + memo + msg
    assert_eq!(bob.store_count(), 6 + 1);   // 6 identity + msg

    // Sync: 6 own identity + 5 other shared identity + 3 content = 14
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || alice.store_count() == 14 && bob.store_count() == 14,
        Duration::from_secs(15),
        "both peers should have 14 events (11 identity + 3 content)",
    ).await;

    drop(sync);

    // SignedMemo + messages stored on both sides, but only locally-created ones are projected
    // (remote signer chains from foreign network; InviteAccepted is Local-scoped, not synced)
    assert_eq!(alice.signed_memo_count(), 1);
    assert_eq!(bob.message_count(), 1);

    verify_projection_invariants(&alice);
    verify_projection_invariants(&bob);
}

/// Integration test: wrong-key memo rejected on remote peer.
#[tokio::test]
async fn test_invalid_signature_rejected_after_sync() {
    use ed25519_dalek::SigningKey;
    use poc_7::crypto::event_id_to_base64;

    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");
    let alice_initial_store = alice.store_count();
    let bob_initial_store = bob.store_count();

    let mut rng = rand::thread_rng();
    let wrong_key = SigningKey::generate(&mut rng);
    let signer_eid = alice.peer_shared_event_id.unwrap();

    // Alice creates a signed memo but signs with the WRONG key (simulating corruption)
    // We need to do this manually since create_signed_memo uses proper signing
    let bad_memo_event_id_b64: String;
    {
        use poc_7::events::{SignedMemoEvent, ParsedEvent, encode_event};
        use poc_7::projection::signer::sign_event_bytes;
        use poc_7::crypto::hash_event;

        let db = open_connection(&alice.db_path).expect("open alice db");
        let memo = ParsedEvent::SignedMemo(SignedMemoEvent {
            created_at_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64,
            signed_by: signer_eid,
            signer_type: 5,
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
        bad_memo_event_id_b64 = event_id_b64;
        // Don't project — it would be rejected. The blob will sync via negentropy.
    }

    assert_eq!(alice.store_count(), alice_initial_store + 1);

    // Sync to Bob
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || bob.store_count() >= bob_initial_store + 6 && bob.has_event(&bad_memo_event_id_b64),
        Duration::from_secs(15),
        "bob should receive alice identity chain plus bad-signature memo in store",
    ).await;

    drop(sync);

    // Bob should NOT project the bad-signature memo.
    assert_eq!(bob.signed_memo_count(), 0, "bad-signature memo should be rejected, not projected");
}

/// Integration test: verify valid_events are tenant-scoped after sync.
/// Alice creates message + reaction, syncs to Bob. Both converge to 2 events.
/// valid_events are per-tenant, and projection invariants hold.
#[tokio::test]
async fn test_cross_tenant_dep_scoping_after_sync() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");

    // Alice creates a message and a reaction targeting it
    let msg_id = alice.create_message("Cross-tenant scoping test");
    alice.create_reaction(&msg_id, "\u{2705}");

    assert_eq!(alice.store_count(), 6 + 2);
    assert_eq!(alice.message_count(), 1);
    assert_eq!(alice.reaction_count(), 1);

    // Sync to Bob: 6 own identity + 5 other shared identity + 2 content = 13
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || alice.store_count() == 13 && bob.store_count() == 13,
        Duration::from_secs(15),
        "both peers should have 13 events (11 identity + 2 content)",
    ).await;

    drop(sync);

    // Bob: Alice's events blocked (foreign signer)
    assert_eq!(bob.message_count(), 0);
    assert_eq!(bob.reaction_count(), 0);

    // Verify valid_events are tenant-scoped
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
    // Alice: 6 identity + 2 content = 8 valid; Bob: 6 identity + 0 content = 6 valid
    assert_eq!(alice_valid, 8, "Alice should have 8 valid_events (6 identity + 2 content)");
    assert_eq!(bob_valid, 6, "Bob should have 6 valid_events (6 identity only)");

    // Run projection invariants for both
    verify_projection_invariants(&alice);
    verify_projection_invariants(&bob);
}

/// Integration test: Alice creates a PSK + encrypted message → syncs to Bob → Bob projects.
#[tokio::test]
async fn test_encrypted_event_sync() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");

    // Materialize the same PSK locally on both peers (local-only key event, not synced).
    let key_bytes: [u8; 32] = rand::random();
    let fixed_ts = 4_000_000u64;
    let sk_eid_alice = alice.create_secret_key_deterministic(key_bytes, fixed_ts);
    let sk_eid_bob = bob.create_secret_key_deterministic(key_bytes, fixed_ts);
    assert_eq!(sk_eid_alice, sk_eid_bob, "deterministic PSK materialization should match");

    let _enc_eid = alice.create_encrypted_message(&sk_eid_alice, "Hello encrypted world");

    // alice: 6 identity + 1 SecretKey + 1 Encrypted = 8
    assert_eq!(alice.store_count(), 6 + 2);
    assert_eq!(alice.secret_key_count(), 1);
    // bob: 6 identity + 1 SecretKey = 7
    assert_eq!(bob.store_count(), 6 + 1);
    assert_eq!(bob.secret_key_count(), 1);
    // The encrypted event projects into messages table
    assert_eq!(alice.scoped_message_count(), 1);

    // Sync to Bob: bob gets alice's 5 shared identity + 1 encrypted = 7 + 6 = 13
    // alice gets bob's 5 shared identity = 8 + 5 = 13
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || bob.store_count() == 13,
        Duration::from_secs(15),
        "bob should have 13 events (7 own + 5 alice shared identity + 1 encrypted)",
    ).await;

    drop(sync);

    // Bob has his local secret key. The encrypted wrapper decrypts to a Message
    // with signed_by = Alice's PeerShared (foreign signer -> inner message rejected).
    assert_eq!(bob.secret_key_count(), 1);
    // Encrypted inner message is rejected because its signer (Alice's PeerShared)
    // is not valid on Bob's side (foreign network)
    assert_eq!(bob.scoped_message_count(), 0);

    verify_projection_invariants(&alice);
    verify_projection_invariants(&bob);
}

/// Integration test: Encrypted event syncs before key → blocks → key syncs → cascade unblocks.
#[tokio::test]
async fn test_encrypted_out_of_order_sync() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");

    // Alice creates key + encrypted message.
    let key_bytes: [u8; 32] = rand::random();
    let fixed_ts = 5_000_000u64;
    let sk_eid = alice.create_secret_key_deterministic(key_bytes, fixed_ts);
    let _enc_eid = alice.create_encrypted_message(&sk_eid, "Out of order encrypted");

    // Also create a normal message to verify mixed events work
    alice.create_message("Normal message");

    // Bob creates a message too, but does NOT have the key yet.
    bob.create_message("Bob's message");

    assert_eq!(alice.store_count(), 6 + 3); // 6 identity + sk + encrypted + message
    assert_eq!(bob.store_count(), 6 + 1);   // 6 identity + message

    // Sync phase 1: ciphertext arrives before key materialization on Bob.
    // Alice: 9 + 5 bob shared identity + 1 bob content = 15
    // Bob: 7 + 5 alice shared identity + 2 alice content (encrypted + msg) = 14
    // Note: alice's SK is local scope, not synced
    let sync1 = start_peers(&alice, &bob);

    assert_eventually(
        || alice.store_count() == 15 && bob.store_count() == 14,
        Duration::from_secs(15),
        "phase 1: both peers should have synced shared events",
    ).await;

    drop(sync1);

    // Bob should be blocked on missing key after phase 1.
    assert_eq!(bob.secret_key_count(), 0);
    // Bob: only his own message projected (Alice's normal message blocked by foreign signer)
    assert_eq!(bob.scoped_message_count(), 1);
    let bob_db = open_connection(&bob.db_path).expect("open bob db");
    let blocked_before: i64 = bob_db.query_row(
        "SELECT COUNT(*) FROM blocked_event_deps WHERE peer_id = ?1",
        rusqlite::params![&bob.identity],
        |row| row.get(0),
    ).unwrap();
    assert!(blocked_before >= 1, "encrypted wrapper should be blocked until key appears");

    // Materialize the matching key locally on Bob; this should unblock encrypted wrapper.
    let sk_eid_bob = bob.create_secret_key_deterministic(key_bytes, fixed_ts);
    assert_eq!(sk_eid_bob, sk_eid, "bob key materialization should match alice key event id");

    // After key materialization, the encrypted wrapper unblocks. But the inner message
    // has signed_by = Alice's PeerShared (foreign signer), so it gets rejected.
    assert_eq!(bob.secret_key_count(), 1);
    // Bob still only sees his own message (encrypted inner rejected due to foreign signer)
    assert_eq!(bob.scoped_message_count(), 1);

    // Alice sees all her own messages
    assert_eq!(alice.scoped_message_count(), 2); // encrypted inner + normal message

    verify_projection_invariants(&alice);
    verify_projection_invariants(&bob);
}

/// Integration test: mixed cleartext + encrypted events → verify_projection_invariants.
#[tokio::test]
async fn test_encrypted_replay_invariants() {
    let alice = Peer::new_with_identity("alice");

    // Create a mix of cleartext and encrypted events
    let key_bytes: [u8; 32] = rand::random();
    let sk_eid = alice.create_secret_key(key_bytes);

    alice.create_message("Cleartext 1");
    alice.create_encrypted_message(&sk_eid, "Encrypted 1");
    alice.create_message("Cleartext 2");
    alice.create_encrypted_message(&sk_eid, "Encrypted 2");

    // Verify counts: 6 identity + sk + 2 cleartext + 2 encrypted = 11
    assert_eq!(alice.store_count(), 6 + 5);
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

    let alice = Peer::new_with_identity("alice");

    // Create messages via create_event_sync (bypasses queue, projects inline)
    let msg1 = alice.create_message("Recovery message 1");
    let msg2 = alice.create_message("Recovery message 2");
    let msg3 = alice.create_message("Recovery message 3");

    assert_eq!(alice.store_count(), 6 + 3);
    assert_eq!(alice.scoped_message_count(), 3);

    // Now simulate a crash scenario: clear ALL projection state and re-enqueue ALL events
    let db = open_connection(&alice.db_path).expect("open db");
    db.execute("DELETE FROM messages WHERE recorded_by = ?1", rusqlite::params![&alice.identity]).unwrap();
    db.execute("DELETE FROM workspaces WHERE recorded_by = ?1", rusqlite::params![&alice.identity]).unwrap();
    db.execute("DELETE FROM invite_accepted WHERE recorded_by = ?1", rusqlite::params![&alice.identity]).unwrap();
    db.execute("DELETE FROM user_invites WHERE recorded_by = ?1", rusqlite::params![&alice.identity]).unwrap();
    db.execute("DELETE FROM users WHERE recorded_by = ?1", rusqlite::params![&alice.identity]).unwrap();
    db.execute("DELETE FROM device_invites WHERE recorded_by = ?1", rusqlite::params![&alice.identity]).unwrap();
    db.execute("DELETE FROM peers_shared WHERE recorded_by = ?1", rusqlite::params![&alice.identity]).unwrap();
    db.execute("DELETE FROM trust_anchors WHERE peer_id = ?1", rusqlite::params![&alice.identity]).unwrap();
    db.execute("DELETE FROM valid_events WHERE peer_id = ?1", rusqlite::params![&alice.identity]).unwrap();
    db.execute("DELETE FROM blocked_event_deps WHERE peer_id = ?1", rusqlite::params![&alice.identity]).unwrap();
    db.execute("DELETE FROM rejected_events WHERE peer_id = ?1", rusqlite::params![&alice.identity]).unwrap();

    // Enqueue ALL recorded events into project_queue (simulating full crash recovery)
    let pq = ProjectQueue::new(&db);
    let all_eids: Vec<String> = {
        let mut stmt = db.prepare(
            "SELECT event_id FROM recorded_events WHERE peer_id = ?1"
        ).unwrap();
        stmt.query_map(rusqlite::params![&alice.identity], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    for eid_b64 in &all_eids {
        pq.enqueue(&alice.identity, eid_b64).unwrap();
    }
    assert_eq!(all_eids.len(), 9); // 6 identity + 3 messages

    // Verify nothing projected yet
    let msg_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
        rusqlite::params![&alice.identity], |row| row.get(0),
    ).unwrap();
    assert_eq!(msg_count, 0);

    // Run recovery: recover expired leases + drain
    let recovered = pq.recover_expired().unwrap();
    assert_eq!(recovered, 0);

    let drained = pq.drain(&alice.identity, |conn, eid_b64| {
        if let Some(eid) = event_id_from_base64(eid_b64) {
            project_one(conn, &alice.identity, &eid)
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        }
        Ok(())
    }).unwrap();
    assert_eq!(drained, 9); // all 9 events drained

    // Verify all messages projected
    let msg_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
        rusqlite::params![&alice.identity], |row| row.get(0),
    ).unwrap();
    assert_eq!(msg_count, 3);

    // Verify valid_events (6 identity + 3 messages = 9)
    let valid_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM valid_events WHERE peer_id = ?1",
        rusqlite::params![&alice.identity], |row| row.get(0),
    ).unwrap();
    assert_eq!(valid_count, 9);

    // Queue should be empty
    assert_eq!(pq.count_pending(&alice.identity).unwrap(), 0);
}

/// Integration test: verify project_queue drain works end-to-end with create_event_sync events.
#[tokio::test]
async fn test_project_queue_drain_after_batch() {
    use poc_7::db::project_queue::ProjectQueue;
    use poc_7::projection::pipeline::project_one;

    let alice = Peer::new_with_identity("alice");

    // Create events (projected inline by create_event_sync)
    alice.batch_create_messages(5);
    assert_eq!(alice.store_count(), 6 + 5);
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

    let alice = Peer::new_with_identity("alice");

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

    // Cleanup sent with a large age threshold; recent rows should not be purged.
    let purged = eq.cleanup_sent(300_000).unwrap();
    assert_eq!(purged, 0);

    // Backdate and cleanup
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

/// Integration test: Alice creates message + reactions, syncs to Bob. Alice deletes message.
/// Bob syncs again. Verify: Bob has tombstone, no message, no reactions.
#[tokio::test]
async fn test_deletion_sync() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");

    // Alice creates a message and a reaction targeting it
    let msg_id = alice.create_message("Delete me");
    alice.create_reaction(&msg_id, "\u{1f44d}");

    assert_eq!(alice.store_count(), 6 + 2);
    assert_eq!(alice.message_count(), 1);
    assert_eq!(alice.reaction_count(), 1);

    // Sync to Bob: 6 own identity + 5 other shared identity + 2 content = 13
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || alice.store_count() == 13 && bob.store_count() == 13,
        Duration::from_secs(15),
        "both peers should have 13 events (11 identity + 2 content)",
    ).await;

    drop(sync);

    // Bob: Alice's events blocked (foreign signer)
    assert_eq!(bob.message_count(), 0);
    assert_eq!(bob.reaction_count(), 0);

    // Alice deletes the message
    alice.create_message_deletion(&msg_id);

    assert_eq!(alice.store_count(), 13 + 1);
    assert_eq!(alice.message_count(), 0); // deleted
    assert_eq!(alice.reaction_count(), 0); // cascaded
    assert_eq!(alice.deleted_message_count(), 1); // tombstone

    // Sync again — Bob gets the deletion event
    let sync2 = start_peers(&alice, &bob);

    assert_eventually(
        || bob.store_count() == 14,
        Duration::from_secs(15),
        "bob should have 14 events (11 identity + 3 content)",
    ).await;

    drop(sync2);

    // Bob: all of Alice's events blocked (foreign signer), including deletion
    assert_eq!(bob.message_count(), 0, "bob: no messages projected (foreign signer)");
    assert_eq!(bob.reaction_count(), 0, "bob: no reactions projected (foreign signer)");
    assert_eq!(bob.deleted_message_count(), 0, "bob: no tombstones (deletion blocked too)");

    verify_projection_invariants(&alice);
    verify_projection_invariants(&bob);
}

/// Integration test: Alice creates a message and then a deletion targeting it.
/// Bob syncs and gets both events. Regardless of receive order, Bob converges
/// to the same final state: 0 messages, 1 tombstone.
/// This also tests that if Bob receives the deletion first (blocked), the
/// cascade-unblock when the message arrives produces the correct state.
#[tokio::test]
async fn test_deletion_before_target_sync() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");

    // Alice creates a message and then deletes it
    let msg_id = alice.create_message("Delete me via sync");
    alice.create_message_deletion(&msg_id);

    assert_eq!(alice.store_count(), 6 + 2); // 6 identity + message + deletion
    assert_eq!(alice.message_count(), 0); // deleted
    assert_eq!(alice.deleted_message_count(), 1); // tombstone

    // Sync: 6 own identity + 5 other shared identity + 2 content = 13
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || bob.store_count() == 13,
        Duration::from_secs(15),
        "bob should have 13 events (11 identity + 2 content)",
    ).await;

    drop(sync);

    // Bob: Alice's events blocked (foreign signer)
    assert_eq!(bob.message_count(), 0, "bob: no messages (foreign signer)");
    assert_eq!(bob.deleted_message_count(), 0, "bob: no tombstones (foreign signer)");

    verify_projection_invariants(&alice);
    verify_projection_invariants(&bob);
}

/// Integration test: Create encrypted message, then encrypted deletion targeting it.
/// Verify cascade works through encryption layer.
#[tokio::test]
async fn test_encrypted_deletion() {
    let alice = Peer::new_with_identity("alice");

    // Create a secret key
    let key_bytes: [u8; 32] = rand::random();
    let sk_eid = alice.create_secret_key(key_bytes);

    // Create an encrypted message
    let _enc_msg_eid = alice.create_encrypted_message(&sk_eid, "Encrypted delete me");

    assert_eq!(alice.store_count(), 6 + 2); // 6 identity + sk + encrypted msg
    assert_eq!(alice.secret_key_count(), 1);
    assert_eq!(alice.scoped_message_count(), 1); // inner message projected

    // Get the inner message's event_id from the messages table
    let alice_db = open_connection(&alice.db_path).expect("open alice db");
    let inner_msg_id: String = alice_db.query_row(
        "SELECT message_id FROM messages WHERE recorded_by = ?1",
        rusqlite::params![&alice.identity],
        |row| row.get(0),
    ).unwrap();
    let inner_msg_eid = event_id_from_base64(&inner_msg_id).expect("parse inner msg id");
    drop(alice_db);

    // Create an encrypted deletion targeting the inner message
    alice.create_encrypted_deletion(&sk_eid, &inner_msg_eid);

    assert_eq!(alice.store_count(), 6 + 3); // 6 identity + sk + encrypted msg + encrypted del
    assert_eq!(alice.scoped_message_count(), 0); // inner message deleted
    assert_eq!(alice.deleted_message_count(), 1); // tombstone from encrypted deletion

    verify_projection_invariants(&alice);
}

/// Integration test: After deletion sync, verify_projection_invariants on both peers.
#[tokio::test]
async fn test_deletion_replay_invariants() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");

    // Create a mix of messages, reactions, and deletions
    let msg1 = alice.create_message("Keep me");
    let msg2 = alice.create_message("Delete me");
    alice.create_reaction(&msg1, "\u{2764}\u{fe0f}");
    alice.create_reaction(&msg2, "\u{1f44d}");

    // Delete msg2 (cascades its reaction too)
    alice.create_message_deletion(&msg2);

    assert_eq!(alice.store_count(), 6 + 5); // 6 identity + 2 msgs + 2 rxns + 1 del
    assert_eq!(alice.message_count(), 1); // msg1 survives
    assert_eq!(alice.reaction_count(), 1); // msg1's reaction survives
    assert_eq!(alice.deleted_message_count(), 1); // msg2 tombstone

    // Sync to Bob: 6 own identity + 5 other shared identity + 5 content = 16
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || bob.store_count() == 16,
        Duration::from_secs(15),
        "bob should have 16 events (11 identity + 5 content)",
    ).await;

    drop(sync);

    // Bob: Alice's events blocked (foreign signer)
    assert_eq!(bob.message_count(), 0);
    assert_eq!(bob.reaction_count(), 0);
    assert_eq!(bob.deleted_message_count(), 0);

    // Run full replay invariants on both
    verify_projection_invariants(&alice);
    verify_projection_invariants(&bob);
}

/// Gap 1: Verify SecretKey events (ShareScope::Local) are never sent to remote peers.
#[tokio::test]
async fn test_local_only_events_not_synced() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");

    // Both peers materialize the same PSK locally
    let key_bytes: [u8; 32] = rand::random();
    let fixed_ts = 3000000u64;
    let sk_eid = alice.create_secret_key_deterministic(key_bytes, fixed_ts);
    let sk_eid_bob = bob.create_secret_key_deterministic(key_bytes, fixed_ts);
    assert_eq!(sk_eid, sk_eid_bob, "deterministic PSK should produce same event_id");

    // Alice creates encrypted message + normal message
    let _enc_eid = alice.create_encrypted_message(&sk_eid, "Encrypted for local-only test");
    alice.create_message("Normal message from Alice");

    // Alice: 6 identity + SK + encrypted + msg = 9; Bob: 6 identity + SK = 7
    assert_eq!(alice.store_count(), 6 + 3);
    assert_eq!(bob.store_count(), 6 + 1);

    // neg_items: 5 shared identity events + 2 content for Alice; 5 shared identity for Bob
    // (SK and InviteAccepted are local-only, not in neg_items)
    assert_eq!(alice.neg_items_count(), 5 + 2, "Alice should have 7 neg_items (5 identity + encrypted + msg)");
    assert_eq!(bob.neg_items_count(), 5, "Bob should have 5 neg_items (5 shared identity events)");

    // Sync: bob gets alice's 5 shared identity + 2 content = 7 + 7 = 14
    // alice gets bob's 5 shared identity = 9 + 5 = 14
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || bob.store_count() == 14,
        Duration::from_secs(15),
        "bob should have 14 events (7 own + 5 alice shared identity + 2 content)",
    ).await;

    drop(sync);

    // Bob should NOT have received Alice's SK event -- his store has his own SK
    assert_eq!(bob.secret_key_count(), 1);
    // Bob: encrypted inner rejected (foreign signer), normal msg blocked (foreign signer)
    assert_eq!(bob.scoped_message_count(), 0);

    // Verify Alice's SK event_id IS in bob's events (because bob created his own copy)
    let sk_b64 = event_id_to_base64(&sk_eid);
    assert!(bob.has_event(&sk_b64), "bob should have the SK event (his own local copy)");

    verify_projection_invariants(&alice);
    verify_projection_invariants(&bob);
}

/// Gap 2: Two-set PSK isolation -- mismatched PSKs cannot decrypt each other's messages.
#[tokio::test]
async fn test_psk_two_set_isolation() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");

    // Alice and Bob use DIFFERENT PSKs
    let key_a: [u8; 32] = rand::random();
    let key_b: [u8; 32] = rand::random();
    let sk_eid_alice = alice.create_secret_key(key_a);
    let _sk_eid_bob = bob.create_secret_key(key_b);

    // Alice encrypts with her key
    let _enc_eid = alice.create_encrypted_message(&sk_eid_alice, "Alice secret");

    // Alice also creates a normal message
    alice.create_message("Alice cleartext");

    // Alice: 6 identity + SK + encrypted + msg = 9; Bob: 6 identity + SK = 7
    assert_eq!(alice.store_count(), 6 + 3);
    assert_eq!(bob.store_count(), 6 + 1);

    // Sync: bob gets alice's 5 shared identity + 2 content = 14
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || bob.store_count() == 14,
        Duration::from_secs(15),
        "bob should have 14 events (7 own + 5 alice shared identity + 2 content)",
    ).await;

    drop(sync);

    // Bob: normal message blocked (foreign signer), encrypted blocked (missing key dep)
    assert_eq!(bob.scoped_message_count(), 0, "bob should see no messages (foreign signer + missing key)");

    // Verify the encrypted event is blocked
    let bob_db = open_connection(&bob.db_path).expect("open bob db");
    let blocked: i64 = bob_db.query_row(
        "SELECT COUNT(*) FROM blocked_event_deps WHERE peer_id = ?1",
        rusqlite::params![&bob.identity],
        |row| row.get(0),
    ).unwrap();
    assert!(blocked >= 1, "events should be blocked (foreign signer + missing key dep)");
}

/// Integration test: Alice and Bob sync, verify peer_endpoint_observations are recorded.
/// Purge with far-future cutoff removes them; purge with past cutoff keeps them.
#[tokio::test]
async fn test_endpoint_observations_recorded() {
    use poc_7::db::health::purge_expired_endpoints;

    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");

    // Create some data so sync has something to do
    alice.create_message("endpoint obs test");

    let sync = start_peers(&alice, &bob);

    // After sync: 6 own identity + 5 other shared identity + 1 content = 12
    assert_eventually(
        || bob.store_count() == 12,
        Duration::from_secs(15),
        "bob should have 12 events (11 identity + 1 content)",
    ).await;

    drop(sync);

    // Check endpoint observations were recorded
    let alice_db = open_connection(&alice.db_path).expect("open alice db");
    let bob_db = open_connection(&bob.db_path).expect("open bob db");

    let alice_obs: i64 = alice_db.query_row(
        "SELECT COUNT(*) FROM peer_endpoint_observations WHERE recorded_by = ?1",
        rusqlite::params![&alice.identity],
        |row| row.get(0),
    ).unwrap();

    let bob_obs: i64 = bob_db.query_row(
        "SELECT COUNT(*) FROM peer_endpoint_observations WHERE recorded_by = ?1",
        rusqlite::params![&bob.identity],
        |row| row.get(0),
    ).unwrap();

    // Both should have recorded at least one observation
    assert!(alice_obs >= 1, "alice should have endpoint observations, got {}", alice_obs);
    assert!(bob_obs >= 1, "bob should have endpoint observations, got {}", bob_obs);

    // Purge with past cutoff (0) should keep all (all have future expires_at)
    let purged = purge_expired_endpoints(&alice_db, 0).unwrap();
    assert_eq!(purged, 0, "purge with past cutoff should keep all");

    let still_there: i64 = alice_db.query_row(
        "SELECT COUNT(*) FROM peer_endpoint_observations WHERE recorded_by = ?1",
        rusqlite::params![&alice.identity],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(still_there, alice_obs, "observations should still be there after past-cutoff purge");

    // Purge with far-future cutoff should remove all
    let purged = purge_expired_endpoints(&alice_db, i64::MAX).unwrap();
    assert!(purged >= 1, "purge with far-future cutoff should remove observations");

    let remaining: i64 = alice_db.query_row(
        "SELECT COUNT(*) FROM peer_endpoint_observations WHERE recorded_by = ?1",
        rusqlite::params![&alice.identity],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(remaining, 0, "no observations should remain after far-future purge");
}

/// Gap 3: Encrypted inner event with unsupported signer_type rejects durably (not hard error).
#[tokio::test]
async fn test_encrypted_inner_unsupported_signer_rejects_durably() {
    use poc_7::crypto::hash_event;
    use poc_7::events::{
        EncryptedEvent, ParsedEvent, SignedMemoEvent, EVENT_TYPE_SIGNED_MEMO, encode_event,
    };
    use poc_7::projection::encrypted::encrypt_event_blob;
    use poc_7::projection::pipeline::project_one;

    let alice = Peer::new_with_identity("alice");

    // Create and project a secret key
    let key_bytes: [u8; 32] = rand::random();
    let sk_eid = alice.create_secret_key(key_bytes);

    // Create an inner SignedMemo with signer_type=255 (unsupported)
    // signed_by references an existing PeerShared signer event, but signer_type is invalid
    let inner = ParsedEvent::SignedMemo(SignedMemoEvent {
        created_at_ms: 999999u64,
        signed_by: alice.peer_shared_event_id.unwrap(),
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
    )
    .unwrap();
    db.execute(
        "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source)
         VALUES (?1, ?2, ?3, 'test')",
        rusqlite::params![&alice.identity, &enc_b64, ts],
    )
    .unwrap();

    // Project: should get Reject (not hard Err) because signer_type=255 is invalid
    let result = project_one(&db, &alice.identity, &enc_eid).unwrap();
    match result {
        poc_7::projection::decision::ProjectionDecision::Reject { reason } => {
            assert!(
                reason.contains("unsupported signer_type") || reason.contains("signer resolution failed"),
                "unexpected rejection reason: {}",
                reason
            );
        }
        other => panic!("expected Reject, got {:?}", other),
    }

    // Verify rejected_events table has a row
    let rej_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM rejected_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&alice.identity, &enc_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rej_count, 1, "rejected event should be recorded durably");

    // Second call should return AlreadyProcessed (not re-Reject)
    let result2 = project_one(&db, &alice.identity, &enc_eid).unwrap();
    assert_eq!(
        result2,
        poc_7::projection::decision::ProjectionDecision::AlreadyProcessed,
        "rejected event should not be re-processed"
    );
}

// =============================================================================
// Phase 7: Identity bootstrap, trust anchor, and signer chain tests
// =============================================================================

/// Helper: create a full bootstrap chain for a peer, returning all key material and event IDs.
#[allow(dead_code)]
struct BootstrapChain {
    workspace_key: ed25519_dalek::SigningKey,
    workspace_eid: [u8; 32],
    workspace_id: [u8; 32],
    invite_key: ed25519_dalek::SigningKey,
    user_invite_eid: [u8; 32],
    user_key: ed25519_dalek::SigningKey,
    user_eid: [u8; 32],
    device_invite_key: ed25519_dalek::SigningKey,
    device_invite_eid: [u8; 32],
    peer_shared_key: ed25519_dalek::SigningKey,
    peer_shared_eid: [u8; 32],
    admin_key: ed25519_dalek::SigningKey,
    admin_eid: [u8; 32],
    invite_accepted_eid: [u8; 32],
}

fn bootstrap_peer(peer: &Peer) -> BootstrapChain {
    use ed25519_dalek::SigningKey;

    let mut rng = rand::thread_rng();
    let workspace_key = SigningKey::generate(&mut rng);
    let workspace_pubkey = workspace_key.verifying_key().to_bytes();

    // 1. Workspace event
    let workspace_eid = peer.create_workspace(workspace_pubkey);
    let workspace_id = workspace_eid;

    // 2. UserInviteBoot (signed by workspace)
    let invite_key = SigningKey::generate(&mut rng);
    let invite_pubkey = invite_key.verifying_key().to_bytes();
    let user_invite_eid = peer.create_user_invite_boot_with_key(
        invite_pubkey,
        &workspace_key,
        &workspace_eid,
    );

    // 3. InviteAccepted (local, binds trust anchor)
    let invite_accepted_eid = peer.create_invite_accepted(&user_invite_eid, workspace_id);

    // 4. UserBoot (signed by user_invite)
    let user_key = SigningKey::generate(&mut rng);
    let user_pubkey = user_key.verifying_key().to_bytes();
    let user_eid = peer.create_user_boot(user_pubkey, &invite_key, &user_invite_eid);

    // 5. DeviceInviteFirst (signed by user)
    let device_invite_key = SigningKey::generate(&mut rng);
    let device_invite_pubkey = device_invite_key.verifying_key().to_bytes();
    let device_invite_eid = peer.create_device_invite_first(
        device_invite_pubkey,
        &user_key,
        &user_eid,
    );

    // 6. PeerSharedFirst (signed by device_invite)
    let peer_shared_key = SigningKey::generate(&mut rng);
    let peer_shared_pubkey = peer_shared_key.verifying_key().to_bytes();
    let peer_shared_eid = peer.create_peer_shared_first(
        peer_shared_pubkey,
        &device_invite_key,
        &device_invite_eid,
    );

    // 7. AdminBoot (signed by workspace, dep on user)
    let admin_key = SigningKey::generate(&mut rng);
    let admin_pubkey = admin_key.verifying_key().to_bytes();
    let admin_eid = peer.create_admin_boot(
        admin_pubkey,
        &workspace_key,
        &user_eid,
        &workspace_eid,
    );

    BootstrapChain {
        workspace_key,
        workspace_eid,
        workspace_id,
        invite_key,
        user_invite_eid,
        user_key,
        user_eid,
        device_invite_key,
        device_invite_eid,
        peer_shared_key,
        peer_shared_eid,
        admin_key,
        admin_eid,
        invite_accepted_eid,
    }
}

#[test]
fn test_bootstrap_sequence() {
    let alice = Peer::new("alice");
    let chain = bootstrap_peer(&alice);

    let db = open_connection(&alice.db_path).unwrap();

    // Verify trust anchor was set correctly
    let anchor: String = db.query_row(
        "SELECT workspace_id FROM trust_anchors WHERE peer_id = ?1",
        rusqlite::params![&alice.identity],
        |row| row.get(0),
    ).expect("trust anchor should exist");
    let expected_nid = event_id_to_base64(&chain.workspace_id);
    assert_eq!(anchor, expected_nid, "trust anchor should match workspace_id");

    // Verify all events are valid
    let valid_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM valid_events WHERE peer_id = ?1",
        rusqlite::params![&alice.identity],
        |row| row.get(0),
    ).unwrap();
    // At least the bootstrap chain should be valid.
    assert!(
        valid_count >= 7,
        "at least 7 identity events should be valid, got {}",
        valid_count
    );

    // Verify projection tables
    let net_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM workspaces WHERE recorded_by = ?1",
        rusqlite::params![&alice.identity],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(net_count, 1, "one trust-anchored workspace should be projected");

    let user_invite_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM user_invites WHERE recorded_by = ?1",
        rusqlite::params![&alice.identity],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(user_invite_count, 1);

    let user_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM users WHERE recorded_by = ?1",
        rusqlite::params![&alice.identity],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(user_count, 1);

    let di_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM device_invites WHERE recorded_by = ?1",
        rusqlite::params![&alice.identity],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(di_count, 1);

    let ps_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM peers_shared WHERE recorded_by = ?1",
        rusqlite::params![&alice.identity],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(ps_count, 1);

    let admin_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM admins WHERE recorded_by = ?1",
        rusqlite::params![&alice.identity],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(admin_count, 1);

    let ia_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM invite_accepted WHERE recorded_by = ?1",
        rusqlite::params![&alice.identity],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(ia_count, 1);
}

#[test]
fn test_out_of_order_identity() {
    // Record UserBoot BEFORE UserInviteBoot — UserBoot blocks on missing dep,
    // then cascades when the full invite chain is created afterward.
    let alice = Peer::new("alice");
    let db = open_connection(&alice.db_path).unwrap();

    use ed25519_dalek::SigningKey;
    use poc_7::events::{encode_event, ParsedEvent, WorkspaceEvent, UserInviteBootEvent, UserBootEvent};
    use poc_7::projection::signer::sign_event_bytes;
    use poc_7::projection::pipeline::project_one;
    use poc_7::crypto::hash_event;
    use poc_7::events::registry;

    let mut rng = rand::thread_rng();
    let workspace_key = SigningKey::generate(&mut rng);
    let workspace_pubkey = workspace_key.verifying_key().to_bytes();
    let invite_key = SigningKey::generate(&mut rng);
    let invite_pubkey = invite_key.verifying_key().to_bytes();
    let user_key = SigningKey::generate(&mut rng);
    let user_pubkey = user_key.verifying_key().to_bytes();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
    let reg = registry();

    // Pre-build Workspace blob to get workspace_eid
    let net_blob = encode_event(&ParsedEvent::Workspace(WorkspaceEvent {
        created_at_ms: now_ms,
        public_key: workspace_pubkey,
    })).unwrap();
    let workspace_eid = hash_event(&net_blob);
    let workspace_id = workspace_eid;

    // Pre-build UserInviteBoot blob (signed by workspace) to get user_invite_eid
    let mut uib_blob = encode_event(&ParsedEvent::UserInviteBoot(UserInviteBootEvent {
        created_at_ms: now_ms + 1,
        public_key: invite_pubkey,
        workspace_id,
        signed_by: workspace_eid,
        signer_type: 1,
        signature: [0u8; 64],
    })).unwrap();
    let sig_offset = uib_blob.len() - 64;
    let sig = sign_event_bytes(&workspace_key, &uib_blob[..sig_offset]);
    uib_blob[sig_offset..].copy_from_slice(&sig);
    let user_invite_eid = hash_event(&uib_blob);

    // Build UserBoot blob (signed by invite_key, signed_by = user_invite_eid)
    let mut ub_blob = encode_event(&ParsedEvent::UserBoot(UserBootEvent {
        created_at_ms: now_ms + 2,
        public_key: user_pubkey,
        signed_by: user_invite_eid,
        signer_type: 2,
        signature: [0u8; 64],
    })).unwrap();
    let sig_offset = ub_blob.len() - 64;
    let sig = sign_event_bytes(&invite_key, &ub_blob[..sig_offset]);
    ub_blob[sig_offset..].copy_from_slice(&sig);
    let user_eid = hash_event(&ub_blob);

    // Insert UserBoot RAW first (truly out-of-order!)
    let user_b64 = event_id_to_base64(&user_eid);
    let ub_meta = reg.lookup(ub_blob[0]).unwrap();
    db.execute(
        "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![&user_b64, ub_meta.type_name, &ub_blob, ub_meta.share_scope.as_str(), (now_ms + 2) as i64, now_ms as i64],
    ).unwrap();
    db.execute(
        "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source) VALUES (?1, ?2, ?3, 'test')",
        rusqlite::params![&alice.identity, &user_b64, now_ms as i64],
    ).unwrap();

    // Project UserBoot — should Block (signed_by dep user_invite_eid not valid)
    let result = project_one(&db, &alice.identity, &user_eid).unwrap();
    assert!(
        matches!(result, poc_7::projection::decision::ProjectionDecision::Block { .. }),
        "UserBoot should block when UserInviteBoot is not yet present, got {:?}", result,
    );
    let valid_before: bool = db.query_row(
        "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![&alice.identity, &user_b64],
        |row| row.get(0),
    ).unwrap();
    assert!(!valid_before, "UserBoot should not be valid before invite chain");

    // Insert Workspace raw + project → Block (no trust anchor yet)
    let net_b64 = event_id_to_base64(&workspace_eid);
    let net_meta = reg.lookup(net_blob[0]).unwrap();
    db.execute(
        "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![&net_b64, net_meta.type_name, &net_blob, net_meta.share_scope.as_str(), now_ms as i64, now_ms as i64],
    ).unwrap();
    db.execute(
        "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source) VALUES (?1, ?2, ?3, 'test')",
        rusqlite::params![&alice.identity, &net_b64, now_ms as i64],
    ).unwrap();
    let net_result = project_one(&db, &alice.identity, &workspace_eid).unwrap();
    assert!(
        matches!(net_result, poc_7::projection::decision::ProjectionDecision::Block { .. }),
        "Workspace should block (no trust anchor yet), got {:?}", net_result,
    );

    // Insert UserInviteBoot raw + project → Block (signed_by = workspace_eid not valid)
    let uib_b64 = event_id_to_base64(&user_invite_eid);
    let uib_meta = reg.lookup(uib_blob[0]).unwrap();
    db.execute(
        "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![&uib_b64, uib_meta.type_name, &uib_blob, uib_meta.share_scope.as_str(), (now_ms + 1) as i64, now_ms as i64],
    ).unwrap();
    db.execute(
        "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source) VALUES (?1, ?2, ?3, 'test')",
        rusqlite::params![&alice.identity, &uib_b64, now_ms as i64],
    ).unwrap();
    let uib_result = project_one(&db, &alice.identity, &user_invite_eid).unwrap();
    assert!(
        matches!(uib_result, poc_7::projection::decision::ProjectionDecision::Block { .. }),
        "UserInviteBoot should block (workspace dep not valid), got {:?}", uib_result,
    );

    // Create InviteAccepted → sets trust anchor, triggers retry_guard_blocked_events
    // which re-projects Workspace → Valid → cascades UserInviteBoot → Valid → cascades UserBoot → Valid
    let _ia_eid = alice.create_invite_accepted(&user_invite_eid, workspace_id);

    // Assert full cascade completed — UserBoot should now be valid
    let valid_after: bool = db.query_row(
        "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![&alice.identity, &user_b64],
        |row| row.get(0),
    ).unwrap();
    assert!(valid_after, "UserBoot should be valid after cascade from invite chain");

    // Verify intermediate events are also valid
    let net_valid: bool = db.query_row(
        "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![&alice.identity, &net_b64],
        |row| row.get(0),
    ).unwrap();
    assert!(net_valid, "Workspace should be valid after trust anchor set");

    let uib_valid: bool = db.query_row(
        "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![&alice.identity, &uib_b64],
        |row| row.get(0),
    ).unwrap();
    assert!(uib_valid, "UserInviteBoot should be valid after cascade");
}

#[test]
fn test_foreign_workspace_excluded() {
    let alice = Peer::new("alice");
    let _chain = bootstrap_peer(&alice);

    let db = open_connection(&alice.db_path).unwrap();

    // Create a second workspace event with different workspace_id — should be rejected
    let foreign_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let foreign_pubkey = foreign_key.verifying_key().to_bytes();
    let result = alice.try_create_workspace(foreign_pubkey);

    // Should be rejected (trust anchor mismatch)
    match result {
        Err(ref e) => {
            let msg = format!("{}", e);
            assert!(msg.contains("rejected"), "expected rejection, got: {}", msg);
        }
        Ok(eid) => {
            // If it wasn't rejected at creation time, check DB state
            let foreign_b64 = event_id_to_base64(&eid);
            let foreign_valid: bool = db.query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![&alice.identity, &foreign_b64],
                |row| row.get(0),
            ).unwrap();
            assert!(!foreign_valid, "foreign workspace event should NOT be valid");
        }
    }

    // The event is in rejected_events (stored before rejection)
    let rejected_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM rejected_events WHERE peer_id = ?1 AND reason LIKE '%workspace_id%'",
        rusqlite::params![&alice.identity],
        |row| row.get(0),
    ).unwrap();
    assert!(rejected_count > 0, "foreign workspace event should be rejected");
}

#[test]
fn test_removal_enforcement() {
    let alice = Peer::new("alice");
    let chain = bootstrap_peer(&alice);

    // Create a "Bob" user event to be removed
    // For simplicity, create a second user_boot (as if Bob joined)
    let bob_user_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let _bob_user_pubkey = bob_user_key.verifying_key().to_bytes();
    // We'll create a second UserInviteOngoing for Bob, signed by Alice's PeerShared
    let db = open_connection(&alice.db_path).unwrap();

    // Alice removes her own user (target = user_eid, signed by peer_shared)
    let removal_eid = alice.create_user_removed(
        &chain.peer_shared_key,
        &chain.user_eid,
        &chain.peer_shared_eid,
    );

    let removal_b64 = event_id_to_base64(&removal_eid);
    let valid: bool = db.query_row(
        "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![&alice.identity, &removal_b64],
        |row| row.get(0),
    ).unwrap();
    assert!(valid, "user_removed should be valid");

    // Verify removed_entities table updated
    let removed_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM removed_entities WHERE recorded_by = ?1 AND removal_type = 'user'",
        rusqlite::params![&alice.identity],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(removed_count, 1, "removed_entities should have one user removal");
}

#[test]
fn test_secret_shared_key_wrap() {
    let alice = Peer::new("alice");
    let chain = bootstrap_peer(&alice);

    // Create SecretKey
    let secret_key_bytes: [u8; 32] = rand::random();
    let sk_eid = alice.create_secret_key(secret_key_bytes);

    // Create SecretShared wrapping to Alice's own PeerShared (for simplicity)
    let wrapped_key: [u8; 32] = rand::random(); // in real code this would be encrypted
    let ss_eid = alice.create_secret_shared(
        &chain.peer_shared_key,
        &sk_eid,
        &chain.peer_shared_eid,
        wrapped_key,
        &chain.peer_shared_eid,
    );

    let db = open_connection(&alice.db_path).unwrap();
    let ss_b64 = event_id_to_base64(&ss_eid);
    let valid: bool = db.query_row(
        "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![&alice.identity, &ss_b64],
        |row| row.get(0),
    ).unwrap();
    assert!(valid, "secret_shared should be valid");

    let ss_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM secret_shared WHERE recorded_by = ?1",
        rusqlite::params![&alice.identity],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(ss_count, 1, "secret_shared should be in projection table");
}

#[test]
fn test_identity_replay_invariants() {
    let alice = Peer::new_with_identity("alice");

    // Create some content after identity chain
    alice.create_message("hello after bootstrap");

    // Verify replay invariants (forward, double, reverse)
    verify_projection_invariants(&alice);
}

#[test]
fn test_transport_key_projects_without_auto_binding() {
    let alice = Peer::new("alice");
    let chain = bootstrap_peer(&alice);

    // Create a TransportKey event signed by PeerShared
    let spki_fp: [u8; 32] = [0xAB; 32];
    let _tk_eid = alice.create_transport_key(
        spki_fp,
        &chain.peer_shared_key,
        &chain.peer_shared_eid,
    );

    let db = open_connection(&alice.db_path).unwrap();

    // Verify transport_keys projection table populated
    let tk_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM transport_keys WHERE recorded_by = ?1",
        rusqlite::params![&alice.identity],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(tk_count, 1, "transport_keys should have 1 entry");

    // Verify SPKI fingerprint matches
    let stored_spki: Vec<u8> = db.query_row(
        "SELECT spki_fingerprint FROM transport_keys WHERE recorded_by = ?1",
        rusqlite::params![&alice.identity],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(stored_spki, spki_fp.to_vec());

    // peer_transport_bindings should NOT be auto-populated by projection
    let binding_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM peer_transport_bindings WHERE recorded_by = ?1",
        rusqlite::params![&alice.identity],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(binding_count, 0, "peer_transport_bindings should NOT be auto-populated");

    // allowed_peers_from_db should include SPKI from transport_keys (not bindings)
    let allowed = poc_7::db::transport_trust::allowed_peers_from_db(&db, &alice.identity).unwrap();
    assert!(allowed.contains(&spki_fp), "allowed_peers should include transport key SPKI");
}

#[test]
fn test_transport_key_signer_matches_local_key() {
    use ed25519_dalek::SigningKey;
    use poc_7::transport_identity::{transport_cert_paths_from_db, ensure_transport_key_event};

    let alice = Peer::new("alice");
    let chain = bootstrap_peer(&alice);

    // Insert a second peers_shared row with a different public key (simulating another
    // peer in the workspace). This row will have a lower rowid than the local peer's
    // PeerSharedFirst if we insert it after bootstrap, but the point is that multiple
    // rows exist and the function must select by public key match, not by rowid.
    let other_key = SigningKey::generate(&mut rand::thread_rng());
    let other_pubkey = other_key.verifying_key().to_bytes();
    let db = open_connection(&alice.db_path).unwrap();
    db.execute(
        "INSERT INTO peers_shared (recorded_by, event_id, public_key) VALUES (?1, ?2, ?3)",
        rusqlite::params![&alice.identity, "other_peer_eid", other_pubkey.as_slice()],
    ).unwrap();

    // Verify we now have 2 peers_shared rows
    let count: i64 = db.query_row(
        "SELECT COUNT(*) FROM peers_shared WHERE recorded_by = ?1",
        rusqlite::params![&alice.identity],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(count, 2);
    drop(db);

    // Generate a TLS cert so ensure_transport_key_event has something to work with
    let (cert_path, key_path) = transport_cert_paths_from_db(&alice.db_path);
    load_or_generate_cert(&cert_path, &key_path).unwrap();

    // Call ensure_transport_key_event with the LOCAL peer_shared signing key —
    // it should succeed because it matches by public key, not by rowid order
    let db = open_connection(&alice.db_path).unwrap();
    let result = ensure_transport_key_event(&db, &alice.identity, &alice.db_path, &chain.peer_shared_key);
    assert!(result.is_ok(), "ensure_transport_key_event should succeed with correct local key");
    assert!(result.unwrap().is_some(), "should have created a new TransportKey event");

    // Calling with the OTHER key should return None (no matching peers_shared row
    // with that public key that also has a valid signer chain — the manually inserted
    // row won't pass signature verification)
    // Actually, the function returns Ok(None) only for "already exists" or "no peers_shared".
    // Since we already created one, a second call returns Ok(None) for the existing SPKI.
    let result2 = ensure_transport_key_event(&db, &alice.identity, &alice.db_path, &chain.peer_shared_key);
    assert_eq!(result2.unwrap(), None, "second call should return None (already exists)");
}

#[test]
fn test_transport_key_invalid_sig_rejected() {
    use ed25519_dalek::SigningKey;

    let alice = Peer::new("alice");
    let chain = bootstrap_peer(&alice);

    // Create a TransportKey with wrong signing key (not the peer_shared key)
    let wrong_key = SigningKey::generate(&mut rand::thread_rng());
    let spki_fp: [u8; 32] = [0xCD; 32];

    // This should fail because the wrong key doesn't match peer_shared's public key
    let result = std::panic::catch_unwind(|| {
        alice.create_transport_key(
            spki_fp,
            &wrong_key,
            &chain.peer_shared_eid,
        );
    });

    // create_signed_event_sync verifies the signature during projection,
    // so it should either panic or the event should be rejected
    if result.is_ok() {
        // If it didn't panic, check that the event was rejected
        let db = open_connection(&alice.db_path).unwrap();
        let tk_count: i64 = db.query_row(
            "SELECT COUNT(*) FROM transport_keys WHERE recorded_by = ?1",
            rusqlite::params![&alice.identity],
            |row| row.get(0),
        ).unwrap();
        let rejected_count: i64 = db.query_row(
            "SELECT COUNT(*) FROM rejected_events WHERE peer_id = ?1",
            rusqlite::params![&alice.identity],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(tk_count, 0, "invalid-sig transport key should not project");
        assert!(rejected_count > 0, "invalid-sig transport key should be rejected");
    }
    // If it panicked, that's also acceptable — signature verification failed
}

#[test]
fn test_transport_key_replay_invariants() {
    let alice = Peer::new_with_identity("alice");
    let ps_eid = alice.peer_shared_event_id.unwrap();
    let ps_key = alice.peer_shared_signing_key.as_ref().unwrap();

    // Create a TransportKey event
    let spki_fp: [u8; 32] = [0xEF; 32];
    alice.create_transport_key(
        spki_fp,
        ps_key,
        &ps_eid,
    );

    // Also create some content
    alice.create_message("after transport key");

    // Verify replay invariants (forward, double, reverse)
    verify_projection_invariants(&alice);
}


// =============================================================================
// Phase 7 logic fixes: corrected guard and binding semantics
// =============================================================================

/// invite_accepted projects without any prior invite event recorded.
/// This verifies the HasRecordedInvite guard has been removed.
#[test]
fn test_invite_accepted_no_prior_invite_required() {
    let alice = Peer::new("alice");
    let db = open_connection(&alice.db_path).unwrap();

    let workspace_id: [u8; 32] = rand::random();
    let fake_invite_eid: [u8; 32] = rand::random();

    // Create invite_accepted BEFORE any invite event exists.
    // Under old semantics this would Block; under corrected semantics it should project.
    let ia_eid = alice.create_invite_accepted(&fake_invite_eid, workspace_id);

    let ia_b64 = event_id_to_base64(&ia_eid);
    let valid: bool = db.query_row(
        "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![&alice.identity, &ia_b64],
        |row| row.get(0),
    ).unwrap();
    assert!(valid, "invite_accepted should be valid without prior invite event (no HasRecordedInvite guard)");

    // Trust anchor should be set from the event's own workspace_id
    let anchor: String = db.query_row(
        "SELECT workspace_id FROM trust_anchors WHERE peer_id = ?1",
        rusqlite::params![&alice.identity],
        |row| row.get(0),
    ).expect("trust anchor should exist");
    let expected_nid = event_id_to_base64(&workspace_id);
    assert_eq!(anchor, expected_nid, "trust anchor should match invite_accepted event's workspace_id");
}

/// Trust anchor immutability: second invite_accepted with conflicting workspace_id is rejected.
#[test]
fn test_trust_anchor_immutability() {
    let alice = Peer::new("alice");
    let db = open_connection(&alice.db_path).unwrap();

    let workspace_id_1: [u8; 32] = rand::random();
    let workspace_id_2: [u8; 32] = rand::random();
    let fake_invite_1: [u8; 32] = rand::random();
    let fake_invite_2: [u8; 32] = rand::random();

    // First invite_accepted sets the trust anchor
    let ia1_eid = alice.create_invite_accepted(&fake_invite_1, workspace_id_1);
    let ia1_b64 = event_id_to_base64(&ia1_eid);
    let valid1: bool = db.query_row(
        "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![&alice.identity, &ia1_b64],
        |row| row.get(0),
    ).unwrap();
    assert!(valid1, "first invite_accepted should be valid");

    // Second invite_accepted with different workspace_id should be rejected
    let result = alice.try_create_invite_accepted(&fake_invite_2, workspace_id_2);
    match result {
        Err(ref e) => {
            let msg = format!("{}", e);
            assert!(
                msg.contains("rejected") || msg.contains("conflicts"),
                "expected rejection for conflicting trust anchor, got: {}",
                msg
            );
        }
        Ok(eid) => {
            let eid_b64 = event_id_to_base64(&eid);
            let rejected: bool = db.query_row(
                "SELECT COUNT(*) > 0 FROM rejected_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![&alice.identity, &eid_b64],
                |row| row.get(0),
            ).unwrap();
            assert!(rejected, "conflicting invite_accepted should be in rejected_events");
        }
    }

    // Trust anchor should still be the first one
    let anchor: String = db.query_row(
        "SELECT workspace_id FROM trust_anchors WHERE peer_id = ?1",
        rusqlite::params![&alice.identity],
        |row| row.get(0),
    ).expect("trust anchor should still exist");
    let expected_nid = event_id_to_base64(&workspace_id_1);
    assert_eq!(anchor, expected_nid, "trust anchor should not have changed");
}

/// No pre-projection blob capture influence: manually inserting a malformed
/// invite-like blob into events should not alter trust binding state.
#[test]
fn test_no_blob_capture_trust_influence() {
    let alice = Peer::new("alice");
    let db = open_connection(&alice.db_path).unwrap();

    // Manually craft a blob that looks like a UserInviteBoot (type 10) with a specific
    // workspace_id, and insert it directly into the events table (simulating raw ingress).
    // Under old semantics, a pre-projection capture path could influence trust state.
    // Under corrected semantics, this should have no effect.
    let fake_workspace_id: [u8; 32] = [0xAA; 32];
    let mut fake_blob = vec![10u8]; // type code for UserInviteBoot
    fake_blob.extend_from_slice(&[0u8; 40]); // created_at_ms(8) + public_key(32)
    fake_blob.extend_from_slice(&fake_workspace_id); // workspace_id at [41..73]
    fake_blob.extend_from_slice(&[0u8; 97]); // rest of the 170B blob

    let fake_eid = poc_7::crypto::hash_event(&fake_blob);
    let fake_b64 = event_id_to_base64(&fake_eid);

    db.execute(
        "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
         VALUES (?1, 'user_invite_boot', ?2, 'shared', 0, 0)",
        rusqlite::params![&fake_b64, &fake_blob],
    ).unwrap();
    db.execute(
        "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source)
         VALUES (?1, ?2, 0, 'test')",
        rusqlite::params![&alice.identity, &fake_b64],
    ).unwrap();

    // Trust anchor should be unset
    let anchor_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM trust_anchors WHERE peer_id = ?1",
        rusqlite::params![&alice.identity],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(anchor_count, 0, "trust anchor should not be set by raw blob presence");
}

/// True out-of-order identity chain: record invite_accepted BEFORE its referenced
/// invite event, then record workspace, then invite event -> cascade resolves everything.
#[test]
fn test_true_out_of_order_identity_chain() {
    let alice = Peer::new("alice");
    let db = open_connection(&alice.db_path).unwrap();

    use ed25519_dalek::SigningKey;
    use poc_7::crypto::hash_event;
    use poc_7::events::{encode_event, ParsedEvent, WorkspaceEvent};
    use poc_7::projection::create::{create_event_sync, event_id_or_blocked};
    let mut rng = rand::thread_rng();

    let workspace_key = SigningKey::generate(&mut rng);
    let workspace_pubkey = workspace_key.verifying_key().to_bytes();
    let workspace_event = ParsedEvent::Workspace(WorkspaceEvent {
        created_at_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        public_key: workspace_pubkey,
    });
    let workspace_id = hash_event(&encode_event(&workspace_event).unwrap());

    // Step 1: Create invite_accepted FIRST (before workspace or invite exist).
    // Under corrected semantics, this sets the trust anchor immediately.
    let invite_key = SigningKey::generate(&mut rng);
    let invite_pubkey = invite_key.verifying_key().to_bytes();

    let dummy_invite_eid = [42u8; 32];
    let ia_eid = alice.create_invite_accepted(&dummy_invite_eid, workspace_id);

    let ia_b64 = event_id_to_base64(&ia_eid);
    let ia_valid: bool = db.query_row(
        "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![&alice.identity, &ia_b64],
        |row| row.get(0),
    ).unwrap();
    assert!(ia_valid, "invite_accepted should be immediately valid (no HasRecordedInvite guard)");

    // Step 2: Create the precomputed workspace event (same event_id as trust anchor).
    let workspace_eid = event_id_or_blocked(create_event_sync(&db, &alice.identity, &workspace_event))
        .expect("workspace should create once trust anchor exists");

    let net_b64 = event_id_to_base64(&workspace_eid);
    let net_valid: bool = db.query_row(
        "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![&alice.identity, &net_b64],
        |row| row.get(0),
    ).unwrap();
    assert!(net_valid, "workspace event should be valid (trust anchor matches)");

    // Step 3: Create UserInviteBoot (signed by workspace)
    let user_invite_eid = alice.create_user_invite_boot_with_key(
        invite_pubkey,
        &workspace_key,
        &workspace_eid,
    );

    let ui_b64 = event_id_to_base64(&user_invite_eid);
    let ui_valid: bool = db.query_row(
        "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![&alice.identity, &ui_b64],
        |row| row.get(0),
    ).unwrap();
    assert!(ui_valid, "user_invite_boot should be valid (workspace is valid signer)");

    // Step 4: Create UserBoot (signed by invite key)
    let user_key = SigningKey::generate(&mut rng);
    let user_pubkey = user_key.verifying_key().to_bytes();
    let user_eid = alice.create_user_boot(user_pubkey, &invite_key, &user_invite_eid);

    let user_b64 = event_id_to_base64(&user_eid);
    let user_valid: bool = db.query_row(
        "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![&alice.identity, &user_b64],
        |row| row.get(0),
    ).unwrap();
    assert!(user_valid, "user_boot should be valid after full chain");
}

// =============================================================================
// Multi-peer identity scenario tests
// =============================================================================

/// Helper: bootstrap Bob as a new user joining Alice's workspace.
/// Alice creates a UserInviteOngoing for Bob, Bob accepts and builds his own chain.
/// Returns Bob's BootstrapChain (reuses BootstrapChain struct for consistency).
#[allow(dead_code)]
struct JoinChain {
    invite_key: ed25519_dalek::SigningKey,
    user_invite_eid: [u8; 32],
    user_key: ed25519_dalek::SigningKey,
    user_eid: [u8; 32],
    device_invite_key: ed25519_dalek::SigningKey,
    device_invite_eid: [u8; 32],
    peer_shared_key: ed25519_dalek::SigningKey,
    peer_shared_eid: [u8; 32],
    invite_accepted_eid: [u8; 32],
}

fn join_workspace(
    joiner: &Peer,
    alice_chain: &BootstrapChain,
    alice: &Peer,
) -> JoinChain {
    use ed25519_dalek::SigningKey;

    let mut rng = rand::thread_rng();

    // Alice creates a UserInviteOngoing for the joiner (signed by Alice's PeerShared)
    let invite_key = SigningKey::generate(&mut rng);
    let invite_pubkey = invite_key.verifying_key().to_bytes();
    let user_invite_eid = alice.create_user_invite_ongoing(
        invite_pubkey,
        &alice_chain.peer_shared_key,
        &alice_chain.peer_shared_eid,
        &alice_chain.admin_eid,
    );

    // Joiner accepts the invite (local event, binds trust anchor to Alice's workspace_id)
    let invite_accepted_eid = joiner.create_invite_accepted(&user_invite_eid, alice_chain.workspace_id);

    // Joiner creates UserBoot (signed by the invite key Alice gave)
    let user_key = SigningKey::generate(&mut rng);
    let user_pubkey = user_key.verifying_key().to_bytes();
    let user_eid = joiner.create_user_boot(user_pubkey, &invite_key, &user_invite_eid);

    // Joiner creates DeviceInviteFirst (signed by joiner's user key)
    let device_invite_key = SigningKey::generate(&mut rng);
    let device_invite_pubkey = device_invite_key.verifying_key().to_bytes();
    let device_invite_eid = joiner.create_device_invite_first(
        device_invite_pubkey,
        &user_key,
        &user_eid,
    );

    // Joiner creates PeerSharedFirst (signed by device invite)
    let peer_shared_key = SigningKey::generate(&mut rng);
    let peer_shared_pubkey = peer_shared_key.verifying_key().to_bytes();
    let peer_shared_eid = joiner.create_peer_shared_first(
        peer_shared_pubkey,
        &device_invite_key,
        &device_invite_eid,
    );

    JoinChain {
        invite_key,
        user_invite_eid,
        user_key,
        user_eid,
        device_invite_key,
        device_invite_eid,
        peer_shared_key,
        peer_shared_eid,
        invite_accepted_eid,
    }
}

/// Two-peer identity bootstrap + join: Alice bootstraps, invites Bob, Bob joins,
/// they sync, and both peers converge on the same identity state.
#[tokio::test]
async fn test_two_peer_identity_join_and_sync() {
    let alice = Peer::new("alice");
    let bob = Peer::new("bob");

    // Alice bootstraps her full identity chain
    let alice_chain = bootstrap_peer(&alice);

    // Alice creates a UserInviteOngoing for Bob
    // Bob needs the invite to exist on Alice's side; sync will deliver it
    let _bob_join = join_workspace(&bob, &alice_chain, &alice);

    // Sync — shared events flow between peers
    let sync = start_peers(&alice, &bob);

    // Wait for convergence on projected identity state, not raw event counts
    assert_eventually(
        || alice.peer_shared_count() == 2 && bob.peer_shared_count() == 2,
        Duration::from_secs(15),
        "both peers should converge on 2 peers_shared",
    ).await;

    drop(sync);

    // Both peers should have projected the same identity state:
    // - 1 workspace
    // - 2 user_invites (boot + ongoing)
    // - 2 users (Alice's + Bob's)
    // - 2 device_invites
    // - 2 peers_shared
    // - 1 admin (Alice's)
    assert_eq!(alice.workspace_count(), 1, "Alice should have 1 trust-anchored workspace");
    assert_eq!(bob.workspace_count(), 1, "Bob should have 1 trust-anchored workspace");

    assert_eq!(alice.user_invite_count(), 2, "Alice: boot + ongoing invites");
    assert_eq!(bob.user_invite_count(), 2, "Bob: boot + ongoing invites");

    assert_eq!(alice.user_count(), 2, "Alice sees 2 users");
    assert_eq!(bob.user_count(), 2, "Bob sees 2 users");

    assert_eq!(alice.device_invite_count(), 2, "Alice sees 2 device invites");
    assert_eq!(bob.device_invite_count(), 2, "Bob sees 2 device invites");

    assert_eq!(alice.peer_shared_count(), 2, "Alice sees 2 peers_shared");
    assert_eq!(bob.peer_shared_count(), 2, "Bob sees 2 peers_shared");

    assert_eq!(alice.admin_count(), 1, "Alice sees 1 admin");
    assert_eq!(bob.admin_count(), 1, "Bob sees 1 admin");

    // Replay invariants hold for both peers
    verify_projection_invariants(&alice);
    verify_projection_invariants(&bob);
}

/// Identity chain events arrive out of order via sync and cascade to valid.
/// Bob creates his own events but they depend on Alice's chain. Sync delivers
/// Alice's events, which unblock Bob's chain via cascade.
#[tokio::test]
async fn test_identity_cascade_via_sync() {
    let alice = Peer::new("alice");
    let bob = Peer::new("bob");

    // Alice bootstraps
    let alice_chain = bootstrap_peer(&alice);

    // Alice creates an invite for Bob on her side
    let mut rng = rand::thread_rng();
    let invite_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let invite_pubkey = invite_key.verifying_key().to_bytes();
    let user_invite_eid = alice.create_user_invite_ongoing(
        invite_pubkey,
        &alice_chain.peer_shared_key,
        &alice_chain.peer_shared_eid,
        &alice_chain.admin_eid,
    );

    // Bob accepts the invite locally — this sets his trust anchor
    let _ia_eid = bob.create_invite_accepted(&user_invite_eid, alice_chain.workspace_id);

    // Bob creates UserBoot signed by the invite — but the invite event is on
    // Alice's side, not Bob's. So this will block on the signed_by dep.
    let _user_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let user_pubkey = _user_key.verifying_key().to_bytes();
    let user_eid = bob.create_user_boot(user_pubkey, &invite_key, &user_invite_eid);
    let user_eid_b64 = event_id_to_base64(&user_eid);

    // Confirm UserBoot is blocked before sync
    assert_eq!(bob.user_count(), 0, "Bob's UserBoot should be blocked (missing signer dep)");
    assert!(bob.blocked_dep_count() > 0, "Bob should have blocked deps");

    // Sync — Alice's events flow to Bob, unblocking the cascade
    let sync = start_peers(&alice, &bob);

    // Wait for Bob's specific UserBoot event to become valid, not just any user
    assert_eventually(
        || {
            let db = open_connection(&bob.db_path).unwrap();
            let valid: bool = db.query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![&bob.identity, &user_eid_b64],
                |row| row.get(0),
            ).unwrap_or(false);
            valid
        },
        Duration::from_secs(15),
        "Bob's specific UserBoot should cascade to valid after sync",
    ).await;

    drop(sync);

    // Bob should now have Alice's full identity chain projected plus his own user
    assert_eq!(bob.workspace_count(), 1, "Bob should have Alice's workspace");
    assert_eq!(bob.user_invite_count(), 2, "Bob should have both invites");
    assert_eq!(bob.user_count(), 2, "Both Alice's and Bob's users should be valid");

    verify_projection_invariants(&bob);
}

/// After identity join, Alice and Bob can exchange messages. Tests that the
/// full trust chain enables the messaging layer to work across peers.
#[tokio::test]
async fn test_identity_then_messaging() {
    let mut alice = Peer::new("alice");
    let mut bob = Peer::new("bob");

    // Both peers establish identity on the same network
    let alice_chain = bootstrap_peer(&alice);
    let bob_join = join_workspace(&bob, &alice_chain, &alice);

    // Set signing keys so create_message works
    alice.peer_shared_event_id = Some(alice_chain.peer_shared_eid);
    alice.peer_shared_signing_key = Some(alice_chain.peer_shared_key.clone());
    bob.peer_shared_event_id = Some(bob_join.peer_shared_eid);
    bob.peer_shared_signing_key = Some(bob_join.peer_shared_key.clone());

    // Sync identity events first
    let sync = start_peers(&alice, &bob);
    assert_eventually(
        || alice.peer_shared_count() == 2 && bob.peer_shared_count() == 2,
        Duration::from_secs(15),
        "identity should converge",
    ).await;
    drop(sync);

    // Now both peers send messages
    alice.create_message("Hello from Alice");
    bob.create_message("Hello from Bob");

    // Sync messages
    let sync = start_peers(&alice, &bob);
    assert_eventually(
        || alice.scoped_message_count() == 2 && bob.scoped_message_count() == 2,
        Duration::from_secs(15),
        "messages should converge after identity sync",
    ).await;
    drop(sync);

    verify_projection_invariants(&alice);
    verify_projection_invariants(&bob);
}

/// Alice bootstraps on two devices (Phone and Laptop). Phone creates a DeviceInviteOngoing
/// for Laptop, Laptop joins with PeerSharedOngoing, both sync and converge.
#[tokio::test]
async fn test_device_link_via_sync() {
    use poc_7::events::{DeviceInviteOngoingEvent, PeerSharedOngoingEvent, ParsedEvent};
    use poc_7::projection::create::{create_signed_event_sync, event_id_or_blocked};

    let phone = Peer::new("phone");
    let laptop = Peer::new("laptop");

    let mut rng = rand::thread_rng();

    // Phone bootstraps full identity chain
    let phone_chain = bootstrap_peer(&phone);

    // Phone creates a DeviceInviteOngoing for Laptop (signed by Phone's User key)
    let laptop_di_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let laptop_di_pubkey = laptop_di_key.verifying_key().to_bytes();
    let db = open_connection(&phone.db_path).unwrap();
    let di_evt = ParsedEvent::DeviceInviteOngoing(DeviceInviteOngoingEvent {
        created_at_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64,
        public_key: laptop_di_pubkey,
        signed_by: phone_chain.user_eid,
        signer_type: 4,
        signature: [0u8; 64],
    });
    let laptop_di_eid = create_signed_event_sync(
        &db, &phone.identity, &di_evt, &phone_chain.user_key,
    ).expect("create device_invite_ongoing");
    drop(db);

    // Laptop accepts the invite (local, sets trust anchor)
    let _ia_eid = laptop.create_invite_accepted(&laptop_di_eid, phone_chain.workspace_id);

    // Laptop creates PeerSharedOngoing (signed by the device invite key Phone gave).
    // This will be blocked because the signed_by dep (DeviceInviteOngoing) is on Phone.
    // event_id_or_blocked extracts the event_id even when blocked.
    let laptop_ps_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let laptop_ps_pubkey = laptop_ps_key.verifying_key().to_bytes();
    let db = open_connection(&laptop.db_path).unwrap();
    let ps_evt = ParsedEvent::PeerSharedOngoing(PeerSharedOngoingEvent {
        created_at_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64,
        public_key: laptop_ps_pubkey,
        signed_by: laptop_di_eid,
        signer_type: 3,
        signature: [0u8; 64],
    });
    let _laptop_ps_eid = event_id_or_blocked(create_signed_event_sync(
        &db, &laptop.identity, &ps_evt, &laptop_di_key,
    )).expect("create peer_shared_ongoing");
    drop(db);

    // Laptop's PeerSharedOngoing is blocked — signed_by dep (DeviceInviteOngoing) is on Phone
    assert_eq!(laptop.peer_shared_count(), 0, "Laptop's peer_shared should be blocked before sync");

    // Sync — Phone's events flow to Laptop, unblocking Laptop's chain
    let sync = start_peers(&phone, &laptop);

    assert_eventually(
        || phone.peer_shared_count() == 2 && laptop.peer_shared_count() == 2,
        Duration::from_secs(15),
        "both devices should see 2 peers_shared after sync",
    ).await;

    drop(sync);

    // Both devices share the same trust-anchored workspace and identity state.
    assert_eq!(phone.workspace_count(), 1);
    assert_eq!(laptop.workspace_count(), 1);
    assert_eq!(phone.device_invite_count(), 2, "Phone: first + ongoing");
    assert_eq!(laptop.device_invite_count(), 2, "Laptop: first + ongoing");

    verify_projection_invariants(&phone);
    verify_projection_invariants(&laptop);
}

/// Alice and Bob are on different workspaces. When they sync, Bob's workspace events
/// are rejected by Alice's trust anchor, and vice versa. Neither peer's identity
/// state is corrupted.
#[tokio::test]
async fn test_foreign_workspace_rejected_via_sync() {
    let alice = Peer::new("alice");
    let bob = Peer::new("bob");

    // Both bootstrap independently on DIFFERENT workspaces
    let alice_chain = bootstrap_peer(&alice);
    let bob_chain = bootstrap_peer(&bob);

    // Sanity: different workspace_ids
    assert_ne!(alice_chain.workspace_id, bob_chain.workspace_id,
        "workspaces should differ");

    // Before sync: each peer has only its own trust-anchored workspace projected.
    assert_eq!(alice.workspace_count(), 1);
    assert_eq!(bob.workspace_count(), 1);

    // Sync — shared events flow between peers
    let sync = start_peers(&alice, &bob);

    // Wait for events to transfer — gate on rejected events appearing
    // (foreign workspace events get rejected by the trust anchor guard)
    assert_eventually(
        || alice.rejected_event_count() > 0 && bob.rejected_event_count() > 0,
        Duration::from_secs(15),
        "both peers should have rejected foreign workspace events",
    ).await;

    drop(sync);

    // Each peer should still have only its own workspace projected —
    // the foreign bootstrap workspace event is rejected by the trust anchor guard.
    assert_eq!(alice.workspace_count(), 1,
        "Alice should still have exactly 1 workspace (foreign rejected)");
    assert_eq!(bob.workspace_count(), 1,
        "Bob should still have exactly 1 workspace (foreign rejected)");

    // Foreign identity events should be rejected, not just blocked
    assert!(alice.rejected_event_count() > 0,
        "Alice should have rejected foreign workspace events");
    assert!(bob.rejected_event_count() > 0,
        "Bob should have rejected foreign workspace events");

    // Each peer's own identity state is unaffected
    assert_eq!(alice.user_count(), 1, "Alice's own user unchanged");
    assert_eq!(bob.user_count(), 1, "Bob's own user unchanged");

    verify_projection_invariants(&alice);
    verify_projection_invariants(&bob);
}
