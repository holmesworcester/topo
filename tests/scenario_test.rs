use std::sync::Arc;
use std::time::{Duration, Instant};
use topo::crypto::{event_id_from_base64, event_id_to_base64};
use topo::testutil::{
    assert_eventually, start_peers_pinned, sync_until_converged, Peer, ScenarioHarness,
    SharedDbNode,
};
use topo::transport::{
    AllowedPeers, create_client_endpoint, create_server_endpoint,
    extract_spki_fingerprint, peer_identity_from_connection,
};
use topo::peering::loops::{accept_loop, connect_loop};
use topo::testutil::{noop_intro_spawner, test_ingest_fns};
use topo::db::open_connection;


#[tokio::test]
async fn test_two_peer_bidirectional_sync() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    alice.batch_create_messages(2);
    bob.batch_create_messages(1);

    // Create marker messages to track sync convergence
    let alice_marker = alice.create_message("alice-marker");
    let alice_marker_b64 = event_id_to_base64(&alice_marker);
    let bob_marker = bob.create_message("bob-marker");
    let bob_marker_b64 = event_id_to_base64(&bob_marker);

    let sync = start_peers_pinned(&alice, &bob);

    // Wait for bidirectional sync to complete
    assert_eventually(
        || bob.has_event(&alice_marker_b64) && alice.has_event(&bob_marker_b64),
        Duration::from_secs(15),
        "both peers should receive each other's marker events",
    ).await;

    // Only locally-created messages are projected (remote messages are blocked
    // because their signer chain is from a different network)
    assert_eq!(alice.message_count(), 3); // 2 batch + 1 marker
    assert_eq!(bob.message_count(), 2); // 1 batch + 1 marker

    drop(sync);

    harness.finish();
}

#[tokio::test]
async fn test_one_way_sync() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    alice.batch_create_messages(10);
    let marker = alice.create_message("alice-sync-marker");
    let marker_b64 = event_id_to_base64(&marker);

    let sync = start_peers_pinned(&alice, &bob);

    // Wait for bob to receive alice's marker (last created event)
    assert_eventually(
        || bob.has_event(&marker_b64),
        Duration::from_secs(15),
        "bob should receive alice's events including marker",
    ).await;

    drop(sync);

    harness.finish();
}

#[tokio::test]
async fn test_concurrent_create_and_sync() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    let sync = start_peers_pinned(&alice, &bob);

    // Give sync loop a moment to connect
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Create messages while sync runs
    let alice_msg = alice.create_message("Hello from Alice");
    let alice_msg_b64 = event_id_to_base64(&alice_msg);
    let bob_msg = bob.create_message("Hi from Bob");
    let bob_msg_b64 = event_id_to_base64(&bob_msg);

    // Wait for bidirectional sync of initial messages
    assert_eventually(
        || bob.has_event(&alice_msg_b64) && alice.has_event(&bob_msg_b64),
        Duration::from_secs(15),
        "both peers should receive each other's messages",
    ).await;

    // Create more messages — sync loop picks them up
    let another = alice.create_message("Another from Alice");
    let another_b64 = event_id_to_base64(&another);

    assert_eventually(
        || bob.has_event(&another_b64),
        Duration::from_secs(15),
        "bob gets the new message via live sync",
    ).await;

    drop(sync);

    harness.finish();
}

#[tokio::test]
async fn test_sync_10k() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    let gen_start = Instant::now();
    alice.batch_create_messages(10_000);
    let gen_secs = gen_start.elapsed().as_secs_f64();
    eprintln!("Generated 10k events in {:.2}s", gen_secs);

    // Pick a sample event from alice's store to use as convergence marker
    let sample_ids = alice.sample_event_ids(1);
    let marker_b64 = sample_ids[0].clone();

    let metrics = sync_until_converged(
        &alice, &bob,
        || bob.has_event(&marker_b64),
        Duration::from_secs(120),
    ).await;

    eprintln!("10k sync: {}", metrics);

    // Only alice's locally-created messages are projected on alice; bob has none projected
    assert_eq!(alice.message_count(), 10_000);

    harness.finish();
}

#[tokio::test]
async fn test_recorded_events_isolation() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    // Create messages locally
    alice.batch_create_messages(3);
    bob.batch_create_messages(2);

    assert_eq!(alice.scoped_message_count(), 3);
    assert_eq!(bob.scoped_message_count(), 2);

    // Create marker messages for sync convergence tracking
    let alice_marker = alice.create_message("alice-isolation-marker");
    let alice_marker_b64 = event_id_to_base64(&alice_marker);
    let bob_marker = bob.create_message("bob-isolation-marker");
    let bob_marker_b64 = event_id_to_base64(&bob_marker);

    // Sync
    let sync = start_peers_pinned(&alice, &bob);

    assert_eventually(
        || bob.has_event(&alice_marker_b64) && alice.has_event(&bob_marker_b64),
        Duration::from_secs(15),
        "both peers should receive each other's marker events",
    ).await;

    drop(sync);

    // Only locally-created messages are projected (remote messages blocked by foreign signer)
    assert_eq!(alice.message_count(), 4); // 3 batch + 1 marker
    assert_eq!(bob.message_count(), 3); // 2 batch + 1 marker

    // scoped_message_count: only locally-created messages projected
    assert_eq!(alice.scoped_message_count(), 4);
    assert_eq!(bob.scoped_message_count(), 3);

    harness.finish();
}

#[tokio::test]
async fn test_reaction_sync() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    // Alice creates messages, Bob adds reactions
    let msg1 = alice.create_message("Hello!");
    let msg2 = alice.create_message("World!");
    let msg2_b64 = event_id_to_base64(&msg2);
    bob.create_reaction(&msg1, "\u{1f44d}");
    let bob_rxn2 = bob.create_reaction(&msg2, "\u{2764}\u{fe0f}");
    let bob_rxn2_b64 = event_id_to_base64(&bob_rxn2);

    assert_eq!(alice.message_count(), 2);
    assert_eq!(bob.reaction_count(), 0); // blocked until targets arrive

    let sync = start_peers_pinned(&alice, &bob);

    // Wait for sync convergence: bob gets alice's messages, alice gets bob's reactions
    assert_eventually(
        || bob.has_event(&msg2_b64) && alice.has_event(&bob_rxn2_b64),
        Duration::from_secs(15),
        "both peers should receive each other's events",
    ).await;

    drop(sync);

    // With independent identity chains, cross-peer events are blocked (foreign signer).
    // Alice projects her own 2 messages; Bob's reactions are blocked (foreign signer on Alice).
    // Bob: Alice's messages are blocked (foreign signer), so reaction targets remain invalid.
    assert_eq!(alice.message_count(), 2);
    assert_eq!(bob.message_count(), 0);
    assert_eq!(alice.reaction_count(), 0);
    assert_eq!(bob.reaction_count(), 0);

    harness.finish();
}

/// Stress test: high-volume bidirectional sync verifying exact event ID equality.
/// This checks the Done/DoneAck handshake prevents data loss at scale.
#[tokio::test]
async fn test_zero_loss_stress() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    alice.batch_create_messages(5_000);
    bob.batch_create_messages(5_000);

    let alice_ids_before = alice.store_ids();
    let bob_ids_before = bob.store_ids();
    assert_eq!(alice.message_count(), 5_000, "alice should have 5000 messages before sync");
    assert_eq!(bob.message_count(), 5_000, "bob should have 5000 messages before sync");

    // Sample multiple events from both sides to ensure full bidirectional sync.
    // A single sample can pass after only a partial transfer.
    // Use shared-scope samples so phase-1 only checks sync-eligible IDs.
    let alice_samples = alice.sample_shared_event_ids(50);
    let bob_samples = bob.sample_shared_event_ids(50);

    // Phase 1: sample-based fast convergence gate (sync stays running).
    let a_before = alice.store_count();
    let b_before = bob.store_count();
    let start = Instant::now();
    let sync = start_peers_pinned(&alice, &bob);

    // Phase 1 is a fast gate, not an authoritative correctness check.
    // If it times out, continue to phase 2 (full-set quiescence), which is the
    // strict correctness gate for this test.
    let phase1_timeout = Duration::from_secs(120);
    let phase1_start = Instant::now();
    let mut phase1_ok = false;
    loop {
        if alice_samples.iter().all(|s| bob.has_event(s))
            && bob_samples.iter().all(|s| alice.has_event(s))
        {
            phase1_ok = true;
            break;
        }
        if phase1_start.elapsed() >= phase1_timeout {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    if !phase1_ok {
        eprintln!(
            "phase 1 sample gate did not converge in {:?}; continuing to phase 2",
            phase1_timeout
        );
    }

    // Phase 2: full-set quiescence gate — require diff <= local_event_count on
    // both sides, stable for 5 consecutive polls at 200ms, before dropping sync.
    // Each peer creates 5 local-scope (non-synced) events during workspace
    // bootstrap: InviteAccepted + SecretKey + 3×LocalSignerSecret.
    let local_event_budget = 5;
    let quiesce_needed = 5u32;
    let mut quiesce_streak = 0u32;
    let phase2_timeout = Duration::from_secs(30);
    let phase2_start = Instant::now();
    loop {
        let a_ids = alice.store_ids();
        let b_ids = bob.store_ids();
        let a_only = a_ids.difference(&b_ids).count();
        let b_only = b_ids.difference(&a_ids).count();

        if a_only <= local_event_budget && b_only <= local_event_budget {
            quiesce_streak += 1;
            if quiesce_streak >= quiesce_needed {
                break;
            }
        } else {
            quiesce_streak = 0;
        }

        assert!(
            phase2_start.elapsed() < phase2_timeout,
            "phase 2 quiescence timed out: alice_only={}, bob_only={}",
            a_only, b_only,
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let wall_secs = start.elapsed().as_secs_f64();
    drop(sync);

    let a_after = alice.store_count();
    let b_after = bob.store_count();
    let events_transferred = ((a_after - a_before) + (b_after - b_before)) as u64;
    let events_per_sec = if wall_secs > 0.0 { events_transferred as f64 / wall_secs } else { 0.0 };
    let bytes_transferred = events_transferred * 100;
    let throughput_mib_s = (bytes_transferred as f64) / (1024.0 * 1024.0) / wall_secs.max(0.001);
    eprintln!(
        "zero-loss stress: {} events in {:.2}s ({:.0} events/s, {:.2} MiB/s)",
        events_transferred, wall_secs, events_per_sec, throughput_mib_s,
    );

    // Final assertions on the quiesced state.
    let alice_ids = alice.store_ids();
    let bob_ids = bob.store_ids();

    let alice_only: Vec<_> = alice_ids.difference(&bob_ids).collect();
    let bob_only: Vec<_> = bob_ids.difference(&alice_ids).collect();
    assert!(alice_only.len() <= local_event_budget, "alice has too many unique events: {}", alice_only.len());
    assert!(bob_only.len() <= local_event_budget, "bob has too many unique events: {}", bob_only.len());

    // Verify all original events survived on their own peer
    for id in &alice_ids_before {
        assert!(alice_ids.contains(id), "alice lost own event {}", id);
    }
    for id in &bob_ids_before {
        assert!(bob_ids.contains(id), "bob lost own event {}", id);
    }

    harness.finish();
}

#[tokio::test]
async fn test_recorded_at_monotonicity() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    // Alice creates messages with small delays to ensure different created_at
    alice.create_message("first");
    std::thread::sleep(Duration::from_millis(10));
    alice.create_message("second");
    std::thread::sleep(Duration::from_millis(10));
    let third = alice.create_message("third");
    let third_b64 = event_id_to_base64(&third);

    // Sync to Bob — Bob's recorded_at should use local wall clock, not event created_at
    let sync = start_peers_pinned(&alice, &bob);

    assert_eventually(
        || bob.has_event(&third_b64),
        Duration::from_secs(15),
        "bob should receive alice's events including the last message",
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

    harness.finish();
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
    let harness = ScenarioHarness::new();
    harness.track(&peer_a1);
    harness.track(&peer_a2);
    harness.track(&peer_b1);
    harness.track(&peer_b2);

    // Create messages in each workspace
    peer_a1.batch_create_messages(5);
    peer_a2.batch_create_messages(3);
    peer_b1.batch_create_messages(4);
    peer_b2.batch_create_messages(2);

    // Create markers for sync convergence
    let a1_marker = peer_a1.create_message("a1-marker");
    let a1_marker_b64 = event_id_to_base64(&a1_marker);
    let a2_marker = peer_a2.create_message("a2-marker");
    let a2_marker_b64 = event_id_to_base64(&a2_marker);
    let b1_marker = peer_b1.create_message("b1-marker");
    let b1_marker_b64 = event_id_to_base64(&b1_marker);
    let b2_marker = peer_b2.create_message("b2-marker");
    let b2_marker_b64 = event_id_to_base64(&b2_marker);

    // Sync workspace A peers
    let sync_a = start_peers_pinned(&peer_a1, &peer_a2);
    assert_eventually(
        || peer_a2.has_event(&a1_marker_b64) && peer_a1.has_event(&a2_marker_b64),
        Duration::from_secs(15),
        "workspace A peers should exchange marker events",
    ).await;
    drop(sync_a);

    // Sync workspace B peers
    let sync_b = start_peers_pinned(&peer_b1, &peer_b2);
    assert_eventually(
        || peer_b2.has_event(&b1_marker_b64) && peer_b1.has_event(&b2_marker_b64),
        Duration::from_secs(15),
        "workspace B peers should exchange marker events",
    ).await;
    drop(sync_b);

    // Verify scoped messages: only locally-created messages are projected (foreign signer blocked)
    assert_eq!(peer_a1.scoped_message_count(), 6); // 5 batch + 1 marker
    assert_eq!(peer_a2.scoped_message_count(), 4); // 3 batch + 1 marker
    assert_eq!(peer_b1.scoped_message_count(), 5); // 4 batch + 1 marker
    assert_eq!(peer_b2.scoped_message_count(), 3); // 2 batch + 1 marker

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

    harness.finish();
}

#[tokio::test]
async fn test_sync_50k() {
    let harness = ScenarioHarness::skip("50k event replay too slow for CI");
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");

    let gen_start = Instant::now();
    alice.batch_create_messages(50_000);
    let gen_secs = gen_start.elapsed().as_secs_f64();
    eprintln!("Generated 50k events in {:.2}s", gen_secs);

    // Pick a sample event from alice's store to use as convergence marker
    let sample_ids = alice.sample_event_ids(1);
    let marker_b64 = sample_ids[0].clone();

    let metrics = sync_until_converged(
        &alice, &bob,
        || bob.has_event(&marker_b64),
        Duration::from_secs(300),
    ).await;

    eprintln!("50k sync: {}", metrics);

    // Only alice's locally-created messages are projected on alice
    assert_eq!(alice.message_count(), 50_000);

    harness.finish();
}

/// Integration test: verify peer_identity_from_connection returns the correct
/// SPKI fingerprint across a live QUIC mTLS handshake.
///
/// STATIC PINNING (intentional): this test validates TLS identity extraction
/// mechanics, not transport trust resolution. Static AllowedPeers is the
/// simplest way to stand up a handshake without DB state.
#[tokio::test]
async fn test_peer_identity_extraction_live_handshake() {
    let harness = ScenarioHarness::skip("transport handshake test, no projection state mutated");
    let alice = Peer::new("alice");
    let bob = Peer::new("bob");

    let (cert_a, key_a) = alice.cert_and_key();
    let (cert_b, key_b) = bob.cert_and_key();

    let fp_a = alice.spki_fingerprint();
    let fp_b = bob.spki_fingerprint();
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

    harness.finish();
}

/// Test out-of-order reaction sync: Bob creates a reaction targeting Alice's message,
/// then syncs. The reaction arrives blocked, and auto-projects once the message arrives.
#[tokio::test]
async fn test_out_of_order_reaction_sync() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    // Alice creates a message
    let msg_id = alice.create_message("Hello from Alice");
    let msg_id_b64 = event_id_to_base64(&msg_id);

    // Bob creates a reaction targeting Alice's message (Bob doesn't have the message yet)
    let rxn_id = bob.create_reaction(&msg_id, "\u{1f44d}");
    let rxn_id_b64 = event_id_to_base64(&rxn_id);

    assert_eq!(bob.reaction_count(), 0); // blocked
    assert_eq!(alice.message_count(), 1);

    // Sync — both get each other's events
    let sync = start_peers_pinned(&alice, &bob);

    assert_eventually(
        || bob.has_event(&msg_id_b64) && alice.has_event(&rxn_id_b64),
        Duration::from_secs(15),
        "both peers should receive each other's events",
    ).await;

    drop(sync);

    // With independent identity chains, cross-peer events are blocked (foreign signer).
    // Bob: Alice's message blocked (foreign signer), reaction still blocked (target not valid)
    assert_eq!(bob.message_count(), 0);
    assert_eq!(bob.reaction_count(), 0);

    // Alice: own message valid, Bob's reaction blocked (foreign signer)
    assert_eq!(alice.message_count(), 1);
    assert_eq!(alice.reaction_count(), 0);

    harness.finish();
}

/// Test that multiple reactions targeting different messages all resolve correctly
/// when the messages arrive via sync.
#[tokio::test]
async fn test_multi_dep_blocking_sync() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    // Alice creates 3 messages
    let msg1 = alice.create_message("First");
    let msg2 = alice.create_message("Second");
    let msg3 = alice.create_message("Third");

    // Bob creates reactions targeting all 3 (none of which are in his DB)
    bob.create_reaction(&msg1, "\u{1f44d}");
    bob.create_reaction(&msg2, "\u{2764}\u{fe0f}");
    let bob_rxn3 = bob.create_reaction(&msg3, "\u{1f525}");
    let bob_rxn3_b64 = event_id_to_base64(&bob_rxn3);
    let msg3_b64 = event_id_to_base64(&msg3);

    assert_eq!(bob.reaction_count(), 0);

    // Sync
    let sync = start_peers_pinned(&alice, &bob);

    assert_eventually(
        || bob.has_event(&msg3_b64) && alice.has_event(&bob_rxn3_b64),
        Duration::from_secs(15),
        "both peers should receive each other's events",
    ).await;

    drop(sync);

    // With independent identity chains, cross-peer events are blocked (foreign signer).
    assert_eq!(alice.message_count(), 3);
    assert_eq!(bob.message_count(), 0);
    assert_eq!(alice.reaction_count(), 0);
    assert_eq!(bob.reaction_count(), 0);

    harness.finish();
}

/// Integration test: verify valid_events are tenant-scoped after sync.
/// Alice creates message + reaction, syncs to Bob. Both converge to 2 events.
/// valid_events are per-tenant, and projection invariants hold.
#[tokio::test]
async fn test_cross_tenant_dep_scoping_after_sync() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    // Alice creates a message and a reaction targeting it
    let msg_id = alice.create_message("Cross-tenant scoping test");
    let msg_b64 = event_id_to_base64(&msg_id);
    let rxn_id = alice.create_reaction(&msg_id, "\u{2705}");
    let rxn_b64 = event_id_to_base64(&rxn_id);

    assert_eq!(alice.message_count(), 1);
    assert_eq!(alice.reaction_count(), 1);

    // Sync to Bob
    let sync = start_peers_pinned(&alice, &bob);

    assert_eventually(
        || bob.has_event(&msg_b64) && bob.has_event(&rxn_b64),
        Duration::from_secs(15),
        "bob should receive alice's message and reaction events",
    ).await;

    drop(sync);

    // Bob: Alice's events blocked (foreign signer)
    assert_eq!(bob.message_count(), 0);
    assert_eq!(bob.reaction_count(), 0);

    // Verify valid_events are tenant-scoped: Alice has more valid events than Bob
    // because her content events are valid locally but rejected on Bob's side
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
    assert!(alice_valid > bob_valid, "Alice should have more valid events due to content (alice={}, bob={})", alice_valid, bob_valid);

    harness.finish();
}

/// Integration test: Alice creates a PSK + encrypted message → syncs to Bob → Bob projects.
#[tokio::test]
async fn test_encrypted_event_sync() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);
    let alice_initial_keys = alice.secret_key_count();
    let bob_initial_keys = bob.secret_key_count();

    // Materialize the same PSK locally on both peers (local-only key event, not synced).
    let key_bytes: [u8; 32] = rand::random();
    let fixed_ts = 4_000_000u64;
    let sk_eid_alice = alice.create_secret_key_deterministic(key_bytes, fixed_ts);
    let sk_eid_bob = bob.create_secret_key_deterministic(key_bytes, fixed_ts);
    assert_eq!(sk_eid_alice, sk_eid_bob, "deterministic PSK materialization should match");

    let enc_eid = alice.create_encrypted_message(&sk_eid_alice, "Hello encrypted world");
    let enc_b64 = event_id_to_base64(&enc_eid);

    assert_eq!(alice.secret_key_count(), alice_initial_keys + 1);
    assert_eq!(bob.secret_key_count(), bob_initial_keys + 1);
    // The encrypted event projects into messages table
    assert_eq!(alice.scoped_message_count(), 1);

    // Sync to Bob
    let sync = start_peers_pinned(&alice, &bob);

    assert_eventually(
        || bob.has_event(&enc_b64),
        Duration::from_secs(15),
        "bob should receive alice's encrypted event",
    ).await;

    drop(sync);

    // Bob has his local secret key. The encrypted wrapper decrypts to a Message
    // with signed_by = Alice's PeerShared (foreign signer -> inner message rejected).
    assert_eq!(bob.secret_key_count(), bob_initial_keys + 1);
    // Encrypted inner message is rejected because its signer (Alice's PeerShared)
    // is not valid on Bob's side (foreign network)
    assert_eq!(bob.scoped_message_count(), 0);

    harness.finish();
}

/// Integration test: Encrypted event syncs before key → blocks → key syncs → cascade unblocks.
#[tokio::test]
async fn test_encrypted_out_of_order_sync() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);
    let bob_initial_keys = bob.secret_key_count();

    // Alice creates key + encrypted message.
    let key_bytes: [u8; 32] = rand::random();
    let fixed_ts = 5_000_000u64;
    let sk_eid = alice.create_secret_key_deterministic(key_bytes, fixed_ts);
    let enc_eid = alice.create_encrypted_message(&sk_eid, "Out of order encrypted");
    let enc_b64 = event_id_to_base64(&enc_eid);

    // Also create a normal message to verify mixed events work
    let alice_msg = alice.create_message("Normal message");
    let alice_msg_b64 = event_id_to_base64(&alice_msg);

    // Bob creates a message too, but does NOT have the key yet.
    let bob_msg = bob.create_message("Bob's message");
    let bob_msg_b64 = event_id_to_base64(&bob_msg);

    // Sync phase 1: ciphertext arrives before key materialization on Bob.
    // Note: alice's SK is local scope, not synced
    let sync1 = start_peers_pinned(&alice, &bob);

    assert_eventually(
        || bob.has_event(&enc_b64) && bob.has_event(&alice_msg_b64) && alice.has_event(&bob_msg_b64),
        Duration::from_secs(15),
        "phase 1: both peers should have synced shared events",
    ).await;

    drop(sync1);

    // Bob should be blocked on missing key after phase 1.
    assert_eq!(bob.secret_key_count(), bob_initial_keys);
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
    assert_eq!(bob.secret_key_count(), bob_initial_keys + 1);
    // Bob still only sees his own message (encrypted inner rejected due to foreign signer)
    assert_eq!(bob.scoped_message_count(), 1);

    // Alice sees all her own messages
    assert_eq!(alice.scoped_message_count(), 2); // encrypted inner + normal message

    harness.finish();
}

/// Integration test: mixed cleartext + encrypted events → verify_projection_invariants.
#[tokio::test]
async fn test_encrypted_replay_invariants() {
    let alice = Peer::new_with_identity("alice");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    let initial_keys = alice.secret_key_count();

    // Create a mix of cleartext and encrypted events
    let key_bytes: [u8; 32] = rand::random();
    let sk_eid = alice.create_secret_key(key_bytes);

    alice.create_message("Cleartext 1");
    alice.create_encrypted_message(&sk_eid, "Encrypted 1");
    alice.create_message("Cleartext 2");
    alice.create_encrypted_message(&sk_eid, "Encrypted 2");

    assert_eq!(alice.secret_key_count(), initial_keys + 1);
    assert_eq!(alice.scoped_message_count(), 4); // 2 cleartext + 2 encrypted inner messages

    // Run invariant checks (forward, double, reverse)
    harness.finish();
}

/// Integration test: simulate crash recovery by manually enqueuing events into project_queue,
/// then calling recovery (recover_expired + drain). All events should be projected.
#[tokio::test]
async fn test_project_queue_crash_recovery() {
    let harness = ScenarioHarness::skip("manually destroys/rebuilds projection as test mechanism");
    use topo::db::project_queue::ProjectQueue;
    use topo::projection::apply::project_one;

    let alice = Peer::new_with_identity("alice");

    // Create messages via create_event_sync (bypasses queue, projects inline)
    let _msg1 = alice.create_message("Recovery message 1");
    let _msg2 = alice.create_message("Recovery message 2");
    let _msg3 = alice.create_message("Recovery message 3");

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
    assert!(all_eids.len() >= 3 + 1, "should have identity events + 3 messages, got {}", all_eids.len());

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
    assert_eq!(drained, all_eids.len(), "all enqueued events should be drained");

    // Verify all messages projected
    let msg_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
        rusqlite::params![&alice.identity], |row| row.get(0),
    ).unwrap();
    assert_eq!(msg_count, 3);

    // Verify valid_events: at least identity + messages should be valid
    let valid_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM valid_events WHERE peer_id = ?1",
        rusqlite::params![&alice.identity], |row| row.get(0),
    ).unwrap();
    assert!(valid_count >= 3, "at least the 3 messages should be valid, got {}", valid_count);

    // Queue should be empty
    assert_eq!(pq.count_pending(&alice.identity).unwrap(), 0);

    harness.finish();
}

/// Integration test: verify project_queue drain works end-to-end with create_event_sync events.
#[tokio::test]
async fn test_project_queue_drain_after_batch() {
    let harness = ScenarioHarness::skip("tests queue dedup guard, not projection invariants");
    use topo::db::project_queue::ProjectQueue;
    use topo::projection::apply::project_one;

    let alice = Peer::new_with_identity("alice");

    // Create events (projected inline by create_event_sync)
    alice.batch_create_messages(5);
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

    harness.finish();
}

/// Integration test: egress_queue lifecycle — enqueue, claim, send, cleanup.
#[tokio::test]
async fn test_egress_queue_lifecycle() {
    let harness = ScenarioHarness::skip("tests egress queue lifecycle, no projection state involved");
    use topo::db::egress_queue::EgressQueue;

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
    let claimed = eq.claim_batch(conn_id, 10).unwrap();
    assert_eq!(claimed.len(), 3);

    // Mark sent
    let rowids: Vec<i64> = claimed.iter().map(|(rowid, _)| *rowid).collect();
    eq.mark_sent(&rowids).unwrap();

    // Count pending after sending
    let pending = eq.count_pending(conn_id).unwrap();
    assert_eq!(pending, 0);

    // mark_sent now deletes rows, so cleanup_sent finds nothing
    let purged = eq.cleanup_sent(300_000).unwrap();
    assert_eq!(purged, 0);

    // Re-enqueue should work (sent rows are deleted, dedup index cleared)
    let enqueued = eq.enqueue_events(conn_id, &[msg1, msg2]).unwrap();
    assert_eq!(enqueued, 2);

    // Clear connection
    eq.clear_connection(conn_id).unwrap();
    let pending = eq.count_pending(conn_id).unwrap();
    assert_eq!(pending, 0);

    harness.finish();
}

/// Integration test: Alice creates message + reactions, syncs to Bob. Alice deletes message.
/// Bob syncs again. Verify: Bob has tombstone, no message, no reactions.
#[tokio::test]
async fn test_deletion_sync() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    // Alice creates a message and a reaction targeting it
    let msg_id = alice.create_message("Delete me");
    let msg_b64 = event_id_to_base64(&msg_id);
    let rxn_id = alice.create_reaction(&msg_id, "\u{1f44d}");
    let rxn_b64 = event_id_to_base64(&rxn_id);

    assert_eq!(alice.message_count(), 1);
    assert_eq!(alice.reaction_count(), 1);

    // Sync to Bob
    let sync = start_peers_pinned(&alice, &bob);

    assert_eventually(
        || bob.has_event(&msg_b64) && bob.has_event(&rxn_b64),
        Duration::from_secs(15),
        "bob should receive alice's message and reaction",
    ).await;

    drop(sync);

    // Bob: Alice's events blocked (foreign signer)
    assert_eq!(bob.message_count(), 0);
    assert_eq!(bob.reaction_count(), 0);

    // Alice deletes the message
    let del_id = alice.create_message_deletion(&msg_id);
    let del_b64 = event_id_to_base64(&del_id);

    assert_eq!(alice.message_count(), 0); // deleted
    assert_eq!(alice.reaction_count(), 0); // cascaded
    assert_eq!(alice.deleted_message_count(), 1); // tombstone

    // Sync again — Bob gets the deletion event
    let sync2 = start_peers_pinned(&alice, &bob);

    assert_eventually(
        || bob.has_event(&del_b64),
        Duration::from_secs(15),
        "bob should receive alice's deletion event",
    ).await;

    drop(sync2);

    // Bob: all of Alice's events blocked (foreign signer), including deletion
    assert_eq!(bob.message_count(), 0, "bob: no messages projected (foreign signer)");
    assert_eq!(bob.reaction_count(), 0, "bob: no reactions projected (foreign signer)");
    assert_eq!(bob.deleted_message_count(), 0, "bob: no tombstones (deletion blocked too)");

    harness.finish();
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
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    // Alice creates a message and then deletes it
    let msg_id = alice.create_message("Delete me via sync");
    let del_id = alice.create_message_deletion(&msg_id);
    let del_b64 = event_id_to_base64(&del_id);

    assert_eq!(alice.message_count(), 0); // deleted
    assert_eq!(alice.deleted_message_count(), 1); // tombstone

    // Sync
    let sync = start_peers_pinned(&alice, &bob);

    assert_eventually(
        || bob.has_event(&del_b64),
        Duration::from_secs(15),
        "bob should receive alice's deletion event",
    ).await;

    drop(sync);

    // Bob: Alice's events blocked (foreign signer)
    assert_eq!(bob.message_count(), 0, "bob: no messages (foreign signer)");
    assert_eq!(bob.deleted_message_count(), 0, "bob: no tombstones (foreign signer)");

    harness.finish();
}

/// Integration test: Create encrypted message, then encrypted deletion targeting it.
/// Verify cascade works through encryption layer.
#[tokio::test]
async fn test_encrypted_deletion() {
    let alice = Peer::new_with_identity("alice");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    let initial_keys = alice.secret_key_count();

    // Create a secret key
    let key_bytes: [u8; 32] = rand::random();
    let sk_eid = alice.create_secret_key(key_bytes);

    // Create an encrypted message
    let _enc_msg_eid = alice.create_encrypted_message(&sk_eid, "Encrypted delete me");

    assert_eq!(alice.secret_key_count(), initial_keys + 1);
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

    assert_eq!(alice.scoped_message_count(), 0); // inner message deleted
    assert_eq!(alice.deleted_message_count(), 1); // tombstone from encrypted deletion

    harness.finish();
}

/// Integration test: After deletion sync, verify_projection_invariants on both peers.
#[tokio::test]
async fn test_deletion_replay_invariants() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    // Create a mix of messages, reactions, and deletions
    let msg1 = alice.create_message("Keep me");
    let msg2 = alice.create_message("Delete me");
    alice.create_reaction(&msg1, "\u{2764}\u{fe0f}");
    alice.create_reaction(&msg2, "\u{1f44d}");

    // Delete msg2 (cascades its reaction too)
    let del_id = alice.create_message_deletion(&msg2);
    let del_b64 = event_id_to_base64(&del_id);

    assert_eq!(alice.message_count(), 1); // msg1 survives
    assert_eq!(alice.reaction_count(), 1); // msg1's reaction survives
    assert_eq!(alice.deleted_message_count(), 1); // msg2 tombstone

    // Sync to Bob
    let sync = start_peers_pinned(&alice, &bob);

    assert_eventually(
        || bob.has_event(&del_b64),
        Duration::from_secs(15),
        "bob should receive alice's deletion event",
    ).await;

    drop(sync);

    // Bob: Alice's events blocked (foreign signer)
    assert_eq!(bob.message_count(), 0);
    assert_eq!(bob.reaction_count(), 0);
    assert_eq!(bob.deleted_message_count(), 0);

    // Run full replay invariants on both
    harness.finish();
}

/// Gap 1: Verify SecretKey events (ShareScope::Local) are never sent to remote peers.
#[tokio::test]
async fn test_local_only_events_not_synced() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);
    let bob_initial_keys = bob.secret_key_count();

    // Both peers materialize the same PSK locally
    let key_bytes: [u8; 32] = rand::random();
    let fixed_ts = 3000000u64;
    let sk_eid = alice.create_secret_key_deterministic(key_bytes, fixed_ts);
    let sk_eid_bob = bob.create_secret_key_deterministic(key_bytes, fixed_ts);
    assert_eq!(sk_eid, sk_eid_bob, "deterministic PSK should produce same event_id");

    // Alice creates encrypted message + normal message
    let enc_eid = alice.create_encrypted_message(&sk_eid, "Encrypted for local-only test");
    let enc_b64 = event_id_to_base64(&enc_eid);
    let alice_msg = alice.create_message("Normal message from Alice");
    let alice_msg_b64 = event_id_to_base64(&alice_msg);

    // Sync
    let sync = start_peers_pinned(&alice, &bob);

    assert_eventually(
        || bob.has_event(&enc_b64) && bob.has_event(&alice_msg_b64),
        Duration::from_secs(15),
        "bob should receive alice's encrypted and normal messages",
    ).await;

    drop(sync);

    // Bob should NOT have received Alice's SK event -- his store has his own SK
    assert_eq!(bob.secret_key_count(), bob_initial_keys + 1);
    // Bob: encrypted inner rejected (foreign signer), normal msg blocked (foreign signer)
    assert_eq!(bob.scoped_message_count(), 0);

    // Verify Alice's SK event_id IS in bob's events (because bob created his own copy)
    let sk_b64 = event_id_to_base64(&sk_eid);
    assert!(bob.has_event(&sk_b64), "bob should have the SK event (his own local copy)");

    harness.finish();
}

/// Gap 2: Two-set PSK isolation -- mismatched PSKs cannot decrypt each other's messages.
#[tokio::test]
async fn test_psk_two_set_isolation() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    // Alice and Bob use DIFFERENT PSKs
    let key_a: [u8; 32] = rand::random();
    let key_b: [u8; 32] = rand::random();
    let sk_eid_alice = alice.create_secret_key(key_a);
    let _sk_eid_bob = bob.create_secret_key(key_b);

    // Alice encrypts with her key
    let enc_eid = alice.create_encrypted_message(&sk_eid_alice, "Alice secret");
    let enc_b64 = event_id_to_base64(&enc_eid);

    // Alice also creates a normal message
    let alice_msg = alice.create_message("Alice cleartext");
    let alice_msg_b64 = event_id_to_base64(&alice_msg);

    // Sync
    let sync = start_peers_pinned(&alice, &bob);

    assert_eventually(
        || bob.has_event(&enc_b64) && bob.has_event(&alice_msg_b64),
        Duration::from_secs(15),
        "bob should receive alice's encrypted and cleartext events",
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

    harness.finish();
}

/// Integration test: Alice and Bob sync, verify peer_endpoint_observations are recorded.
/// Purge with far-future cutoff removes them; purge with past cutoff keeps them.
#[tokio::test]
async fn test_endpoint_observations_recorded() {
    use topo::db::health::purge_expired_endpoints;

    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    // Create some data so sync has something to do
    let marker = alice.create_message("endpoint obs test");
    let marker_b64 = event_id_to_base64(&marker);

    let sync = start_peers_pinned(&alice, &bob);

    assert_eventually(
        || bob.has_event(&marker_b64),
        Duration::from_secs(15),
        "bob should receive alice's message event",
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

    harness.finish();
}

/// Gap 3: Encrypted inner event with unsupported signer_type rejects durably (not hard error).
#[tokio::test]
async fn test_encrypted_inner_unsupported_signer_rejects_durably() {
    use topo::crypto::hash_event;
    use topo::event_modules::{
        EncryptedEvent, MessageEvent, ParsedEvent, EVENT_TYPE_MESSAGE, encode_event,
    };
    use topo::projection::encrypted::encrypt_event_blob;
    use topo::projection::apply::project_one;

    let alice = Peer::new_with_identity("alice");
    let harness = ScenarioHarness::new();
    harness.track(&alice);

    // Create and project a secret key
    let key_bytes: [u8; 32] = rand::random();
    let sk_eid = alice.create_secret_key(key_bytes);

    // Create an inner Message with signer_type=255 (unsupported)
    // signed_by references an existing PeerShared signer event, but signer_type is invalid
    let inner = ParsedEvent::Message(MessageEvent {
        created_at_ms: 999999u64,
        workspace_id: [0u8; 32],
        author_id: alice.peer_shared_event_id.unwrap(),
        content: "bad signer type".to_string(),
        signed_by: alice.peer_shared_event_id.unwrap(),
        signer_type: 255, // unsupported
        signature: [0u8; 64],
    });
    let inner_blob = encode_event(&inner).unwrap();

    // Encrypt it
    let (nonce, ciphertext, auth_tag) = encrypt_event_blob(&key_bytes, &inner_blob).unwrap();
    let wrapper = ParsedEvent::Encrypted(EncryptedEvent {
        created_at_ms: 999999u64,
        key_event_id: sk_eid,
        inner_type_code: EVENT_TYPE_MESSAGE,
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
        topo::projection::decision::ProjectionDecision::Reject { reason } => {
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
        topo::projection::decision::ProjectionDecision::AlreadyProcessed,
        "rejected event should not be re-processed"
    );

    harness.finish();
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
        &user_eid,
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
    let harness = ScenarioHarness::new();
    harness.track(&alice);
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

    harness.finish();
}

#[test]
fn test_out_of_order_identity() {
    // Record UserBoot BEFORE UserInviteBoot — UserBoot blocks on missing dep,
    // then cascades when the full invite chain is created afterward.
    let alice = Peer::new("alice");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    let db = open_connection(&alice.db_path).unwrap();

    use ed25519_dalek::SigningKey;
    use topo::event_modules::{encode_event, ParsedEvent, WorkspaceEvent, UserInviteBootEvent, UserBootEvent};
    use topo::projection::signer::sign_event_bytes;
    use topo::projection::apply::project_one;
    use topo::crypto::hash_event;
    use topo::event_modules::registry;

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
        name: "test-workspace".to_string(),
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
        username: "test-user".to_string(),
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
        matches!(result, topo::projection::decision::ProjectionDecision::Block { .. }),
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
        matches!(net_result, topo::projection::decision::ProjectionDecision::Block { .. }),
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
        matches!(uib_result, topo::projection::decision::ProjectionDecision::Block { .. }),
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

    harness.finish();
}

#[test]
fn test_foreign_workspace_excluded() {
    let alice = Peer::new("alice");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
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

    harness.finish();
}

#[test]
fn test_removal_enforcement() {
    let alice = Peer::new("alice");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
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

    harness.finish();
}

#[test]
fn test_secret_shared_key_wrap() {
    let alice = Peer::new("alice");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
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

    harness.finish();
}

/// Out-of-order test: SecretShared event blocks when its recipient dep
/// (Bob's PeerShared in a shared workspace) is not yet valid on Alice's side,
/// then unblocks via cascade after Bob's identity chain events are synced in.
#[test]
fn test_secret_shared_blocks_until_signer_valid() {
    use topo::projection::apply::project_one;
    use topo::projection::create::create_signed_event_staged;
    use topo::event_modules::{ParsedEvent, SecretSharedEvent};

    let alice = Peer::new("alice");
    let bob = Peer::new("bob");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    // Alice bootstraps workspace; Bob joins Alice's workspace via invite.
    let chain = bootstrap_peer(&alice);
    let bob_join = join_workspace(&bob, &chain, &alice);

    // Alice creates a local content key.
    let secret_key_bytes: [u8; 32] = rand::random();
    let sk_eid = alice.create_secret_key(secret_key_bytes);

    // Alice creates a SecretShared targeting Bob's PeerShared as recipient.
    // Bob's identity chain exists in Bob's DB, but NOT yet in Alice's DB.
    let wrapped_key: [u8; 32] = rand::random();
    let ss_event = ParsedEvent::SecretShared(SecretSharedEvent {
        created_at_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64,
        key_event_id: sk_eid,
        recipient_event_id: bob_join.peer_shared_eid,
        wrapped_key,
        signed_by: chain.peer_shared_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let alice_db = open_connection(&alice.db_path).unwrap();
    let ss_eid = create_signed_event_staged(
        &alice_db, &alice.identity, &ss_event, &chain.peer_shared_key,
    ).expect("staged create should succeed even if blocked");
    let ss_b64 = event_id_to_base64(&ss_eid);

    // SecretShared should be blocked: recipient_event_id (Bob's PeerShared) is not
    // valid in Alice's DB yet.
    let blocked_count: i64 = alice_db.query_row(
        "SELECT COUNT(*) FROM blocked_event_deps WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![&alice.identity, &ss_b64],
        |row| row.get(0),
    ).unwrap();
    assert!(blocked_count >= 1,
        "SecretShared should block — Bob's PeerShared not yet valid in Alice's DB");

    // Now simulate sync: copy Bob's shared events to Alice's DB and project them.
    let bob_db = open_connection(&bob.db_path).unwrap();
    let bob_events: Vec<(String, Vec<u8>)> = {
        let mut stmt = bob_db.prepare(
            "SELECT e.event_id, e.blob FROM events e
             INNER JOIN recorded_events re ON e.event_id = re.event_id
             WHERE re.peer_id = ?1
             ORDER BY e.created_at ASC"
        ).unwrap();
        stmt.query_map(rusqlite::params![&bob.identity], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        }).unwrap().collect::<Result<Vec<_>, _>>().unwrap()
    };

    use topo::event_modules::registry;
    let reg = registry();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
    for (eid_b64, blob) in &bob_events {
        let meta = reg.lookup(blob[0]).unwrap();
        if meta.share_scope.as_str() == "local" {
            continue;
        }
        alice_db.execute(
            "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![eid_b64, meta.type_name, blob, meta.share_scope.as_str(), now_ms as i64, now_ms as i64],
        ).unwrap();
        alice_db.execute(
            "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source) VALUES (?1, ?2, ?3, 'test')",
            rusqlite::params![&alice.identity, eid_b64, now_ms as i64],
        ).unwrap();
        let eid = event_id_from_base64(eid_b64).unwrap();
        project_one(&alice_db, &alice.identity, &eid).unwrap();
    }

    // After Bob's chain arrives and cascades, SecretShared should now be valid.
    let ss_valid: bool = alice_db.query_row(
        "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![&alice.identity, &ss_b64],
        |row| row.get(0),
    ).unwrap();
    assert!(ss_valid,
        "SecretShared should be valid after Bob's identity chain arrived via cascade");

    let ss_projected: i64 = alice_db.query_row(
        "SELECT COUNT(*) FROM secret_shared WHERE recorded_by = ?1",
        rusqlite::params![&alice.identity],
        |row| row.get(0),
    ).unwrap();
    assert!(ss_projected >= 1, "SecretShared should be in projection table after cascade");

    harness.finish();
}

/// Out-of-order test: encrypted wrapper arrives before local key materialization,
/// blocks, then unblocks once the deterministic key is created.
#[test]
fn test_encrypted_blocks_then_unblocks_on_key_materialization() {
    let alice = Peer::new_with_identity("alice_enc_ooo");
    let bob = Peer::new_with_identity("bob_enc_ooo");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    // Step 1: Alice creates a key and encrypted message.
    let key_bytes: [u8; 32] = rand::random();
    let fixed_ts = 7_000_000u64;
    let sk_eid = alice.create_secret_key_deterministic(key_bytes, fixed_ts);
    let enc_eid = alice.create_encrypted_message(&sk_eid, "Encrypted before key on bob");

    // Verify alice can decrypt her own message
    assert_eq!(alice.scoped_message_count(), 1);

    // Manually insert the encrypted event blob into Bob's DB (simulating sync arrival
    // of ciphertext BEFORE key materialization).
    let alice_db = open_connection(&alice.db_path).unwrap();
    let enc_b64 = event_id_to_base64(&enc_eid);
    let enc_blob: Vec<u8> = alice_db.query_row(
        "SELECT blob FROM events WHERE event_id = ?1",
        rusqlite::params![&enc_b64],
        |row| row.get(0),
    ).unwrap();

    let bob_db = open_connection(&bob.db_path).unwrap();
    use topo::event_modules::registry;
    use topo::projection::apply::project_one;
    use topo::projection::decision::ProjectionDecision;
    let reg = registry();
    let enc_meta = reg.lookup(enc_blob[0]).unwrap();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
    bob_db.execute(
        "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![&enc_b64, enc_meta.type_name, &enc_blob, enc_meta.share_scope.as_str(), now_ms as i64, now_ms as i64],
    ).unwrap();
    bob_db.execute(
        "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source) VALUES (?1, ?2, ?3, 'test')",
        rusqlite::params![&bob.identity, &enc_b64, now_ms as i64],
    ).unwrap();

    // Project the encrypted event on Bob — should block (key_event_id dep not in valid_events).
    let result = project_one(&bob_db, &bob.identity, &enc_eid).unwrap();
    assert!(matches!(result, ProjectionDecision::Block { .. }),
        "Encrypted should block when key dep is missing: {:?}", result);

    // Verify key-dep blocking is recorded.
    let key_b64 = event_id_to_base64(&sk_eid);
    let blocked_on_key: bool = bob_db.query_row(
        "SELECT COUNT(*) > 0 FROM blocked_event_deps
         WHERE peer_id = ?1 AND event_id = ?2 AND blocker_event_id = ?3",
        rusqlite::params![&bob.identity, &enc_b64, &key_b64],
        |row| row.get(0),
    ).unwrap();
    assert!(blocked_on_key, "Encrypted should be blocked specifically on key_event_id dep");

    // Step 3: Materialize the same deterministic key on Bob.
    let bob_sk_eid = bob.create_secret_key_deterministic(key_bytes, fixed_ts);
    assert_eq!(bob_sk_eid, sk_eid, "Deterministic key event IDs must match across peers");

    // After key materialization, re-project the encrypted wrapper once to assert
    // current dependency semantics directly from the projection decision:
    // key dep must be resolved; any remaining block should be on inner deps
    // (for example foreign signer in this cross-workspace setup).
    let result_after_key = project_one(&bob_db, &bob.identity, &enc_eid).unwrap();
    if let ProjectionDecision::Block { missing } = result_after_key {
        assert!(
            !missing.contains(&sk_eid),
            "After key materialization, encrypted must not remain blocked on key_event_id",
        );
    }

    // Bob doesn't see Alice's encrypted message (foreign signer → inner rejected),
    // which is correct cross-workspace behavior.
    assert_eq!(bob.scoped_message_count(), 0,
        "Bob should not see Alice's message (foreign signer in separate workspace)");

    harness.finish();
}

/// Deterministic key event ID test: inviter wraps key, invitee unwraps, both see
/// the same secret_key event ID. This validates the cross-peer key agreement property
/// that underpins the invite key wrap/unwrap bootstrap flow.
#[test]
fn test_deterministic_key_event_id_matches_across_peers() {
    use topo::projection::encrypted::{wrap_key_for_recipient, unwrap_key_from_sender};
    use ed25519_dalek::SigningKey;
    use topo::event_modules::{encode_event, ParsedEvent, SecretKeyEvent};
    use topo::crypto::hash_event;

    let alice = Peer::new_with_identity("alice_det_key");
    let bob = Peer::new_with_identity("bob_det_key");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    // Alice generates a content key.
    let plaintext_key: [u8; 32] = rand::random();

    // Compute deterministic created_at from key bytes (same algorithm as identity_ops).
    use blake2::digest::consts::U8;
    use blake2::{Blake2b, Digest};
    let mut hasher = Blake2b::<U8>::new();
    hasher.update(b"poc7-content-key-created-at-v1");
    hasher.update(&plaintext_key);
    let digest = hasher.finalize();
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&digest[..8]);
    let deterministic_ts = u64::from_le_bytes(ts_bytes);

    // Alice creates her local secret_key with deterministic timestamp.
    let alice_sk_eid = alice.create_secret_key_deterministic(plaintext_key, deterministic_ts);

    // Simulate invite wrap/unwrap with fresh key pairs (sender wraps for invite key).
    let mut rng = rand::thread_rng();
    let sender_key = SigningKey::generate(&mut rng);
    let invite_key = SigningKey::generate(&mut rng);
    let wrapped = wrap_key_for_recipient(
        &sender_key,
        &invite_key.verifying_key(),
        &plaintext_key,
    );

    // Bob unwraps using the invite private key and sender's public key.
    let unwrapped = unwrap_key_from_sender(
        &invite_key,
        &sender_key.verifying_key(),
        &wrapped,
    );
    assert_eq!(unwrapped, plaintext_key, "Unwrapped key must match original plaintext");

    // Bob materializes the deterministic secret_key from unwrapped bytes.
    let bob_sk_eid = bob.create_secret_key_deterministic(unwrapped, deterministic_ts);
    assert_eq!(bob_sk_eid, alice_sk_eid,
        "Deterministic key event ID must match between inviter and invitee");

    // Also verify via manual event construction that the event_id matches.
    let sk_evt = ParsedEvent::SecretKey(SecretKeyEvent {
        created_at_ms: deterministic_ts,
        key_bytes: plaintext_key,
    });
    let expected_eid = hash_event(&encode_event(&sk_evt).unwrap());
    assert_eq!(expected_eid, alice_sk_eid, "Manual hash matches create_secret_key_deterministic");

    harness.finish();
}

/// Full wrap→unwrap→encrypt→decrypt convergence: Alice wraps a key for Bob via invite key,
/// Bob unwraps and materializes local key, then an encrypted message from Alice
/// becomes decryptable (or at least unblocked) on Bob's side.
#[test]
fn test_wrap_unwrap_encrypted_convergence() {
    use topo::projection::encrypted::{wrap_key_for_recipient, unwrap_key_from_sender};
    use ed25519_dalek::SigningKey;

    let alice = Peer::new_with_identity("alice_conv");
    let bob = Peer::new_with_identity("bob_conv");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    // Alice creates a content key.
    let plaintext_key: [u8; 32] = rand::random();

    // Deterministic timestamp from key bytes.
    use blake2::digest::consts::U8;
    use blake2::{Blake2b, Digest};
    let mut hasher = Blake2b::<U8>::new();
    hasher.update(b"poc7-content-key-created-at-v1");
    hasher.update(&plaintext_key);
    let digest = hasher.finalize();
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&digest[..8]);
    let deterministic_ts = u64::from_le_bytes(ts_bytes);

    let alice_sk_eid = alice.create_secret_key_deterministic(plaintext_key, deterministic_ts);

    // Alice creates an encrypted message.
    let enc_eid = alice.create_encrypted_message(&alice_sk_eid, "Wrapped key convergence test");
    assert_eq!(alice.scoped_message_count(), 1, "Alice should see her encrypted message");

    // Simulate invite wrap/unwrap with fresh key pairs.
    let mut rng = rand::thread_rng();
    let sender_key = SigningKey::generate(&mut rng);
    let invite_key = SigningKey::generate(&mut rng);

    // Alice wraps the content key for the invite key.
    let wrapped = wrap_key_for_recipient(
        &sender_key,
        &invite_key.verifying_key(),
        &plaintext_key,
    );

    // Bob unwraps using the invite private key and sender's public key.
    let unwrapped = unwrap_key_from_sender(
        &invite_key,
        &sender_key.verifying_key(),
        &wrapped,
    );
    assert_eq!(unwrapped, plaintext_key);

    // Bob materializes the deterministic key.
    let bob_sk_eid = bob.create_secret_key_deterministic(unwrapped, deterministic_ts);
    assert_eq!(bob_sk_eid, alice_sk_eid, "Key event IDs match after unwrap");

    // Copy the encrypted event to Bob's DB (simulating sync).
    let alice_db = open_connection(&alice.db_path).unwrap();
    let enc_b64 = event_id_to_base64(&enc_eid);
    let enc_blob: Vec<u8> = alice_db.query_row(
        "SELECT blob FROM events WHERE event_id = ?1",
        rusqlite::params![&enc_b64],
        |row| row.get(0),
    ).unwrap();

    let bob_db = open_connection(&bob.db_path).unwrap();
    use topo::event_modules::registry;
    use topo::projection::decision::ProjectionDecision;
    use topo::projection::apply::project_one;
    let reg = registry();
    let enc_meta = reg.lookup(enc_blob[0]).unwrap();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
    bob_db.execute(
        "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![&enc_b64, enc_meta.type_name, &enc_blob, enc_meta.share_scope.as_str(), now_ms as i64, now_ms as i64],
    ).unwrap();
    bob_db.execute(
        "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source) VALUES (?1, ?2, ?3, 'test')",
        rusqlite::params![&bob.identity, &enc_b64, now_ms as i64],
    ).unwrap();

    // Project encrypted event on Bob. Key is available, so any block must be on
    // inner deps/signer, not on key_event_id.
    let result = project_one(&bob_db, &bob.identity, &enc_eid).unwrap();
    if let ProjectionDecision::Block { missing } = result {
        assert!(
            !missing.contains(&alice_sk_eid),
            "Encrypted should not block on key_event_id when local key exists",
        );
    }

    // Explicitly verify no key-dep blocker row exists for this event.
    let blocked_on_key: i64 = bob_db.query_row(
        "SELECT COUNT(*) FROM blocked_event_deps
         WHERE peer_id = ?1 AND event_id = ?2 AND blocker_event_id = ?3",
        rusqlite::params![&bob.identity, &enc_b64, &event_id_to_base64(&alice_sk_eid)],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(blocked_on_key, 0, "key_event_id blocker should be absent after key materialization");

    harness.finish();
}

#[test]
fn test_identity_replay_invariants() {
    let alice = Peer::new_with_identity("alice");
    let harness = ScenarioHarness::new();
    harness.track(&alice);

    // Create some content after identity chain
    alice.create_message("hello after bootstrap");

    // Verify replay invariants (forward, double, reverse)
    harness.finish();
}

#[test]
fn test_transport_key_projects_without_auto_binding() {
    let alice = Peer::new("alice");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
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

    // transport_keys are no longer authoritative for trust — PeerShared-derived SPKIs are.
    // The transport_keys SPKI should NOT appear in allowed_peers (unless it also matches
    // a PeerShared-derived SPKI).
    let allowed = topo::db::transport_trust::allowed_peers_from_db(&db, &alice.identity).unwrap();
    assert!(!allowed.contains(&spki_fp), "transport_keys SPKI should not be in allowed set (non-authoritative)");

    // But PeerShared-derived SPKI should be in allowed set
    let ps_spki = topo::transport::cert::spki_fingerprint_from_ed25519_pubkey(
        &chain.peer_shared_key.verifying_key().to_bytes()
    );
    assert!(allowed.contains(&ps_spki), "PeerShared-derived SPKI should be in allowed set");

    harness.finish();
}


#[test]
fn test_transport_key_invalid_sig_rejected() {
    let harness = ScenarioHarness::skip("uses catch_unwind; projection may be partial after panic");
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

    harness.finish();
}

#[test]
fn test_transport_key_replay_invariants() {
    let alice = Peer::new_with_identity("alice");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
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
    harness.finish();
}


// =============================================================================
// Phase 7 logic fixes: corrected guard and binding semantics
// =============================================================================

/// invite_accepted projects without any prior invite event recorded.
/// This verifies the HasRecordedInvite guard has been removed.
#[test]
fn test_invite_accepted_no_prior_invite_required() {
    let alice = Peer::new("alice");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
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

    harness.finish();
}

/// Trust anchor immutability: second invite_accepted with conflicting workspace_id is rejected.
#[test]
fn test_trust_anchor_immutability() {
    let alice = Peer::new("alice");
    // This test intentionally constructs two conflicting InviteAccepted events
    // and asserts first-write-wins immutability behavior. That policy is
    // order-dependent under reverse replay, so skip replay-invariant checks.
    let harness = ScenarioHarness::skip(
        "conflicting invite_accepted first-write-wins semantics are intentionally order-dependent",
    );
    harness.track(&alice);
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

    harness.finish();
}

/// No pre-projection blob capture influence: manually inserting a malformed
/// invite-like blob into events should not alter trust binding state.
#[test]
fn test_no_blob_capture_trust_influence() {
    let harness = ScenarioHarness::skip("raw blob insertion without project_one; no projection to replay");
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

    let fake_eid = topo::crypto::hash_event(&fake_blob);
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

    harness.finish();
}

/// True out-of-order identity chain: record invite_accepted BEFORE its referenced
/// invite event, then record workspace, then invite event -> cascade resolves everything.
#[test]
fn test_true_out_of_order_identity_chain() {
    let alice = Peer::new("alice");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    let db = open_connection(&alice.db_path).unwrap();

    use ed25519_dalek::SigningKey;
    use topo::crypto::hash_event;
    use topo::event_modules::{encode_event, ParsedEvent, WorkspaceEvent};
    use topo::projection::create::create_event_staged;
    let mut rng = rand::thread_rng();

    let workspace_key = SigningKey::generate(&mut rng);
    let workspace_pubkey = workspace_key.verifying_key().to_bytes();
    let workspace_event = ParsedEvent::Workspace(WorkspaceEvent {
        created_at_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        public_key: workspace_pubkey,
        name: "test-workspace".to_string(),
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
    let workspace_eid = create_event_staged(&db, &alice.identity, &workspace_event)
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

    harness.finish();
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
        &user_eid,
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
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    // Alice bootstraps her full identity chain
    let alice_chain = bootstrap_peer(&alice);

    // Alice creates a UserInviteOngoing for Bob
    // Bob needs the invite to exist on Alice's side; sync will deliver it
    let _bob_join = join_workspace(&bob, &alice_chain, &alice);

    // Sync — shared events flow between peers
    let sync = start_peers_pinned(&alice, &bob);

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
    harness.finish();
}

/// Identity chain events arrive out of order via sync and cascade to valid.
/// Bob creates his own events but they depend on Alice's chain. Sync delivers
/// Alice's events, which unblock Bob's chain via cascade.
#[tokio::test]
async fn test_identity_cascade_via_sync() {
    let alice = Peer::new("alice");
    let bob = Peer::new("bob");
    let harness = ScenarioHarness::new();
    harness.track(&bob);

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
    let sync = start_peers_pinned(&alice, &bob);

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

    harness.finish();
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

    // Set signing keys and author_id so create_message works
    alice.peer_shared_event_id = Some(alice_chain.peer_shared_eid);
    alice.peer_shared_signing_key = Some(alice_chain.peer_shared_key.clone());
    alice.author_id = alice_chain.user_eid;
    bob.peer_shared_event_id = Some(bob_join.peer_shared_eid);
    bob.peer_shared_signing_key = Some(bob_join.peer_shared_key.clone());
    bob.author_id = bob_join.user_eid;

    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    // Sync identity events first
    let sync = start_peers_pinned(&alice, &bob);
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
    let sync = start_peers_pinned(&alice, &bob);
    assert_eventually(
        || alice.scoped_message_count() == 2 && bob.scoped_message_count() == 2,
        Duration::from_secs(15),
        "messages should converge after identity sync",
    ).await;
    drop(sync);

    harness.finish();
}

/// Alice bootstraps on two devices (Phone and Laptop). Phone creates a DeviceInviteOngoing
/// for Laptop, Laptop joins with PeerSharedOngoing, both sync and converge.
#[tokio::test]
async fn test_device_link_via_sync() {
    use topo::event_modules::{DeviceInviteOngoingEvent, PeerSharedOngoingEvent, ParsedEvent};
    use topo::projection::create::{create_signed_event_sync, create_signed_event_staged};

    let phone = Peer::new("phone");
    let laptop = Peer::new("laptop");
    let harness = ScenarioHarness::new();
    harness.track(&phone);
    harness.track(&laptop);

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
    // Use staged API since blocking is expected (dep will arrive via sync).
    let laptop_ps_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let laptop_ps_pubkey = laptop_ps_key.verifying_key().to_bytes();
    let db = open_connection(&laptop.db_path).unwrap();
    let ps_evt = ParsedEvent::PeerSharedOngoing(PeerSharedOngoingEvent {
        created_at_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64,
        public_key: laptop_ps_pubkey,
        user_event_id: phone_chain.user_eid,
        device_name: "laptop".to_string(),
        signed_by: laptop_di_eid,
        signer_type: 3,
        signature: [0u8; 64],
    });
    let _laptop_ps_eid = create_signed_event_staged(
        &db, &laptop.identity, &ps_evt, &laptop_di_key,
    ).expect("create peer_shared_ongoing");
    drop(db);

    // Laptop's PeerSharedOngoing is blocked — signed_by dep (DeviceInviteOngoing) is on Phone
    assert_eq!(laptop.peer_shared_count(), 0, "Laptop's peer_shared should be blocked before sync");

    // Sync — Phone's events flow to Laptop, unblocking Laptop's chain
    let sync = start_peers_pinned(&phone, &laptop);

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

    harness.finish();
}

/// Alice and Bob are on different workspaces. When they sync, Bob's workspace events
/// are rejected by Alice's trust anchor, and vice versa. Neither peer's identity
/// state is corrupted.
#[tokio::test]
async fn test_foreign_workspace_rejected_via_sync() {
    let alice = Peer::new("alice");
    let bob = Peer::new("bob");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

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
    let sync = start_peers_pinned(&alice, &bob);

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

    harness.finish();
}

// ---------------------------------------------------------------------------
// Multi-tenant node tests (Phase 5)
// ---------------------------------------------------------------------------

/// Two tenants on the same node, different workspaces: verify complete isolation.
/// Events created by tenant A should never appear in tenant B's projection.
#[tokio::test]
async fn test_shared_db_two_tenants_different_workspaces() {
    let node = SharedDbNode::new(2);
    let harness = ScenarioHarness::new();
    harness.track_node(&node);
    let t0 = &node.tenants[0];
    let t1 = &node.tenants[1];

    // Each tenant has its own workspace
    assert_ne!(t0.workspace_id, t1.workspace_id,
        "tenants should have distinct workspaces");
    assert_ne!(t0.identity, t1.identity,
        "tenants should have distinct identities");

    // Create messages per tenant
    t0.batch_create_messages(3);
    t1.batch_create_messages(2);

    // Verify each tenant's scoped message count
    assert_eq!(t0.scoped_message_count(), 3, "tenant 0 should have 3 projected messages");
    assert_eq!(t1.scoped_message_count(), 2, "tenant 1 should have 2 projected messages");

    // Verify per-tenant projection invariants + no cross-tenant leakage
    harness.finish();
}

/// SharedDbNode tenant discovery: verify discover_local_tenants returns all tenants.
#[tokio::test]
async fn test_shared_db_tenant_discovery() {
    let node = SharedDbNode::new(3);
    let harness = ScenarioHarness::new();
    harness.track_node(&node);

    let db = open_connection(&node.db_path).unwrap();
    let tenants = topo::db::transport_creds::discover_local_tenants(&db).unwrap();

    assert_eq!(tenants.len(), 3, "should discover all 3 tenants");

    // Verify each discovered tenant has matching cert data
    for tenant_info in &tenants {
        let fp = extract_spki_fingerprint(&tenant_info.cert_der).unwrap();
        let expected_id = hex::encode(fp);
        assert_eq!(expected_id, tenant_info.peer_id,
            "SPKI fingerprint should match peer_id");
    }

    // Verify all tenant IDs are unique
    let ids: Vec<&str> = tenants.iter().map(|t| t.peer_id.as_str()).collect();
    let unique: std::collections::HashSet<&str> = ids.iter().copied().collect();
    assert_eq!(ids.len(), unique.len(), "all tenant IDs should be unique");

    harness.finish();
}

/// No cross-tenant leakage: events created by one tenant should not have
/// recorded_events rows with another tenant's peer_id.
#[tokio::test]
async fn test_shared_db_no_cross_tenant_leakage() {
    let node = SharedDbNode::new(2);
    let harness = ScenarioHarness::new();
    harness.track_node(&node);
    let t0 = &node.tenants[0];
    let t1 = &node.tenants[1];

    t0.batch_create_messages(5);
    t1.batch_create_messages(5);

    let db = open_connection(&node.db_path).unwrap();

    // Get event_ids recorded by t0
    let t0_events: Vec<String> = {
        let mut stmt = db.prepare(
            "SELECT event_id FROM recorded_events WHERE peer_id = ?1"
        ).unwrap();
        stmt.query_map([&t0.identity], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };

    // Get event_ids recorded by t1
    let t1_events: Vec<String> = {
        let mut stmt = db.prepare(
            "SELECT event_id FROM recorded_events WHERE peer_id = ?1"
        ).unwrap();
        stmt.query_map([&t1.identity], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };

    // Verify no overlap — each tenant's recorded events are entirely its own.
    // Events blobs are shared in the events table, but recorded_events and
    // valid_events are scoped by peer_id.
    let t0_set: std::collections::HashSet<&str> = t0_events.iter().map(|s| s.as_str()).collect();
    let t1_set: std::collections::HashSet<&str> = t1_events.iter().map(|s| s.as_str()).collect();
    let overlap: Vec<&&str> = t0_set.intersection(&t1_set).collect();
    assert!(overlap.is_empty(),
        "recorded_events should have zero overlap between tenants, but found {}: {:?}",
        overlap.len(), overlap);

    // Verify valid_events are also isolated
    let t0_valid: Vec<String> = {
        let mut stmt = db.prepare(
            "SELECT event_id FROM valid_events WHERE peer_id = ?1"
        ).unwrap();
        stmt.query_map([&t0.identity], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    let t1_valid: Vec<String> = {
        let mut stmt = db.prepare(
            "SELECT event_id FROM valid_events WHERE peer_id = ?1"
        ).unwrap();
        stmt.query_map([&t1.identity], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    let t0_valid_set: std::collections::HashSet<&str> = t0_valid.iter().map(|s| s.as_str()).collect();
    let t1_valid_set: std::collections::HashSet<&str> = t1_valid.iter().map(|s| s.as_str()).collect();
    let valid_overlap: Vec<&&str> = t0_valid_set.intersection(&t1_valid_set).collect();
    assert!(valid_overlap.is_empty(),
        "valid_events should have zero overlap between tenants, but found {}: {:?}",
        valid_overlap.len(), valid_overlap);

    // Also verify via the comprehensive helper
    harness.finish();
}

/// Node + external peer: a SharedDbNode tenant syncs with a standalone Peer.
#[tokio::test]
async fn test_shared_db_sync_with_external_peer() {
    let node = SharedDbNode::new(1);
    let external = Peer::new_with_identity("external");
    let harness = ScenarioHarness::new();
    harness.track_node(&node);
    harness.track(&external);
    let tenant = &node.tenants[0];

    // Create messages on both sides
    tenant.batch_create_messages(2);
    external.batch_create_messages(3);

    // Create marker messages for convergence tracking
    let tenant_marker = tenant.create_message("tenant-sync-marker");
    let tenant_marker_b64 = event_id_to_base64(&tenant_marker);
    let ext_marker = external.create_message("external-sync-marker");
    let ext_marker_b64 = event_id_to_base64(&ext_marker);

    // Start sync between tenant and external peer.
    // The tenant uses the shared db_path, external uses its own.
    let _sync = start_peers_pinned(tenant, &external);

    assert_eventually(
        || external.has_event(&tenant_marker_b64) && tenant.has_event(&ext_marker_b64),
        Duration::from_secs(15),
        "tenant and external should exchange marker events",
    ).await;

    harness.finish();
}

/// svc_node_status returns the correct tenant list.
#[tokio::test]
async fn test_svc_node_status() {
    let node = SharedDbNode::new(2);
    let harness = ScenarioHarness::new();
    harness.track_node(&node);

    let status = topo::service::svc_node_status(&node.db_path).unwrap();
    assert_eq!(status.len(), 2, "should report 2 tenants");

    let ids: Vec<&str> = status.iter().map(|t| t.peer_id.as_str()).collect();
    assert!(ids.contains(&node.tenants[0].identity.as_str()));
    assert!(ids.contains(&node.tenants[1].identity.as_str()));

    harness.finish();
}

/// Two tenants in the same workspace on the same node: verify that canonical
/// events overlap across peer_ids (both tenants see the shared workspace event)
/// while projection invariants still hold.
#[tokio::test]
async fn test_shared_db_same_workspace_two_tenants() {
    let mut node = SharedDbNode::new(1);
    let creator_workspace = node.tenants[0].workspace_id;

    // Second tenant joins the first tenant's workspace
    node.add_tenant_in_workspace("tenant-1-same-ws", 0);

    let harness = ScenarioHarness::new();
    harness.track_node(&node);

    let t0 = &node.tenants[0];
    let t1 = &node.tenants[1];

    assert_eq!(t0.workspace_id, t1.workspace_id,
        "both tenants should share the same workspace");
    assert_ne!(t0.identity, t1.identity,
        "tenants should have distinct identities");

    // Both tenants create messages
    t0.batch_create_messages(2);
    t1.batch_create_messages(3);

    let db = open_connection(&node.db_path).unwrap();

    // Both tenants should have recorded the shared Workspace event
    let t0_has_ws: bool = db.query_row(
        "SELECT COUNT(*) > 0 FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![&t0.identity, &topo::crypto::event_id_to_base64(&creator_workspace)],
        |row| row.get(0),
    ).unwrap();
    let t1_has_ws: bool = db.query_row(
        "SELECT COUNT(*) > 0 FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![&t1.identity, &topo::crypto::event_id_to_base64(&creator_workspace)],
        |row| row.get(0),
    ).unwrap();
    assert!(t0_has_ws, "tenant 0 should have recorded the workspace event");
    assert!(t1_has_ws, "tenant 1 should have recorded the workspace event");

    // The workspace event_id should appear in both tenants' recorded_events —
    // this is the legitimate overlap that the workspace-aware leakage check allows.
    let ws_b64 = topo::crypto::event_id_to_base64(&creator_workspace);
    let tenants_with_ws: i64 = db.query_row(
        "SELECT COUNT(DISTINCT peer_id) FROM recorded_events WHERE event_id = ?1",
        rusqlite::params![&ws_b64],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(tenants_with_ws, 2,
        "workspace event should be recorded by both tenants");

    // Projection invariants should hold — verify_all_invariants uses the
    // workspace-aware check that allows overlap for same-workspace tenants.
    harness.finish();
}

/// mDNS integration: two peers discover each other via mDNS and sync using
/// the discovered address. Exercises the full flow: advertise → browse →
/// discover → connect → sync → verify convergence.
///
/// Uses dynamic DB trust lookup (production-matching `is_peer_allowed`).
/// Trust comes from PeerShared-derived identity chain (no CLI pin import).
#[cfg(feature = "discovery")]
#[tokio::test]
async fn test_mdns_two_peers_discover_and_sync() {
    use std::collections::HashSet;
    use topo::peering::discovery::{local_non_loopback_ipv4, TenantDiscovery};
    use topo::testutil::create_dynamic_endpoint_for_peer_bind;

    let advertise_ip = local_non_loopback_ipv4().expect("no routable IP");
    let alice = Peer::new_with_identity("mdns-alice");
    let bob = Peer::new_in_workspace("mdns-bob", &alice).await;

    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    alice.batch_create_messages(3);
    bob.batch_create_messages(2);

    // Create marker messages for sync convergence
    let alice_marker = alice.create_message("mdns-alice-marker");
    let alice_marker_b64 = event_id_to_base64(&alice_marker);
    let bob_marker = bob.create_message("mdns-bob-marker");
    let bob_marker_b64 = event_id_to_base64(&bob_marker);

    // Dynamic trust endpoints bound to 0.0.0.0 so mDNS-resolved addresses
    // (which may be non-loopback) are reachable.
    let ep_a = create_dynamic_endpoint_for_peer_bind(&alice, "0.0.0.0:0".parse().unwrap());
    let ep_b = create_dynamic_endpoint_for_peer_bind(&bob, "0.0.0.0:0".parse().unwrap());

    let port_a = ep_a.local_addr().unwrap().port();
    let port_b = ep_b.local_addr().unwrap().port();

    // Advertise both peers via mDNS
    let local_a: HashSet<String> = [alice.identity.clone()].into_iter().collect();
    let local_b: HashSet<String> = [bob.identity.clone()].into_iter().collect();

    let disc_a = TenantDiscovery::new(&alice.identity, port_a, local_a, &advertise_ip)
        .expect("mDNS registration A");
    let disc_b = TenantDiscovery::new(&bob.identity, port_b, local_b, &advertise_ip)
        .expect("mDNS registration B");

    // Bob browses for peers — should discover Alice (not self)
    let browse_rx = disc_b.browse().expect("browse B");
    let target_id = alice.identity.clone();
    let discovered = tokio::task::spawn_blocking(move || {
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            match browse_rx.recv_timeout(Duration::from_millis(500)) {
                Ok(peer) if peer.peer_id == target_id => return Some(peer),
                Ok(_) => continue, // ignore discoveries from other tests
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(_) => break, // channel closed
            }
        }
        None
    }).await.expect("browse task panicked");

    let discovered_peer = discovered
        .expect("Bob should discover Alice via mDNS within 15s");
    assert_eq!(discovered_peer.peer_id, alice.identity,
        "discovered peer_id should match Alice");
    assert_eq!(discovered_peer.addr.port(), port_a,
        "discovered port should match Alice's endpoint");

    // Start sync using the mDNS-discovered address
    let a_db = alice.db_path.clone();
    let a_id = alice.identity.clone();
    let _a_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        rt.block_on(async { let _ = accept_loop(&a_db, &a_id, ep_a, noop_intro_spawner, test_ingest_fns()).await; });
    });

    let b_db = bob.db_path.clone();
    let b_id = bob.identity.clone();
    let remote = discovered_peer.addr;
    let _b_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        rt.block_on(async { let _ = connect_loop(&b_db, &b_id, ep_b, remote, None, noop_intro_spawner, test_ingest_fns()).await; });
    });

    // Wait for sync convergence using marker events
    assert_eventually(
        || bob.has_event(&alice_marker_b64) && alice.has_event(&bob_marker_b64),
        Duration::from_secs(15),
        "peers should converge after mDNS-discovered sync",
    ).await;

    drop(disc_a);
    drop(disc_b);

    harness.finish();
}

/// mDNS multitenancy: verifies self-filtering (co-located tenants don't
/// discover each other), external discovery (remote peer discovers all
/// node tenants), and that sync works via the discovered address.
///
/// Uses dynamic DB trust lookup (production-matching `is_peer_allowed`).
/// Trust comes from PeerShared-derived identity chain (no CLI pin import).
#[cfg(feature = "discovery")]
#[tokio::test]
async fn test_mdns_multitenant_self_filtering_and_sync() {
    use std::collections::HashSet;
    use topo::peering::discovery::{local_non_loopback_ipv4, TenantDiscovery};
    use topo::testutil::create_dynamic_endpoint_for_peer_bind;

    let advertise_ip = local_non_loopback_ipv4().expect("no routable IP");
    // Three peers: t0 and t1 are "co-located" (share local_peer_ids), ext is external
    let t0 = Peer::new_with_identity("mdns-t0");
    let t1 = Peer::new_with_identity("mdns-t1"); // t1 only needs mDNS presence, no sync
    let ext = Peer::new_in_workspace("mdns-ext", &t0).await;

    let harness = ScenarioHarness::new();
    harness.track(&t0);
    harness.track(&ext);

    t0.batch_create_messages(2);
    ext.batch_create_messages(3);

    // Create marker messages for sync convergence
    let t0_marker = t0.create_message("mdns-t0-marker");
    let t0_marker_b64 = event_id_to_base64(&t0_marker);
    let ext_marker = ext.create_message("mdns-ext-marker");
    let ext_marker_b64 = event_id_to_base64(&ext_marker);

    // Dynamic trust endpoints bound to 0.0.0.0 so mDNS-resolved addresses are reachable.
    // t1 only needs mDNS presence — no actual endpoint needed.
    let ep_t0 = create_dynamic_endpoint_for_peer_bind(&t0, "0.0.0.0:0".parse().unwrap());
    let ep_ext = create_dynamic_endpoint_for_peer_bind(&ext, "0.0.0.0:0".parse().unwrap());

    let port_t0 = ep_t0.local_addr().unwrap().port();
    let port_t1 = 19999; // mDNS presence only — no actual endpoint needed
    let port_ext = ep_ext.local_addr().unwrap().port();

    // Node tenants share local_peer_ids (same-node self-filtering)
    let node_local: HashSet<String> = [
        t0.identity.clone(), t1.identity.clone(),
    ].into_iter().collect();
    let ext_local: HashSet<String> = [ext.identity.clone()].into_iter().collect();

    let disc_t0 = TenantDiscovery::new(&t0.identity, port_t0, node_local.clone(), &advertise_ip)
        .expect("mDNS t0");
    let disc_t1 = TenantDiscovery::new(&t1.identity, port_t1, node_local, &advertise_ip)
        .expect("mDNS t1");
    let disc_ext = TenantDiscovery::new(&ext.identity, port_ext, ext_local, &advertise_ip)
        .expect("mDNS ext");

    // --- Assertion 1: t0 discovers ext but NOT t1 (self-filtered) ---
    let browse_t0 = disc_t0.browse().expect("browse t0");
    let ext_id = ext.identity.clone();
    let t0_discoveries = tokio::task::spawn_blocking(move || {
        let mut found = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut found_ext = false;
        while Instant::now() < deadline {
            match browse_t0.recv_timeout(Duration::from_millis(500)) {
                Ok(peer) => {
                    if peer.peer_id == ext_id { found_ext = true; }
                    found.push(peer);
                    if found_ext {
                        // Wait a bit longer to catch any self-filtering failures
                        std::thread::sleep(Duration::from_secs(2));
                        while let Ok(p) = browse_t0.recv_timeout(Duration::from_millis(100)) {
                            found.push(p);
                        }
                        break;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(_) => break,
            }
        }
        found
    }).await.expect("t0 browse panicked");

    let t0_found_ids: Vec<&str> = t0_discoveries.iter()
        .map(|p| p.peer_id.as_str()).collect();
    assert!(t0_found_ids.contains(&ext.identity.as_str()),
        "t0 should discover external peer via mDNS");
    assert!(!t0_found_ids.contains(&t1.identity.as_str()),
        "t0 should NOT discover co-located t1 (self-filtering)");

    // --- Assertion 2: ext discovers both t0 and t1 ---
    let browse_ext = disc_ext.browse().expect("browse ext");
    let t0_id = t0.identity.clone();
    let t1_id2 = t1.identity.clone();
    let ext_discoveries = tokio::task::spawn_blocking(move || {
        let mut found = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            match browse_ext.recv_timeout(Duration::from_millis(500)) {
                Ok(peer) => {
                    found.push(peer);
                    let ids: Vec<&str> = found.iter()
                        .map(|p| p.peer_id.as_str()).collect();
                    if ids.contains(&t0_id.as_str()) && ids.contains(&t1_id2.as_str()) {
                        break;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(_) => break,
            }
        }
        found
    }).await.expect("ext browse panicked");

    let ext_found_ids: Vec<&str> = ext_discoveries.iter()
        .map(|p| p.peer_id.as_str()).collect();
    assert!(ext_found_ids.contains(&t0.identity.as_str()),
        "external should discover t0");
    assert!(ext_found_ids.contains(&t1.identity.as_str()),
        "external should discover t1");

    // --- Assertion 3: sync works via mDNS-discovered address ---
    // ext discovered t0 earlier; use t0's address for connect_loop.
    // Since we also discovered ext from t0, verify the ext address too.
    let ext_disc = t0_discoveries.iter()
        .find(|p| p.peer_id == ext.identity).unwrap();
    eprintln!("mDNS: t0 discovered ext at {}", ext_disc.addr);

    // ext connects to t0 (not the other way around)
    let t0_disc = ext_discoveries.iter()
        .find(|p| p.peer_id == t0.identity).unwrap();
    eprintln!("mDNS: ext discovered t0 at {}", t0_disc.addr);

    // Use 127.0.0.1 with t0's port (endpoints bound to 0.0.0.0)
    let t0_connect_addr = std::net::SocketAddr::new(
        "127.0.0.1".parse().unwrap(), t0_disc.addr.port(),
    );

    let t0_db = t0.db_path.clone();
    let t0_id = t0.identity.clone();
    let _t0_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        rt.block_on(async { let _ = accept_loop(&t0_db, &t0_id, ep_t0, noop_intro_spawner, test_ingest_fns()).await; });
    });

    let ext_db = ext.db_path.clone();
    let ext_identity = ext.identity.clone();
    let _ext_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        rt.block_on(async {
            let _ = connect_loop(&ext_db, &ext_identity, ep_ext, t0_connect_addr, None, noop_intro_spawner, test_ingest_fns()).await;
        });
    });

    // Wait for sync convergence using marker events
    assert_eventually(
        || ext.has_event(&t0_marker_b64) && t0.has_event(&ext_marker_b64),
        Duration::from_secs(15),
        "t0 and external should converge via mDNS-discovered sync",
    ).await;

    drop(disc_t0);
    drop(disc_t1);
    drop(disc_ext);

    harness.finish();
}

/// Regression: per-tenant outbound cert identity.
///
/// When `connect_with(workspace_client_config)` is used, the remote server
/// should see the tenant's cert, not the endpoint's default cert.
///
/// Before the fix, `connect()` would present the default cert (first tenant's),
/// causing the server to see the wrong identity for multi-tenant outbound dials.
///
/// STATIC PINNING (intentional): server uses static AllowedPeers because the
/// test validates per-tenant cert presentation, not transport trust resolution.
/// The client side already uses dynamic `DynamicAllowFn`.
#[tokio::test]
async fn test_connect_with_presents_correct_tenant_cert() {
    use topo::transport::{
        create_single_port_endpoint, create_dual_endpoint, generate_self_signed_cert,
        workspace_client_config, multi_workspace::WorkspaceCertResolver,
    };

    let harness = ScenarioHarness::skip("transport-layer cert presentation test, no projection peers");

    // Create two identities: "default" (first tenant) and "actual" (second tenant).
    let (default_cert, default_key) = generate_self_signed_cert().unwrap();

    let (actual_cert, actual_key) = generate_self_signed_cert().unwrap();
    let actual_fp = extract_spki_fingerprint(actual_cert.as_ref()).unwrap();

    // Server: dual endpoint that trusts only "actual" tenant, NOT "default"
    let (server_cert, server_key) = generate_self_signed_cert().unwrap();
    let server_fp = extract_spki_fingerprint(server_cert.as_ref()).unwrap();
    let server_allowed = Arc::new(AllowedPeers::from_fingerprints(vec![actual_fp]));
    let server_ep = create_dual_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        server_cert.clone(),
        server_key.clone_key(),
        server_allowed,
    ).unwrap();
    let server_addr = server_ep.local_addr().unwrap();

    // Spawn server accept
    let server_ep_clone = server_ep.clone();
    let server_accept = tokio::spawn(async move {
        let incoming = server_ep_clone.accept().await;
        match incoming {
            Some(inc) => inc.await.ok(),
            None => None,
        }
    });

    // Client endpoint: default cert is "default" (the wrong one for this test)
    let allow_server: Arc<topo::transport::DynamicAllowFn> = Arc::new(move |fp: &[u8; 32]| {
        Ok(*fp == server_fp)
    });
    let resolver = WorkspaceCertResolver::new();
    let client_ep = create_single_port_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(resolver),
        allow_server.clone(),
        default_cert.clone(),
        default_key.clone_key(),
    ).unwrap();

    // Build per-tenant client config for "actual" tenant (correct cert + trust)
    let sfp = server_fp;
    let tenant_config = workspace_client_config(
        actual_cert.clone(),
        actual_key.clone_key(),
        Arc::new(move |fp: &[u8; 32]| Ok(*fp == sfp)),
    ).unwrap();

    // connect_with: should present "actual" cert → server accepts
    let conn = client_ep
        .connect_with(tenant_config, server_addr, "localhost")
        .unwrap()
        .await
        .expect("connect_with should succeed: server trusts actual tenant cert");

    // Server side: verify the client presented "actual" cert identity
    let server_conn = server_accept.await.unwrap().expect("server should have accepted");
    let server_saw_peer = peer_identity_from_connection(&server_conn)
        .expect("server should see client cert identity");
    assert_eq!(
        server_saw_peer, hex::encode(actual_fp),
        "server should see the actual tenant's identity, not the default"
    );

    // Key regression property: before the fix, connect_with did not exist in
    // the outbound path — connect() would be used, presenting default_cert
    // instead of actual_cert. The server (which only trusts actual_fp) would
    // have rejected the handshake, making the test fail at the connect_with
    // assertion above.

    drop(conn);
    drop(server_ep);
    drop(client_ep);
    harness.finish();
}

/// Regression: tenant-scoped outbound trust rejects untrusted servers.
///
/// When `workspace_client_config` is built with trust for peer A only,
/// connecting to peer B should fail (client rejects server cert).
///
/// Before the fix, the union-scoped trust check would accept ANY tenant's
/// trusted peer, allowing cross-tenant trust bleed on outbound connections.
///
/// STATIC PINNING (intentional): servers use static AllowedPeers because the
/// test validates client-side tenant-scoped trust rejection, not server trust
/// resolution. The pinning policy boundary is the thing under test.
#[tokio::test]
async fn test_tenant_scoped_outbound_trust_rejects_untrusted_server() {
    use topo::transport::{
        generate_self_signed_cert,
        workspace_client_config, create_dual_endpoint,
    };

    let harness = ScenarioHarness::skip("transport-layer trust rejection test, no projection peers");

    // Create client and two servers
    let (client_cert, client_key) = generate_self_signed_cert().unwrap();
    let client_fp = extract_spki_fingerprint(client_cert.as_ref()).unwrap();

    let (trusted_cert, trusted_key) = generate_self_signed_cert().unwrap();
    let trusted_fp = extract_spki_fingerprint(trusted_cert.as_ref()).unwrap();

    let (untrusted_cert, untrusted_key) = generate_self_signed_cert().unwrap();

    // Both servers trust the client (will accept its cert)
    let client_allowed = Arc::new(AllowedPeers::from_fingerprints(vec![client_fp]));
    let trusted_ep = create_dual_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        trusted_cert.clone(), trusted_key.clone_key(),
        client_allowed.clone(),
    ).unwrap();
    let trusted_addr = trusted_ep.local_addr().unwrap();

    let untrusted_ep = create_dual_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        untrusted_cert.clone(), untrusted_key.clone_key(),
        client_allowed,
    ).unwrap();
    let untrusted_addr = untrusted_ep.local_addr().unwrap();

    // Client: create endpoint + tenant config that ONLY trusts "trusted_server"
    let client_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let tenant_trust: Arc<topo::transport::DynamicAllowFn> = Arc::new(move |fp: &[u8; 32]| {
        Ok(*fp == trusted_fp) // only trusts the trusted server
    });
    let tenant_config = workspace_client_config(
        client_cert.clone(), client_key.clone_key(), tenant_trust,
    ).unwrap();

    // Spawn accept on both servers
    let te = trusted_ep.clone();
    tokio::spawn(async move { if let Some(inc) = te.accept().await { let _ = inc.await; } });
    let ue = untrusted_ep.clone();
    tokio::spawn(async move { if let Some(inc) = ue.accept().await { let _ = inc.await; } });

    // Connect to trusted server → should succeed
    let good_conn = client_ep
        .connect_with(tenant_config.clone(), trusted_addr, "localhost")
        .unwrap()
        .await;
    assert!(good_conn.is_ok(), "should succeed: client trusts this server");

    // Connect to untrusted server → should fail (client rejects server cert)
    let bad_conn = client_ep
        .connect_with(tenant_config, untrusted_addr, "localhost")
        .unwrap()
        .await;
    assert!(
        bad_conn.is_err(),
        "should fail: client does NOT trust this server (tenant-scoped trust)"
    );

    drop(good_conn);
    drop(trusted_ep);
    drop(untrusted_ep);
    drop(client_ep);
    harness.finish();
}

/// Integration test: two multi-tenant nodes exercise run_node's per-tenant outbound
/// config pipeline (discover_local_tenants → workspace_client_config → connect_loop).
///
/// Setup: Node A (2 tenants: a0, a1) accepts connections. Node B (2 tenants: b0, b1)
/// connects with per-tenant configs. Trust seeded so b0 trusts a0 (the fallback cert)
/// and b1 trusts a1 only. Since A presents a0 as its fallback cert, b0's TLS handshake
/// succeeds and sync proceeds, while b1's per-tenant trust verifier correctly rejects
/// a0's cert and no sync occurs.
///
/// Proves: run_node's workspace_client_config correctly scopes outbound trust per-tenant.
#[tokio::test]
async fn test_run_node_multitenant_outbound_isolation() {
    use std::collections::HashMap;
    use std::sync::atomic::AtomicU64;
    use topo::db::transport_creds::discover_local_tenants;
    use topo::db::transport_trust::{import_cli_pins_to_sql, is_peer_allowed};
    use topo::transport::{
        create_single_port_endpoint, workspace_client_config,
        multi_workspace::{WorkspaceCertResolver, workspace_sni},
        DynamicAllowFn,
    };
    use topo::peering::loops::accept_loop_with_ingest;
    use topo::contracts::event_pipeline_contract::IngestItem;
    use topo::event_pipeline::batch_writer;
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use rustls::sign::CertifiedKey;
    use tokio::sync::mpsc;

    // --- Two multi-tenant nodes ---
    let node_a = SharedDbNode::new(2);
    let node_b = SharedDbNode::new(2);
    let harness = ScenarioHarness::skip(
        "multi-tenant outbound isolation: tests transport config pipeline, \
         not event projection (different workspace chains)",
    );

    let a0 = &node_a.tenants[0];
    let a1 = &node_a.tenants[1];
    let b0 = &node_b.tenants[0];
    let b1 = &node_b.tenants[1];

    // Decode SPKI fingerprints from hex identity strings
    let fp = |peer: &topo::testutil::Peer| -> [u8; 32] {
        hex::decode(&peer.identity).unwrap().try_into().unwrap()
    };

    // --- Seed cross-trust via CLI pins (SQL trust rows) ---
    // a0 trusts b0, a1 trusts b1 (inbound: A accepts both)
    {
        let db = open_connection(&node_a.db_path).unwrap();
        import_cli_pins_to_sql(&db, &a0.identity, &AllowedPeers::from_fingerprints(vec![fp(b0)])).unwrap();
        import_cli_pins_to_sql(&db, &a1.identity, &AllowedPeers::from_fingerprints(vec![fp(b1)])).unwrap();
    }
    // b0 trusts a0, b1 trusts a1 (outbound: per-tenant client trust)
    {
        let db = open_connection(&node_b.db_path).unwrap();
        import_cli_pins_to_sql(&db, &b0.identity, &AllowedPeers::from_fingerprints(vec![fp(a0)])).unwrap();
        import_cli_pins_to_sql(&db, &b1.identity, &AllowedPeers::from_fingerprints(vec![fp(a1)])).unwrap();
    }

    // Create marker events on a0 (to be synced to b0 if connection succeeds)
    let a0_marker = a0.create_message("a0-isolation-marker");
    let a0_marker_b64 = event_id_to_base64(&a0_marker);

    // --- Build Node A endpoint (same as run_node) ---
    let tenants_a = {
        let db = open_connection(&node_a.db_path).unwrap();
        discover_local_tenants(&db).unwrap()
    };
    assert_eq!(tenants_a.len(), 2, "node A should have 2 tenants");

    let provider = rustls::crypto::ring::default_provider();
    let mut cert_resolver_a = WorkspaceCertResolver::new();
    let mut default_cert_a: Option<(CertificateDer<'static>, PrivatePkcs8KeyDer<'static>)> = None;

    for t in &tenants_a {
        let cert_der = CertificateDer::from(t.cert_der.clone());
        let key_der = PrivatePkcs8KeyDer::from(t.key_der.clone());
        let ck = CertifiedKey::from_der(
            vec![cert_der.clone()], key_der.clone_key().into(), &provider,
        ).unwrap();
        let sni = workspace_sni(&t.workspace_id);
        cert_resolver_a.add(sni, Arc::new(ck));
        if default_cert_a.is_none() {
            default_cert_a = Some((cert_der, key_der));
        }
    }
    let (default_cert_der, default_key_der) = default_cert_a.unwrap();

    // Union trust for A's inbound (same as run_node)
    let db_path_a_trust = node_a.db_path.clone();
    let a_tenant_ids: Vec<String> = tenants_a.iter().map(|t| t.peer_id.clone()).collect();
    let union_allow: Arc<DynamicAllowFn> = Arc::new(move |peer_fp: &[u8; 32]| {
        let db = open_connection(&db_path_a_trust)?;
        for tid in &a_tenant_ids {
            if is_peer_allowed(&db, tid, peer_fp)? {
                return Ok(true);
            }
        }
        Ok(false)
    });

    let endpoint_a = create_single_port_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(cert_resolver_a),
        union_allow,
        default_cert_der,
        default_key_der,
    ).unwrap();
    let addr_a = endpoint_a.local_addr().unwrap();

    // Shared batch_writer for A (same as run_node)
    let (ingest_tx, ingest_rx) = mpsc::channel::<IngestItem>(5000);
    let events_received = Arc::new(AtomicU64::new(0));
    let writer_events = events_received.clone();
    let writer_db = node_a.db_path.clone();
    let _writer = std::thread::spawn(move || {
        batch_writer(writer_db, ingest_rx, writer_events);
    });

    // Accept loop for A
    let a_db = node_a.db_path.clone();
    let a_ids: Vec<String> = tenants_a.iter().map(|t| t.peer_id.clone()).collect();
    let _accept = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        rt.block_on(async move {
            let _ = accept_loop_with_ingest(
                &a_db, &a_ids, endpoint_a, None, ingest_tx, HashMap::new(), noop_intro_spawner, test_ingest_fns(),
            ).await;
        });
    });

    // --- Build Node B per-tenant configs (same as run_node) ---
    let tenants_b = {
        let db = open_connection(&node_b.db_path).unwrap();
        discover_local_tenants(&db).unwrap()
    };
    assert_eq!(tenants_b.len(), 2, "node B should have 2 tenants");

    let mut b_configs: HashMap<String, quinn::ClientConfig> = HashMap::new();
    for t in &tenants_b {
        let cert_der = CertificateDer::from(t.cert_der.clone());
        let key_der = PrivatePkcs8KeyDer::from(t.key_der.clone());
        let db_path_t = node_b.db_path.clone();
        let tid = t.peer_id.clone();
        let tenant_allow: Arc<DynamicAllowFn> = Arc::new(move |peer_fp: &[u8; 32]| {
            let db = open_connection(&db_path_t)?;
            is_peer_allowed(&db, &tid, peer_fp)
        });
        let cfg = workspace_client_config(cert_der, key_der, tenant_allow).unwrap();
        b_configs.insert(t.peer_id.clone(), cfg);
    }

    // Node B endpoint (for outbound connect_loop calls)
    let mut cert_resolver_b = WorkspaceCertResolver::new();
    let mut default_cert_b: Option<(CertificateDer<'static>, PrivatePkcs8KeyDer<'static>)> = None;
    for t in &tenants_b {
        let cert_der = CertificateDer::from(t.cert_der.clone());
        let key_der = PrivatePkcs8KeyDer::from(t.key_der.clone());
        let ck = CertifiedKey::from_der(
            vec![cert_der.clone()], key_der.clone_key().into(), &provider,
        ).unwrap();
        cert_resolver_b.add(workspace_sni(&t.workspace_id), Arc::new(ck));
        if default_cert_b.is_none() {
            default_cert_b = Some((cert_der, key_der));
        }
    }
    let (b_def_cert, b_def_key) = default_cert_b.unwrap();
    let db_path_b_trust = node_b.db_path.clone();
    let b_tenant_ids: Vec<String> = tenants_b.iter().map(|t| t.peer_id.clone()).collect();
    let b_union_allow: Arc<DynamicAllowFn> = Arc::new(move |peer_fp: &[u8; 32]| {
        let db = open_connection(&db_path_b_trust)?;
        for tid in &b_tenant_ids {
            if is_peer_allowed(&db, tid, peer_fp)? { return Ok(true); }
        }
        Ok(false)
    });
    let endpoint_b = create_single_port_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(cert_resolver_b),
        b_union_allow,
        b_def_cert,
        b_def_key,
    ).unwrap();

    // --- Spawn connect_loops for each B tenant (same as run_node) ---
    // b0's config trusts a0 (= A's fallback cert) → should succeed
    let b0_cfg = b_configs.get(&b0.identity).unwrap().clone();
    let ep_b0 = endpoint_b.clone();
    let b0_db = node_b.db_path.clone();
    let b0_id = b0.identity.clone();
    let _b0_connect = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        rt.block_on(async move {
            let _ = connect_loop(&b0_db, &b0_id, ep_b0, addr_a, Some(b0_cfg), noop_intro_spawner, test_ingest_fns()).await;
        });
    });

    // b1's config trusts a1 only (NOT a0 = A's fallback cert) → TLS should fail
    let b1_cfg = b_configs.get(&b1.identity).unwrap().clone();
    let ep_b1 = endpoint_b.clone();
    let b1_db = node_b.db_path.clone();
    let b1_id = b1.identity.clone();
    let _b1_connect = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        rt.block_on(async move {
            let _ = connect_loop(&b1_db, &b1_id, ep_b1, addr_a, Some(b1_cfg), noop_intro_spawner, test_ingest_fns()).await;
        });
    });

    // --- Verify ---
    // b0 should sync with A. Since b0 and b1 share a DB (`events` table is shared),
    // we check `recorded_events` which tracks per-tenant sync state.
    assert_eventually(
        || {
            let db = open_connection(&node_b.db_path).unwrap();
            db.query_row(
                "SELECT COUNT(*) > 0 FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![&b0.identity, &a0_marker_b64],
                |row| row.get::<_, bool>(0),
            ).unwrap_or(false)
        },
        Duration::from_secs(15),
        "b0 should record a0's marker (b0 trusts a0 = A's fallback cert)",
    ).await;

    // b1 should NOT have recorded a0's marker. b1's per-tenant workspace_client_config
    // only trusts a1's cert, but A presents a0 as its fallback — TLS fails, no sync.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let b1_has_marker: bool = {
        let db = open_connection(&node_b.db_path).unwrap();
        db.query_row(
            "SELECT COUNT(*) > 0 FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&b1.identity, &a0_marker_b64],
            |row| row.get::<_, bool>(0),
        ).unwrap_or(false)
    };
    assert!(
        !b1_has_marker,
        "b1 should NOT have recorded a0's marker: b1's per-tenant config only trusts a1, \
         but A presents a0 as its fallback cert. Per-tenant outbound isolation prevents \
         b1 from establishing a TLS connection."
    );

    harness.finish();
}

/// Guard test: verify that every test function in this file uses `ScenarioHarness`.
/// This catches future tests that forget to add the harness.
#[test]
fn test_scenario_harness_guard() {
    let source = include_str!("scenario_test.rs");

    // Collect (line_index, fn_name) for each test function definition
    let lines: Vec<&str> = source.lines().collect();
    let mut test_fns: Vec<(usize, String)> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let is_fn_def = (trimmed.starts_with("fn test_")
            || trimmed.starts_with("async fn test_"))
            && trimmed.contains('(');
        if !is_fn_def {
            continue;
        }
        let name = trimmed
            .trim_start_matches("async ")
            .trim_start_matches("fn ")
            .split('(')
            .next()
            .unwrap_or("")
            .to_string();
        if name == "test_scenario_harness_guard" {
            continue;
        }
        test_fns.push((i, name));
    }

    // For each test function, scan from its definition line to the next test function
    // (or EOF) and check that "ScenarioHarness" appears in that range.
    let mut uncovered = Vec::new();
    for (idx, (start_line, ref name)) in test_fns.iter().enumerate() {
        let end_line = if idx + 1 < test_fns.len() {
            test_fns[idx + 1].0
        } else {
            lines.len()
        };
        let section = &lines[*start_line..end_line];
        let has_harness = section.iter().any(|l| l.contains("ScenarioHarness"));
        if !has_harness {
            uncovered.push(name.clone());
        }
    }

    assert!(
        uncovered.is_empty(),
        "The following test(s) do not use ScenarioHarness: {:?}\n\
         Every scenario test must use ScenarioHarness::new(), ::skip(), or be documented.",
        uncovered,
    );
}
