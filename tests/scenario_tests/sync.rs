use std::time::{Duration, Instant};
use topo::crypto::event_id_to_base64;
use topo::db::open_connection;
use topo::testutil::{
    assert_eventually, start_peers_pinned, sync_until_converged, Peer, ScenarioHarness,
};

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
    )
    .await;

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
    )
    .await;

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
    )
    .await;

    // Create more messages — sync loop picks them up
    let another = alice.create_message("Another from Alice");
    let another_b64 = event_id_to_base64(&another);

    assert_eventually(
        || bob.has_event(&another_b64),
        Duration::from_secs(15),
        "bob gets the new message via live sync",
    )
    .await;

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

    // Convergence gate on stored Message events (canonical events table).
    let alice_messages_before_sync = alice.stored_message_event_count();
    let bob_messages_before_sync = bob.stored_message_event_count();
    let expected_bob_messages = bob_messages_before_sync + alice_messages_before_sync;

    let metrics = sync_until_converged(
        &alice,
        &bob,
        || bob.stored_message_event_count() >= expected_bob_messages,
        Duration::from_secs(120),
    )
    .await;

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
    )
    .await;

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
    )
    .await;

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
    assert_eq!(
        alice.message_count(),
        5_000,
        "alice should have 5000 messages before sync"
    );
    assert_eq!(
        bob.message_count(),
        5_000,
        "bob should have 5000 messages before sync"
    );

    // Count/set-based convergence only (no marker/sample phase).
    let a_before = alice.stored_message_event_count();
    let b_before = bob.stored_message_event_count();
    let start = Instant::now();
    let sync = start_peers_pinned(&alice, &bob);

    // Full-set quiescence gate — require diff <= local_event_count on
    // both sides, stable for 5 consecutive polls at 200ms, before dropping sync.
    // Each peer creates local-scope (non-synced) events during workspace
    // bootstrap/key setup:
    // InviteAccepted + Secret + 3×PeerSecret (+ optional InviteSecret).
    let local_event_budget = 8;
    let quiesce_needed = 5u32;
    let mut quiesce_streak = 0u32;
    let quiesce_timeout = Duration::from_secs(120);
    let quiesce_start = Instant::now();
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
            quiesce_start.elapsed() < quiesce_timeout,
            "quiescence timed out: alice_only={}, bob_only={}",
            a_only,
            b_only,
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let wall_secs = start.elapsed().as_secs_f64();
    drop(sync);

    let a_after = alice.stored_message_event_count();
    let b_after = bob.stored_message_event_count();
    let message_events_transferred = ((a_after - a_before) + (b_after - b_before)) as u64;
    let events_per_sec = if wall_secs > 0.0 {
        message_events_transferred as f64 / wall_secs
    } else {
        0.0
    };
    let bytes_transferred = message_events_transferred * 100;
    let throughput_mib_s = (bytes_transferred as f64) / (1024.0 * 1024.0) / wall_secs.max(0.001);
    eprintln!(
        "zero-loss stress: {} events in {:.2}s ({:.0} events/s, {:.2} MiB/s)",
        message_events_transferred, wall_secs, events_per_sec, throughput_mib_s,
    );

    // Final assertions on the quiesced state.
    let alice_ids = alice.store_ids();
    let bob_ids = bob.store_ids();

    let alice_only: Vec<_> = alice_ids.difference(&bob_ids).collect();
    let bob_only: Vec<_> = bob_ids.difference(&alice_ids).collect();
    assert!(
        alice_only.len() <= local_event_budget,
        "alice has too many unique events: {}",
        alice_only.len()
    );
    assert!(
        bob_only.len() <= local_event_budget,
        "bob has too many unique events: {}",
        bob_only.len()
    );

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
    )
    .await;

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

        assert!(
            timestamps.len() >= 3,
            "expected >= 3 recorded events for {}",
            peer.name
        );

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
            "SELECT MIN(recorded_at) FROM recorded_events WHERE peer_id = ?1 AND source LIKE 'quic_recv:%'",
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
    )
    .await;
    drop(sync_a);

    // Sync workspace B peers
    let sync_b = start_peers_pinned(&peer_b1, &peer_b2);
    assert_eventually(
        || peer_b2.has_event(&b1_marker_b64) && peer_b1.has_event(&b2_marker_b64),
        Duration::from_secs(15),
        "workspace B peers should exchange marker events",
    )
    .await;
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

    // Convergence gate on stored Message events (canonical events table).
    let alice_messages_before_sync = alice.stored_message_event_count();
    let bob_messages_before_sync = bob.stored_message_event_count();
    let expected_bob_messages = bob_messages_before_sync + alice_messages_before_sync;

    let metrics = sync_until_converged(
        &alice,
        &bob,
        || bob.stored_message_event_count() >= expected_bob_messages,
        Duration::from_secs(300),
    )
    .await;

    eprintln!("50k sync: {}", metrics);

    // Only alice's locally-created messages are projected on alice
    assert_eq!(alice.message_count(), 50_000);

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
    )
    .await;

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
    )
    .await;

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
    )
    .await;

    drop(sync);

    // Bob: Alice's events blocked (foreign signer)
    assert_eq!(bob.message_count(), 0);
    assert_eq!(bob.reaction_count(), 0);

    // Verify valid_events are tenant-scoped: Alice has more valid events than Bob
    // because her content events are valid locally but rejected on Bob's side
    let alice_db = open_connection(&alice.db_path).expect("open alice db");
    let bob_db = open_connection(&bob.db_path).expect("open bob db");

    let alice_valid: i64 = alice_db
        .query_row(
            "SELECT COUNT(*) FROM valid_events WHERE peer_id = ?1",
            rusqlite::params![&alice.identity],
            |row| row.get(0),
        )
        .unwrap();
    let bob_valid: i64 = bob_db
        .query_row(
            "SELECT COUNT(*) FROM valid_events WHERE peer_id = ?1",
            rusqlite::params![&bob.identity],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        alice_valid > bob_valid,
        "Alice should have more valid events due to content (alice={}, bob={})",
        alice_valid,
        bob_valid
    );

    harness.finish();
}

#[tokio::test]
async fn test_local_only_events_not_synced() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);
    let bob_initial_keys = bob.key_secret_count();

    // Both peers materialize the same PSK locally
    let key_bytes: [u8; 32] = rand::random();
    let fixed_ts = 3000000u64;
    let sk_eid = alice.create_key_secret_deterministic(key_bytes, fixed_ts);
    let sk_eid_bob = bob.create_key_secret_deterministic(key_bytes, fixed_ts);
    assert_eq!(
        sk_eid, sk_eid_bob,
        "deterministic PSK should produce same event_id"
    );

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
    )
    .await;

    drop(sync);

    // Bob should NOT have received Alice's SK event -- his store has his own SK
    assert_eq!(bob.key_secret_count(), bob_initial_keys + 1);
    // Bob: encrypted inner rejected (foreign signer), normal msg blocked (foreign signer)
    assert_eq!(bob.scoped_message_count(), 0);

    // Verify Alice's SK event_id IS in bob's events (because bob created his own copy)
    let sk_b64 = event_id_to_base64(&sk_eid);
    assert!(
        bob.has_event(&sk_b64),
        "bob should have the SK event (his own local copy)"
    );

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
    let sk_eid_alice = alice.create_key_secret(key_a);
    let _sk_eid_bob = bob.create_key_secret(key_b);

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
    )
    .await;

    drop(sync);

    // Bob: normal message blocked (foreign signer), encrypted blocked (missing key dep)
    assert_eq!(
        bob.scoped_message_count(),
        0,
        "bob should see no messages (foreign signer + missing key)"
    );

    // Verify the encrypted event is blocked
    let bob_db = open_connection(&bob.db_path).expect("open bob db");
    let blocked: i64 = bob_db
        .query_row(
            "SELECT COUNT(*) FROM blocked_event_deps WHERE peer_id = ?1",
            rusqlite::params![&bob.identity],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        blocked >= 1,
        "events should be blocked (foreign signer + missing key dep)"
    );

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
    )
    .await;

    drop(sync);

    // Check endpoint observations were recorded
    let alice_db = open_connection(&alice.db_path).expect("open alice db");
    let bob_db = open_connection(&bob.db_path).expect("open bob db");

    let alice_obs: i64 = alice_db
        .query_row(
            "SELECT COUNT(*) FROM peer_endpoint_observations WHERE recorded_by = ?1",
            rusqlite::params![&alice.identity],
            |row| row.get(0),
        )
        .unwrap();

    let bob_obs: i64 = bob_db
        .query_row(
            "SELECT COUNT(*) FROM peer_endpoint_observations WHERE recorded_by = ?1",
            rusqlite::params![&bob.identity],
            |row| row.get(0),
        )
        .unwrap();

    // Both should have recorded at least one observation
    assert!(
        alice_obs >= 1,
        "alice should have endpoint observations, got {}",
        alice_obs
    );
    assert!(
        bob_obs >= 1,
        "bob should have endpoint observations, got {}",
        bob_obs
    );

    // Purge with past cutoff (0) should keep all (all have future expires_at)
    let purged = purge_expired_endpoints(&alice_db, 0).unwrap();
    assert_eq!(purged, 0, "purge with past cutoff should keep all");

    let still_there: i64 = alice_db
        .query_row(
            "SELECT COUNT(*) FROM peer_endpoint_observations WHERE recorded_by = ?1",
            rusqlite::params![&alice.identity],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        still_there, alice_obs,
        "observations should still be there after past-cutoff purge"
    );

    // Purge with far-future cutoff should remove all
    let purged = purge_expired_endpoints(&alice_db, i64::MAX).unwrap();
    assert!(
        purged >= 1,
        "purge with far-future cutoff should remove observations"
    );

    let remaining: i64 = alice_db
        .query_row(
            "SELECT COUNT(*) FROM peer_endpoint_observations WHERE recorded_by = ?1",
            rusqlite::params![&alice.identity],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        remaining, 0,
        "no observations should remain after far-future purge"
    );

    harness.finish();
}
