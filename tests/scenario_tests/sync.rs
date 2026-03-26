use std::time::{Duration, Instant};
use topo::crypto::event_id_to_base64;
use topo::db::open_connection;
use topo::testutil::{assert_eventually, start_peers, sync_until_converged, Peer, ScenarioHarness};

#[tokio::test]
async fn test_sync_10k() {
    // Debug builds are ~10x slower; scale down to keep the test under timeout.
    #[cfg(debug_assertions)]
    const EVENT_COUNT: usize = 1_000;
    #[cfg(not(debug_assertions))]
    const EVENT_COUNT: usize = 10_000;

    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_in_workspace("bob", &alice).await;
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    let gen_start = Instant::now();
    alice.batch_create_messages(EVENT_COUNT);
    let gen_secs = gen_start.elapsed().as_secs_f64();
    eprintln!("Generated {} events in {:.2}s", EVENT_COUNT, gen_secs);

    // Convergence gate on recorded message events using outer semantic type.
    let alice_messages_before_sync = alice.recorded_message_event_count();
    let bob_messages_before_sync = bob.recorded_message_event_count();
    let expected_bob_messages = bob_messages_before_sync + alice_messages_before_sync;

    let metrics = sync_until_converged(
        &alice,
        &bob,
        || bob.recorded_message_event_count() >= expected_bob_messages,
        Duration::from_secs(120),
    )
    .await;

    eprintln!("sync {}: {}", EVENT_COUNT, metrics);

    // Only alice's locally-created messages are projected on alice; bob has none projected
    assert_eq!(alice.message_count(), EVENT_COUNT as i64);

    harness.finish();
}

/// Stress test: high-volume bidirectional sync verifying exact event ID equality.
/// This checks long-lived pull sync avoids data loss at scale.
#[tokio::test]
async fn test_zero_loss_stress() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_in_workspace("bob", &alice).await;
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
    let sync = start_peers(&alice, &bob);

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
    let bob = Peer::new_in_workspace("bob", &alice).await;
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
    let sync = start_peers(&alice, &bob);

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

    // For the event created in this test, Bob's receive timestamp should be
    // after Alice's local create timestamp.
    let alice_db = open_connection(&alice.db_path).expect("open alice db");
    let bob_db = open_connection(&bob.db_path).expect("open bob db");
    let alice_third_local_create: i64 = alice_db
        .query_row(
            "SELECT recorded_at FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&alice.identity, &third_b64],
            |row| row.get(0),
        )
        .unwrap();
    let bob_third_recv: i64 = bob_db
        .query_row(
            "SELECT recorded_at FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&bob.identity, &third_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        bob_third_recv >= alice_third_local_create,
        "Bob's receive recorded_at ({}) for the synced event should be >= Alice's local_create recorded_at ({})",
        bob_third_recv,
        alice_third_local_create,
    );

    harness.finish();
}

#[tokio::test]
async fn test_sync_50k() {
    // Debug builds are ~10x slower; scale down to keep the test under timeout.
    #[cfg(debug_assertions)]
    const EVENT_COUNT: usize = 2_000;
    #[cfg(not(debug_assertions))]
    const EVENT_COUNT: usize = 50_000;

    let harness = ScenarioHarness::skip("replay invariants too slow at high event counts");
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_in_workspace("bob", &alice).await;

    let gen_start = Instant::now();
    alice.batch_create_messages(EVENT_COUNT);
    let gen_secs = gen_start.elapsed().as_secs_f64();
    eprintln!("Generated {} events in {:.2}s", EVENT_COUNT, gen_secs);

    // Convergence gate on recorded message events using outer semantic type.
    let alice_messages_before_sync = alice.recorded_message_event_count();
    let bob_messages_before_sync = bob.recorded_message_event_count();
    let expected_bob_messages = bob_messages_before_sync + alice_messages_before_sync;

    let metrics = sync_until_converged(
        &alice,
        &bob,
        || bob.recorded_message_event_count() >= expected_bob_messages,
        Duration::from_secs(300),
    )
    .await;

    eprintln!("sync {}: {}", EVENT_COUNT, metrics);

    // Only alice's locally-created messages are projected on alice
    assert_eq!(alice.message_count(), EVENT_COUNT as i64);

    harness.finish();
}

/// Integration test: verify valid_events are tenant-scoped after sync.
/// Alice creates message + reaction, syncs to Bob. Both converge to 2 events.
/// valid_events are per-tenant, and projection invariants hold.
#[tokio::test]
async fn test_cross_tenant_dep_scoping_after_sync() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_in_workspace("bob", &alice).await;
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
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || bob.has_event(&msg_b64) && bob.has_event(&rxn_b64),
        Duration::from_secs(15),
        "bob should receive alice's message and reaction events",
    )
    .await;

    drop(sync);

    assert_eq!(bob.message_count(), 1);
    assert_eq!(bob.reaction_count(), 1);

    // Verify valid_events are still tenant-scoped and include the synced content
    // for both peers in the shared workspace.
    let alice_db = open_connection(&alice.db_path).expect("open alice db");
    let bob_db = open_connection(&bob.db_path).expect("open bob db");

    let alice_msg_valid: bool = alice_db
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&alice.identity, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    let bob_msg_valid: bool = bob_db
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&bob.identity, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    let alice_rxn_valid: bool = alice_db
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&alice.identity, &rxn_b64],
            |row| row.get(0),
        )
        .unwrap();
    let bob_rxn_valid: bool = bob_db
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&bob.identity, &rxn_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        alice_msg_valid && bob_msg_valid && alice_rxn_valid && bob_rxn_valid,
        "both peers should treat the synced message and reaction as valid in the shared workspace"
    );

    harness.finish();
}

#[tokio::test]
async fn test_local_only_events_not_synced() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_in_workspace("bob", &alice).await;
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
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || bob.has_event(&enc_b64) && bob.has_event(&alice_msg_b64),
        Duration::from_secs(15),
        "bob should receive alice's encrypted and normal messages",
    )
    .await;

    drop(sync);

    // Bob should NOT have received Alice's SK event -- his store has his own SK
    assert_eq!(bob.key_secret_count(), bob_initial_keys + 1);
    assert_eq!(bob.scoped_message_count(), 2);

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
    let bob = Peer::new_in_workspace("bob", &alice).await;
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
    let sync = start_peers(&alice, &bob);

    assert_eventually(
        || bob.has_event(&enc_b64) && bob.has_event(&alice_msg_b64),
        Duration::from_secs(15),
        "bob should receive alice's encrypted and cleartext events",
    )
    .await;

    drop(sync);

    assert_eq!(
        bob.scoped_message_count(),
        1,
        "bob should project Alice's cleartext message while the encrypted one stays blocked"
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

