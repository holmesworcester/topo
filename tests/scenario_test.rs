use std::sync::Arc;
use std::time::{Duration, Instant};
use poc_7::testutil::{Peer, start_peers, assert_eventually, sync_until_converged, verify_projection_invariants};
use poc_7::transport::{
    AllowedPeers, create_client_endpoint, create_server_endpoint,
    extract_spki_fingerprint, load_or_generate_cert, peer_identity_from_connection,
};
use poc_7::identity::cert_paths_from_db;

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
