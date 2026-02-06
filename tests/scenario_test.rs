use std::time::{Duration, Instant};
use poc_7::testutil::{Peer, start_peers, assert_eventually, sync_until_converged};

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
