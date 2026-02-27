//! Performance benchmarks for sync system
//!
//! Run with: cargo test --release --test perf_test -- --nocapture
//! Slow tests: cargo test --release --test perf_test -- --nocapture --ignored

use std::time::{Duration, Instant};
use topo::testutil::{Peer, assert_eventually, start_peers_pinned, sync_until_converged};



/// Read peak resident set size from /proc/self/status (Linux only).
fn peak_rss_mib() -> f64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if line.starts_with("VmHWM:") {
            // Format: "VmHWM:    12345 kB"
            let kb: f64 = line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0.0);
            return kb / 1024.0;
        }
    }
    0.0
}

/// 50k one-way sync: generate on one side, sync until all 50k messages
/// are projected on the receiving peer. Reports msgs/s, wall time,
/// and peak memory.
#[tokio::test]
async fn perf_sync_50k() {
    const N: i64 = 50_000;

    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_in_workspace("bob", &alice).await;

    let gen_start = Instant::now();
    alice.batch_create_messages(N as usize);
    let gen_secs = gen_start.elapsed().as_secs_f64();
    eprintln!("Generated {N} messages in {gen_secs:.2}s");

    let rss_before = peak_rss_mib();

    let metrics = sync_until_converged(
        &alice, &bob, || bob.message_count() == N, Duration::from_secs(300),
    ).await;

    let rss_after = peak_rss_mib();

    assert_eq!(bob.message_count(), N);

    let msgs_per_sec = N as f64 / metrics.wall_secs;

    eprintln!();
    eprintln!("=== 50k one-way sync ===");
    eprintln!("  Wall time:    {:.2}s", metrics.wall_secs);
    eprintln!("  Messages:     {N}");
    eprintln!("  Msgs/s:       {msgs_per_sec:.0}");
    eprintln!("  Peak RSS:     {:.1} MiB (before: {:.1}, after: {:.1})",
        rss_after, rss_before, rss_after);
    eprintln!();
}

/// 10k bidirectional sync: generate 5k on each side, sync until all 10k
/// messages are projected on both peers.
#[tokio::test]
async fn perf_sync_10k() {
    const N: i64 = 5_000;

    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_in_workspace("bob", &alice).await;

    let gen_start = Instant::now();
    alice.batch_create_messages(N as usize);
    bob.batch_create_messages(N as usize);
    let gen_secs = gen_start.elapsed().as_secs_f64();
    eprintln!("Generated {} messages ({N} each) in {gen_secs:.2}s", N * 2);

    let rss_before = peak_rss_mib();

    let metrics = sync_until_converged(
        &alice, &bob,
        || alice.message_count() == N * 2 && bob.message_count() == N * 2,
        Duration::from_secs(120),
    ).await;

    let rss_after = peak_rss_mib();

    assert_eq!(alice.message_count(), N * 2);
    assert_eq!(bob.message_count(), N * 2);

    let msgs_per_sec = (N * 2) as f64 / metrics.wall_secs;

    eprintln!();
    eprintln!("=== 10k bidirectional sync ===");
    eprintln!("  Wall time:    {:.2}s", metrics.wall_secs);
    eprintln!("  Messages:     {}", N * 2);
    eprintln!("  Msgs/s:       {msgs_per_sec:.0}");
    eprintln!("  Peak RSS:     {:.1} MiB (before: {:.1}, after: {:.1})",
        rss_after, rss_before, rss_after);
    eprintln!();
}

/// 10k continuous: start sync first, then inject 5k messages on each side
/// while sync is running. Measures how well sync keeps up with ongoing writes.
#[tokio::test]
async fn perf_continuous_10k() {
    let alice = Peer::new_with_identity("alice");
    // Use a shared workspace so workspace-scoped sync transfers content events.
    let bob = Peer::new_in_workspace("bob", &alice).await;

    let rss_before = peak_rss_mib();

    // Start sync between peers in the same workspace.
    let sync = start_peers_pinned(&alice, &bob);

    // Give sync a moment to connect
    tokio::time::sleep(Duration::from_millis(500)).await;

    let start = Instant::now();

    // Inject 5k messages on each side in batches while sync runs.
    // Using batch_create_messages would lock the DB for too long,
    // so we do smaller batches to let sync interleave.
    let alice_db = alice.db_path.clone();
    let alice_author = alice.author_id;
    let alice_channel = alice.workspace_id;
    let alice_identity = alice.identity.clone();
    let alice_signer_eid = alice.peer_shared_event_id.expect("alice has identity");
    let alice_signing_key = alice.peer_shared_signing_key.clone().expect("alice has signing key");
    let bob_db = bob.db_path.clone();
    let bob_author = bob.author_id;
    let bob_channel = bob.workspace_id;
    let bob_identity = bob.identity.clone();
    let bob_signer_eid = bob.peer_shared_event_id.expect("bob has identity");
    let bob_signing_key = bob.peer_shared_signing_key.clone().expect("bob has signing key");

    let alice_writer = std::thread::spawn(move || {
        inject_messages_batched(&alice_db, alice_channel, alice_author, "alice", 5_000, 100, &alice_identity, alice_signer_eid, &alice_signing_key);
    });

    let bob_writer = std::thread::spawn(move || {
        inject_messages_batched(&bob_db, bob_channel, bob_author, "bob", 5_000, 100, &bob_identity, bob_signer_eid, &bob_signing_key);
    });

    alice_writer.join().expect("alice writer panicked");
    bob_writer.join().expect("bob writer panicked");

    let inject_secs = start.elapsed().as_secs_f64();
    eprintln!("Injected 10k events (5k each) in {:.2}s", inject_secs);

    // In a shared workspace, both peers should project all 10k messages.
    let expected_messages: i64 = 10_000;

    // Wait for convergence (projection + minimal store sanity).
    assert_eventually(
        || alice.message_count() == expected_messages && bob.message_count() == expected_messages
            && alice.store_count() >= expected_messages && bob.store_count() >= expected_messages,
        Duration::from_secs(300),
        &format!(
            "convergence to {} projected messages (store: a={}, b={}; projected: a={}, b={})",
            expected_messages,
            alice.store_count(),
            bob.store_count(),
            alice.message_count(),
            bob.message_count(),
        ),
    ).await;

    let wall_secs = start.elapsed().as_secs_f64();
    let rss_after = peak_rss_mib();

    drop(sync);

    let events_transferred = 10_000u64; // 5k each direction
    let bytes_transferred = events_transferred * 100; // variable-length estimate
    let events_per_sec = events_transferred as f64 / wall_secs;
    let throughput_mib_s = (bytes_transferred as f64) / (1024.0 * 1024.0) / wall_secs.max(0.001);

    assert_eq!(alice.message_count(), expected_messages);
    assert_eq!(bob.message_count(), expected_messages);

    eprintln!();
    eprintln!("=== 10k continuous sync (inject while syncing) ===");
    eprintln!("  Wall time:    {:.2}s (inject: {:.2}s)", wall_secs, inject_secs);
    eprintln!("  Events:       {}", events_transferred);
    eprintln!("  Events/s:     {:.0}", events_per_sec);
    eprintln!("  Throughput:   {:.2} MiB/s", throughput_mib_s);
    eprintln!("  Peak RSS:     {:.1} MiB (before: {:.1}, after: {:.1})",
        rss_after, rss_before, rss_after);
    eprintln!();
}

/// 100k one-way sync.
#[tokio::test]
#[ignore]
async fn perf_sync_100k() {
    const N: i64 = 100_000;

    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_in_workspace("bob", &alice).await;

    let gen_start = Instant::now();
    alice.batch_create_messages(N as usize);
    let gen_secs = gen_start.elapsed().as_secs_f64();
    eprintln!("Generated {N} messages in {gen_secs:.2}s");

    let rss_before = peak_rss_mib();

    let metrics = sync_until_converged(
        &alice, &bob, || bob.message_count() == N, Duration::from_secs(600),
    ).await;

    let rss_after = peak_rss_mib();

    assert_eq!(bob.message_count(), N);

    let msgs_per_sec = N as f64 / metrics.wall_secs;

    eprintln!();
    eprintln!("=== 100k one-way sync ===");
    eprintln!("  Wall time:    {:.2}s", metrics.wall_secs);
    eprintln!("  Messages:     {N}");
    eprintln!("  Msgs/s:       {msgs_per_sec:.0}");
    eprintln!("  Peak RSS:     {:.1} MiB (before: {:.1}, after: {:.1})",
        rss_after, rss_before, rss_after);
    eprintln!();
}

/// 200k one-way sync.
#[tokio::test]
#[ignore]
async fn perf_sync_200k() {
    const N: i64 = 200_000;

    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_in_workspace("bob", &alice).await;

    let gen_start = Instant::now();
    alice.batch_create_messages(N as usize);
    let gen_secs = gen_start.elapsed().as_secs_f64();
    eprintln!("Generated {N} messages in {gen_secs:.2}s");

    let rss_before = peak_rss_mib();

    let metrics = sync_until_converged(
        &alice, &bob, || bob.message_count() == N, Duration::from_secs(600),
    ).await;

    let rss_after = peak_rss_mib();

    assert_eq!(bob.message_count(), N);

    let msgs_per_sec = N as f64 / metrics.wall_secs;

    eprintln!();
    eprintln!("=== 200k one-way sync ===");
    eprintln!("  Wall time:    {:.2}s", metrics.wall_secs);
    eprintln!("  Messages:     {N}");
    eprintln!("  Msgs/s:       {msgs_per_sec:.0}");
    eprintln!("  Peak RSS:     {:.1} MiB (before: {:.1}, after: {:.1})",
        rss_after, rss_before, rss_after);
    eprintln!();
}

/// 500k one-way sync.
#[tokio::test]
#[ignore]
async fn perf_sync_500k() {
    const N: i64 = 500_000;

    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_in_workspace("bob", &alice).await;

    let gen_start = Instant::now();
    alice.batch_create_messages(N as usize);
    let gen_secs = gen_start.elapsed().as_secs_f64();
    eprintln!("Generated {N} messages in {gen_secs:.2}s");

    let rss_before = peak_rss_mib();

    let metrics = sync_until_converged(
        &alice, &bob, || bob.message_count() == N, Duration::from_secs(1200),
    ).await;

    let rss_after = peak_rss_mib();

    assert_eq!(bob.message_count(), N);

    let msgs_per_sec = N as f64 / metrics.wall_secs;

    eprintln!();
    eprintln!("=== 500k one-way sync ===");
    eprintln!("  Wall time:    {:.2}s", metrics.wall_secs);
    eprintln!("  Messages:     {N}");
    eprintln!("  Msgs/s:       {msgs_per_sec:.0}");
    eprintln!("  Peak RSS:     {:.1} MiB (before: {:.1}, after: {:.1})",
        rss_after, rss_before, rss_after);
    eprintln!();
}

/// Insert messages in small batches, yielding between batches so sync can interleave.
/// Messages are signed with the given PeerShared key for proper identity chain verification.
fn inject_messages_batched(
    db_path: &str,
    workspace_id: [u8; 32],
    author_id: [u8; 32],
    name: &str,
    total: usize,
    batch_size: usize,
    recorded_by: &str,
    signer_eid: [u8; 32],
    signing_key: &ed25519_dalek::SigningKey,
) {
    use std::time::{SystemTime, UNIX_EPOCH};
    use topo::db::open_connection;
    use topo::event_modules::{MessageEvent, ParsedEvent};
    use topo::projection::create::create_signed_event_sync;

    let db = open_connection(db_path).expect("failed to open db");

    let mut i = 0;
    while i < total {
        let end = (i + batch_size).min(total);
        db.execute("BEGIN", []).expect("failed to begin");
        for j in i..end {
            let created_at_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
            let msg = ParsedEvent::Message(MessageEvent {
                created_at_ms,
                workspace_id,
                author_id,
                content: format!("Msg {} from {}", j, name),
                signed_by: signer_eid,
                signer_type: 5,
                signature: [0u8; 64],
            });
            create_signed_event_sync(&db, recorded_by, &msg, signing_key).expect("create_signed_event_sync failed");
        }
        db.execute("COMMIT", []).expect("failed to commit");
        i = end;
        // Yield briefly so sync can grab the DB
        std::thread::sleep(Duration::from_millis(1));
    }
}
