//! Performance benchmarks for sync system
//!
//! Run with: cargo test --release --test perf_test -- --nocapture

use std::time::{Duration, Instant};
use poc_7::testutil::{Peer, start_peers, assert_eventually, sync_until_converged};

fn test_channel() -> [u8; 32] {
    let mut ch = [0u8; 32];
    ch[0..4].copy_from_slice(b"perf");
    ch
}

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

/// 50k one-way sync: generate on one side, sync to empty peer.
/// Reports MB/s, events/s, wall time, and peak memory.
#[tokio::test]
async fn perf_sync_50k() {
    let channel = test_channel();
    let alice = Peer::new("alice", channel);
    let bob = Peer::new("bob", channel);

    let gen_start = Instant::now();
    alice.batch_create_messages(50_000);
    let gen_secs = gen_start.elapsed().as_secs_f64();
    eprintln!("Generated 50k events in {:.2}s", gen_secs);

    let rss_before = peak_rss_mib();

    let metrics = sync_until_converged(
        &alice, &bob, 50_000, Duration::from_secs(300),
    ).await;

    let rss_after = peak_rss_mib();

    assert_eq!(alice.store_count(), 50_000);
    assert_eq!(bob.store_count(), 50_000);

    eprintln!();
    eprintln!("=== 50k one-way sync ===");
    eprintln!("  Wall time:    {:.2}s", metrics.wall_secs);
    eprintln!("  Events:       {}", metrics.events_transferred);
    eprintln!("  Events/s:     {:.0}", metrics.events_per_sec);
    eprintln!("  Throughput:   {:.2} MiB/s", metrics.throughput_mib_s);
    eprintln!("  Peak RSS:     {:.1} MiB (before: {:.1}, after: {:.1})",
        rss_after, rss_before, rss_after);
    eprintln!();
}

/// 10k bidirectional sync: generate on one side, sync to empty peer.
/// Reports MB/s, events/s, wall time, and peak memory.
#[tokio::test]
async fn perf_sync_10k() {
    let channel = test_channel();
    let alice = Peer::new("alice", channel);
    let bob = Peer::new("bob", channel);

    let gen_start = Instant::now();
    alice.batch_create_messages(5_000);
    bob.batch_create_messages(5_000);
    let gen_secs = gen_start.elapsed().as_secs_f64();
    eprintln!("Generated 10k events (5k each) in {:.2}s", gen_secs);

    let rss_before = peak_rss_mib();

    let metrics = sync_until_converged(
        &alice, &bob, 10_000, Duration::from_secs(120),
    ).await;

    let rss_after = peak_rss_mib();

    assert_eq!(alice.store_count(), 10_000);
    assert_eq!(bob.store_count(), 10_000);

    eprintln!();
    eprintln!("=== 10k bidirectional sync ===");
    eprintln!("  Wall time:    {:.2}s", metrics.wall_secs);
    eprintln!("  Events:       {}", metrics.events_transferred);
    eprintln!("  Events/s:     {:.0}", metrics.events_per_sec);
    eprintln!("  Throughput:   {:.2} MiB/s", metrics.throughput_mib_s);
    eprintln!("  Peak RSS:     {:.1} MiB (before: {:.1}, after: {:.1})",
        rss_after, rss_before, rss_after);
    eprintln!();
}

/// 10k continuous: start sync first, then inject 5k messages on each side
/// while sync is running. Measures how well sync keeps up with ongoing writes.
#[tokio::test]
async fn perf_continuous_10k() {
    let channel = test_channel();
    let alice = Peer::new("alice", channel);
    let bob = Peer::new("bob", channel);

    let rss_before = peak_rss_mib();

    // Start sync with empty peers
    let sync = start_peers(&alice, &bob);

    // Give sync a moment to connect
    tokio::time::sleep(Duration::from_millis(500)).await;

    let start = Instant::now();

    // Inject 5k messages on each side in batches while sync runs.
    // Using batch_create_messages would lock the DB for too long,
    // so we do smaller batches to let sync interleave.
    let alice_db = alice.db_path.clone();
    let alice_author = alice.author_id;
    let alice_channel = alice.channel_id;
    let alice_identity = alice.identity.clone();
    let bob_db = bob.db_path.clone();
    let bob_author = bob.author_id;
    let bob_channel = bob.channel_id;
    let bob_identity = bob.identity.clone();

    let alice_writer = std::thread::spawn(move || {
        inject_messages_batched(&alice_db, alice_channel, alice_author, "alice", 5_000, 100, &alice_identity);
    });

    let bob_writer = std::thread::spawn(move || {
        inject_messages_batched(&bob_db, bob_channel, bob_author, "bob", 5_000, 100, &bob_identity);
    });

    alice_writer.join().expect("alice writer panicked");
    bob_writer.join().expect("bob writer panicked");

    let inject_secs = start.elapsed().as_secs_f64();
    eprintln!("Injected 10k events (5k each) in {:.2}s", inject_secs);

    // Wait for convergence
    assert_eventually(
        || alice.store_count() == 10_000 && bob.store_count() == 10_000,
        Duration::from_secs(120),
        &format!(
            "convergence to 10000 events (a={}, b={})",
            alice.store_count(),
            bob.store_count(),
        ),
    ).await;

    let wall_secs = start.elapsed().as_secs_f64();
    let rss_after = peak_rss_mib();

    drop(sync);

    let events_transferred = 10_000u64; // 5k each direction
    let bytes_transferred = events_transferred * 100; // variable-length estimate
    let events_per_sec = events_transferred as f64 / wall_secs;
    let throughput_mib_s = (bytes_transferred as f64) / (1024.0 * 1024.0) / wall_secs.max(0.001);

    assert_eq!(alice.store_count(), 10_000);
    assert_eq!(bob.store_count(), 10_000);
    assert_eq!(alice.message_count(), 10_000);
    assert_eq!(bob.message_count(), 10_000);

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

/// Insert messages in small batches, yielding between batches so sync can interleave.
fn inject_messages_batched(
    db_path: &str,
    channel_id: [u8; 32],
    author_id: [u8; 32],
    name: &str,
    total: usize,
    batch_size: usize,
    recorded_by: &str,
) {
    use std::time::{SystemTime, UNIX_EPOCH};
    use poc_7::crypto::{hash_event, event_id_to_base64};
    use poc_7::db::open_connection;
    use poc_7::events::{self, MessageEvent, ParsedEvent};

    let db = open_connection(db_path).expect("failed to open db");

    let mut neg_stmt = db.prepare(
        "INSERT OR IGNORE INTO neg_items (ts, id) VALUES (?1, ?2)"
    ).expect("failed to prepare neg_items stmt");
    let mut msg_stmt = db.prepare(
        "INSERT OR IGNORE INTO messages (message_id, channel_id, author_id, content, created_at, recorded_by)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
    ).expect("failed to prepare messages stmt");
    let mut rec_stmt = db.prepare(
        "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source)
         VALUES (?1, ?2, ?3, ?4)"
    ).expect("failed to prepare recorded_events stmt");
    let mut events_stmt = db.prepare(
        "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
    ).expect("failed to prepare events stmt");

    let mut i = 0;
    while i < total {
        let end = (i + batch_size).min(total);
        db.execute("BEGIN", []).expect("failed to begin");
        for j in i..end {
            let content = format!("Msg {} from {}", j, name);
            let created_at_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
            let msg_event = MessageEvent {
                created_at_ms,
                channel_id,
                author_id,
                content: content.clone(),
            };
            let blob = events::encode_event(&ParsedEvent::Message(msg_event))
                .expect("failed to encode message");
            let event_id = hash_event(&blob);

            neg_stmt.execute(rusqlite::params![
                created_at_ms as i64,
                event_id.as_slice()
            ]).expect("neg_items insert");

            let message_id = event_id_to_base64(&event_id);
            let channel_id_b64 = event_id_to_base64(&channel_id);
            let author_id_b64 = event_id_to_base64(&author_id);
            msg_stmt.execute(rusqlite::params![
                message_id, channel_id_b64, author_id_b64, content, created_at_ms as i64, recorded_by
            ]).expect("messages insert");

            events_stmt.execute(rusqlite::params![
                message_id, "message", blob.as_slice(), "shared", created_at_ms as i64, created_at_ms as i64
            ]).expect("events insert");
            let recorded_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64;
            rec_stmt.execute(rusqlite::params![
                recorded_by, &message_id, recorded_at, "local_create"
            ]).expect("recorded_events insert");
        }
        db.execute("COMMIT", []).expect("failed to commit");
        i = end;
        // Yield briefly so sync can grab the DB
        std::thread::sleep(Duration::from_millis(1));
    }
}
