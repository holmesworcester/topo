//! Performance benchmarks for sync system
//!
//! Run with: cargo test --release --test perf_test -- --nocapture
//! Slow tests: cargo test --release --test perf_test -- --nocapture --ignored

mod perf_metrics;

use perf_metrics::{
    bandwidth_summary, delay_from, diff_new_ids, enable_projection_timeline, max_opt, min_opt,
    projection_window, total_event_blob_bytes,
};
use std::time::{Duration, Instant};
use topo::testutil::{assert_eventually, start_peers, sync_until_converged, Peer};

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

fn current_timestamp_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_millis() as i64
}

struct ProjectionPerfSummary {
    first_recorded_at_delay_ms: Option<i64>,
    last_recorded_at_delay_ms: Option<i64>,
    first_projected_at_delay_ms: Option<i64>,
    last_projected_at_delay_ms: Option<i64>,
    projected_tail_ms: Option<i64>,
    payload: perf_metrics::BandwidthSummary,
}

fn summarize_projection(
    request_start_ms: i64,
    windows: &[perf_metrics::ProjectionWindow],
    payload_bytes: u64,
    wall_secs: f64,
) -> ProjectionPerfSummary {
    let mut first_recorded_at = None;
    let mut last_recorded_at = None;
    let mut first_projected_at = None;
    let mut last_projected_at = None;

    for window in windows {
        first_recorded_at = min_opt(first_recorded_at, window.recorded_at.first_at_ms);
        last_recorded_at = max_opt(last_recorded_at, window.recorded_at.last_at_ms);
        first_projected_at = min_opt(first_projected_at, window.projected_at.first_at_ms);
        last_projected_at = max_opt(last_projected_at, window.projected_at.last_at_ms);
    }

    ProjectionPerfSummary {
        first_recorded_at_delay_ms: delay_from(request_start_ms, first_recorded_at),
        last_recorded_at_delay_ms: delay_from(request_start_ms, last_recorded_at),
        first_projected_at_delay_ms: delay_from(request_start_ms, first_projected_at),
        last_projected_at_delay_ms: delay_from(request_start_ms, last_projected_at),
        projected_tail_ms: match (last_recorded_at, last_projected_at) {
            (Some(recorded), Some(projected)) => Some(projected.saturating_sub(recorded)),
            _ => None,
        },
        payload: bandwidth_summary(payload_bytes, wall_secs, None),
    }
}

fn fmt_delay(label: &str, delay_ms: Option<i64>) {
    if let Some(delay_ms) = delay_ms {
        eprintln!("  {label:<18} {delay_ms} ms after start");
    }
}

/// 50k one-way sync: generate on one side, sync until all 50k messages
/// are projected on the receiving peer. Reports msgs/s, wall time,
/// and peak memory.
#[tokio::test]
#[ignore]
async fn perf_sync_50k() {
    const N: i64 = 50_000;
    enable_projection_timeline();

    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_in_workspace("bob", &alice).await;
    let alice_baseline_ids = alice.recorded_message_event_ids();

    let gen_start = Instant::now();
    alice.batch_create_messages(N as usize);
    let gen_secs = gen_start.elapsed().as_secs_f64();
    eprintln!("Generated {N} messages in {gen_secs:.2}s");
    let alice_target_ids = diff_new_ids(&alice_baseline_ids, &alice.recorded_message_event_ids());

    let rss_before = peak_rss_mib();
    let request_start_ms = current_timestamp_ms();

    let metrics = sync_until_converged(
        &alice,
        &bob,
        || bob.message_count() == N,
        Duration::from_secs(300),
    )
    .await;

    let rss_after = peak_rss_mib();

    assert_eq!(bob.message_count(), N);

    let msgs_per_sec = N as f64 / metrics.wall_secs;
    let projection = summarize_projection(
        request_start_ms,
        &[projection_window(
            &bob.db_path,
            &bob.identity,
            &alice_target_ids,
        )],
        total_event_blob_bytes(&alice.db_path, &alice_target_ids),
        metrics.wall_secs,
    );

    eprintln!();
    eprintln!("=== 50k one-way sync ===");
    eprintln!("  Full projected_count: {:.2}s", metrics.wall_secs);
    fmt_delay("First recorded_at:", projection.first_recorded_at_delay_ms);
    fmt_delay("Last recorded_at:", projection.last_recorded_at_delay_ms);
    fmt_delay(
        "First projected_at:",
        projection.first_projected_at_delay_ms,
    );
    fmt_delay("Last projected_at:", projection.last_projected_at_delay_ms);
    if let Some(projected_tail_ms) = projection.projected_tail_ms {
        eprintln!(
            "  Projected tail:    {projected_tail_ms} ms (last recorded_at -> last projected_at)"
        );
    }
    eprintln!("  Generate:          {gen_secs:.2}s");
    eprintln!("  Messages:     {N}");
    eprintln!("  Projected msgs/s:  {msgs_per_sec:.0}");
    eprintln!("  Payload bytes:     {}", projection.payload.payload_bytes);
    eprintln!(
        "  Payload MiB/s:     {:.2}",
        projection.payload.payload_mib_s
    );
    eprintln!(
        "  Payload Mbps:      {:.2}",
        projection.payload.payload_mbps
    );
    eprintln!(
        "  Peak RSS:     {:.1} MiB (before: {:.1}, after: {:.1})",
        rss_after, rss_before, rss_after
    );
    eprintln!();
}

/// 10k bidirectional sync: generate 5k on each side, sync until all 10k
/// messages are projected on both peers.
#[tokio::test]
#[ignore]
async fn perf_sync_10k() {
    const N: i64 = 5_000;
    enable_projection_timeline();

    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_in_workspace("bob", &alice).await;
    let alice_baseline_ids = alice.recorded_message_event_ids();
    let bob_baseline_ids = bob.recorded_message_event_ids();

    let gen_start = Instant::now();
    alice.batch_create_messages(N as usize);
    bob.batch_create_messages(N as usize);
    let gen_secs = gen_start.elapsed().as_secs_f64();
    eprintln!("Generated {} messages ({N} each) in {gen_secs:.2}s", N * 2);
    let alice_target_ids = diff_new_ids(&alice_baseline_ids, &alice.recorded_message_event_ids());
    let bob_target_ids = diff_new_ids(&bob_baseline_ids, &bob.recorded_message_event_ids());

    let rss_before = peak_rss_mib();
    let request_start_ms = current_timestamp_ms();

    let metrics = sync_until_converged(
        &alice,
        &bob,
        || alice.message_count() == N * 2 && bob.message_count() == N * 2,
        Duration::from_secs(120),
    )
    .await;

    let rss_after = peak_rss_mib();

    assert_eq!(alice.message_count(), N * 2);
    assert_eq!(bob.message_count(), N * 2);

    let msgs_per_sec = (N * 2) as f64 / metrics.wall_secs;
    let projection = summarize_projection(
        request_start_ms,
        &[
            projection_window(&alice.db_path, &alice.identity, &bob_target_ids),
            projection_window(&bob.db_path, &bob.identity, &alice_target_ids),
        ],
        total_event_blob_bytes(&alice.db_path, &alice_target_ids)
            + total_event_blob_bytes(&bob.db_path, &bob_target_ids),
        metrics.wall_secs,
    );

    eprintln!();
    eprintln!("=== 10k bidirectional sync ===");
    eprintln!("  Full projected_count: {:.2}s", metrics.wall_secs);
    fmt_delay("First recorded_at:", projection.first_recorded_at_delay_ms);
    fmt_delay("Last recorded_at:", projection.last_recorded_at_delay_ms);
    fmt_delay(
        "First projected_at:",
        projection.first_projected_at_delay_ms,
    );
    fmt_delay("Last projected_at:", projection.last_projected_at_delay_ms);
    if let Some(projected_tail_ms) = projection.projected_tail_ms {
        eprintln!(
            "  Projected tail:    {projected_tail_ms} ms (last recorded_at -> last projected_at)"
        );
    }
    eprintln!("  Generate:          {gen_secs:.2}s");
    eprintln!("  Messages:     {}", N * 2);
    eprintln!("  Projected msgs/s:  {msgs_per_sec:.0}");
    eprintln!("  Payload bytes:     {}", projection.payload.payload_bytes);
    eprintln!(
        "  Payload MiB/s:     {:.2}",
        projection.payload.payload_mib_s
    );
    eprintln!(
        "  Payload Mbps:      {:.2}",
        projection.payload.payload_mbps
    );
    eprintln!(
        "  Peak RSS:     {:.1} MiB (before: {:.1}, after: {:.1})",
        rss_after, rss_before, rss_after
    );
    eprintln!();
}

/// 10k continuous: start sync first, then inject 5k messages on each side
/// while sync is running. Measures how well sync keeps up with ongoing writes.
#[tokio::test]
#[ignore]
async fn perf_continuous_10k() {
    enable_projection_timeline();
    let alice = Peer::new_with_identity("alice");
    // Use a shared workspace so workspace-scoped sync transfers content events.
    let bob = Peer::new_in_workspace("bob", &alice).await;
    let alice_baseline_ids = alice.recorded_message_event_ids();
    let bob_baseline_ids = bob.recorded_message_event_ids();

    let rss_before = peak_rss_mib();

    // Start sync between peers in the same workspace.
    let sync = start_peers(&alice, &bob);

    // Give sync a moment to connect
    tokio::time::sleep(Duration::from_millis(500)).await;

    let start = Instant::now();
    let request_start_ms = current_timestamp_ms();

    // Inject 5k messages on each side in batches while sync runs.
    // Using batch_create_messages would lock the DB for too long,
    // so we do smaller batches to let sync interleave.
    let alice_db = alice.db_path.clone();
    let alice_author = alice.author_id;
    let alice_channel = alice.workspace_id;
    let alice_identity = alice.identity.clone();
    let alice_signer_eid = alice.peer_shared_event_id.expect("alice has identity");
    let alice_signing_key = alice
        .peer_shared_signing_key
        .clone()
        .expect("alice has signing key");
    let alice_key_event_id = alice.ensure_content_key_event_id();
    let bob_db = bob.db_path.clone();
    let bob_author = bob.author_id;
    let bob_channel = bob.workspace_id;
    let bob_identity = bob.identity.clone();
    let bob_signer_eid = bob.peer_shared_event_id.expect("bob has identity");
    let bob_signing_key = bob
        .peer_shared_signing_key
        .clone()
        .expect("bob has signing key");
    let bob_key_event_id = bob.ensure_content_key_event_id();

    let alice_writer = std::thread::spawn(move || {
        inject_messages_batched(
            &alice_db,
            alice_channel,
            alice_author,
            "alice",
            5_000,
            100,
            &alice_identity,
            alice_key_event_id,
            alice_signer_eid,
            &alice_signing_key,
        );
    });

    let bob_writer = std::thread::spawn(move || {
        inject_messages_batched(
            &bob_db,
            bob_channel,
            bob_author,
            "bob",
            5_000,
            100,
            &bob_identity,
            bob_key_event_id,
            bob_signer_eid,
            &bob_signing_key,
        );
    });

    alice_writer.join().expect("alice writer panicked");
    bob_writer.join().expect("bob writer panicked");

    let inject_secs = start.elapsed().as_secs_f64();
    eprintln!("Injected 10k events (5k each) in {:.2}s", inject_secs);
    let alice_target_ids = diff_new_ids(&alice_baseline_ids, &alice.recorded_message_event_ids());
    let bob_target_ids = diff_new_ids(&bob_baseline_ids, &bob.recorded_message_event_ids());

    // In a shared workspace, both peers should project all 10k messages.
    let expected_messages: i64 = 10_000;

    // Wait for convergence on projected messages.
    assert_eventually(
        || alice.message_count() == expected_messages && bob.message_count() == expected_messages,
        Duration::from_secs(300),
        &format!(
            "convergence to {} projected messages (projected: a={}, b={})",
            expected_messages,
            alice.message_count(),
            bob.message_count(),
        ),
    )
    .await;

    let wall_secs = start.elapsed().as_secs_f64();
    let rss_after = peak_rss_mib();

    drop(sync);

    let events_transferred = 10_000u64; // 5k each direction
    let events_per_sec = events_transferred as f64 / wall_secs;
    let projection = summarize_projection(
        request_start_ms,
        &[
            projection_window(&alice.db_path, &alice.identity, &bob_target_ids),
            projection_window(&bob.db_path, &bob.identity, &alice_target_ids),
        ],
        total_event_blob_bytes(&alice.db_path, &alice_target_ids)
            + total_event_blob_bytes(&bob.db_path, &bob_target_ids),
        wall_secs,
    );

    assert_eq!(alice.message_count(), expected_messages);
    assert_eq!(bob.message_count(), expected_messages);

    eprintln!();
    eprintln!("=== 10k continuous sync (inject while syncing) ===");
    eprintln!("  Full projected_count: {:.2}s", wall_secs);
    fmt_delay("First recorded_at:", projection.first_recorded_at_delay_ms);
    fmt_delay("Last recorded_at:", projection.last_recorded_at_delay_ms);
    fmt_delay(
        "First projected_at:",
        projection.first_projected_at_delay_ms,
    );
    fmt_delay("Last projected_at:", projection.last_projected_at_delay_ms);
    if let Some(projected_tail_ms) = projection.projected_tail_ms {
        eprintln!(
            "  Projected tail:    {projected_tail_ms} ms (last recorded_at -> last projected_at)"
        );
    }
    eprintln!("  Generate:          {:.2}s", inject_secs);
    eprintln!("  Events:       {}", events_transferred);
    eprintln!("  Projected msgs/s:  {:.0}", events_per_sec);
    eprintln!("  Payload bytes:     {}", projection.payload.payload_bytes);
    eprintln!(
        "  Payload MiB/s:     {:.2}",
        projection.payload.payload_mib_s
    );
    eprintln!(
        "  Payload Mbps:      {:.2}",
        projection.payload.payload_mbps
    );
    eprintln!(
        "  Peak RSS:     {:.1} MiB (before: {:.1}, after: {:.1})",
        rss_after, rss_before, rss_after
    );
    eprintln!();
}

/// 100k one-way sync.
#[tokio::test]
#[ignore]
async fn perf_sync_100k() {
    const N: i64 = 100_000;
    enable_projection_timeline();

    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_in_workspace("bob", &alice).await;
    let alice_baseline_ids = alice.recorded_message_event_ids();

    let gen_start = Instant::now();
    alice.batch_create_messages(N as usize);
    let gen_secs = gen_start.elapsed().as_secs_f64();
    eprintln!("Generated {N} messages in {gen_secs:.2}s");
    let alice_target_ids = diff_new_ids(&alice_baseline_ids, &alice.recorded_message_event_ids());

    let rss_before = peak_rss_mib();
    let request_start_ms = current_timestamp_ms();

    let metrics = sync_until_converged(
        &alice,
        &bob,
        || bob.message_count() == N,
        Duration::from_secs(600),
    )
    .await;

    let rss_after = peak_rss_mib();

    assert_eq!(bob.message_count(), N);

    let msgs_per_sec = N as f64 / metrics.wall_secs;
    let projection = summarize_projection(
        request_start_ms,
        &[projection_window(
            &bob.db_path,
            &bob.identity,
            &alice_target_ids,
        )],
        total_event_blob_bytes(&alice.db_path, &alice_target_ids),
        metrics.wall_secs,
    );

    eprintln!();
    eprintln!("=== 100k one-way sync ===");
    eprintln!("  Full projected_count: {:.2}s", metrics.wall_secs);
    fmt_delay("First recorded_at:", projection.first_recorded_at_delay_ms);
    fmt_delay("Last recorded_at:", projection.last_recorded_at_delay_ms);
    fmt_delay(
        "First projected_at:",
        projection.first_projected_at_delay_ms,
    );
    fmt_delay("Last projected_at:", projection.last_projected_at_delay_ms);
    if let Some(projected_tail_ms) = projection.projected_tail_ms {
        eprintln!(
            "  Projected tail:    {projected_tail_ms} ms (last recorded_at -> last projected_at)"
        );
    }
    eprintln!("  Generate:          {gen_secs:.2}s");
    eprintln!("  Messages:     {N}");
    eprintln!("  Projected msgs/s:  {msgs_per_sec:.0}");
    eprintln!("  Payload bytes:     {}", projection.payload.payload_bytes);
    eprintln!(
        "  Payload MiB/s:     {:.2}",
        projection.payload.payload_mib_s
    );
    eprintln!(
        "  Payload Mbps:      {:.2}",
        projection.payload.payload_mbps
    );
    eprintln!(
        "  Peak RSS:     {:.1} MiB (before: {:.1}, after: {:.1})",
        rss_after, rss_before, rss_after
    );
    eprintln!();
}

/// 200k one-way sync.
#[tokio::test]
#[ignore]
async fn perf_sync_200k() {
    const N: i64 = 200_000;
    enable_projection_timeline();

    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_in_workspace("bob", &alice).await;
    let alice_baseline_ids = alice.recorded_message_event_ids();

    let gen_start = Instant::now();
    alice.batch_create_messages(N as usize);
    let gen_secs = gen_start.elapsed().as_secs_f64();
    eprintln!("Generated {N} messages in {gen_secs:.2}s");
    let alice_target_ids = diff_new_ids(&alice_baseline_ids, &alice.recorded_message_event_ids());

    let rss_before = peak_rss_mib();
    let request_start_ms = current_timestamp_ms();

    let metrics = sync_until_converged(
        &alice,
        &bob,
        || bob.message_count() == N,
        Duration::from_secs(600),
    )
    .await;

    let rss_after = peak_rss_mib();

    assert_eq!(bob.message_count(), N);

    let msgs_per_sec = N as f64 / metrics.wall_secs;
    let projection = summarize_projection(
        request_start_ms,
        &[projection_window(
            &bob.db_path,
            &bob.identity,
            &alice_target_ids,
        )],
        total_event_blob_bytes(&alice.db_path, &alice_target_ids),
        metrics.wall_secs,
    );

    eprintln!();
    eprintln!("=== 200k one-way sync ===");
    eprintln!("  Full projected_count: {:.2}s", metrics.wall_secs);
    fmt_delay("First recorded_at:", projection.first_recorded_at_delay_ms);
    fmt_delay("Last recorded_at:", projection.last_recorded_at_delay_ms);
    fmt_delay(
        "First projected_at:",
        projection.first_projected_at_delay_ms,
    );
    fmt_delay("Last projected_at:", projection.last_projected_at_delay_ms);
    if let Some(projected_tail_ms) = projection.projected_tail_ms {
        eprintln!(
            "  Projected tail:    {projected_tail_ms} ms (last recorded_at -> last projected_at)"
        );
    }
    eprintln!("  Generate:          {gen_secs:.2}s");
    eprintln!("  Messages:     {N}");
    eprintln!("  Projected msgs/s:  {msgs_per_sec:.0}");
    eprintln!("  Payload bytes:     {}", projection.payload.payload_bytes);
    eprintln!(
        "  Payload MiB/s:     {:.2}",
        projection.payload.payload_mib_s
    );
    eprintln!(
        "  Payload Mbps:      {:.2}",
        projection.payload.payload_mbps
    );
    eprintln!(
        "  Peak RSS:     {:.1} MiB (before: {:.1}, after: {:.1})",
        rss_after, rss_before, rss_after
    );
    eprintln!();
}

/// 500k one-way sync.
#[tokio::test]
#[ignore]
async fn perf_sync_500k() {
    // Enable tracing for sync diagnostics
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("info"))
        .with_writer(std::io::stderr)
        .try_init();
    enable_projection_timeline();

    const N: i64 = 500_000;

    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_in_workspace("bob", &alice).await;
    let alice_baseline_ids = alice.recorded_message_event_ids();

    let gen_start = Instant::now();
    alice.batch_create_messages(N as usize);
    let gen_secs = gen_start.elapsed().as_secs_f64();
    eprintln!("Generated {N} messages in {gen_secs:.2}s");
    let alice_target_ids = diff_new_ids(&alice_baseline_ids, &alice.recorded_message_event_ids());

    let rss_before = peak_rss_mib();

    let sync_start = Instant::now();
    let request_start_ms = current_timestamp_ms();
    let sync = start_peers(&alice, &bob);

    // Poll with progress reporting
    let timeout = Duration::from_secs(1200);
    let mut last_count = 0i64;
    let mut last_report = Instant::now();
    loop {
        if bob.message_count() >= N {
            break;
        }
        if sync_start.elapsed() >= timeout {
            let count = bob.message_count();
            eprintln!(
                "TIMEOUT: bob has {}/{} projected messages, alice stored_messages={}, bob stored_messages={}",
                count,
                N,
                alice.stored_message_event_count(),
                bob.stored_message_event_count()
            );
            panic!("500k sync timed out after {}s", timeout.as_secs());
        }
        if last_report.elapsed() >= Duration::from_secs(5) {
            let count = bob.message_count();
            let delta = count - last_count;
            let elapsed = sync_start.elapsed().as_secs();
            eprintln!(
                "[+{}s] bob projected messages: {}/{} (delta: +{}), stored_messages: alice={} bob={}, RSS: {:.0} MiB",
                elapsed,
                count,
                N,
                delta,
                alice.stored_message_event_count(),
                bob.stored_message_event_count(),
                peak_rss_mib()
            );
            last_count = count;
            last_report = Instant::now();
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let wall_secs = sync_start.elapsed().as_secs_f64();
    drop(sync);

    let rss_after = peak_rss_mib();

    assert_eq!(bob.message_count(), N);

    let msgs_per_sec = N as f64 / wall_secs;
    let projection = summarize_projection(
        request_start_ms,
        &[projection_window(
            &bob.db_path,
            &bob.identity,
            &alice_target_ids,
        )],
        total_event_blob_bytes(&alice.db_path, &alice_target_ids),
        wall_secs,
    );

    eprintln!();
    eprintln!("=== 500k one-way sync ===");
    eprintln!("  Full projected_count: {:.2}s", wall_secs);
    fmt_delay("First recorded_at:", projection.first_recorded_at_delay_ms);
    fmt_delay("Last recorded_at:", projection.last_recorded_at_delay_ms);
    fmt_delay(
        "First projected_at:",
        projection.first_projected_at_delay_ms,
    );
    fmt_delay("Last projected_at:", projection.last_projected_at_delay_ms);
    if let Some(projected_tail_ms) = projection.projected_tail_ms {
        eprintln!(
            "  Projected tail:    {projected_tail_ms} ms (last recorded_at -> last projected_at)"
        );
    }
    eprintln!("  Generate:          {gen_secs:.2}s");
    eprintln!("  Messages:     {N}");
    eprintln!("  Projected msgs/s:  {msgs_per_sec:.0}");
    eprintln!("  Payload bytes:     {}", projection.payload.payload_bytes);
    eprintln!(
        "  Payload MiB/s:     {:.2}",
        projection.payload.payload_mib_s
    );
    eprintln!(
        "  Payload Mbps:      {:.2}",
        projection.payload.payload_mbps
    );
    eprintln!(
        "  Peak RSS:     {:.1} MiB (before: {:.1}, after: {:.1})",
        rss_after, rss_before, rss_after
    );
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
    key_event_id: [u8; 32],
    signer_eid: [u8; 32],
    signing_key: &ed25519_dalek::SigningKey,
) {
    use std::time::{SystemTime, UNIX_EPOCH};
    use topo::db::open_connection;
    use topo::event_modules::{MessageEvent, ParsedEvent};
    use topo::projection::create::create_encrypted_event_synchronous;
    use topo::projection::create::CreateEventError;
    use topo::state::db::queue::SQLITE_BUSY_RETRY_BASE_MS;

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
            let mut created = None;
            for attempt in 0..8 {
                match create_encrypted_event_synchronous(
                    &db,
                    recorded_by,
                    &key_event_id,
                    &msg,
                    Some(signing_key),
                ) {
                    Ok(event_id) => {
                        created = Some(event_id);
                        break;
                    }
                    Err(CreateEventError::DbError(err))
                        if err.contains("database is locked") && attempt + 1 < 8 =>
                    {
                        std::thread::sleep(Duration::from_millis(
                            SQLITE_BUSY_RETRY_BASE_MS << attempt,
                        ));
                    }
                    Err(err) => panic!("create_encrypted_event_synchronous failed: {err:?}"),
                }
            }
            assert!(
                created.is_some(),
                "message create should eventually succeed"
            );
        }
        db.execute("COMMIT", []).expect("failed to commit");
        i = end;
        // Yield briefly so sync can grab the DB
        std::thread::sleep(Duration::from_millis(1));
    }
}
