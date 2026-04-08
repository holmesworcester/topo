//! Legacy in-process sync graph benchmarks (NOT maintained perf suite).
//!
//! These tests use the in-process `Peer` harness and measure shared-process RSS,
//! which is not representative of real daemon performance. The maintained perf
//! benchmarks are in `daemon_perf_test.rs` (real daemon processes, warm-start
//! timing, per-daemon VmHWM).
//!
//! Family A: Chain propagation (P0 <-> P1 <-> ... <-> Pn)
//! Family B: Multi-source catchup (S1..Sn feed lagging sink via coordinated download)
//!
//! Run smoke tests:    cargo test --release --test sync_graph_test -- --nocapture
//! Run all:            cargo test --release --test sync_graph_test -- --nocapture --include-ignored

mod cli_harness;

use cli_harness::hold_network_test_lock_for_binary;
use rusqlite::OptionalExtension;
use std::collections::BTreeSet;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use topo::crypto::event_id_to_base64;
use topo::db::open_connection;
use topo::db::sync_log::{ensure_schema, update_config, SyncLogConfigPatch};
use topo::testutil::{
    assert_eventually, clone_events_to, converge_sink_download_transport,
    converge_workspace_transport_graph, start_chain, start_sink_download,
    start_sink_download_with_shutdown, Peer,
};

const HOUR_MS: u64 = 60 * 60 * 1000;
const DAY_MS: u64 = 24 * HOUR_MS;
const YEAR_MS: u64 = 365 * DAY_MS;
const THREE_YEARS_MS: u64 = 3 * YEAR_MS;

fn graph_test_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

async fn acquire_graph_test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    hold_network_test_lock_for_binary();
    graph_test_lock().lock().await
}

fn enable_sync_logging(peer: &Peer) {
    let conn = open_connection(&peer.db_path).expect("open db for sync-log config");
    ensure_schema(&conn).expect("ensure sync-log schema");
    update_config(
        &conn,
        SyncLogConfigPatch {
            enabled: Some(true),
            changed_only: Some(false),
            ..Default::default()
        },
    )
    .expect("enable sync-log config");
}

fn projected_message_ids(peer: &Peer) -> BTreeSet<String> {
    let conn = open_connection(&peer.db_path).expect("open sink db for sync-log query");
    let mut stmt = conn
        .prepare(
            "SELECT message_id
               FROM messages
              WHERE recorded_by = ?1
              ORDER BY message_id",
        )
        .expect("prepare projected message query");
    stmt.query_map(rusqlite::params![&peer.identity], |row| {
        topo::db::sql_types::get_text(row, 0)
    })
    .expect("query projected message rows")
    .collect::<Result<BTreeSet<_>, _>>()
    .expect("collect projected message rows")
}

/// Read peak resident set size from /proc/self/status (Linux only).
fn peak_rss_mib() -> f64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if line.starts_with("VmHWM:") {
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

/// Compute per-hop delays (ms) from full-convergence timestamps across a chain.
fn compute_hop_delays(reach_ms: &[u64]) -> Vec<f64> {
    let mut hop_delays = Vec::with_capacity(reach_ms.len().saturating_sub(1));
    for window in reach_ms.windows(2) {
        hop_delays.push(window[1].saturating_sub(window[0]) as f64);
    }
    hop_delays.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    hop_delays
}

/// Wait until each peer reaches full convergence on recorded Message events and
/// return per-peer convergence timestamps (ms since `start`) in peer order.
async fn wait_for_full_message_convergence_times(
    peers: &[Peer],
    expected_message_count: i64,
    timeout: Duration,
    start: Instant,
) -> Vec<u64> {
    let mut reached: Vec<Option<u64>> = vec![None; peers.len()];
    loop {
        let elapsed_ms = start.elapsed().as_millis() as u64;
        let counts: Vec<i64> = peers
            .iter()
            .map(Peer::recorded_message_event_count)
            .collect();
        for (i, count) in counts.iter().enumerate() {
            if reached[i].is_none() && *count == expected_message_count {
                reached[i] = Some(elapsed_ms);
            }
        }

        if reached.iter().all(Option::is_some) {
            return reached
                .into_iter()
                .map(|ts| ts.expect("all peers reached convergence"))
                .collect();
        }

        assert!(
            start.elapsed() < timeout,
            "chain message convergence timed out after {:?}: message_counts={:?}, expected={}",
            timeout,
            counts,
            expected_message_count
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn percentile(sorted: &[f64], pct: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 * pct) as usize).min(sorted.len() - 1);
    sorted[idx]
}

/// Print per-peer stored message-event counts for a chain.
fn print_chain_message_counts(peers: &[Peer]) {
    for (i, peer) in peers.iter().enumerate() {
        eprintln!(
            "  P{} recorded message events: {}",
            i,
            peer.recorded_message_event_count()
        );
    }
}

/// Collect per-event delivery latencies (ms) from origin to sink.
fn collect_per_event_delivery_latencies(origin: &Peer, sink: &Peer) -> Vec<i64> {
    let origin_conn = open_connection(&origin.db_path).expect("open origin db");
    let sink_conn = open_connection(&sink.db_path).expect("open sink db");
    let mut stmt = origin_conn
        .prepare(
            "SELECT e.event_id, e.created_at
             FROM events e
             JOIN recorded_events re ON re.event_id = e.event_id
             WHERE re.peer_id = ?1
               AND re.source = 'local_create'
               AND e.share_scope = 'shared'",
        )
        .expect("prepare origin query");
    let rows: Vec<(String, i64)> = stmt
        .query_map(rusqlite::params![&origin.identity], |row| {
            Ok((
                topo::db::sql_types::get_text(row, 0)?,
                row.get::<_, i64>(1)?,
            ))
        })
        .expect("query origin events")
        .filter_map(|r| r.ok())
        .collect();
    let mut latencies = Vec::with_capacity(rows.len());
    for (event_id_b64, created_at_ms) in &rows {
        let recorded_at: Option<i64> = sink_conn
            .query_row(
                "SELECT recorded_at FROM recorded_events
                 WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![&sink.identity, event_id_b64],
                |row| row.get(0),
            )
            .optional()
            .expect("query sink received_at");
        if let Some(received) = recorded_at {
            latencies.push(received - created_at_ms);
        }
    }
    latencies.sort();
    latencies
}

fn env_usize_sg(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

// ---------------------------------------------------------------------------
// Family A: Chain propagation
// ---------------------------------------------------------------------------

/// Run a chain propagation benchmark.
/// Injects `event_count` events at P0 and waits for convergence at P_{n-1}.
async fn run_chain_bench(n: usize, event_count: usize) {
    let _guard = acquire_graph_test_guard().await;
    let mut peers = Vec::with_capacity(n);
    peers.push(Peer::new_with_identity("p0"));
    for i in 1..n {
        let joined = Peer::new_in_workspace(&format!("p{}", i), &peers[0]).await;
        peers.push(joined);
    }
    converge_workspace_transport_graph(&peers).await;

    let gen_start = Instant::now();
    peers[0].batch_create_messages(event_count);
    let gen_secs = gen_start.elapsed().as_secs_f64();
    eprintln!("Generated {} events at P0 in {:.2}s", event_count, gen_secs);

    // Convergence target on recorded message events: all peers should
    // eventually record the same message event set from P0 even though the
    // local tenant may not be able to decrypt another workspace's content.
    let expected_message_count = event_count as i64;

    let rss_before = peak_rss_mib();
    let start = Instant::now();

    let handles = start_chain(&peers);

    // Count-only timing: convergence is measured from per-peer recorded
    // message-event counts using the encrypted wrapper's outer semantic type.
    let convergence_ms = wait_for_full_message_convergence_times(
        &peers,
        expected_message_count,
        Duration::from_secs(600),
        start,
    )
    .await;
    let tail_wall_ms = convergence_ms[n - 1];
    let all_wall_ms = *convergence_ms
        .iter()
        .max()
        .expect("non-empty convergence timestamps");
    let rss_after = peak_rss_mib();

    // Hop delay analysis from adjacent peer convergence timestamps.
    let hop_delays = compute_hop_delays(&convergence_ms);
    let hop_p50 = percentile(&hop_delays, 0.50);
    let hop_p95 = percentile(&hop_delays, 0.95);

    let tail_secs = tail_wall_ms as f64 / 1000.0;
    let events_per_sec = event_count as f64 / tail_secs;
    let msg_bytes = topo::event_modules::message::MESSAGE_WIRE_SIZE;
    let mb_per_sec = events_per_sec * msg_bytes as f64 / (1024.0 * 1024.0);

    drop(handles);

    let delivery_ms = collect_per_event_delivery_latencies(&peers[0], &peers[n - 1]);

    eprintln!();
    eprintln!("=== Chain: {} peers, {} events ===", n, event_count);
    eprintln!("  Tail converge:    {} ms", tail_wall_ms);
    eprintln!("  All converge:     {} ms", all_wall_ms);
    eprintln!("  Events/s (tail):  {:.0}", events_per_sec);
    eprintln!("  MB/s (tail):      {:.1}", mb_per_sec);
    eprintln!(
        "  Hop latency P50:  {:.1} ms ({} samples)",
        hop_p50,
        hop_delays.len()
    );
    eprintln!("  Hop latency P95:  {:.1} ms", hop_p95);
    if !delivery_ms.is_empty() {
        let avg = delivery_ms.iter().sum::<i64>() as f64 / delivery_ms.len() as f64;
        let best = delivery_ms[0];
        let worst = delivery_ms[delivery_ms.len() - 1];
        let p50 =
            delivery_ms[((delivery_ms.len() as f64 * 0.50) as usize).min(delivery_ms.len() - 1)];
        let p95 =
            delivery_ms[((delivery_ms.len() as f64 * 0.95) as usize).min(delivery_ms.len() - 1)];
        eprintln!(
            "  Delivery P0->P{}: best={} avg={:.0} p50={} p95={} worst={} ms ({} events)",
            n - 1,
            best,
            avg,
            p50,
            p95,
            worst,
            delivery_ms.len()
        );
    }
    eprintln!(
        "  Peak RSS:         {:.1} MiB (before: {:.1})",
        rss_after, rss_before
    );
    print_chain_message_counts(&peers);
    eprintln!();
}

// ---------------------------------------------------------------------------
// Family A2: Live-rate chain propagation
// ---------------------------------------------------------------------------

async fn run_chain_live_rate(n: usize, messages_per_sec: usize, live_seconds: usize) {
    let _guard = acquire_graph_test_guard().await;
    assert!(n >= 2);
    assert!(messages_per_sec > 0);
    assert!(live_seconds > 0);

    let mut peers = Vec::with_capacity(n);
    peers.push(Peer::new_with_identity("p0"));
    for i in 1..n {
        let joined = Peer::new_in_workspace(&format!("p{}", i), &peers[0]).await;
        peers.push(joined);
    }
    converge_workspace_transport_graph(&peers).await;
    let handles = start_chain(&peers);

    let warmup_id = peers[0].create_message("chain-warmup");
    let warmup_b64 = event_id_to_base64(&warmup_id);
    let tail = &peers[n - 1];
    assert_eventually(
        || tail.has_event(&warmup_b64),
        Duration::from_secs(120),
        "chain warmup convergence at tail",
    )
    .await;

    let total_messages = messages_per_sec * live_seconds;
    let start = Instant::now();
    for seq in 0..total_messages {
        let target_elapsed = Duration::from_secs_f64(seq as f64 / messages_per_sec as f64);
        if let Some(remaining) = target_elapsed.checked_sub(start.elapsed()) {
            std::thread::sleep(remaining);
        }
        peers[0].create_message(&format!("live-{}", seq));
    }

    let expected_count = (total_messages + 1) as i64;
    assert_eventually(
        || tail.recorded_message_event_count() >= expected_count,
        Duration::from_secs(300),
        "chain live-rate convergence at tail",
    )
    .await;
    let wall_secs = start.elapsed().as_secs_f64();

    let delivery_ms = collect_per_event_delivery_latencies(&peers[0], tail);
    drop(handles);

    let avg = if delivery_ms.is_empty() {
        0.0
    } else {
        delivery_ms.iter().sum::<i64>() as f64 / delivery_ms.len() as f64
    };
    let best = delivery_ms.first().copied().unwrap_or(0);
    let worst = delivery_ms.last().copied().unwrap_or(0);
    let p50_idx =
        ((delivery_ms.len() as f64 * 0.50) as usize).min(delivery_ms.len().saturating_sub(1));
    let p95_idx =
        ((delivery_ms.len() as f64 * 0.95) as usize).min(delivery_ms.len().saturating_sub(1));
    let p50 = delivery_ms.get(p50_idx).copied().unwrap_or(0);
    let p95 = delivery_ms.get(p95_idx).copied().unwrap_or(0);

    eprintln!();
    eprintln!(
        "=== Chain live-rate: {} peers, {} msg/s, {}s ===",
        n, messages_per_sec, live_seconds
    );
    eprintln!("  Messages:         {}", total_messages);
    eprintln!("  Wall time:        {:.1}s", wall_secs);
    eprintln!(
        "  Delivery P0->P{}: best={} avg={:.0} p50={} p95={} worst={} ms ({} events)",
        n - 1,
        best,
        avg,
        p50,
        p95,
        worst,
        delivery_ms.len()
    );
    eprintln!();
}

#[tokio::test]
#[ignore]
async fn ten_hop_chain_live_rate() {
    let mps = env_usize_sg("TOPO_PERF_MESSAGES_PER_SEC", 2);
    let secs = env_usize_sg("TOPO_PERF_LIVE_SECONDS", 15);
    run_chain_live_rate(10, mps, secs).await;
}

/// 10-hop chain smoke: 10 peers, 1k events (pre-seeded bulk).
#[tokio::test]
#[ignore = "legacy in-process graph benchmark is too slow/noisy for the default serial suite; run explicitly"]
async fn ten_hop_chain_1k_smoke() {
    run_chain_bench(10, 1_000).await;
}

/// 10-hop chain soak: 10 peers, 10k events (pre-seeded bulk).
#[tokio::test]
#[ignore]
async fn ten_hop_chain_10k() {
    run_chain_bench(10, 10_000).await;
}

/// 10-hop chain: 10 peers, 50k events.
#[tokio::test]
#[ignore]
async fn ten_hop_chain_50k() {
    run_chain_bench(10, 50_000).await;
}

// ---------------------------------------------------------------------------
// Family B: Multi-source catchup (sink-driven coordinated download)
// ---------------------------------------------------------------------------

/// Run a coordinated sink-driven download benchmark.
///
/// Sources share the same pre-seeded dataset (cloned from S0). The sink
/// connects to all sources as initiator using coordinated round-based assignment.
async fn run_catchup_bench(source_count: usize, events_per_source: usize) {
    let _guard = acquire_graph_test_guard().await;
    assert!(source_count >= 1, "source_count must be >= 1");
    let mut sources: Vec<Peer> = Vec::with_capacity(source_count);
    sources.push(Peer::new_with_identity("ds0"));
    for i in 1..source_count {
        let joined = Peer::new_in_workspace(&format!("ds{}", i), &sources[0]).await;
        sources.push(joined);
    }
    let sink = Peer::new_in_workspace("dsink", &sources[0]).await;
    sources.push(sink);
    converge_workspace_transport_graph(&sources).await;
    let sink = sources.pop().expect("sink peer missing after convergence");
    converge_sink_download_transport(&sources, &sink).await;

    // Generate events at S0 only
    let gen_start = Instant::now();
    sources[0].batch_create_messages(events_per_source);
    let gen_secs = gen_start.elapsed().as_secs_f64();
    let seeded_messages = events_per_source as i64;
    eprintln!(
        "Generated {} events at S0 in {:.2}s, cloning to {} sources...",
        seeded_messages,
        gen_secs,
        source_count - 1
    );

    // Clone S0's data to all other sources (overlapping data)
    if source_count > 1 {
        let targets: Vec<&Peer> = sources[1..].iter().collect();
        clone_events_to(&sources[0], &targets);
        eprintln!("  Cloned to S1..S{}", source_count - 1);
    }

    // Convergence target: union of all source message event IDs, using the
    // encrypted wrapper's outer semantic type instead of decrypted validity.
    let expected_sink_message_ids: BTreeSet<String> = sources
        .iter()
        .flat_map(|s| s.recorded_message_event_ids().into_iter())
        .collect();
    let expected_sink_message_count = expected_sink_message_ids.len() as i64;

    let rss_before = peak_rss_mib();
    let start = Instant::now();

    // Sink-driven download: sink connects to all sources with claimed set
    let handles = start_sink_download(&sources, &sink);

    let timeout_secs = if events_per_source >= 100_000 {
        600
    } else {
        120
    };
    assert_eventually(
        || sink.recorded_message_event_count() == expected_sink_message_count,
        Duration::from_secs(timeout_secs),
        &format!(
            "sink reaches expected recorded_message_event_count={}",
            expected_sink_message_count
        ),
    )
    .await;

    let wall_ms = start.elapsed().as_millis() as u64;
    let rss_after = peak_rss_mib();
    let wall_secs = wall_ms as f64 / 1000.0;
    let events_per_sec = expected_sink_message_count as f64 / wall_secs;
    let msg_bytes = topo::event_modules::message::MESSAGE_WIRE_SIZE;
    let mb_per_sec = events_per_sec * msg_bytes as f64 / (1024.0 * 1024.0);

    // Exact set equality validates full message dataset catchup.
    let sink_ids = sink.recorded_message_event_ids();
    assert_eq!(
        sink_ids, expected_sink_message_ids,
        "sink message IDs must match union of source message IDs"
    );

    drop(handles);

    eprintln!();
    eprintln!(
        "=== Multi-source catchup: {} sources x {} events (sink-driven rounds) ===",
        source_count, events_per_source,
    );
    eprintln!("  Unique messages:  {}", expected_sink_message_count);
    eprintln!("  Catchup wall:     {} ms", wall_ms);
    eprintln!("  Events/s:         {:.0}", events_per_sec);
    eprintln!("  MB/s:             {:.2}", mb_per_sec);
    eprintln!(
        "  Sink recorded msgs: {}",
        sink.recorded_message_event_count()
    );
    eprintln!(
        "  Peak RSS:         {:.1} MiB (before: {:.1})",
        rss_after, rss_before
    );
    eprintln!();
}

/// Catchup smoke: 4 sources, 100k overlapping events.
#[tokio::test]
#[ignore]
async fn catchup_4x_100k() {
    run_catchup_bench(4, 100_000).await;
}

/// Catchup: 8 sources, 100k overlapping events.
#[tokio::test]
#[ignore]
async fn catchup_8x_100k() {
    run_catchup_bench(8, 100_000).await;
}

/// Replicated-source smoke: sink should converge to the projected message set
/// visible from the replicated sources without depending on transport internals.
#[tokio::test]
#[ignore = "legacy in-process replicated-source benchmark; replace with a daemon-based projected-visibility test"]
async fn catchup_4x_240_spread_uses_multiple_sources_efficiently() {
    let _guard = acquire_graph_test_guard().await;

    let source_count = 4;
    let total_messages = 240usize;
    let start_ms = topo::db::queue::current_timestamp_ms() as u64 - THREE_YEARS_MS;

    let mut sources: Vec<Peer> = Vec::with_capacity(source_count);
    sources.push(Peer::new_with_identity("ms0"));
    for i in 1..source_count {
        let joined = Peer::new_in_workspace(&format!("ms{}", i), &sources[0]).await;
        sources.push(joined);
    }
    let sink = Peer::new_in_workspace("mssink", &sources[0]).await;
    sources.push(sink);
    eprintln!("  Created peers, converging transport graph...");
    converge_workspace_transport_graph(&sources).await;
    let sink = sources.pop().expect("sink peer missing after convergence");
    converge_sink_download_transport(&sources, &sink).await;

    eprintln!("  Generating spread messages...");
    sources[0].batch_create_messages_spread(total_messages, start_ms, THREE_YEARS_MS);
    let targets: Vec<&Peer> = sources[1..].iter().collect();
    eprintln!("  Cloning spread history to replicated sources...");
    clone_events_to(&sources[0], &targets);
    let source_marker_ids: Vec<String> = sources
        .iter()
        .enumerate()
        .map(|(idx, source)| {
            event_id_to_base64(&source.create_message(&format!("spread-src-{idx}")))
        })
        .collect();
    enable_sync_logging(&sink);

    let expected_projected_ids: BTreeSet<String> = sources
        .iter()
        .flat_map(|source| projected_message_ids(source).into_iter())
        .collect();
    let expected_count = expected_projected_ids.len() as i64;
    let start = Instant::now();
    eprintln!("  Starting sink download...");
    let handles = start_sink_download(&sources, &sink);

    assert_eventually(
        || sink.scoped_message_count() >= expected_count,
        Duration::from_secs(180),
        &format!(
            "sink projects all {} spread messages (current: {})",
            expected_count,
            sink.scoped_message_count()
        ),
    )
    .await;

    let wall_secs = start.elapsed().as_secs_f64();
    drop(handles);

    let sink_projected_ids = projected_message_ids(&sink);
    let visible_markers = source_marker_ids
        .iter()
        .filter(|id| sink_projected_ids.contains(*id))
        .count();

    eprintln!();
    eprintln!("=== Replicated spread catchup: 4 sources x 240 messages ===");
    eprintln!("  Wall time:           {:.2}s", wall_secs);
    eprintln!("  Visible messages:    {}", expected_count);
    eprintln!(
        "  Visible source marks: {}/{}",
        visible_markers,
        source_marker_ids.len()
    );
    eprintln!();

    assert_eq!(
        sink_projected_ids, expected_projected_ids,
        "sink projected message IDs must match the union visible from the sources"
    );
    assert!(
        visible_markers == source_marker_ids.len(),
        "sink should project one visible marker message from every source"
    );
}

// ---------------------------------------------------------------------------
// Family C: Multi-source large-file catchup with source attribution
// ---------------------------------------------------------------------------

/// Run a multi-source file-slice catchup test.
///
/// Creates a file of `total_slices` slices at S0, clones the data to all
/// other sources, then has a sink download from all sources.  After sync,
/// verifies:
/// 1. Sink received all expected file-slice events (via events + recorded_events).
/// 2. Every non-sink source contributed a meaningful share of slices
///    (source attribution via `recorded_events.source`).
async fn run_catchup_large_file(
    source_count: usize,
    total_slices: usize,
    min_contributing_sources: usize,
) {
    let _guard = acquire_graph_test_guard().await;
    let mut sources = Vec::with_capacity(source_count);
    sources.push(Peer::new_with_identity("fs0"));
    for i in 1..source_count {
        let joined = Peer::new_in_workspace(&format!("fs{}", i), &sources[0]).await;
        sources.push(joined);
    }
    let sink = Peer::new_in_workspace("fsink", &sources[0]).await;
    sources.push(sink);
    converge_workspace_transport_graph(&sources).await;
    let sink = sources.pop().expect("sink peer missing after convergence");
    converge_sink_download_transport(&sources, &sink).await;

    // Generate file slices at S0
    let gen_start = Instant::now();
    let _file_id = sources[0].batch_create_file_slices(total_slices);
    let gen_secs = gen_start.elapsed().as_secs_f64();
    eprintln!(
        "Generated {} file slices at S0 in {:.2}s, cloning to {} sources...",
        total_slices,
        gen_secs,
        source_count - 1
    );

    // Clone S0's data to all other sources
    if source_count > 1 {
        let targets: Vec<&Peer> = sources[1..].iter().collect();
        clone_events_to(&sources[0], &targets);
        eprintln!("  Cloned to S1..S{}", source_count - 1);
    }

    // Debug aid: show source SPKI mapping used by quic_recv attribution keys.
    for (idx, source) in sources.iter().enumerate() {
        let fp_hex: String = source
            .spki_fingerprint()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let file_slice_count = source.event_ids_by_type("file_slice").len();
        let message_count = source.recorded_message_event_count();
        eprintln!("  Source map: S{} -> {}", idx, fp_hex);
        eprintln!(
            "    Source counts: file_slice={} message={}",
            file_slice_count, message_count
        );
    }

    // Add per-source unique marker messages
    let source_markers: Vec<String> = sources
        .iter()
        .enumerate()
        .map(|(i, source)| {
            let marker = source.create_message(&format!("filesrc-{}-marker", i));
            event_id_to_base64(&marker)
        })
        .collect();

    let sample = sources[0].sample_event_ids(1)[0].clone();

    let rss_before = peak_rss_mib();
    let start = Instant::now();

    let handles = start_sink_download(&sources, &sink);

    let timeout_secs = 600;
    assert_eventually(
        || sink.has_event(&sample) && source_markers.iter().all(|m| sink.has_event(m)),
        Duration::from_secs(timeout_secs),
        "sink receives sampled event and all source markers",
    )
    .await;

    // Wait for all file_slice events to arrive (events + recorded_events, no projection needed)
    let expected_slices = total_slices as i64;
    assert_eventually(
        || sink.file_slice_event_count() >= expected_slices,
        Duration::from_secs(120),
        &format!(
            "sink receives all {} file_slice events (current: {})",
            expected_slices,
            sink.file_slice_event_count()
        ),
    )
    .await;

    let wall_ms = start.elapsed().as_millis() as u64;
    let rss_after = peak_rss_mib();

    drop(handles);

    // === Source attribution assertions ===
    let source_counts = sink.file_slice_event_counts_by_source();
    let message_source_counts = sink.recorded_event_type_counts_by_source("message", "quic_recv:");
    let total_attributed: i64 = source_counts.values().sum();

    let wall_secs = wall_ms as f64 / 1000.0;
    let events_per_sec = total_slices as f64 / wall_secs;
    let blob_bytes = topo::event_modules::file_slice::FILE_SLICE_WIRE_SIZE;
    let total_bytes = total_slices as f64 * blob_bytes as f64;
    let mb_per_sec = total_bytes / wall_secs / (1024.0 * 1024.0);

    eprintln!();
    eprintln!(
        "=== Multi-source file catchup: {} sources x {} slices ===",
        source_count, total_slices
    );
    eprintln!("  Catchup wall:     {} ms", wall_ms);
    eprintln!("  Events/s:         {:.0}", events_per_sec);
    eprintln!("  MB/s:             {:.1}", mb_per_sec);
    eprintln!("  Total attributed: {}", total_attributed);
    eprintln!(
        "  Peak RSS:         {:.1} MiB (before: {:.1})",
        rss_after, rss_before
    );
    for (source, count) in &source_counts {
        let pct = *count as f64 / total_slices as f64 * 100.0;
        eprintln!("  Source {}: {} slices ({:.1}%)", source, count, pct);
    }
    eprintln!(
        "  Message attribution sources (quic_recv): {:?}",
        message_source_counts
    );
    eprintln!();

    // 1. Sink received all file_slice events
    assert_eq!(
        sink.file_slice_event_count(),
        expected_slices,
        "sink must have all {} file_slice events",
        expected_slices,
    );

    // 2. Total attributed slices matches expected
    assert_eq!(
        total_attributed, expected_slices,
        "total attributed slices must equal expected ({} vs {})",
        total_attributed, expected_slices,
    );

    // 3. Every source contributed at least a meaningful floor.
    //    With coordinated download across N sources, each source should
    //    contribute at least 5% of total slices (generous floor to avoid
    //    flakiness while still proving distribution).
    let floor = (total_slices as f64 * 0.05) as i64;
    assert!(
        floor > 0,
        "floor must be > 0 for meaningful source distribution check"
    );
    // Count how many distinct sources contributed at least floor slices
    let contributing = source_counts.values().filter(|&&c| c >= floor).count();
    assert!(
        min_contributing_sources >= 1 && min_contributing_sources <= source_count,
        "invalid min_contributing_sources={} for source_count={}",
        min_contributing_sources,
        source_count,
    );
    assert!(
        contributing >= min_contributing_sources,
        "expected >= {} contributing sources (>= {} slices each), got {} with counts {:?}",
        min_contributing_sources,
        floor,
        contributing,
        source_counts,
    );
}

/// Multi-source file: 4 sources, 1024 slices (256 MiB).
#[tokio::test]
#[ignore]
async fn catchup_large_file_4x_1024_slices() {
    run_catchup_large_file(4, 1024, 4).await;
}

/// Multi-source file: 4 sources, 400 slices (100 MiB).
///
/// Stand-in for "100 files x 1 MiB" delta volume, represented in canonical
/// 256 KiB file-slice events (4 slices per MiB file).
#[tokio::test]
#[ignore]
async fn catchup_large_file_4x_400_slices() {
    run_catchup_large_file(4, 400, 3).await;
}

/// Multi-source file: 8 sources, 1024 slices (256 MiB).
#[tokio::test]
#[ignore]
async fn catchup_large_file_8x_1024_slices() {
    run_catchup_large_file(8, 1024, 8).await;
}

// ---------------------------------------------------------------------------
// Family D: Range partition correctness regression tests
// ---------------------------------------------------------------------------

/// Test: non-uniform source data still converges under range partitioning.
///
/// Each source has shared events (cloned) plus unique events only on that source.
/// A sink downloading from all sources must still converge on the full union even
/// though no single source owns every event.
///
/// This is now a diagnostic-only probe: the current range-partition design is
/// optimized for replicated source sets, not for guaranteed recovery of
/// same-range unique events that exist on exactly one source.
#[tokio::test]
#[ignore = "diagnostic probe for non-replicated source sets; not part of the current replicated-source correctness contract"]
async fn catchup_non_uniform_sources() {
    let _guard = acquire_graph_test_guard().await;
    let source_count = 4;
    // Debug builds are ~10x slower; scale down to keep under timeout.
    #[cfg(debug_assertions)]
    let shared_count = 10;
    #[cfg(not(debug_assertions))]
    let shared_count = 50;
    // Must exceed total_peers * FALLBACK_THRESHOLD_FACTOR (4*20=80) after
    // the first session claims its owned subset (~25%). 200 * 0.75 = 150 > 80,
    // so the remaining source-unique events permanently stall without the fix.
    #[cfg(debug_assertions)]
    let unique_per_source = 40;
    #[cfg(not(debug_assertions))]
    let unique_per_source = 200;

    let mut sources = Vec::with_capacity(source_count);
    sources.push(Peer::new_with_identity("nu0"));
    for i in 1..source_count {
        let joined = Peer::new_in_workspace(&format!("nu{}", i), &sources[0]).await;
        sources.push(joined);
    }
    let sink = Peer::new_in_workspace("nusink", &sources[0]).await;
    sources.push(sink);
    converge_workspace_transport_graph(&sources).await;
    let sink = sources.pop().expect("sink peer missing after convergence");
    converge_sink_download_transport(&sources, &sink).await;

    // Create shared messages at S0
    for i in 0..shared_count {
        sources[0].create_message(&format!("shared-{}", i));
    }

    // Clone shared data to S1..S3
    let targets: Vec<&Peer> = sources[1..].iter().collect();
    clone_events_to(&sources[0], &targets);

    // Create unique messages at each source (AFTER cloning)
    let mut unique_ids: Vec<Vec<String>> = Vec::new();
    for (src_idx, source) in sources.iter().enumerate() {
        let mut ids = Vec::new();
        for j in 0..unique_per_source {
            let eid = source.create_message(&format!("unique-s{}-{}", src_idx, j));
            ids.push(event_id_to_base64(&eid));
        }
        unique_ids.push(ids);
    }

    // Total expected message events at sink:
    // shared_count + source_count * unique_per_source
    let total_expected = (shared_count + source_count * unique_per_source) as i64;

    let start = Instant::now();
    let handles = start_sink_download(&sources, &sink);

    // Wait for all messages to arrive
    assert_eventually(
        || sink.recorded_message_event_count() >= total_expected,
        Duration::from_secs(120),
        &format!(
            "sink receives all {} messages (current: {})",
            total_expected,
            sink.recorded_message_event_count()
        ),
    )
    .await;

    let wall_secs = start.elapsed().as_secs_f64();
    let msgs_per_sec = total_expected as f64 / wall_secs;
    drop(handles);

    // Verify every source's unique events made it to the sink
    for (src_idx, ids) in unique_ids.iter().enumerate() {
        let missing: Vec<&str> = ids
            .iter()
            .filter(|id| !sink.has_event(id))
            .map(|s| s.as_str())
            .collect();
        assert!(
            missing.is_empty(),
            "source {} has {} unique events missing at sink (first: {:?})",
            src_idx,
            missing.len(),
            missing.first()
        );
    }

    eprintln!();
    eprintln!(
        "=== Non-uniform sources: {} sources, {} shared + {} unique/source ===",
        source_count, shared_count, unique_per_source
    );
    eprintln!("  Total expected: {}", total_expected);
    eprintln!("  Sink received:  {}", sink.recorded_message_event_count());
    eprintln!("  Wall time:      {:.2}s", wall_secs);
    eprintln!("  Messages:       {}", total_expected);
    eprintln!("  Msgs/s:         {:.0}", msgs_per_sec);
    eprintln!();
}

/// Test: dead peer does not strand a range partition forever.
///
/// All sources share identical data. Source[2] is shut down immediately after
/// sync starts. Subsequent range sessions recompute partitions from the remaining
/// live peers, so the sink must still converge on the full dataset.
#[tokio::test]
#[ignore = "legacy in-process graph benchmark is too slow/noisy for the default serial suite; run explicitly"]
async fn catchup_dead_peer_dropout() {
    let _guard = acquire_graph_test_guard().await;
    let source_count = 4;
    // Large enough that session 2 can't finish syncing before we kill it.
    // Debug builds are ~10x slower; scale down to keep under timeout.
    #[cfg(debug_assertions)]
    let event_count = 1_000;
    #[cfg(not(debug_assertions))]
    let event_count = 10_000;

    let mut sources = Vec::with_capacity(source_count);
    sources.push(Peer::new_with_identity("dp0"));
    for i in 1..source_count {
        let joined = Peer::new_in_workspace(&format!("dp{}", i), &sources[0]).await;
        sources.push(joined);
    }
    let sink = Peer::new_in_workspace("dpsink", &sources[0]).await;
    sources.push(sink);
    converge_workspace_transport_graph(&sources).await;
    let sink = sources.pop().expect("sink peer missing after convergence");
    converge_sink_download_transport(&sources, &sink).await;

    // Create events at S0
    sources[0].batch_create_messages(event_count);

    // Clone to all other sources (identical data)
    let targets: Vec<&Peer> = sources[1..].iter().collect();
    clone_events_to(&sources[0], &targets);

    let expected_count = event_count as i64;

    let start = Instant::now();
    let dl_handles = start_sink_download_with_shutdown(&sources, &sink);

    // Immediately kill source[2] — simulates peer dropout.
    // This closes the QUIC endpoint (severing any active connection) and
    // cancels the connect loop so it stops retrying.
    dl_handles.shutdown_source(2);
    eprintln!("  Shut down source 2 at {:?}", start.elapsed());

    // Wait for convergence: sink must get ALL events despite dead source.
    assert_eventually(
        || sink.recorded_message_event_count() >= expected_count,
        Duration::from_secs(120),
        &format!(
            "sink receives all {} messages despite dead source (current: {})",
            expected_count,
            sink.recorded_message_event_count()
        ),
    )
    .await;

    let wall_secs = start.elapsed().as_secs_f64();
    let msgs_per_sec = expected_count as f64 / wall_secs;
    drop(dl_handles);

    eprintln!();
    eprintln!(
        "=== Dead peer dropout: {} sources, source[2] killed, {} events ===",
        source_count, event_count
    );
    eprintln!("  Expected: {}", expected_count);
    eprintln!("  Sink received: {}", sink.recorded_message_event_count());
    eprintln!("  Wall time: {:.2}s", wall_secs);
    eprintln!("  Messages: {}", expected_count);
    eprintln!("  Msgs/s:   {:.0}", msgs_per_sec);
    eprintln!();

    assert_eq!(
        sink.recorded_message_event_count(),
        expected_count,
        "sink must have all {} messages even with dead source (got {})",
        expected_count,
        sink.recorded_message_event_count(),
    );
}
