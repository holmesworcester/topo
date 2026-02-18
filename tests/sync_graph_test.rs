//! Sync graph performance benchmarks
//!
//! Family A: Chain propagation (P0 <-> P1 <-> ... <-> Pn)
//! Family B: Multi-source catchup (S1..Sn feed lagging sink)
//!   - serial:       sources sync one at a time (pairwise baseline)
//!   - overlap:      all sources connect concurrently, identical data
//!   - partitioned:  all sources connect concurrently, disjoint data
//!   - coordinated:  sink drives download with round-based assignment
//!
//! Run smoke tests:    cargo test --release --test sync_graph_test -- --nocapture --test-threads=1
//! Run all:            cargo test --release --test sync_graph_test -- --nocapture --include-ignored --test-threads=1
//!
//! NOTE: --test-threads=1 is required; concurrent heavy tests trigger a negentropy
//! race condition (duplicate items from concurrent reads/writes to neg_items).

use std::time::{Duration, Instant};
use topo::testutil::{
    Peer, start_chain, start_multi_source, start_sink_download,
    sync_until_converged, assert_eventually, clone_events_to,
};

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

/// Compute per-hop latencies (ms) from sampled events across a chain.
/// Returns a sorted vector of all per-hop delays observed.
fn compute_hop_latencies(peers: &[Peer], sample_event_ids: &[String]) -> Vec<f64> {
    let mut hop_delays: Vec<f64> = Vec::new();
    for eid in sample_event_ids {
        let mut timestamps: Vec<Option<i64>> = Vec::new();
        for peer in peers {
            timestamps.push(peer.recorded_at_for_event(eid));
        }
        for i in 0..timestamps.len() - 1 {
            if let (Some(t_prev), Some(t_next)) = (timestamps[i], timestamps[i + 1]) {
                let delay_ms = (t_next - t_prev) as f64;
                if delay_ms >= 0.0 {
                    hop_delays.push(delay_ms);
                }
            }
        }
    }
    hop_delays.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    hop_delays
}

fn percentile(sorted: &[f64], pct: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 * pct) as usize).min(sorted.len() - 1);
    sorted[idx]
}

/// Print per-peer store counts for a chain.
fn print_chain_counts(peers: &[Peer]) {
    for (i, peer) in peers.iter().enumerate() {
        eprintln!("  P{} store:         {}", i, peer.store_count());
    }
}

// ---------------------------------------------------------------------------
// Family A: Chain propagation
// ---------------------------------------------------------------------------

/// Run a chain propagation benchmark.
/// Injects `event_count` events at P0 and waits for convergence at P_{n-1}.
async fn run_chain_bench(n: usize, event_count: usize) {
    let peers: Vec<Peer> = (0..n)
        .map(|i| Peer::new_with_identity(&format!("p{}", i)))
        .collect();

    let gen_start = Instant::now();
    peers[0].batch_create_messages(event_count);
    let gen_secs = gen_start.elapsed().as_secs_f64();
    eprintln!("Generated {} events at P0 in {:.2}s", event_count, gen_secs);

    // Sample an event from P0 to use as convergence marker
    let sample = peers[0].sample_event_ids(1)[0].clone();

    let rss_before = peak_rss_mib();
    let start = Instant::now();

    let handles = start_chain(&peers);

    let timeout = Duration::from_secs(600);

    // Wait for tail peer to have the sampled event
    assert_eventually(
        || peers[n - 1].has_event(&sample),
        timeout,
        &format!("chain tail P{} receives sampled event", n - 1),
    )
    .await;

    let tail_wall_ms = start.elapsed().as_millis() as u64;

    // Wait for ALL peers to have the sampled event
    assert_eventually(
        || peers.iter().all(|p| p.has_event(&sample)),
        Duration::from_secs(60),
        "all peers receive sampled event",
    )
    .await;

    let all_wall_ms = start.elapsed().as_millis() as u64;
    let rss_after = peak_rss_mib();

    // Sample events for hop latency analysis
    let sample_ids = peers[0].sample_event_ids(200);
    let hop_delays = compute_hop_latencies(&peers, &sample_ids);
    let hop_p50 = percentile(&hop_delays, 0.50);
    let hop_p95 = percentile(&hop_delays, 0.95);

    let events_per_sec = event_count as f64 / (tail_wall_ms as f64 / 1000.0);

    drop(handles);

    eprintln!();
    eprintln!("=== Chain: {} peers, {} events ===", n, event_count);
    eprintln!("  Tail converge:    {} ms", tail_wall_ms);
    eprintln!("  All converge:     {} ms", all_wall_ms);
    eprintln!("  Events/s (tail):  {:.0}", events_per_sec);
    eprintln!("  Hop latency P50:  {:.1} ms ({} samples)", hop_p50, hop_delays.len());
    eprintln!("  Hop latency P95:  {:.1} ms", hop_p95);
    eprintln!("  Peak RSS:         {:.1} MiB (before: {:.1})", rss_after, rss_before);
    print_chain_counts(&peers);
    eprintln!();
}

/// Chain smoke: 5 peers, 10k events.
#[tokio::test]
async fn chain_5_peers_10k() {
    run_chain_bench(5, 10_000).await;
}

/// Chain primary: 10 peers, 10k events.
#[tokio::test]
#[ignore]
async fn chain_10_peers_10k() {
    run_chain_bench(10, 10_000).await;
}

/// Chain primary: 10 peers, 50k events.
#[tokio::test]
#[ignore]
async fn chain_10_peers_50k() {
    run_chain_bench(10, 50_000).await;
}

/// Chain stress: 20 peers, 10k events.
#[tokio::test]
#[ignore]
async fn chain_20_peers_10k() {
    run_chain_bench(20, 10_000).await;
}

// ---------------------------------------------------------------------------
// Family B-serial: Multi-source catchup (serialized pairwise baseline)
// ---------------------------------------------------------------------------

/// Run a serialized multi-source catchup benchmark.
///
/// Uses pairwise sync: each source syncs with the sink one at a time.
/// This measures the serialized baseline performance.
///
/// After each pairwise sync:
/// - Sink accumulates more events
/// - Source also receives sink's events (from previous sources)
async fn run_multi_source_bench(source_count: usize, events_per_source: usize) {
    let sources: Vec<Peer> = (0..source_count)
        .map(|i| Peer::new_with_identity(&format!("s{}", i)))
        .collect();
    let sink = Peer::new_with_identity("sink");

    let gen_start = Instant::now();
    for (i, source) in sources.iter().enumerate() {
        source.batch_create_messages(events_per_source);
        eprintln!("  Source S{}: generated {} events", i, events_per_source);
    }
    let gen_secs = gen_start.elapsed().as_secs_f64();
    let total_messages = (source_count * events_per_source) as i64;
    eprintln!(
        "Generated {} total events across {} sources in {:.2}s",
        total_messages, source_count, gen_secs
    );

    let rss_before = peak_rss_mib();
    let start = Instant::now();

    // Sync each source with sink pairwise (serialized B0 baseline).
    for (i, source) in sources.iter().enumerate() {
        let source_start = Instant::now();

        // Sample an event from this source as convergence marker
        let sample = source.sample_event_ids(1)[0].clone();
        let metrics = sync_until_converged(
            source, &sink, || sink.has_event(&sample), Duration::from_secs(120),
        ).await;

        let source_ms = source_start.elapsed().as_millis() as u64;
        eprintln!(
            "  S{}: {} events synced in {}ms ({:.0} events/s)",
            i, metrics.events_transferred, source_ms, metrics.events_per_sec,
        );
    }

    let wall_ms = start.elapsed().as_millis() as u64;
    let rss_after = peak_rss_mib();
    let events_per_sec = total_messages as f64 / (wall_ms as f64 / 1000.0);

    eprintln!();
    eprintln!(
        "=== Multi-source serial: {} sources x {} events = {} total ===",
        source_count, events_per_source, total_messages
    );
    eprintln!("  Catchup wall:     {} ms", wall_ms);
    eprintln!("  Events/s:         {:.0}", events_per_sec);
    eprintln!("  Sink store:       {}", sink.store_count());
    eprintln!("  Peak RSS:         {:.1} MiB (before: {:.1})", rss_after, rss_before);
    for (i, source) in sources.iter().enumerate() {
        eprintln!("  S{} store:          {}", i, source.store_count());
    }
    eprintln!();
}

/// Serial smoke: 2 sources, 5k each (10k total).
#[tokio::test]
async fn multi_source_serial_2x_5k() {
    run_multi_source_bench(2, 5_000).await;
}

/// Serial: 4 sources, 5k each (20k total).
#[tokio::test]
#[ignore]
async fn multi_source_serial_4x_5k() {
    run_multi_source_bench(4, 5_000).await;
}

/// Serial: 8 sources, ~6.25k each (50k total).
#[tokio::test]
#[ignore]
async fn multi_source_serial_8x_6250() {
    run_multi_source_bench(8, 6_250).await;
}

/// Serial single-source reference: 1 source, 50k events.
#[tokio::test]
#[ignore]
async fn multi_source_serial_1x_50k() {
    run_multi_source_bench(1, 50_000).await;
}

// ---------------------------------------------------------------------------
// Family B-overlap: Multi-source concurrent (overlapping / identical data)
// ---------------------------------------------------------------------------

/// Run a concurrent multi-source catchup benchmark with overlapping data.
///
/// All sources have identical data (cloned from S0). The sink runs
/// `accept_loop` and sources run `connect_loop` (repeated sessions).
/// Over multiple negentropy rounds, sources discover the sink already has events
/// from other sources and skip redundant transfers — the dedup ratio converges
/// toward 1.0x naturally.
async fn run_multi_source_concurrent_bench(source_count: usize, events_per_source: usize) {
    let sources: Vec<Peer> = (0..source_count)
        .map(|i| Peer::new_with_identity(&format!("cs{}", i)))
        .collect();
    let sink = Peer::new_with_identity("csink");

    // Generate events at S0 only
    let gen_start = Instant::now();
    sources[0].batch_create_messages(events_per_source);
    let gen_secs = gen_start.elapsed().as_secs_f64();
    let total_messages = events_per_source as i64;
    eprintln!(
        "Generated {} events at S0 in {:.2}s, cloning to {} sources...",
        total_messages, gen_secs, source_count - 1
    );

    // Sample a convergence marker from S0 before cloning
    let sample = sources[0].sample_event_ids(1)[0].clone();

    // Clone S0's data to all other sources (overlapping data)
    if source_count > 1 {
        let targets: Vec<&Peer> = sources[1..].iter().collect();
        clone_events_to(&sources[0], &targets);
        for i in 1..source_count {
            assert!(sources[i].has_event(&sample),
                "S{} should have cloned event", i);
        }
        eprintln!("  Cloned to S1..S{}", source_count - 1);
    }

    let rss_before = peak_rss_mib();
    let start = Instant::now();

    // Start concurrent sink + all sources with connect_loop (repeated sessions)
    let handles = start_multi_source(&sources, &sink);

    // Wait for sink to receive the sampled event (scale timeout with event count)
    let timeout_secs = if events_per_source >= 100_000 { 600 } else { 120 };
    assert_eventually(
        || sink.has_event(&sample),
        Duration::from_secs(timeout_secs),
        "concurrent sink receives sampled event",
    ).await;

    let wall_ms = start.elapsed().as_millis() as u64;
    let rss_after = peak_rss_mib();
    let events_per_sec = total_messages as f64 / (wall_ms as f64 / 1000.0);

    // Drop handles to stop all loops
    drop(handles);

    eprintln!();
    eprintln!(
        "=== Multi-source overlap: {} sources x {} events (identical data) ===",
        source_count, events_per_source,
    );
    eprintln!("  Unique events:    {}", total_messages);
    eprintln!("  Catchup wall:     {} ms", wall_ms);
    eprintln!("  Events/s:         {:.0}", events_per_sec);
    eprintln!("  Sink store:       {}", sink.store_count());
    eprintln!("  Peak RSS:         {:.1} MiB (before: {:.1})", rss_after, rss_before);
    eprintln!();
}

/// Overlap smoke: 2 sources, 5k overlapping events.
#[tokio::test]
async fn multi_source_overlap_2x_5k() {
    run_multi_source_concurrent_bench(2, 5_000).await;
}

/// Overlap: 4 sources, 5k overlapping events.
#[tokio::test]
#[ignore]
async fn multi_source_overlap_4x_5k() {
    run_multi_source_concurrent_bench(4, 5_000).await;
}

/// Overlap: 8 sources, 6.25k overlapping events.
#[tokio::test]
#[ignore]
async fn multi_source_overlap_8x_6250() {
    run_multi_source_concurrent_bench(8, 6_250).await;
}

/// Overlap ~10MB: 1 source, 100k events (solo baseline).
#[tokio::test]
#[ignore]
async fn multi_source_overlap_1x_100k() {
    run_multi_source_concurrent_bench(1, 100_000).await;
}

/// Overlap ~10MB: 2 sources, 100k overlapping events.
#[tokio::test]
#[ignore]
async fn multi_source_overlap_2x_100k() {
    run_multi_source_concurrent_bench(2, 100_000).await;
}

/// Overlap ~10MB: 4 sources, 100k overlapping events.
#[tokio::test]
#[ignore]
async fn multi_source_overlap_4x_100k() {
    run_multi_source_concurrent_bench(4, 100_000).await;
}

/// Overlap ~10MB: 8 sources, 100k overlapping events.
#[tokio::test]
#[ignore]
async fn multi_source_overlap_8x_100k() {
    run_multi_source_concurrent_bench(8, 100_000).await;
}

/// Overlap ~100MB: 8 sources, ~1M overlapping events (≈96 bytes/event × 1M ≈ 96MB unique data).
#[tokio::test]
#[ignore]
async fn multi_source_overlap_8x_100mb() {
    run_multi_source_concurrent_bench(8, 1_000_000).await;
}

/// Overlap diagnostic: 1 source, 1M events — isolates scale from concurrency.
#[tokio::test]
#[ignore]
async fn multi_source_overlap_1x_1m_diag() {
    run_multi_source_concurrent_bench(1, 1_000_000).await;
}

// ---------------------------------------------------------------------------
// Family B-partitioned: Multi-source concurrent (disjoint / non-overlapping data)
// ---------------------------------------------------------------------------

/// Run a concurrent multi-source benchmark with partitioned data.
///
/// Each source generates its own unique events (total_events / source_count each).
/// No overlap between sources — every event exists at exactly one source.
/// The sink must collect all events from all sources concurrently.
///
/// This models the "swarming" scenario: each peer has a different piece of the
/// total dataset. Negentropy sessions discover non-overlapping have_ids, so
/// there is zero redundant transfer and no dedup overhead.
async fn run_multi_source_partitioned_bench(source_count: usize, total_events: usize) {
    let events_per_source = total_events / source_count;
    let sources: Vec<Peer> = (0..source_count)
        .map(|i| Peer::new_with_identity(&format!("ps{}", i)))
        .collect();
    let sink = Peer::new_with_identity("psink");

    // Each source generates its own unique events
    let gen_start = Instant::now();
    for (i, source) in sources.iter().enumerate() {
        source.batch_create_messages(events_per_source);
        eprintln!("  S{}: generated {} events", i, events_per_source);
    }
    let gen_secs = gen_start.elapsed().as_secs_f64();
    let total_messages = (source_count * events_per_source) as i64;
    eprintln!(
        "Generated {} total unique events across {} sources in {:.2}s ({} each, no overlap)",
        total_messages, source_count, gen_secs, events_per_source,
    );

    // Sample one event from each source as convergence markers
    let samples: Vec<String> = sources.iter()
        .map(|s| s.sample_event_ids(1)[0].clone())
        .collect();

    let rss_before = peak_rss_mib();
    let start = Instant::now();

    let handles = start_multi_source(&sources, &sink);

    let timeout_secs = if total_events >= 100_000 { 600 } else { 120 };
    assert_eventually(
        || samples.iter().all(|s| sink.has_event(s)),
        Duration::from_secs(timeout_secs),
        "partitioned sink receives events from all sources",
    ).await;

    let wall_ms = start.elapsed().as_millis() as u64;
    let rss_after = peak_rss_mib();
    let events_per_sec = total_messages as f64 / (wall_ms as f64 / 1000.0);
    let mb_per_sec = events_per_sec * 100.0 / 1_000_000.0;

    drop(handles);

    eprintln!();
    eprintln!(
        "=== Multi-source partitioned: {} sources x {} events = {} total (no overlap) ===",
        source_count, events_per_source, total_messages,
    );
    eprintln!("  Unique events:    {}", total_messages);
    eprintln!("  Catchup wall:     {} ms", wall_ms);
    eprintln!("  Events/s:         {:.0}", events_per_sec);
    eprintln!("  MB/s:             {:.2}", mb_per_sec);
    eprintln!("  Sink store:       {}", sink.store_count());
    eprintln!("  Peak RSS:         {:.1} MiB (before: {:.1})", rss_after, rss_before);
    eprintln!();
}

/// Partitioned: 1 source, 100k events (solo baseline for partitioned comparison).
#[tokio::test]
#[ignore]
async fn multi_source_partitioned_1x_100k() {
    run_multi_source_partitioned_bench(1, 100_000).await;
}

/// Partitioned: 2 sources, 50k each = 100k total.
#[tokio::test]
#[ignore]
async fn multi_source_partitioned_2x_100k() {
    run_multi_source_partitioned_bench(2, 100_000).await;
}

/// Partitioned: 4 sources, 25k each = 100k total.
#[tokio::test]
#[ignore]
async fn multi_source_partitioned_4x_100k() {
    run_multi_source_partitioned_bench(4, 100_000).await;
}

/// Partitioned: 8 sources, 12.5k each = 100k total.
#[tokio::test]
#[ignore]
async fn multi_source_partitioned_8x_100k() {
    run_multi_source_partitioned_bench(8, 100_000).await;
}

// ---------------------------------------------------------------------------
// Family B-coordinated: Sink-driven download with coordinated round-based assignment
// ---------------------------------------------------------------------------

/// Run a coordinated sink-driven download benchmark.
///
/// All sources have identical data (cloned from S0). The sink connects to all
/// sources as initiator, using coordinated round-based assignment to split
/// downloads across sources. A coordinator thread collects need_ids from all
/// peers, assigns events via greedy load balancing (least-loaded peer that
/// has the event). Undelivered events re-appear in the next round.
async fn run_sink_download_bench(source_count: usize, events_per_source: usize) {
    let sources: Vec<Peer> = (0..source_count)
        .map(|i| Peer::new_with_identity(&format!("ds{}", i)))
        .collect();
    let sink = Peer::new_with_identity("dsink");

    // Generate events at S0 only
    let gen_start = Instant::now();
    sources[0].batch_create_messages(events_per_source);
    let gen_secs = gen_start.elapsed().as_secs_f64();
    let total_messages = events_per_source as i64;
    eprintln!(
        "Generated {} events at S0 in {:.2}s, cloning to {} sources...",
        total_messages, gen_secs, source_count - 1
    );

    // Clone S0's data to all other sources (overlapping data)
    if source_count > 1 {
        let targets: Vec<&Peer> = sources[1..].iter().collect();
        clone_events_to(&sources[0], &targets);
        eprintln!("  Cloned to S1..S{}", source_count - 1);
    }

    // Sample a convergence marker from S0
    let sample = sources[0].sample_event_ids(1)[0].clone();

    let rss_before = peak_rss_mib();
    let start = Instant::now();

    // Sink-driven download: sink connects to all sources with claimed set
    let handles = start_sink_download(&sources, &sink);

    let timeout_secs = if events_per_source >= 100_000 { 600 } else { 120 };
    assert_eventually(
        || sink.has_event(&sample),
        Duration::from_secs(timeout_secs),
        "sink download receives sampled event",
    ).await;

    let wall_ms = start.elapsed().as_millis() as u64;
    let rss_after = peak_rss_mib();
    let events_per_sec = total_messages as f64 / (wall_ms as f64 / 1000.0);
    let mb_per_sec = events_per_sec * 100.0 / 1_000_000.0;

    drop(handles);

    eprintln!();
    eprintln!(
        "=== Multi-source coordinated: {} sources x {} events (sink-driven rounds) ===",
        source_count, events_per_source,
    );
    eprintln!("  Unique events:    {}", total_messages);
    eprintln!("  Catchup wall:     {} ms", wall_ms);
    eprintln!("  Events/s:         {:.0}", events_per_sec);
    eprintln!("  MB/s:             {:.2}", mb_per_sec);
    eprintln!("  Sink store:       {}", sink.store_count());
    eprintln!("  Peak RSS:         {:.1} MiB (before: {:.1})", rss_after, rss_before);
    eprintln!();
}

/// Coordinated smoke: 2 sources, 5k overlapping events.
#[tokio::test]
async fn multi_source_coordinated_2x_5k() {
    run_sink_download_bench(2, 5_000).await;
}

/// Coordinated: 1 source, 100k events (solo baseline).
#[tokio::test]
#[ignore]
async fn multi_source_coordinated_1x_100k() {
    run_sink_download_bench(1, 100_000).await;
}

/// Coordinated: 2 sources, 100k overlapping events.
#[tokio::test]
#[ignore]
async fn multi_source_coordinated_2x_100k() {
    run_sink_download_bench(2, 100_000).await;
}

/// Coordinated: 4 sources, 100k overlapping events.
#[tokio::test]
#[ignore]
async fn multi_source_coordinated_4x_100k() {
    run_sink_download_bench(4, 100_000).await;
}

/// Coordinated: 8 sources, 100k overlapping events.
#[tokio::test]
#[ignore]
async fn multi_source_coordinated_8x_100k() {
    run_sink_download_bench(8, 100_000).await;
}
