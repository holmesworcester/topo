//! Sync graph performance benchmarks
//!
//! Family A: Chain propagation (P0 <-> P1 <-> ... <-> Pn)
//! Family B: Multi-source catchup (S1..Sn feed lagging sink via coordinated download)
//!
//! Run smoke tests:    cargo test --release --test sync_graph_test -- --nocapture --test-threads=1
//! Run all:            cargo test --release --test sync_graph_test -- --nocapture --include-ignored --test-threads=1
//!
//! NOTE: --test-threads=1 is required; concurrent heavy tests trigger a negentropy
//! race condition (duplicate items from concurrent reads/writes to neg_items).

use std::collections::BTreeSet;
use std::time::{Duration, Instant};
use topo::testutil::{assert_eventually, clone_events_to, start_chain, start_sink_download, Peer};

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

/// Wait until each peer reaches full store convergence and return per-peer
/// convergence timestamps (ms since `start`) in peer order.
async fn wait_for_full_convergence_times(
    peers: &[Peer],
    expected_store_count: i64,
    timeout: Duration,
    start: Instant,
) -> Vec<u64> {
    let mut reached: Vec<Option<u64>> = vec![None; peers.len()];
    loop {
        let elapsed_ms = start.elapsed().as_millis() as u64;
        for (i, peer) in peers.iter().enumerate() {
            if reached[i].is_none() && peer.store_count() == expected_store_count {
                reached[i] = Some(elapsed_ms);
            }
        }

        if reached.iter().all(Option::is_some) {
            return reached
                .into_iter()
                .map(|ts| ts.expect("all peers reached convergence"))
                .collect();
        }

        let counts: Vec<i64> = peers.iter().map(Peer::store_count).collect();
        assert!(
            start.elapsed() < timeout,
            "chain full convergence timed out after {:?}: counts={:?}, expected={}",
            timeout,
            counts,
            expected_store_count
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

    // Count-based convergence target: union of all pre-sync store IDs.
    let expected_store_count = {
        let mut ids = BTreeSet::new();
        for peer in &peers {
            ids.extend(peer.store_ids());
        }
        ids.len() as i64
    };

    let rss_before = peak_rss_mib();
    let start = Instant::now();

    let handles = start_chain(&peers);

    // Count-only timing: convergence is measured from per-peer store_count.
    let convergence_ms = wait_for_full_convergence_times(
        &peers,
        expected_store_count,
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

    let events_per_sec = event_count as f64 / (tail_wall_ms as f64 / 1000.0);

    drop(handles);

    eprintln!();
    eprintln!("=== Chain: {} peers, {} events ===", n, event_count);
    eprintln!("  Tail converge:    {} ms", tail_wall_ms);
    eprintln!("  All converge:     {} ms", all_wall_ms);
    eprintln!("  Events/s (tail):  {:.0}", events_per_sec);
    eprintln!(
        "  Hop latency P50:  {:.1} ms ({} samples)",
        hop_p50,
        hop_delays.len()
    );
    eprintln!("  Hop latency P95:  {:.1} ms", hop_p95);
    eprintln!(
        "  Peak RSS:         {:.1} MiB (before: {:.1})",
        rss_after, rss_before
    );
    print_chain_counts(&peers);
    eprintln!();
}

/// 10-hop chain smoke: 10 peers, 10k events.
#[tokio::test]
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
    assert!(source_count >= 1, "source_count must be >= 1");
    let mut sources: Vec<Peer> = Vec::with_capacity(source_count);
    // S0 owns canonical event generation identity chain.
    sources.push(Peer::new_with_identity("ds0"));
    // Remaining sources are transport-only peers; clone S0 dataset into them.
    for i in 1..source_count {
        sources.push(Peer::new(&format!("ds{}", i)));
    }
    let sink = Peer::new_with_identity("dsink");

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

    // Count-based convergence target: union of all source store IDs.
    let expected_sink_ids: BTreeSet<String> = sources
        .iter()
        .flat_map(|s| s.store_ids().into_iter())
        .collect();
    let expected_sink_count = expected_sink_ids.len() as i64;

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
        || sink.store_count() == expected_sink_count,
        Duration::from_secs(timeout_secs),
        &format!("sink reaches expected store_count={}", expected_sink_count),
    )
    .await;

    let wall_ms = start.elapsed().as_millis() as u64;
    let rss_after = peak_rss_mib();
    let events_per_sec = expected_sink_count as f64 / (wall_ms as f64 / 1000.0);
    let mb_per_sec = events_per_sec * 100.0 / 1_000_000.0;

    // Exact set equality validates full dataset catchup (no marker shortcuts).
    let sink_ids = sink.store_ids();
    assert_eq!(
        sink_ids, expected_sink_ids,
        "sink store IDs must match union of source store IDs"
    );

    drop(handles);

    eprintln!();
    eprintln!(
        "=== Multi-source catchup: {} sources x {} events (sink-driven rounds) ===",
        source_count, events_per_source,
    );
    eprintln!("  Unique events:    {}", expected_sink_count);
    eprintln!("  Catchup wall:     {} ms", wall_ms);
    eprintln!("  Events/s:         {:.0}", events_per_sec);
    eprintln!("  MB/s:             {:.2}", mb_per_sec);
    eprintln!("  Sink store:       {}", sink.store_count());
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
