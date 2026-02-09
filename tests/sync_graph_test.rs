//! Sync graph performance benchmarks
//!
//! Family A: Chain propagation (P0 <-> P1 <-> ... <-> Pn)
//! Family B: Multi-source catchup (S1..Sn feed lagging peer L)
//!
//! Run smoke tests:    cargo test --release --test sync_graph_test -- --nocapture --test-threads=1
//! Run all:            cargo test --release --test sync_graph_test -- --nocapture --include-ignored --test-threads=1
//!
//! NOTE: --test-threads=1 is required; concurrent heavy tests trigger a negentropy
//! race condition (duplicate items from concurrent reads/writes to neg_items).

use std::time::{Duration, Instant};
use poc_7::testutil::{
    Peer, start_chain, sync_until_converged, assert_eventually,
};

fn test_channel() -> [u8; 32] {
    let mut ch = [0u8; 32];
    ch[0..5].copy_from_slice(b"graph");
    ch
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
    let channel = test_channel();
    let peers: Vec<Peer> = (0..n)
        .map(|i| Peer::new(&format!("p{}", i), channel))
        .collect();

    let gen_start = Instant::now();
    peers[0].batch_create_messages(event_count);
    let gen_secs = gen_start.elapsed().as_secs_f64();
    eprintln!("Generated {} events at P0 in {:.2}s", event_count, gen_secs);

    let rss_before = peak_rss_mib();
    let start = Instant::now();

    let handles = start_chain(&peers);

    let expected = event_count as i64;
    let timeout = Duration::from_secs(600);

    // Wait for tail peer to converge
    assert_eventually(
        || peers[n - 1].store_count() == expected,
        timeout,
        &format!(
            "chain tail P{} convergence to {}",
            n - 1,
            expected,
        ),
    )
    .await;

    let tail_wall_ms = start.elapsed().as_millis() as u64;

    // Wait for ALL peers to converge
    assert_eventually(
        || peers.iter().all(|p| p.store_count() == expected),
        Duration::from_secs(60),
        "all peers converge",
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
// Family B: Multi-source catchup (B0 baseline: serialized)
// ---------------------------------------------------------------------------

/// Run a multi-source catchup benchmark (B0 baseline).
///
/// Uses pairwise sync: each source syncs with the sink one at a time.
/// This measures the B0 baseline (serialized accept behavior).
///
/// After each pairwise sync:
/// - Sink accumulates more events
/// - Source also receives sink's events (from previous sources)
async fn run_multi_source_bench(source_count: usize, events_per_source: usize) {
    let channel = test_channel();
    let sources: Vec<Peer> = (0..source_count)
        .map(|i| Peer::new(&format!("s{}", i), channel))
        .collect();
    let sink = Peer::new("sink", channel);

    let gen_start = Instant::now();
    for (i, source) in sources.iter().enumerate() {
        source.batch_create_messages(events_per_source);
        eprintln!("  Source S{}: generated {} events", i, events_per_source);
    }
    let gen_secs = gen_start.elapsed().as_secs_f64();
    let total_unique = (source_count * events_per_source) as i64;
    eprintln!(
        "Generated {} total events across {} sources in {:.2}s",
        total_unique, source_count, gen_secs
    );

    let rss_before = peak_rss_mib();
    let start = Instant::now();

    // Sync each source with sink pairwise (serialized B0 baseline)
    let mut cumulative: i64 = 0;
    for (i, source) in sources.iter().enumerate() {
        cumulative += events_per_source as i64;
        let source_start = Instant::now();

        // Both peers converge to cumulative count:
        // sink gets this source's events, source gets sink's accumulated events
        let metrics = sync_until_converged(
            source, &sink, cumulative, Duration::from_secs(120),
        ).await;

        let source_ms = source_start.elapsed().as_millis() as u64;
        eprintln!(
            "  S{}: {} events synced in {}ms ({:.0} events/s)",
            i, metrics.events_transferred, source_ms, metrics.events_per_sec,
        );
    }

    let wall_ms = start.elapsed().as_millis() as u64;
    let rss_after = peak_rss_mib();
    let events_per_sec = total_unique as f64 / (wall_ms as f64 / 1000.0);

    assert_eq!(sink.store_count(), total_unique);

    eprintln!();
    eprintln!(
        "=== Multi-source B0: {} sources x {} events = {} total ===",
        source_count, events_per_source, total_unique
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

/// Multi-source smoke: 2 sources, 5k each (10k total).
#[tokio::test]
async fn multi_source_b0_2x_5k() {
    run_multi_source_bench(2, 5_000).await;
}

/// Multi-source B0 baseline: 4 sources, 5k each (20k total).
#[tokio::test]
#[ignore]
async fn multi_source_b0_4x_5k() {
    run_multi_source_bench(4, 5_000).await;
}

/// Multi-source B0 baseline: 8 sources, ~6.25k each (50k total).
#[tokio::test]
#[ignore]
async fn multi_source_b0_8x_6250() {
    run_multi_source_bench(8, 6_250).await;
}

/// Multi-source B0 single-source reference: 1 source, 50k events.
#[tokio::test]
#[ignore]
async fn multi_source_b0_1x_50k() {
    run_multi_source_bench(1, 50_000).await;
}
