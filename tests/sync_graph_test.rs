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

use std::time::{Duration, Instant};
use topo::crypto::event_id_to_base64;
use topo::testutil::{
    Peer, start_chain, start_sink_download,
    assert_eventually, clone_events_to,
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


// ---------------------------------------------------------------------------
// Family B: Multi-source catchup (sink-driven coordinated download)
// ---------------------------------------------------------------------------

/// Run a coordinated sink-driven download benchmark.
///
/// Sources share a large overlapping dataset (cloned from S0) plus one
/// source-unique marker each. The sink connects to all sources as initiator
/// using coordinated round-based assignment.
///
/// The unique marker per source gives a hard "no-cheat" proof that every source
/// contributed real data to sink catchup.
async fn run_catchup_bench(source_count: usize, events_per_source: usize) {
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

    // Add one source-unique marker on each source so we can prove each source
    // contributed data to sink catchup.
    let source_markers: Vec<String> = sources
        .iter()
        .enumerate()
        .map(|(i, source)| {
            let marker = source.create_message(&format!("source-{}-unique-marker", i));
            event_id_to_base64(&marker)
        })
        .collect();

    // Sample a convergence marker from S0.
    let sample = sources[0].sample_event_ids(1)[0].clone();

    let rss_before = peak_rss_mib();
    let start = Instant::now();

    // Sink-driven download: sink connects to all sources with claimed set
    let handles = start_sink_download(&sources, &sink);

    let timeout_secs = if events_per_source >= 100_000 { 600 } else { 120 };
    assert_eventually(
        || {
            sink.has_event(&sample) && source_markers.iter().all(|marker| sink.has_event(marker))
        },
        Duration::from_secs(timeout_secs),
        "sink download receives sampled event and per-source unique markers",
    ).await;

    let wall_ms = start.elapsed().as_millis() as u64;
    let rss_after = peak_rss_mib();
    let events_per_sec = total_messages as f64 / (wall_ms as f64 / 1000.0);
    let mb_per_sec = events_per_sec * 100.0 / 1_000_000.0;

    let contributing_sources = source_markers
        .iter()
        .filter(|marker| sink.has_event(marker))
        .count();
    assert_eq!(
        contributing_sources, source_count,
        "sink must receive at least one unique marker from each source"
    );

    drop(handles);

    eprintln!();
    eprintln!(
        "=== Multi-source catchup: {} sources x {} events (sink-driven rounds) ===",
        source_count, events_per_source,
    );
    eprintln!("  Unique events:    {}", total_messages);
    eprintln!("  Catchup wall:     {} ms", wall_ms);
    eprintln!("  Events/s:         {:.0}", events_per_sec);
    eprintln!("  MB/s:             {:.2}", mb_per_sec);
    eprintln!("  Contributing src: {}/{}", contributing_sources, source_count);
    eprintln!("  Sink store:       {}", sink.store_count());
    eprintln!("  Peak RSS:         {:.1} MiB (before: {:.1})", rss_after, rss_before);
    eprintln!();
}

/// Catchup smoke: 2 sources, 5k overlapping events.
#[tokio::test]
async fn catchup_2x_5k() {
    run_catchup_bench(2, 5_000).await;
}

/// Catchup: 4 sources, 100k overlapping events.
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
