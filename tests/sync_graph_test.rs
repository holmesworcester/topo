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
use topo::crypto::event_id_to_base64;
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

/// Wait until each peer reaches full convergence on stored Message events and
/// return per-peer convergence timestamps (ms since `start`) in peer order.
async fn wait_for_full_stored_message_convergence_times(
    peers: &[Peer],
    expected_stored_message_count: i64,
    timeout: Duration,
    start: Instant,
) -> Vec<u64> {
    let mut reached: Vec<Option<u64>> = vec![None; peers.len()];
    loop {
        let elapsed_ms = start.elapsed().as_millis() as u64;
        let counts: Vec<i64> = peers.iter().map(Peer::stored_message_event_count).collect();
        for (i, count) in counts.iter().enumerate() {
            if reached[i].is_none() && *count == expected_stored_message_count {
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
            "chain stored-message convergence timed out after {:?}: stored_message_counts={:?}, expected={}",
            timeout,
            counts,
            expected_stored_message_count
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
            "  P{} stored messages: {}",
            i,
            peer.stored_message_event_count()
        );
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

    // Convergence target on canonical stored Message events: all peers should
    // eventually store the same message event set from P0.
    let expected_stored_message_count = event_count as i64;

    let rss_before = peak_rss_mib();
    let start = Instant::now();

    let handles = start_chain(&peers);

    // Count-only timing: convergence is measured from per-peer stored Message
    // event counts (canonical events table, not local-scoped projection rows).
    let convergence_ms = wait_for_full_stored_message_convergence_times(
        &peers,
        expected_stored_message_count,
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
    eprintln!(
        "  Peak RSS:         {:.1} MiB (before: {:.1})",
        rss_after, rss_before
    );
    print_chain_message_counts(&peers);
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

    // Convergence target: union of all source Message event IDs.
    let expected_sink_message_ids: BTreeSet<String> = sources
        .iter()
        .flat_map(|s| s.event_ids_by_type("message").into_iter())
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
        || sink.stored_message_event_count() == expected_sink_message_count,
        Duration::from_secs(timeout_secs),
        &format!(
            "sink reaches expected stored_message_event_count={}",
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
    let sink_ids = sink.event_ids_by_type("message");
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
    eprintln!("  Sink stored msgs: {}", sink.stored_message_event_count());
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
async fn run_catchup_large_file(source_count: usize, total_slices: usize) {
    let sources: Vec<Peer> = (0..source_count)
        .map(|i| Peer::new_with_identity(&format!("fs{}", i)))
        .collect();
    let sink = Peer::new_with_identity("fsink");

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
    let contributing = source_counts
        .values()
        .filter(|&&c| c >= floor)
        .count();
    assert_eq!(
        contributing, source_count,
        "all {} sources must contribute >= {} slices each; got: {:?}",
        source_count, floor, source_counts,
    );
}

/// Multi-source file: 4 sources, 1024 slices (256 MiB).
#[tokio::test]
#[ignore]
async fn catchup_large_file_4x_1024_slices() {
    run_catchup_large_file(4, 1024).await;
}

/// Multi-source file: 8 sources, 1024 slices (256 MiB).
#[tokio::test]
#[ignore]
async fn catchup_large_file_8x_1024_slices() {
    run_catchup_large_file(8, 1024).await;
}
