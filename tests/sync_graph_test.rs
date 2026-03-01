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
use topo::crypto::hash_event;
use topo::db::open_connection;
use topo::event_modules::{
    file_slice::FILE_SLICE_CIPHERTEXT_BYTES, FileSliceEvent, MessageAttachmentEvent, ParsedEvent,
};
use topo::projection::create::create_signed_event_sync;
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

    // Count-based convergence target: union of all source shared store IDs.
    let expected_sink_ids: BTreeSet<String> = sources
        .iter()
        .flat_map(|s| s.shared_store_ids().into_iter())
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
    let sink_ids = sink.shared_store_ids();
    assert_eq!(
        sink_ids, expected_sink_ids,
        "sink shared store IDs must match union of source shared store IDs"
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

fn seed_large_file_on_source(source: &Peer, total_slices: u32) {
    let signer_eid = source
        .peer_shared_event_id
        .expect("source must have peer_shared signer event");
    let signing_key = source
        .peer_shared_signing_key
        .as_ref()
        .expect("source must have peer_shared signing key");
    let db = open_connection(&source.db_path).expect("open source db");

    let msg_id = source.create_message("multi-source large-file anchor");
    let key_id = source.create_secret_key([0xA5; 32]);
    let file_id =
        hash_event(format!("multi-source-file:{}:{}", source.identity, total_slices).as_bytes());

    let att = ParsedEvent::MessageAttachment(MessageAttachmentEvent {
        created_at_ms: 1_700_000_000_000,
        message_id: msg_id,
        file_id,
        blob_bytes: total_slices as u64 * FILE_SLICE_CIPHERTEXT_BYTES as u64,
        total_slices,
        slice_bytes: FILE_SLICE_CIPHERTEXT_BYTES as u32,
        root_hash: [0x5A; 32],
        key_event_id: key_id,
        filename: "multi-source-bench.bin".to_string(),
        mime_type: "application/octet-stream".to_string(),
        signed_by: signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    create_signed_event_sync(&db, &source.identity, &att, signing_key)
        .expect("create message_attachment");

    let ciphertext = vec![0xC3; FILE_SLICE_CIPHERTEXT_BYTES];
    for slice in 0..total_slices {
        let fs = ParsedEvent::FileSlice(FileSliceEvent {
            created_at_ms: 1_700_000_000_000 + slice as u64 + 1,
            file_id,
            slice_number: slice,
            ciphertext: ciphertext.clone(),
            signed_by: signer_eid,
            signer_type: 5,
            signature: [0u8; 64],
        });
        create_signed_event_sync(&db, &source.identity, &fs, signing_key)
            .expect("create file_slice");
    }
}

fn per_source_slice_counts(sink: &Peer, sources: &[Peer]) -> Vec<(String, i64)> {
    let by_source = sink.recorded_event_type_counts_by_source("file_slice", "quic_recv:");
    sources
        .iter()
        .map(|source| {
            let prefix = format!("quic_recv:{}@", source.identity);
            let count = by_source
                .iter()
                .filter(|(tag, _)| tag.starts_with(&prefix))
                .map(|(_, count)| *count)
                .sum::<i64>();
            (source.identity.clone(), count)
        })
        .collect()
}

/// Run a coordinated multi-source large-file catchup benchmark.
///
/// All sources except sink are seeded with identical file-slice data.
/// Success requires:
/// 1) sink file-slice ID set equals source set exactly
/// 2) every source contributes a substantial share of ingested slices
async fn run_multi_source_large_file_catchup_bench(
    source_count: usize,
    total_slices: u32,
    min_fair_share_fraction: f64,
) {
    assert!(source_count >= 2, "source_count must be >= 2");
    assert!(total_slices > 0, "total_slices must be > 0");
    assert!(
        min_fair_share_fraction > 0.0 && min_fair_share_fraction <= 1.0,
        "min_fair_share_fraction must be in (0, 1]"
    );

    let mut sources: Vec<Peer> = Vec::with_capacity(source_count);
    sources.push(Peer::new_with_identity("fs0"));
    for i in 1..source_count {
        sources.push(Peer::new(&format!("fs{}", i)));
    }
    let sink = Peer::new_with_identity("fssink");

    let seed_start = Instant::now();
    seed_large_file_on_source(&sources[0], total_slices);
    let seed_secs = seed_start.elapsed().as_secs_f64();

    let targets: Vec<&Peer> = sources[1..].iter().collect();
    if !targets.is_empty() {
        clone_events_to(&sources[0], &targets);
    }

    let expected_slice_ids = sources[0].event_ids_by_type("file_slice");
    assert_eq!(
        expected_slice_ids.len(),
        total_slices as usize,
        "source seed file-slice count mismatch"
    );

    let rss_before = peak_rss_mib();
    let start = Instant::now();
    let handles = start_sink_download(&sources, &sink);

    assert_eventually(
        || sink.event_ids_by_type("file_slice").len() == expected_slice_ids.len(),
        Duration::from_secs(900),
        &format!(
            "sink reaches expected file_slice count={}",
            expected_slice_ids.len()
        ),
    )
    .await;

    let wall_ms = start.elapsed().as_millis() as u64;
    let sink_slice_ids = sink.event_ids_by_type("file_slice");
    assert_eq!(
        sink_slice_ids, expected_slice_ids,
        "sink file_slice IDs must match seeded source set"
    );

    let per_source = per_source_slice_counts(&sink, &sources);
    let total_attributed: i64 = per_source.iter().map(|(_, c)| *c).sum();
    assert_eq!(
        total_attributed, total_slices as i64,
        "sum of source-attributed file_slice ingest must equal total slices"
    );

    let fair_share = total_slices as f64 / source_count as f64;
    let min_substantial = (fair_share * min_fair_share_fraction).floor() as i64;
    let min_substantial = min_substantial.max(1);
    for (source_id, count) in &per_source {
        assert!(
            *count >= min_substantial,
            "source {} contribution too small: {} < {} (fair_share={:.2}, fraction={:.2})",
            source_id,
            count,
            min_substantial,
            fair_share,
            min_fair_share_fraction
        );
    }

    let rss_after = peak_rss_mib();
    let secs = wall_ms as f64 / 1000.0;
    let mib = (total_slices as f64 * FILE_SLICE_CIPHERTEXT_BYTES as f64) / (1024.0 * 1024.0);
    let mib_per_sec = mib / secs.max(0.001);
    drop(handles);

    eprintln!();
    eprintln!(
        "=== Multi-source large-file catchup: {} sources, {} slices ===",
        source_count, total_slices
    );
    eprintln!("  Seed time:         {:.2}s", seed_secs);
    eprintln!("  Catchup wall:      {} ms", wall_ms);
    eprintln!("  Volume:            {:.1} MiB", mib);
    eprintln!("  Throughput:        {:.2} MiB/s", mib_per_sec);
    eprintln!(
        "  Min/source floor:  {} slices ({:.0}% of fair share)",
        min_substantial,
        min_fair_share_fraction * 100.0
    );
    for (source_id, count) in per_source {
        eprintln!("  Source {}: {} slices", source_id, count);
    }
    eprintln!(
        "  Peak RSS:          {:.1} MiB (before: {:.1})",
        rss_after, rss_before
    );
    eprintln!();
}

/// Large-file catchup smoke (ignored by default): 4 identical sources, 1024 slices (~256 MiB).
#[tokio::test]
#[ignore]
async fn catchup_large_file_4x_1024_slices() {
    run_multi_source_large_file_catchup_bench(4, 1_024, 0.10).await;
}

/// Large-file catchup scalability run (ignored): 8 identical sources, 1024 slices (~256 MiB).
#[tokio::test]
#[ignore]
async fn catchup_large_file_8x_1024_slices() {
    run_multi_source_large_file_catchup_bench(8, 1_024, 0.10).await;
}
