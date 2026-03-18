//! Two-peer delivery latency benchmark using the in-process `Peer` harness.
//!
//! Default run:
//! `cargo test --release --test multi_peer_delivery_latency_perf_test -- --ignored --nocapture --test-threads=1`
//!
//! Tunables:
//! `TOPO_PERF_PRELOAD_MESSAGES` default `0`
//! `TOPO_PERF_MESSAGES_PER_SEC` default `5`
//! `TOPO_PERF_LIVE_SECONDS` default `60`

use std::sync::{Arc, Barrier, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use rusqlite::OptionalExtension;
use topo::db::timeline::{EventTimeline, EventTimelineRow};
use topo::testutil::{assert_eventually, start_peers_runtime_affine, Peer};

const DEFAULT_MESSAGES_PER_SEC: usize = 5;
const DEFAULT_LIVE_SECONDS: usize = 60;
const TWO_PEER_GATE_MESSAGES_PER_SEC: usize = 2;
const TWO_PEER_GATE_MAX_WORST_MS: i64 = 50;

#[derive(Clone)]
struct SentMessage {
    origin_index: usize,
    origin_seq: usize,
    event_id_b64: String,
    event_id_hex: String,
    created_at_ms: i64,
}

#[derive(Clone)]
struct DeliverySample {
    sent_order: usize,
    origin_seq: usize,
    origin_name: String,
    sink_name: String,
    event_id_b64: String,
    event_id_hex: String,
    created_at_ms: i64,
    latency_ms: i64,
}

#[derive(Clone)]
struct DeliveryExtremum {
    latency_ms: i64,
    origin_name: String,
    sink_name: String,
    event_id_hex: String,
}

struct DeliveryLatencyReport {
    sample_count: usize,
    avg_ms: f64,
    p50_ms: f64,
    p95_ms: f64,
    best: DeliveryExtremum,
    worst: DeliveryExtremum,
}

struct DeliveryWindowReport {
    start_order: usize,
    end_order: usize,
    start_elapsed_secs: f64,
    end_elapsed_secs: f64,
    avg_ms: f64,
    p50_ms: f64,
    p95_ms: f64,
    best_ms: i64,
    worst_ms: i64,
}

#[derive(Clone)]
struct StageTimingSample {
    sample: DeliverySample,
    origin_row: Option<EventTimelineRow>,
    sink_row: Option<EventTimelineRow>,
    created_to_need_sent_ms: Option<i64>,
    need_transit_ms: Option<i64>,
    need_recv_to_wanted_ms: Option<i64>,
    wanted_to_credit_ms: Option<i64>,
    credit_to_request_selected_ms: Option<i64>,
    wanted_to_request_selected_ms: Option<i64>,
    selected_to_request_sent_ms: Option<i64>,
    request_transit_ms: Option<i64>,
    request_recv_to_response_sent_ms: Option<i64>,
    response_transit_ms: Option<i64>,
    response_recv_to_persisted_ms: Option<i64>,
    persisted_to_projected_ms: Option<i64>,
    origin_timeline: Option<String>,
    sink_timeline: Option<String>,
}

struct StageTimingSummary {
    label: &'static str,
    count: usize,
    avg_ms: f64,
    p95_ms: f64,
    worst_ms: i64,
}

struct DeliveryStageReport {
    summaries: Vec<StageTimingSummary>,
    samples: Vec<StageTimingSample>,
    worst_sample: StageTimingSample,
}

fn env_usize(name: &str, default: usize) -> usize {
    match std::env::var(name) {
        Ok(value) => value
            .parse::<usize>()
            .unwrap_or_else(|err| panic!("{name} must be a positive integer: {err}")),
        Err(_) => default,
    }
}

fn env_flag(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(value) => !matches!(value.as_str(), "0" | "false" | "FALSE" | "no" | "NO"),
        Err(_) => default,
    }
}

fn stage_breakdown_enabled() -> bool {
    env_flag("TOPO_PERF_STAGE_BREAKDOWN", false)
}

fn stage_csv_enabled() -> bool {
    env_flag("TOPO_PERF_STAGE_CSV", true)
}

fn maybe_enable_timeline_recording() {
    if stage_breakdown_enabled() || stage_csv_enabled() {
        std::env::set_var("TOPO_EVENT_TIMELINE", "1");
    }
}

fn maybe_settle_after_join() {
    let settle_ms = env_usize("TOPO_PERF_POST_JOIN_SETTLE_MS", 0);
    if settle_ms > 0 {
        std::thread::sleep(Duration::from_millis(settle_ms as u64));
    }
}

fn maybe_warm_sync() {
    let warmup_ms = env_usize("TOPO_PERF_WARMUP_MS", 0);
    if warmup_ms > 0 {
        std::thread::sleep(Duration::from_millis(warmup_ms as u64));
    }
}

fn maybe_init_tracing() {
    static INIT: OnceLock<()> = OnceLock::new();
    if std::env::var("TOPO_PERF_TRACE")
        .ok()
        .is_none_or(|value| value == "0" || value.eq_ignore_ascii_case("false"))
    {
        return;
    }
    INIT.get_or_init(|| {
        let filter = std::env::var("TOPO_PERF_TRACE_FILTER")
            .unwrap_or_else(|_| "info,quinn=warn,rustls=warn".to_string());
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
            .with_writer(std::io::stderr)
            .try_init();
    });
}

fn sanitize_run_id(component: &str) -> String {
    component
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

async fn warm_two_peer_sync(peers: &[Peer], baseline_messages: i64) {
    assert_eq!(peers.len(), 2, "warm_two_peer_sync expects exactly 2 peers");
    peers[0].create_message("warmup-alice");
    peers[1].create_message("warmup-bob");
    let expected_total = baseline_messages + 2;
    assert_eventually(
        || {
            peers
                .iter()
                .all(|peer| peer.message_count() == expected_total)
        },
        Duration::from_secs(60),
        "two-peer warm sync convergence",
    )
    .await;
}

fn lookup_message_created_at_ms(peer: &Peer, event_id_b64: &str) -> i64 {
    let conn = topo::db::open_connection(&peer.db_path).expect("open peer db for created_at");
    conn.query_row(
        "SELECT created_at
         FROM messages
         WHERE recorded_by = ?1 AND message_id = ?2",
        rusqlite::params![&peer.identity, event_id_b64],
        |row| row.get::<_, i64>(0),
    )
    .optional()
    .expect("query created_at")
    .unwrap_or_else(|| {
        panic!(
            "missing local message row for peer={} event={}",
            peer.name, event_id_b64
        )
    })
}

fn lookup_received_at_ms(peer: &Peer, event_id_b64: &str) -> i64 {
    let conn = topo::db::open_connection(&peer.db_path).expect("open peer db for received_at_ms");
    conn.query_row(
        "SELECT received_at_ms
         FROM recorded_events
         WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![&peer.identity, event_id_b64],
        |row| row.get::<_, i64>(0),
    )
    .optional()
    .expect("query received_at_ms")
    .unwrap_or_else(|| {
        panic!(
            "missing recorded_events row for peer={} event={}",
            peer.name, event_id_b64
        )
    })
}

fn lookup_timeline_row(peer: &Peer, event_id_b64: &str) -> Option<EventTimelineRow> {
    let conn = topo::db::open_connection(&peer.db_path).expect("open peer db for timeline");
    EventTimeline::new(&conn)
        .load(event_id_b64)
        .expect("query event_timeline")
}

fn timeline_summary(peer: &Peer, event_id_b64: &str) -> Option<String> {
    let conn = topo::db::open_connection(&peer.db_path).expect("open peer db for timeline");
    EventTimeline::new(&conn)
        .summary(event_id_b64)
        .expect("query event_timeline summary")
}

fn run_live_rate_limited_senders(
    peers: &[Peer],
    messages_per_sec: usize,
    live_seconds: usize,
) -> Vec<SentMessage> {
    assert_eq!(peers.len(), 2, "expected exactly two peers");
    assert!(messages_per_sec > 0, "messages_per_sec must be >= 1");
    assert!(live_seconds > 0, "live_seconds must be >= 1");

    let per_peer_messages = messages_per_sec
        .checked_mul(live_seconds)
        .expect("per_peer_messages overflow");
    let barrier = Arc::new(Barrier::new(peers.len()));
    let mut sent = Vec::with_capacity(peers.len() * per_peer_messages);

    thread::scope(|scope| {
        let mut handles = Vec::new();
        for (origin_index, peer) in peers.iter().enumerate() {
            let barrier = Arc::clone(&barrier);
            handles.push(scope.spawn(move || {
                let mut event_ids = Vec::with_capacity(per_peer_messages);
                barrier.wait();
                let start = Instant::now();
                for seq in 0..per_peer_messages {
                    let target_elapsed =
                        Duration::from_secs_f64(seq as f64 / messages_per_sec as f64);
                    if let Some(remaining) = target_elapsed.checked_sub(start.elapsed()) {
                        thread::sleep(remaining);
                    }
                    let content = format!("live-{}-{}", peer.name, seq);
                    event_ids.push((seq, peer.create_message(&content)));
                }
                (origin_index, event_ids)
            }));
        }

        for handle in handles {
            let (origin_index, event_ids) = handle.join().expect("live sender thread panicked");
            let origin_peer = &peers[origin_index];
            for (origin_seq, event_id) in event_ids {
                let event_id_b64 = topo::crypto::event_id_to_base64(&event_id);
                let created_at_ms = lookup_message_created_at_ms(origin_peer, &event_id_b64);
                sent.push(SentMessage {
                    origin_index,
                    origin_seq,
                    event_id_hex: hex::encode(event_id),
                    event_id_b64,
                    created_at_ms,
                });
            }
        }
    });

    sent
}

fn percentile(sorted: &[i64], pct: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 * pct) as usize).min(sorted.len() - 1);
    sorted[idx] as f64
}

fn collect_delivery_samples(peers: &[Peer], sent_messages: &[SentMessage]) -> Vec<DeliverySample> {
    let expected_samples = sent_messages.len();
    let mut samples = Vec::with_capacity(expected_samples);

    for sent in sent_messages {
        let origin = &peers[sent.origin_index];
        let sink_index = if sent.origin_index == 0 { 1 } else { 0 };
        let sink = &peers[sink_index];
        let received_at_ms = lookup_received_at_ms(sink, &sent.event_id_b64);
        let latency_ms = received_at_ms - sent.created_at_ms;
        assert!(
            latency_ms >= 0,
            "negative delivery latency for event {} origin={} sink={} created_at_ms={} received_at_ms={}",
            sent.event_id_hex,
            origin.name,
            sink.name,
            sent.created_at_ms,
            received_at_ms
        );
        samples.push(DeliverySample {
            sent_order: 0,
            origin_seq: sent.origin_seq,
            origin_name: origin.name.clone(),
            sink_name: sink.name.clone(),
            event_id_b64: sent.event_id_b64.clone(),
            event_id_hex: sent.event_id_hex.clone(),
            created_at_ms: sent.created_at_ms,
            latency_ms,
        });
    }

    samples.sort_by(|left, right| {
        left.created_at_ms
            .cmp(&right.created_at_ms)
            .then_with(|| left.origin_name.cmp(&right.origin_name))
            .then_with(|| left.origin_seq.cmp(&right.origin_seq))
            .then_with(|| left.event_id_hex.cmp(&right.event_id_hex))
    });
    for (index, sample) in samples.iter_mut().enumerate() {
        sample.sent_order = index + 1;
    }

    assert_eq!(samples.len(), expected_samples);
    samples
}

fn collect_delivery_latency_report(samples: &[DeliverySample]) -> DeliveryLatencyReport {
    let mut latencies_ms: Vec<i64> = samples.iter().map(|sample| sample.latency_ms).collect();
    let mut best: Option<DeliveryExtremum> = None;
    let mut worst: Option<DeliveryExtremum> = None;

    for sample in samples {
        let extremum = DeliveryExtremum {
            latency_ms: sample.latency_ms,
            origin_name: sample.origin_name.clone(),
            sink_name: sample.sink_name.clone(),
            event_id_hex: sample.event_id_hex.clone(),
        };
        if best
            .as_ref()
            .map(|current| extremum.latency_ms < current.latency_ms)
            .unwrap_or(true)
        {
            best = Some(extremum.clone());
        }
        if worst
            .as_ref()
            .map(|current| extremum.latency_ms > current.latency_ms)
            .unwrap_or(true)
        {
            worst = Some(extremum);
        }
    }

    latencies_ms.sort_unstable();
    let total_ms: i64 = latencies_ms.iter().sum();
    DeliveryLatencyReport {
        sample_count: latencies_ms.len(),
        avg_ms: total_ms as f64 / latencies_ms.len() as f64,
        p50_ms: percentile(&latencies_ms, 0.50),
        p95_ms: percentile(&latencies_ms, 0.95),
        best: best.expect("at least one delivery sample"),
        worst: worst.expect("at least one delivery sample"),
    }
}

fn build_delivery_windows(
    samples: &[DeliverySample],
    window_count: usize,
) -> Vec<DeliveryWindowReport> {
    assert!(!samples.is_empty(), "need at least one delivery sample");
    let window_count = window_count.max(1).min(samples.len());
    let chunk_size = samples.len().div_ceil(window_count);
    let base_created_at_ms = samples[0].created_at_ms;
    let mut reports = Vec::new();

    for chunk in samples.chunks(chunk_size) {
        let mut latencies_ms: Vec<i64> = chunk.iter().map(|sample| sample.latency_ms).collect();
        latencies_ms.sort_unstable();
        let total_ms: i64 = latencies_ms.iter().sum();
        reports.push(DeliveryWindowReport {
            start_order: chunk.first().expect("non-empty chunk").sent_order,
            end_order: chunk.last().expect("non-empty chunk").sent_order,
            start_elapsed_secs: (chunk.first().expect("non-empty chunk").created_at_ms
                - base_created_at_ms) as f64
                / 1000.0,
            end_elapsed_secs: (chunk.last().expect("non-empty chunk").created_at_ms
                - base_created_at_ms) as f64
                / 1000.0,
            avg_ms: total_ms as f64 / latencies_ms.len() as f64,
            p50_ms: percentile(&latencies_ms, 0.50),
            p95_ms: percentile(&latencies_ms, 0.95),
            best_ms: *latencies_ms.first().expect("non-empty latencies"),
            worst_ms: *latencies_ms.last().expect("non-empty latencies"),
        });
    }

    reports
}

fn emit_window_table(summary: &mut String, windows: &[DeliveryWindowReport]) {
    summary.push_str("  Progress windows:\n");
    for window in windows {
        summary.push_str(&format!(
            "    sent {:>5}-{:>5}  t={:>5.1}-{:>5.1}s  avg={:>7.1}  p50={:>7.1}  p95={:>7.1}  best={:>4}  worst={:>4}\n",
            window.start_order,
            window.end_order,
            window.start_elapsed_secs,
            window.end_elapsed_secs,
            window.avg_ms,
            window.p50_ms,
            window.p95_ms,
            window.best_ms,
            window.worst_ms,
        ));
    }
}

fn emit_progress_csv(path_name: &str, samples: &[DeliverySample]) {
    let output_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/perf-results");
    std::fs::create_dir_all(&output_dir).expect("create target/perf-results");
    let mut csv =
        String::from("sent_order,created_at_ms,latency_ms,origin_name,sink_name,event_id_hex\n");
    for sample in samples {
        csv.push_str(&format!(
            "{},{},{},{},{},{}\n",
            sample.sent_order,
            sample.created_at_ms,
            sample.latency_ms,
            sample.origin_name,
            sample.sink_name,
            sample.event_id_hex
        ));
    }
    std::fs::write(output_dir.join(path_name), csv).expect("write latency csv");
}

fn stage_delta(start: Option<i64>, end: Option<i64>) -> Option<i64> {
    Some(end?.saturating_sub(start?))
}

fn summarize_stage(label: &'static str, values: Vec<i64>) -> StageTimingSummary {
    let mut sorted = values;
    sorted.sort_unstable();
    let total_ms: i64 = sorted.iter().sum();
    StageTimingSummary {
        label,
        count: sorted.len(),
        avg_ms: total_ms as f64 / sorted.len() as f64,
        p95_ms: percentile(&sorted, 0.95),
        worst_ms: *sorted.last().expect("non-empty stage values"),
    }
}

fn fmt_csv_opt(value: Option<i64>) -> String {
    value.map(|v| v.to_string()).unwrap_or_default()
}

fn row_ts<F>(row: &Option<EventTimelineRow>, f: F) -> Option<i64>
where
    F: Fn(&EventTimelineRow) -> Option<i64>,
{
    row.as_ref().and_then(f)
}

fn collect_stage_report(peers: &[Peer], samples: &[DeliverySample]) -> DeliveryStageReport {
    let mut created_to_need_sent = Vec::new();
    let mut need_transit = Vec::new();
    let mut need_recv_to_wanted = Vec::new();
    let mut wanted_to_credit = Vec::new();
    let mut credit_to_request_selected = Vec::new();
    let mut wanted_to_request_selected = Vec::new();
    let mut selected_to_request_sent = Vec::new();
    let mut request_transit = Vec::new();
    let mut request_recv_to_response_sent = Vec::new();
    let mut response_transit = Vec::new();
    let mut response_recv_to_persisted = Vec::new();
    let mut persisted_to_projected = Vec::new();
    let mut stage_samples = Vec::with_capacity(samples.len());

    for sample in samples {
        let origin = peers
            .iter()
            .find(|peer| peer.name == sample.origin_name)
            .unwrap_or_else(|| panic!("missing origin peer {}", sample.origin_name));
        let sink = peers
            .iter()
            .find(|peer| peer.name == sample.sink_name)
            .unwrap_or_else(|| panic!("missing sink peer {}", sample.sink_name));
        let origin_row = lookup_timeline_row(origin, &sample.event_id_b64);
        let sink_row = lookup_timeline_row(sink, &sample.event_id_b64);
        let origin_summary = timeline_summary(origin, &sample.event_id_b64);
        let sink_summary = timeline_summary(sink, &sample.event_id_b64);

        let created_to_need_sent_ms = stage_delta(
            Some(sample.created_at_ms),
            row_ts(&origin_row, |row| row.need_list_sent_at),
        );
        let need_transit_ms = stage_delta(
            row_ts(&origin_row, |row| row.need_list_sent_at),
            row_ts(&sink_row, |row| row.need_list_received_at),
        );
        let need_recv_to_wanted_ms = stage_delta(
            row_ts(&sink_row, |row| row.need_list_received_at),
            row_ts(&sink_row, |row| row.wanted_discovered_at),
        );
        let wanted_to_credit_ms = stage_delta(
            row_ts(&sink_row, |row| row.wanted_discovered_at),
            row_ts(&sink_row, |row| row.request_credit_received_at),
        );
        let credit_to_request_selected_ms = stage_delta(
            row_ts(&sink_row, |row| row.request_credit_received_at),
            row_ts(&sink_row, |row| row.request_selected_at),
        );
        let wanted_to_request_selected_ms = stage_delta(
            row_ts(&sink_row, |row| row.wanted_discovered_at),
            row_ts(&sink_row, |row| row.request_selected_at),
        );
        let selected_to_request_sent_ms = stage_delta(
            row_ts(&sink_row, |row| row.request_selected_at),
            row_ts(&sink_row, |row| row.request_sent_at),
        );
        let request_transit_ms = stage_delta(
            row_ts(&sink_row, |row| row.request_sent_at),
            row_ts(&origin_row, |row| row.request_received_at),
        );
        let request_recv_to_response_sent_ms = stage_delta(
            row_ts(&origin_row, |row| row.request_received_at),
            row_ts(&origin_row, |row| row.response_sent_at),
        );
        let response_transit_ms = stage_delta(
            row_ts(&origin_row, |row| row.response_sent_at),
            row_ts(&sink_row, |row| row.response_received_at),
        );
        let response_recv_to_persisted_ms = stage_delta(
            row_ts(&sink_row, |row| row.response_received_at),
            row_ts(&sink_row, |row| row.persisted_at),
        );
        let persisted_to_projected_ms = stage_delta(
            row_ts(&sink_row, |row| row.persisted_at),
            row_ts(&sink_row, |row| row.projected_at),
        );

        for (bucket, value) in [
            (&mut created_to_need_sent, created_to_need_sent_ms),
            (&mut need_transit, need_transit_ms),
            (&mut need_recv_to_wanted, need_recv_to_wanted_ms),
            (&mut wanted_to_credit, wanted_to_credit_ms),
            (
                &mut credit_to_request_selected,
                credit_to_request_selected_ms,
            ),
            (
                &mut wanted_to_request_selected,
                wanted_to_request_selected_ms,
            ),
            (&mut selected_to_request_sent, selected_to_request_sent_ms),
            (&mut request_transit, request_transit_ms),
            (
                &mut request_recv_to_response_sent,
                request_recv_to_response_sent_ms,
            ),
            (&mut response_transit, response_transit_ms),
            (
                &mut response_recv_to_persisted,
                response_recv_to_persisted_ms,
            ),
            (&mut persisted_to_projected, persisted_to_projected_ms),
        ] {
            if let Some(ms) = value {
                bucket.push(ms);
            }
        }

        stage_samples.push(StageTimingSample {
            sample: sample.clone(),
            origin_row,
            sink_row,
            created_to_need_sent_ms,
            need_transit_ms,
            need_recv_to_wanted_ms,
            wanted_to_credit_ms,
            credit_to_request_selected_ms,
            wanted_to_request_selected_ms,
            selected_to_request_sent_ms,
            request_transit_ms,
            request_recv_to_response_sent_ms,
            response_transit_ms,
            response_recv_to_persisted_ms,
            persisted_to_projected_ms,
            origin_timeline: origin_summary,
            sink_timeline: sink_summary,
        });
    }

    stage_samples.sort_by_key(|sample| sample.sample.latency_ms);
    let worst_sample = stage_samples
        .last()
        .expect("need at least one stage timing sample")
        .clone();

    let stage_specs = [
        ("create_to_need_sent_ms", created_to_need_sent),
        ("need_transit_ms", need_transit),
        ("need_recv_to_wanted_ms", need_recv_to_wanted),
        ("wanted_to_credit_ms", wanted_to_credit),
        ("credit_to_request_selected_ms", credit_to_request_selected),
        ("wanted_to_request_selected_ms", wanted_to_request_selected),
        ("selected_to_request_sent_ms", selected_to_request_sent),
        ("request_transit_ms", request_transit),
        (
            "request_recv_to_response_sent_ms",
            request_recv_to_response_sent,
        ),
        ("response_transit_ms", response_transit),
        ("response_recv_to_persisted_ms", response_recv_to_persisted),
        ("persisted_to_projected_ms", persisted_to_projected),
    ];
    let summaries = stage_specs
        .into_iter()
        .filter_map(|(label, values)| (!values.is_empty()).then(|| summarize_stage(label, values)))
        .collect();

    DeliveryStageReport {
        summaries,
        samples: stage_samples,
        worst_sample,
    }
}

fn emit_stage_csv(path_name: &str, report: &DeliveryStageReport) {
    let output_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/perf-results");
    std::fs::create_dir_all(&output_dir).expect("create target/perf-results");
    let mut csv = String::from(
        "sent_order,origin_seq,origin_name,sink_name,event_id_b64,event_id_hex,created_at_ms,latency_ms,\
origin_need_list_sent_at,sink_need_list_received_at,sink_wanted_discovered_at,sink_request_credit_received_at,\
sink_request_selected_at,sink_request_sent_at,origin_request_received_at,origin_response_sent_at,\
sink_response_received_at,sink_persisted_at,sink_projected_at,\
created_to_need_sent_ms,need_transit_ms,need_recv_to_wanted_ms,wanted_to_credit_ms,credit_to_request_selected_ms,\
wanted_to_request_selected_ms,selected_to_request_sent_ms,request_transit_ms,request_recv_to_response_sent_ms,\
response_transit_ms,response_recv_to_persisted_ms,persisted_to_projected_ms\n",
    );
    for sample in &report.samples {
        let row = [
            sample.sample.sent_order.to_string(),
            sample.sample.origin_seq.to_string(),
            sample.sample.origin_name.clone(),
            sample.sample.sink_name.clone(),
            sample.sample.event_id_b64.clone(),
            sample.sample.event_id_hex.clone(),
            sample.sample.created_at_ms.to_string(),
            sample.sample.latency_ms.to_string(),
            fmt_csv_opt(row_ts(&sample.origin_row, |row| row.need_list_sent_at)),
            fmt_csv_opt(row_ts(&sample.sink_row, |row| row.need_list_received_at)),
            fmt_csv_opt(row_ts(&sample.sink_row, |row| row.wanted_discovered_at)),
            fmt_csv_opt(row_ts(&sample.sink_row, |row| {
                row.request_credit_received_at
            })),
            fmt_csv_opt(row_ts(&sample.sink_row, |row| row.request_selected_at)),
            fmt_csv_opt(row_ts(&sample.sink_row, |row| row.request_sent_at)),
            fmt_csv_opt(row_ts(&sample.origin_row, |row| row.request_received_at)),
            fmt_csv_opt(row_ts(&sample.origin_row, |row| row.response_sent_at)),
            fmt_csv_opt(row_ts(&sample.sink_row, |row| row.response_received_at)),
            fmt_csv_opt(row_ts(&sample.sink_row, |row| row.persisted_at)),
            fmt_csv_opt(row_ts(&sample.sink_row, |row| row.projected_at)),
            fmt_csv_opt(sample.created_to_need_sent_ms),
            fmt_csv_opt(sample.need_transit_ms),
            fmt_csv_opt(sample.need_recv_to_wanted_ms),
            fmt_csv_opt(sample.wanted_to_credit_ms),
            fmt_csv_opt(sample.credit_to_request_selected_ms),
            fmt_csv_opt(sample.wanted_to_request_selected_ms),
            fmt_csv_opt(sample.selected_to_request_sent_ms),
            fmt_csv_opt(sample.request_transit_ms),
            fmt_csv_opt(sample.request_recv_to_response_sent_ms),
            fmt_csv_opt(sample.response_transit_ms),
            fmt_csv_opt(sample.response_recv_to_persisted_ms),
            fmt_csv_opt(sample.persisted_to_projected_ms),
        ];
        csv.push_str(&row.join(","));
        csv.push('\n');
    }
    std::fs::write(output_dir.join(path_name), csv).expect("write stage csv");
}

fn emit_stage_report(summary: &mut String, report: &DeliveryStageReport) {
    summary.push_str("  Stage breakdown avg/p95/worst:\n");
    for stage in &report.summaries {
        summary.push_str(&format!(
            "    {:<30} avg={:>7.1}  p95={:>7.1}  worst={:>4}  n={}\n",
            stage.label, stage.avg_ms, stage.p95_ms, stage.worst_ms, stage.count
        ));
    }
    let worst = &report.worst_sample;
    summary.push_str(&format!(
        "  Worst sample stages:   {} -> {} event={} total={} ms\n",
        worst.sample.origin_name,
        worst.sample.sink_name,
        worst.sample.event_id_hex,
        worst.sample.latency_ms
    ));
    for (label, value) in [
        ("create_to_need_sent_ms", worst.created_to_need_sent_ms),
        ("need_transit_ms", worst.need_transit_ms),
        ("need_recv_to_wanted_ms", worst.need_recv_to_wanted_ms),
        ("wanted_to_credit_ms", worst.wanted_to_credit_ms),
        (
            "credit_to_request_selected_ms",
            worst.credit_to_request_selected_ms,
        ),
        (
            "wanted_to_request_selected_ms",
            worst.wanted_to_request_selected_ms,
        ),
        (
            "selected_to_request_sent_ms",
            worst.selected_to_request_sent_ms,
        ),
        ("request_transit_ms", worst.request_transit_ms),
        (
            "request_recv_to_response_sent_ms",
            worst.request_recv_to_response_sent_ms,
        ),
        ("response_transit_ms", worst.response_transit_ms),
        (
            "response_recv_to_persisted_ms",
            worst.response_recv_to_persisted_ms,
        ),
        ("persisted_to_projected_ms", worst.persisted_to_projected_ms),
    ] {
        summary.push_str(&format!(
            "    {:<30} {}\n",
            label,
            value
                .map(|ms| ms.to_string())
                .unwrap_or_else(|| "-".to_string())
        ));
    }
    if let Some(origin_summary) = &worst.origin_timeline {
        summary.push_str(&format!("  Worst source timeline: {origin_summary}\n"));
    }
    if let Some(sink_summary) = &worst.sink_timeline {
        summary.push_str(&format!("  Worst sink timeline:   {sink_summary}\n"));
    }
}

fn emit_summary(
    title: &str,
    summary_path_name: &str,
    preload_messages: usize,
    messages_per_sec: usize,
    live_seconds: usize,
    total_live_messages: usize,
    wall_secs: f64,
    latency: &DeliveryLatencyReport,
    windows: &[DeliveryWindowReport],
    stage_report: Option<&DeliveryStageReport>,
) {
    let mut summary = String::new();
    summary.push_str(&format!("=== {title} ===\n"));
    summary.push_str("  Peers:                2\n");
    summary.push_str(&format!("  Preload messages:     {preload_messages}\n"));
    summary.push_str(&format!(
        "  Live rate per peer:   {messages_per_sec} msg/s\n"
    ));
    summary.push_str(&format!("  Live duration:        {live_seconds}s\n"));
    summary.push_str(&format!("  Live messages sent:   {total_live_messages}\n"));
    summary.push_str(&format!(
        "  Remote deliveries:    {}\n",
        latency.sample_count
    ));
    summary.push_str(&format!("  Wall time:            {wall_secs:.2}s\n"));
    summary.push_str(&format!(
        "  Delivery best case:   {} ms ({} -> {} event={})\n",
        latency.best.latency_ms,
        latency.best.origin_name,
        latency.best.sink_name,
        latency.best.event_id_hex
    ));
    summary.push_str(&format!(
        "  Delivery worst case:  {} ms ({} -> {} event={})\n",
        latency.worst.latency_ms,
        latency.worst.origin_name,
        latency.worst.sink_name,
        latency.worst.event_id_hex
    ));
    summary.push_str(&format!(
        "  Delivery avg:         {:.1} ms\n",
        latency.avg_ms
    ));
    summary.push_str(&format!(
        "  Delivery p50:         {:.1} ms\n",
        latency.p50_ms
    ));
    summary.push_str(&format!(
        "  Delivery p95:         {:.1} ms\n",
        latency.p95_ms
    ));
    if let Some(stage_report) = stage_report {
        emit_stage_report(&mut summary, stage_report);
    }
    emit_window_table(&mut summary, windows);

    eprintln!("\n{summary}");
    let summary_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/perf-results");
    std::fs::create_dir_all(&summary_dir).expect("create target/perf-results");
    std::fs::write(summary_dir.join(summary_path_name), summary)
        .expect("write benchmark summary file");
}

async fn run_two_peer_latency_benchmark(
    title: &str,
    summary_prefix: &str,
    preload_messages: usize,
    messages_per_sec: usize,
    live_seconds: usize,
    window_count: usize,
) -> (Vec<DeliverySample>, DeliveryLatencyReport) {
    maybe_enable_timeline_recording();
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_in_workspace("bob", &alice).await;
    let peers = vec![alice, bob];
    maybe_settle_after_join();

    let preload_distribution = [
        preload_messages / 2,
        preload_messages - (preload_messages / 2),
    ];
    for (peer, count) in peers.iter().zip(preload_distribution) {
        if count > 0 {
            peer.batch_create_messages(count);
        }
    }

    let sync_handles = start_peers_runtime_affine(&peers[0], &peers[1]);
    maybe_warm_sync();
    assert_eventually(
        || {
            peers
                .iter()
                .all(|peer| peer.message_count() == preload_messages as i64)
        },
        Duration::from_secs(600),
        "two-peer preload message convergence",
    )
    .await;
    warm_two_peer_sync(&peers, preload_messages as i64).await;

    let start = Instant::now();
    let sent_messages = run_live_rate_limited_senders(&peers, messages_per_sec, live_seconds);
    let total_live_messages = sent_messages.len();
    let expected_total = preload_messages as i64 + 2 + total_live_messages as i64;

    assert_eventually(
        || {
            peers
                .iter()
                .all(|peer| peer.message_count() == expected_total)
        },
        Duration::from_secs(600),
        "two-peer live message convergence",
    )
    .await;

    let wall_secs = start.elapsed().as_secs_f64();
    let samples = collect_delivery_samples(&peers, &sent_messages);
    let latency = collect_delivery_latency_report(&samples);
    let windows = build_delivery_windows(&samples, window_count);
    let stage_report = (stage_breakdown_enabled() || stage_csv_enabled())
        .then(|| collect_stage_report(&peers, &samples));
    let run_id = sanitize_run_id(&format!(
        "{summary_prefix}-pre{}-m{}-s{}-w{}",
        preload_messages, messages_per_sec, live_seconds, window_count
    ));
    if let Some(stage_report) = stage_report.as_ref() {
        emit_stage_csv(&format!("{run_id}.stages.csv"), stage_report);
    }

    emit_summary(
        title,
        &format!("{run_id}.summary"),
        preload_messages,
        messages_per_sec,
        live_seconds,
        total_live_messages,
        wall_secs,
        &latency,
        &windows,
        stage_report.as_ref(),
    );
    emit_progress_csv(&format!("{run_id}.csv"), &samples);

    drop(sync_handles);
    (samples, latency)
}

#[tokio::test]
#[ignore]
async fn perf_two_peer_delivery_latency_over_time() {
    maybe_init_tracing();
    let preload_messages = env_usize("TOPO_PERF_PRELOAD_MESSAGES", 0);
    let messages_per_sec = env_usize("TOPO_PERF_MESSAGES_PER_SEC", DEFAULT_MESSAGES_PER_SEC);
    let live_seconds = env_usize("TOPO_PERF_LIVE_SECONDS", DEFAULT_LIVE_SECONDS);
    let window_count = env_usize("TOPO_PERF_PROGRESS_WINDOWS", 10);

    let _ = run_two_peer_latency_benchmark(
        "Two-peer delivery latency over time (in-process peer harness)",
        "two-peer",
        preload_messages,
        messages_per_sec,
        live_seconds,
        window_count,
    )
    .await;
}

#[tokio::test]
#[ignore]
async fn perf_two_peer_delivery_latency_gate() {
    maybe_init_tracing();
    let preload_messages = env_usize("TOPO_PERF_PRELOAD_MESSAGES", 0);
    let messages_per_sec = env_usize("TOPO_PERF_MESSAGES_PER_SEC", TWO_PEER_GATE_MESSAGES_PER_SEC);
    let live_seconds = env_usize("TOPO_PERF_LIVE_SECONDS", 15);
    let window_count = env_usize("TOPO_PERF_PROGRESS_WINDOWS", 6);

    let (_, latency) = run_two_peer_latency_benchmark(
        "Two-peer delivery latency gate (in-process peer harness)",
        "two-peer-gate",
        preload_messages,
        messages_per_sec,
        live_seconds,
        window_count,
    )
    .await;

    assert!(
        latency.worst.latency_ms <= TWO_PEER_GATE_MAX_WORST_MS,
        "delivery latency gate failed: worst {} ms exceeded {} ms at {} msg/s over {}s",
        latency.worst.latency_ms,
        TWO_PEER_GATE_MAX_WORST_MS,
        messages_per_sec,
        live_seconds
    );
}
