//! Saturating valid-event sender benchmark.
//!
//! Opens one live QUIC session and sends valid message events over the data
//! stream with two sender modes:
//! - open-loop: source pushes blobs as fast as the transport will take them
//! - watermarked: sink drives flow with request and credit hysteresis
//!
//! Both modes bypass discovery and the normal wanted planner so we can isolate
//! how receipt, import, and projection behave once valid events are in flight.

use std::collections::BTreeSet;
use std::error::Error;
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;

use topo::contracts::event_pipeline_contract::IngestItem;
use topo::crypto::{event_id_from_base64, event_id_to_base64, EventId};
use topo::db::{open_connection, receipt_spool, store::Store};
use topo::protocol::{encode_frame, parse_frame, Frame};
use topo::testutil::{create_dynamic_endpoint_for_peer, Peer};
use topo::transport::{
    accept_session_provider, dial_session_provider, multi_workspace::transport_sni, SessionEnvelope,
};
use topo::tuning::{
    response_credit_high_watermark_bytes, response_credit_low_watermark_bytes,
    wanted_high_watermark, wanted_low_watermark, wanted_refill_quantum,
};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const INGEST_CHANNEL_CAP: usize = 10_000;
const SEND_FLUSH_BATCH: usize = 512;

struct ScopedEnv {
    key: &'static str,
    prior: Option<String>,
}

impl ScopedEnv {
    fn set(key: &'static str, value: &str) -> Self {
        let prior = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self { key, prior }
    }
}

impl Drop for ScopedEnv {
    fn drop(&mut self) {
        if let Some(prior) = &self.prior {
            std::env::set_var(self.key, prior);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProjectionMode {
    ReceiptOnly,
    RecordedAndProjected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SenderMode {
    OpenLoop,
    Watermarked,
}

#[derive(Debug)]
struct SaturatingMeasurement {
    first_durable_at_delay_ms: i64,
    all_durable_wall_secs: f64,
    last_durable_at_delay_ms: i64,
    first_recorded_at_delay_ms: Option<i64>,
    all_recorded_wall_secs: Option<f64>,
    last_recorded_at_delay_ms: Option<i64>,
    first_projected_at_delay_ms: Option<i64>,
    all_projected_wall_secs: Option<f64>,
    last_projected_at_delay_ms: Option<i64>,
    messages: usize,
    bytes_sent: u64,
    payload_mib_s: f64,
    payload_mbps: f64,
    durable_msgs_per_sec: f64,
    recorded_msgs_per_sec: Option<f64>,
    projected_msgs_per_sec: Option<f64>,
}

#[derive(Debug, Clone, Copy)]
struct CountWindow {
    all_at_ms: i64,
}

#[derive(Debug, Clone, Copy, Default)]
struct TimestampWindow {
    first_at_ms: Option<i64>,
    last_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Copy, Default)]
struct SyncStageTimestamps {
    recorded_at: TimestampWindow,
    projected_at: TimestampWindow,
}

fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn is_peer_stopped_error(err: &dyn std::fmt::Display) -> bool {
    err.to_string().contains("sending stopped by peer")
}

fn write_summary(summary_key: &str, summary: &str) {
    let summary_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/perf-results");
    std::fs::create_dir_all(&summary_dir).expect("create target/perf-results");
    std::fs::write(summary_dir.join(format!("{summary_key}.summary")), summary)
        .expect("write benchmark summary file");
}

fn emit_summary(summary_key: &str, title: &str, measurement: &SaturatingMeasurement) {
    let mut projection_lines = String::new();
    if let (Some(first), Some(all), Some(last)) = (
        measurement.first_recorded_at_delay_ms,
        measurement.all_recorded_wall_secs,
        measurement.last_recorded_at_delay_ms,
    ) {
        projection_lines.push_str(&format!(
            "  First recorded_at:    {first} ms after send start\n  All recorded_count:   {all:.2}s\n  Last recorded_at:     {last} ms after send start\n"
        ));
    }
    if let (Some(first), Some(all), Some(last)) = (
        measurement.first_projected_at_delay_ms,
        measurement.all_projected_wall_secs,
        measurement.last_projected_at_delay_ms,
    ) {
        projection_lines.push_str(&format!(
            "  First projected_at:   {first} ms after send start\n  All projected_count:  {all:.2}s\n  Last projected_at:    {last} ms after send start\n"
        ));
    }

    let mut throughput_lines = format!(
        "  Durable msgs/s:       {:.0}\n",
        measurement.durable_msgs_per_sec
    );
    if let Some(value) = measurement.recorded_msgs_per_sec {
        throughput_lines.push_str(&format!("  Recorded msgs/s:      {:.0}\n", value));
    }
    if let Some(value) = measurement.projected_msgs_per_sec {
        throughput_lines.push_str(&format!("  Projected msgs/s:     {:.0}\n", value));
    }

    let summary = format!(
        "=== {title} ===\n  First durable_at:     {first_durable} ms after send start\n  All durable_count:    {all_durable:.2}s\n  Last durable_at:      {last_durable} ms after send start\n{projection_lines}  Messages:             {messages}\n{throughput_lines}  Bytes sent:           {bytes_sent}\n  Payload MiB/s:        {payload_mib_s:.2}\n  Payload Mbps:         {payload_mbps:.2}\n",
        title = title,
        first_durable = measurement.first_durable_at_delay_ms,
        all_durable = measurement.all_durable_wall_secs,
        last_durable = measurement.last_durable_at_delay_ms,
        projection_lines = projection_lines,
        messages = measurement.messages,
        throughput_lines = throughput_lines,
        bytes_sent = measurement.bytes_sent,
        payload_mib_s = measurement.payload_mib_s,
        payload_mbps = measurement.payload_mbps,
    );
    eprintln!("\n{summary}");
    write_summary(summary_key, &summary);
}

fn new_message_ids_since(peer: &Peer, baseline: &BTreeSet<String>) -> Vec<EventId> {
    peer.recorded_message_event_ids()
        .difference(baseline)
        .map(|id_b64| {
            event_id_from_base64(id_b64)
                .unwrap_or_else(|| panic!("invalid message event id `{id_b64}`"))
        })
        .collect()
}

fn target_event_ids_b64(event_ids: &[EventId]) -> Vec<String> {
    event_ids.iter().map(event_id_to_base64).collect()
}

fn with_temp_target_event_ids<T, F>(db_path: &str, event_ids_b64: &[String], f: F) -> TestResult<T>
where
    F: FnOnce(&rusqlite::Connection) -> rusqlite::Result<T>,
{
    let conn = open_connection(db_path)?;
    conn.execute_batch(
        "DROP TABLE IF EXISTS temp.raw_saturating_target_event_ids;
         CREATE TEMP TABLE raw_saturating_target_event_ids (
             event_id TEXT PRIMARY KEY
         );",
    )?;
    {
        let tx = conn.unchecked_transaction()?;
        let mut stmt =
            tx.prepare("INSERT INTO temp.raw_saturating_target_event_ids (event_id) VALUES (?1)")?;
        for event_id in event_ids_b64 {
            stmt.execute(rusqlite::params![event_id])?;
        }
        drop(stmt);
        tx.commit()?;
    }

    let result = f(&conn);
    let cleanup = conn.execute_batch("DROP TABLE IF EXISTS temp.raw_saturating_target_event_ids");
    match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(err), _) => Err(Box::new(err)),
        (Ok(_), Err(err)) => Err(Box::new(err)),
    }
}

fn sync_stage_timestamps(
    db_path: &str,
    recorded_by: &str,
    event_ids: &[EventId],
) -> TestResult<SyncStageTimestamps> {
    let event_ids_b64 = target_event_ids_b64(event_ids);
    with_temp_target_event_ids(db_path, &event_ids_b64, |conn| {
        let recorded_at = conn.query_row(
            "SELECT MIN(re.recorded_at), MAX(re.recorded_at)
             FROM recorded_events re
             INNER JOIN temp.raw_saturating_target_event_ids target
                     ON target.event_id = re.event_id
             WHERE re.peer_id = ?1",
            rusqlite::params![recorded_by],
            |row| {
                Ok(TimestampWindow {
                    first_at_ms: row.get(0)?,
                    last_at_ms: row.get(1)?,
                })
            },
        )?;
        let projected_at = conn.query_row(
            "SELECT MIN(et.projected_at), MAX(et.projected_at)
             FROM event_timeline et
             INNER JOIN temp.raw_saturating_target_event_ids target
                     ON target.event_id = et.event_id",
            [],
            |row| {
                Ok(TimestampWindow {
                    first_at_ms: row.get(0)?,
                    last_at_ms: row.get(1)?,
                })
            },
        )?;
        Ok(SyncStageTimestamps {
            recorded_at,
            projected_at,
        })
    })
}

fn recorded_message_count(db_path: &str, recorded_by: &str) -> i64 {
    let db = open_connection(db_path).expect("open db for recorded message count");
    db.query_row(
        "SELECT COUNT(*)
         FROM recorded_events re
         JOIN events e ON e.event_id = re.event_id
         WHERE re.peer_id = ?1
           AND (
                e.event_type = 'message'
                OR (
                    e.event_type = 'encrypted'
                    AND substr(e.blob, 42, 1) = ?2
                )
           )",
        rusqlite::params![recorded_by, vec![topo::event_modules::EVENT_TYPE_MESSAGE]],
        |row| row.get(0),
    )
    .expect("query recorded message count")
}

fn projected_message_count(db_path: &str, recorded_by: &str) -> i64 {
    let db = open_connection(db_path).expect("open db for projected message count");
    db.query_row(
        "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
        |row| row.get(0),
    )
    .expect("query projected message count")
}

fn total_shared_bytes(db_path: &str, event_ids: &[EventId]) -> TestResult<u64> {
    let db = open_connection(db_path)?;
    let store = Store::new(&db);
    let mut total = 0u64;
    for chunk in event_ids.chunks(SEND_FLUSH_BATCH) {
        let blobs = store.get_shared_batch(chunk)?;
        for event_id in chunk {
            if let Some(blob) = blobs.get(event_id) {
                total = total.saturating_add(blob.len() as u64);
            }
        }
    }
    Ok(total)
}

async fn wait_for_receipt_spool_count(
    db_path: &str,
    expected: usize,
    timeout: Duration,
) -> receipt_spool::ReceiptSpoolStats {
    let start = Instant::now();
    loop {
        let stats = receipt_spool::stats_for_db_path(db_path, 0).expect("load receipt stats");
        if stats.count >= expected as i64 {
            return stats;
        }
        assert!(
            start.elapsed() < timeout,
            "receipt spool timed out after {:?}: expected_at_least={}, actual={}",
            timeout,
            expected,
            stats.count
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_count_window<F>(
    baseline: i64,
    expected_delta: i64,
    timeout: Duration,
    label: &str,
    mut current_count: F,
) -> CountWindow
where
    F: FnMut() -> i64,
{
    let start = Instant::now();
    loop {
        let actual = current_count();
        let delta = actual.saturating_sub(baseline);
        if delta >= expected_delta {
            return CountWindow {
                all_at_ms: current_timestamp_ms(),
            };
        }
        assert!(
            start.elapsed() < timeout,
            "{label} timed out after {:?}: baseline={}, expected_delta={}, actual={}, delta={}",
            timeout,
            baseline,
            expected_delta,
            actual,
            delta
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn run_source_session_open_loop(
    alice_db: String,
    session: SessionEnvelope,
    event_ids: Vec<EventId>,
) -> TestResult<u64> {
    let mut parts = session.io.split();
    let db = open_connection(&alice_db)?;
    let store = Store::new(&db);
    let mut sent_bytes = 0u64;

    for chunk in event_ids.chunks(SEND_FLUSH_BATCH) {
        let blobs = store.get_shared_batch(chunk)?;
        for event_id in chunk {
            let Some(blob) = blobs.get(event_id) else {
                continue;
            };
            parts
                .data_send
                .send(&encode_frame(&Frame::Event { blob: blob.clone() }))
                .await?;
            sent_bytes = sent_bytes.saturating_add(blob.len() as u64);
        }
        parts.data_send.flush().await?;
    }

    Ok(sent_bytes)
}

async fn run_source_session_watermarked(
    alice_db: String,
    session: SessionEnvelope,
    expected_ids: Vec<EventId>,
) -> TestResult<u64> {
    use std::collections::VecDeque;

    let mut parts = session.io.split();
    let db = open_connection(&alice_db)?;
    let store = Store::new(&db);
    let mut available_credit_bytes = 0usize;
    let mut pending_ids = VecDeque::new();
    let mut sent_events = 0usize;
    let mut sent_bytes = 0u64;
    let expected_events = expected_ids.len();

    while sent_events < expected_events {
        while !pending_ids.is_empty() && available_credit_bytes > 0 && sent_events < expected_events
        {
            let mut fetch_chunk = Vec::with_capacity(SEND_FLUSH_BATCH);
            while fetch_chunk.len() < SEND_FLUSH_BATCH {
                let Some(event_id) = pending_ids.pop_front() else {
                    break;
                };
                fetch_chunk.push(event_id);
            }
            if fetch_chunk.is_empty() {
                break;
            }

            let blobs = store.get_shared_batch(&fetch_chunk)?;
            let mut sent_any = false;
            let mut iter = fetch_chunk.into_iter();
            while let Some(event_id) = iter.next() {
                let Some(blob) = blobs.get(&event_id) else {
                    continue;
                };
                if blob.len() > available_credit_bytes {
                    let mut unsent = vec![event_id];
                    unsent.extend(iter);
                    for queued in unsent.into_iter().rev() {
                        pending_ids.push_front(queued);
                    }
                    break;
                }
                parts
                    .data_send
                    .send(&encode_frame(&Frame::Event { blob: blob.clone() }))
                    .await?;
                available_credit_bytes = available_credit_bytes.saturating_sub(blob.len());
                sent_events += 1;
                sent_bytes = sent_bytes.saturating_add(blob.len() as u64);
                sent_any = true;
            }

            if sent_any {
                parts.data_send.flush().await?;
            } else {
                break;
            }
        }

        if sent_events >= expected_events {
            break;
        }

        let frame_bytes = parts.control.recv().await?;
        let (frame, consumed) = parse_frame(&frame_bytes)?;
        if consumed != frame_bytes.len() {
            return Err(Box::new(std::io::Error::other(format!(
                "control frame had trailing bytes: consumed={}, total={}",
                consumed,
                frame_bytes.len()
            ))));
        }
        match frame {
            Frame::ResponseCredit { bytes } => {
                available_credit_bytes = available_credit_bytes.saturating_add(bytes as usize);
            }
            Frame::RequestIds { ids } => {
                pending_ids.extend(ids);
            }
            other => {
                return Err(Box::new(std::io::Error::other(format!(
                    "unexpected control frame on source: {other:?}"
                ))));
            }
        }
    }

    Ok(sent_bytes)
}

async fn run_sink_session_open_loop(
    bob_identity: String,
    session: SessionEnvelope,
    expected_events: usize,
    ingest_tx: mpsc::Sender<IngestItem>,
) -> TestResult<usize> {
    let mut parts = session.io.split();
    let mut received = 0usize;
    let source_tag = format!("raw_saturating:{}", session.peer_id);

    while received < expected_events {
        let frame_bytes = parts.data_recv.recv().await?;
        let (frame, consumed) = parse_frame(&frame_bytes)?;
        if consumed != frame_bytes.len() {
            return Err(Box::new(std::io::Error::other(format!(
                "data frame had trailing bytes: consumed={}, total={}",
                consumed,
                frame_bytes.len()
            ))));
        }
        match frame {
            Frame::Event { blob } => {
                ingest_tx
                    .send((
                        [0u8; 32],
                        blob,
                        bob_identity.clone(),
                        source_tag.clone(),
                        current_timestamp_ms(),
                    ))
                    .await
                    .map_err(|_| std::io::Error::other("ingest channel closed"))?;
                received += 1;
            }
            other => {
                return Err(Box::new(std::io::Error::other(format!(
                    "unexpected frame on sink data stream: {other:?}"
                ))));
            }
        }
    }

    Ok(received)
}

async fn run_sink_session_watermarked(
    bob_identity: String,
    requested_ids: Vec<EventId>,
    session: SessionEnvelope,
    ingest_tx: mpsc::Sender<IngestItem>,
) -> TestResult<usize> {
    let mut parts = session.io.split();
    let expected_events = requested_ids.len();
    let source_tag = format!("raw_saturating:{}", session.peer_id);
    let credit_high = response_credit_high_watermark_bytes().max(1);
    let credit_low = response_credit_low_watermark_bytes().min(credit_high.saturating_sub(1));
    let wanted_high = wanted_high_watermark().max(1);
    let wanted_low = wanted_low_watermark().min(wanted_high.saturating_sub(1));
    let request_quantum = wanted_refill_quantum().max(1);

    let initial_grant = credit_high.min(u32::MAX as usize) as u32;
    parts
        .control
        .send(&encode_frame(&Frame::ResponseCredit {
            bytes: initial_grant,
        }))
        .await?;

    let mut credit_remaining = initial_grant as usize;
    let mut next_request_index = 0usize;
    let mut outstanding_requests = 0usize;
    while outstanding_requests < wanted_high && next_request_index < requested_ids.len() {
        let available_slots = wanted_high.saturating_sub(outstanding_requests);
        let chunk_len = available_slots
            .min(request_quantum)
            .min(SEND_FLUSH_BATCH)
            .min(requested_ids.len().saturating_sub(next_request_index));
        if chunk_len == 0 {
            break;
        }
        parts
            .control
            .send(&encode_frame(&Frame::RequestIds {
                ids: requested_ids[next_request_index..next_request_index + chunk_len].to_vec(),
            }))
            .await?;
        outstanding_requests += chunk_len;
        next_request_index += chunk_len;
    }
    parts.control.flush().await?;

    let mut received_events = 0usize;
    let mut control_open = true;
    while received_events < expected_events {
        let frame_bytes = parts.data_recv.recv().await?;
        let (frame, consumed) = parse_frame(&frame_bytes)?;
        if consumed != frame_bytes.len() {
            return Err(Box::new(std::io::Error::other(format!(
                "data frame had trailing bytes: consumed={}, total={}",
                consumed,
                frame_bytes.len()
            ))));
        }
        match frame {
            Frame::Event { blob } => {
                let blob_len = blob.len();
                ingest_tx
                    .send((
                        [0u8; 32],
                        blob,
                        bob_identity.clone(),
                        source_tag.clone(),
                        current_timestamp_ms(),
                    ))
                    .await
                    .map_err(|_| std::io::Error::other("ingest channel closed"))?;
                received_events += 1;
                outstanding_requests = outstanding_requests.saturating_sub(1);
                credit_remaining = credit_remaining.saturating_sub(blob_len);

                let mut sent_control = false;
                if control_open
                    && received_events < expected_events
                    && credit_remaining <= credit_low
                {
                    let grant = credit_high
                        .saturating_sub(credit_remaining)
                        .min(u32::MAX as usize);
                    if grant > 0 {
                        match parts
                            .control
                            .send(&encode_frame(&Frame::ResponseCredit {
                                bytes: grant as u32,
                            }))
                            .await
                        {
                            Ok(()) => {
                                credit_remaining = credit_remaining.saturating_add(grant);
                                sent_control = true;
                            }
                            Err(err) if is_peer_stopped_error(&err) => {
                                control_open = false;
                            }
                            Err(err) => return Err(Box::new(err)),
                        }
                    }
                }

                while control_open
                    && outstanding_requests <= wanted_low
                    && next_request_index < requested_ids.len()
                {
                    let available_slots = wanted_high.saturating_sub(outstanding_requests);
                    let chunk_len = available_slots
                        .min(request_quantum)
                        .min(SEND_FLUSH_BATCH)
                        .min(requested_ids.len().saturating_sub(next_request_index));
                    if chunk_len == 0 {
                        break;
                    }
                    match parts
                        .control
                        .send(&encode_frame(&Frame::RequestIds {
                            ids: requested_ids[next_request_index..next_request_index + chunk_len]
                                .to_vec(),
                        }))
                        .await
                    {
                        Ok(()) => {
                            next_request_index += chunk_len;
                            outstanding_requests += chunk_len;
                            sent_control = true;
                        }
                        Err(err) if is_peer_stopped_error(&err) => {
                            control_open = false;
                            break;
                        }
                        Err(err) => return Err(Box::new(err)),
                    }
                }

                if control_open && sent_control {
                    match parts.control.flush().await {
                        Ok(()) => {}
                        Err(err) if is_peer_stopped_error(&err) => {
                            control_open = false;
                        }
                        Err(err) => return Err(Box::new(err)),
                    }
                }
            }
            other => {
                return Err(Box::new(std::io::Error::other(format!(
                    "unexpected frame on sink data stream: {other:?}"
                ))));
            }
        }
    }

    Ok(received_events)
}

async fn run_saturating_valid_event_sync(
    message_count: usize,
    sender_mode: SenderMode,
    projection_mode: ProjectionMode,
    timeout: Duration,
) -> TestResult<SaturatingMeasurement> {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_in_workspace("bob", &alice).await;

    let baseline_ids = alice.recorded_message_event_ids();
    let generate_start = Instant::now();
    alice.batch_create_messages(message_count);
    let _generate_secs = generate_start.elapsed().as_secs_f64();
    let event_ids = new_message_ids_since(&alice, &baseline_ids);
    assert_eq!(event_ids.len(), message_count, "unexpected message delta");
    let expected_events = event_ids.len();
    let bytes_sent = total_shared_bytes(&alice.db_path, &event_ids)?;

    let _import_enabled = ScopedEnv::set(
        "TOPO_RECEIPT_SPOOL_IMPORT_ENABLED",
        match projection_mode {
            ProjectionMode::ReceiptOnly => "0",
            ProjectionMode::RecordedAndProjected => "1",
        },
    );
    let _defer_hash = ScopedEnv::set("TOPO_RECEIPT_SPOOL_DEFER_HASH", "1");
    let _timeline_enabled = match projection_mode {
        ProjectionMode::ReceiptOnly => None,
        ProjectionMode::RecordedAndProjected => Some(ScopedEnv::set("TOPO_EVENT_TIMELINE", "1")),
    };
    let _timeline_groups = match projection_mode {
        ProjectionMode::ReceiptOnly => None,
        ProjectionMode::RecordedAndProjected => {
            Some(ScopedEnv::set("TOPO_EVENT_TIMELINE_GROUPS", "projection"))
        }
    };

    let bob_recorded_baseline = recorded_message_count(&bob.db_path, &bob.identity);
    let bob_projected_baseline = projected_message_count(&bob.db_path, &bob.identity);
    receipt_spool::reset_for_db_path(&bob.db_path)?;

    let (ingest_tx, ingest_rx) = mpsc::channel::<IngestItem>(INGEST_CHANNEL_CAP);
    let writer_events = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let writer_db = bob.db_path.clone();
    let writer_handle = thread::spawn(move || {
        topo::event_pipeline::batch_writer(writer_db, ingest_rx, writer_events);
    });

    let server_endpoint = create_dynamic_endpoint_for_peer(&alice);
    let client_endpoint = create_dynamic_endpoint_for_peer(&bob);
    let server_addr = server_endpoint.local_addr()?;
    let sni = transport_sni(&alice.transport_peer_id());
    let connect_timeout = timeout.min(Duration::from_secs(30));
    let (server_provider, client_provider) = tokio::time::timeout(connect_timeout, async {
        let (server_provider_result, client_provider_result) = tokio::join!(
            accept_session_provider(&server_endpoint),
            dial_session_provider(&client_endpoint, server_addr, &sni, None)
        );
        let server_provider = server_provider_result?.ok_or_else(|| {
            std::io::Error::other("server endpoint closed before accepting session")
        })?;
        let client_provider = client_provider_result?;
        Ok::<_, Box<dyn Error + Send + Sync>>((server_provider, client_provider))
    })
    .await??;

    let (server_session, client_session) = tokio::time::timeout(connect_timeout, async {
        let (server_session_result, client_session_result) = tokio::join!(
            server_provider.next_session(),
            client_provider.next_session()
        );
        let server_session = server_session_result?;
        let client_session = client_session_result?;
        Ok::<_, Box<dyn Error + Send + Sync>>((server_session, client_session))
    })
    .await??;

    let send_start_ms = current_timestamp_ms();
    let expected_delta = expected_events as i64;
    let event_ids_for_timestamps = event_ids.clone();
    let recorded_db = bob.db_path.clone();
    let recorded_by = bob.identity.clone();
    let projected_db = bob.db_path.clone();
    let projected_by = bob.identity.clone();

    let source_db = alice.db_path.clone();
    let source_event_ids = event_ids.clone();
    let source_future = async move {
        match sender_mode {
            SenderMode::OpenLoop => {
                run_source_session_open_loop(source_db, server_session, source_event_ids).await
            }
            SenderMode::Watermarked => {
                run_source_session_watermarked(source_db, server_session, source_event_ids).await
            }
        }
    };
    let sink_identity = bob.identity.clone();
    let sink_requested_ids = event_ids.clone();
    let sink_future = async move {
        match sender_mode {
            SenderMode::OpenLoop => {
                run_sink_session_open_loop(
                    sink_identity,
                    client_session,
                    expected_events,
                    ingest_tx,
                )
                .await
            }
            SenderMode::Watermarked => {
                run_sink_session_watermarked(
                    sink_identity,
                    sink_requested_ids,
                    client_session,
                    ingest_tx,
                )
                .await
            }
        }
    };
    let durable_wait = async {
        let stats = wait_for_receipt_spool_count(&bob.db_path, expected_events, timeout).await;
        (stats, current_timestamp_ms())
    };
    let recorded_wait = async move {
        match projection_mode {
            ProjectionMode::ReceiptOnly => None,
            ProjectionMode::RecordedAndProjected => Some(
                wait_for_count_window(
                    bob_recorded_baseline,
                    expected_delta,
                    timeout,
                    "recorded message count",
                    || recorded_message_count(&recorded_db, &recorded_by),
                )
                .await,
            ),
        }
    };
    let projected_wait = async move {
        match projection_mode {
            ProjectionMode::ReceiptOnly => None,
            ProjectionMode::RecordedAndProjected => Some(
                wait_for_count_window(
                    bob_projected_baseline,
                    expected_delta,
                    timeout,
                    "projected message count",
                    || projected_message_count(&projected_db, &projected_by),
                )
                .await,
            ),
        }
    };

    let (source_result, sink_result, durable_outcome, recorded_window, projected_window) =
        tokio::time::timeout(timeout, async {
            tokio::join!(
                source_future,
                sink_future,
                durable_wait,
                recorded_wait,
                projected_wait
            )
        })
        .await
        .map_err(|_| {
            std::io::Error::other(format!(
                "saturating valid-event sync timed out after {timeout:?}"
            ))
        })?;

    let sent_bytes = source_result?;
    let received = sink_result?;
    assert_eq!(sent_bytes, bytes_sent, "source sent unexpected byte count");
    assert_eq!(
        received, expected_events,
        "sink received unexpected event count"
    );

    if let Err(err) = writer_handle.join() {
        return Err(Box::new(std::io::Error::other(format!(
            "writer thread panicked: {err:?}"
        ))));
    }

    let (durable_stats, all_durable_at_ms) = durable_outcome;
    let all_durable_wall_secs = (all_durable_at_ms.saturating_sub(send_start_ms) as f64) / 1000.0;
    let first_durable_at_ms = durable_stats
        .first_durable_at_ms
        .expect("missing first durable timestamp");
    let last_durable_at_ms = durable_stats
        .last_durable_at_ms
        .expect("missing last durable timestamp");
    let first_durable_at_delay_ms = first_durable_at_ms.saturating_sub(send_start_ms);
    let last_durable_at_delay_ms = last_durable_at_ms.saturating_sub(send_start_ms);

    let all_recorded_wall_secs = recorded_window
        .as_ref()
        .map(|window| (window.all_at_ms.saturating_sub(send_start_ms) as f64) / 1000.0);
    let all_projected_wall_secs = projected_window
        .as_ref()
        .map(|window| (window.all_at_ms.saturating_sub(send_start_ms) as f64) / 1000.0);

    let stage_timestamps = match projection_mode {
        ProjectionMode::ReceiptOnly => None,
        ProjectionMode::RecordedAndProjected => Some(sync_stage_timestamps(
            &bob.db_path,
            &bob.identity,
            &event_ids_for_timestamps,
        )?),
    };

    let first_recorded_at_delay_ms = stage_timestamps
        .as_ref()
        .and_then(|stages| stages.recorded_at.first_at_ms)
        .map(|ts| ts.saturating_sub(send_start_ms));
    let last_recorded_at_delay_ms = stage_timestamps
        .as_ref()
        .and_then(|stages| stages.recorded_at.last_at_ms)
        .map(|ts| ts.saturating_sub(send_start_ms));
    let first_projected_at_delay_ms = stage_timestamps
        .as_ref()
        .and_then(|stages| stages.projected_at.first_at_ms)
        .map(|ts| ts.saturating_sub(send_start_ms));
    let last_projected_at_delay_ms = stage_timestamps
        .as_ref()
        .and_then(|stages| stages.projected_at.last_at_ms)
        .map(|ts| ts.saturating_sub(send_start_ms));

    let durable_msgs_per_sec = expected_events as f64 / all_durable_wall_secs.max(0.001);
    let recorded_msgs_per_sec =
        all_recorded_wall_secs.map(|secs| expected_events as f64 / secs.max(0.001));
    let projected_msgs_per_sec =
        all_projected_wall_secs.map(|secs| expected_events as f64 / secs.max(0.001));
    let payload_mib_s = (sent_bytes as f64 / (1024.0 * 1024.0)) / all_durable_wall_secs.max(0.001);
    let payload_mbps = (sent_bytes as f64 * 8.0 / 1_000_000.0) / all_durable_wall_secs.max(0.001);

    Ok(SaturatingMeasurement {
        first_durable_at_delay_ms,
        all_durable_wall_secs,
        last_durable_at_delay_ms,
        first_recorded_at_delay_ms,
        all_recorded_wall_secs,
        last_recorded_at_delay_ms,
        first_projected_at_delay_ms,
        all_projected_wall_secs,
        last_projected_at_delay_ms,
        messages: expected_events,
        bytes_sent: sent_bytes,
        payload_mib_s,
        payload_mbps,
        durable_msgs_per_sec,
        recorded_msgs_per_sec,
        projected_msgs_per_sec,
    })
}

fn run_bench(
    summary_key: &str,
    title: &str,
    message_count: usize,
    sender_mode: SenderMode,
    projection_mode: ProjectionMode,
    timeout: Duration,
) {
    let runtime = tokio::runtime::Runtime::new().expect("create runtime");
    let measurement = runtime
        .block_on(run_saturating_valid_event_sync(
            message_count,
            sender_mode,
            projection_mode,
            timeout,
        ))
        .expect("run saturating valid-event sync");
    emit_summary(summary_key, title, &measurement);
}

#[test]
fn perf_saturating_valid_events_10k_receipt_only() {
    run_bench(
        "raw_saturating_valid_events_perf_test.perf_saturating_valid_events_10k_receipt_only",
        "10k saturating valid events (receipt only)",
        10_000,
        SenderMode::OpenLoop,
        ProjectionMode::ReceiptOnly,
        Duration::from_secs(180),
    );
}

#[test]
fn perf_saturating_valid_events_10k_projected() {
    run_bench(
        "raw_saturating_valid_events_perf_test.perf_saturating_valid_events_10k_projected",
        "10k saturating valid events (recorded + projected)",
        10_000,
        SenderMode::OpenLoop,
        ProjectionMode::RecordedAndProjected,
        Duration::from_secs(180),
    );
}

#[test]
fn perf_saturating_valid_events_10k_receipt_only_watermarked() {
    run_bench(
        "raw_saturating_valid_events_perf_test.perf_saturating_valid_events_10k_receipt_only_watermarked",
        "10k saturating valid events (receipt only, watermarked sender)",
        10_000,
        SenderMode::Watermarked,
        ProjectionMode::ReceiptOnly,
        Duration::from_secs(180),
    );
}

#[test]
fn perf_saturating_valid_events_10k_projected_watermarked() {
    run_bench(
        "raw_saturating_valid_events_perf_test.perf_saturating_valid_events_10k_projected_watermarked",
        "10k saturating valid events (recorded + projected, watermarked sender)",
        10_000,
        SenderMode::Watermarked,
        ProjectionMode::RecordedAndProjected,
        Duration::from_secs(180),
    );
}

#[test]
#[ignore]
fn perf_saturating_valid_events_50k_receipt_only() {
    run_bench(
        "raw_saturating_valid_events_perf_test.perf_saturating_valid_events_50k_receipt_only",
        "50k saturating valid events (receipt only)",
        50_000,
        SenderMode::OpenLoop,
        ProjectionMode::ReceiptOnly,
        Duration::from_secs(600),
    );
}

#[test]
#[ignore]
fn perf_saturating_valid_events_50k_projected() {
    run_bench(
        "raw_saturating_valid_events_perf_test.perf_saturating_valid_events_50k_projected",
        "50k saturating valid events (recorded + projected)",
        50_000,
        SenderMode::OpenLoop,
        ProjectionMode::RecordedAndProjected,
        Duration::from_secs(600),
    );
}

#[test]
#[ignore]
fn perf_saturating_valid_events_50k_receipt_only_watermarked() {
    run_bench(
        "raw_saturating_valid_events_perf_test.perf_saturating_valid_events_50k_receipt_only_watermarked",
        "50k saturating valid events (receipt only, watermarked sender)",
        50_000,
        SenderMode::Watermarked,
        ProjectionMode::ReceiptOnly,
        Duration::from_secs(600),
    );
}

#[test]
#[ignore]
fn perf_saturating_valid_events_50k_projected_watermarked() {
    run_bench(
        "raw_saturating_valid_events_perf_test.perf_saturating_valid_events_50k_projected_watermarked",
        "50k saturating valid events (recorded + projected, watermarked sender)",
        50_000,
        SenderMode::Watermarked,
        ProjectionMode::RecordedAndProjected,
        Duration::from_secs(600),
    );
}
