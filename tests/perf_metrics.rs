use std::collections::BTreeSet;

use rusqlite::Connection;
use topo::db::open_connection;

#[derive(Debug, Clone, Copy, Default)]
pub struct TimestampWindow {
    pub first_at_ms: Option<i64>,
    pub last_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ProjectionWindow {
    pub recorded_at: TimestampWindow,
    pub projected_at: TimestampWindow,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ShapedNetworkCeiling {
    pub bandwidth_mbps_per_direction: f64,
    pub rtt_ms: u64,
    pub loss_percent: f64,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Default)]
pub struct BandwidthSummary {
    pub payload_bytes: u64,
    pub payload_mib_s: f64,
    pub payload_mbps: f64,
    pub perfect_payload_mbps: Option<f64>,
    pub estimated_quic_ceiling_mbps: Option<f64>,
    pub bandwidth_saturation_pct: Option<f64>,
}

#[derive(Debug, Clone, Copy)]
struct SpanStats {
    avg_ms: f64,
    p50_ms: i64,
    p95_ms: i64,
    max_ms: i64,
}

pub fn enable_projection_timeline() {
    std::env::set_var("TOPO_EVENT_TIMELINE", "1");
    std::env::set_var("TOPO_EVENT_TIMELINE_GROUPS", "projection");
}

#[allow(dead_code)]
pub fn recorded_message_event_ids(db_path: &str, recorded_by: &str) -> BTreeSet<String> {
    let db = open_connection(db_path).expect("open db for recorded message ids");
    let mut stmt = db
        .prepare(
            "SELECT re.event_id
             FROM recorded_events re
             JOIN events e ON e.event_id = re.event_id
             WHERE re.peer_id = ?1
               AND (
                    e.event_type = 'message'
                    OR (
                        e.event_type = 'encrypted'
                        AND substr(e.blob, 42, 1) = ?2
                    )
               )
             ORDER BY re.event_id",
        )
        .expect("prepare recorded message ids query");
    stmt.query_map(
        rusqlite::params![recorded_by, vec![topo::event_modules::EVENT_TYPE_MESSAGE]],
        |row| row.get::<_, String>(0),
    )
    .expect("query recorded message ids")
    .collect::<Result<BTreeSet<_>, _>>()
    .expect("collect recorded message ids")
}

pub fn diff_new_ids(baseline: &BTreeSet<String>, current: &BTreeSet<String>) -> Vec<String> {
    current.difference(baseline).cloned().collect()
}

fn with_temp_target_event_ids<T, F>(
    db_path: &str,
    event_ids_b64: &[String],
    f: F,
) -> rusqlite::Result<T>
where
    F: FnOnce(&Connection) -> rusqlite::Result<T>,
{
    let conn = open_connection(db_path).expect("open db for perf target ids");
    conn.execute_batch(
        "DROP TABLE IF EXISTS temp.perf_target_event_ids;
         CREATE TEMP TABLE perf_target_event_ids (
             event_id TEXT PRIMARY KEY
         );",
    )?;
    {
        let tx = conn.unchecked_transaction()?;
        let mut stmt =
            tx.prepare("INSERT INTO temp.perf_target_event_ids (event_id) VALUES (?1)")?;
        for event_id in event_ids_b64 {
            stmt.execute(rusqlite::params![event_id])?;
        }
        drop(stmt);
        tx.commit()?;
    }

    let result = f(&conn);
    let cleanup = conn.execute_batch("DROP TABLE IF EXISTS temp.perf_target_event_ids");
    match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(err), _) => Err(err),
        (Ok(_), Err(err)) => Err(err),
    }
}

pub fn projection_window(
    db_path: &str,
    recorded_by: &str,
    event_ids_b64: &[String],
) -> ProjectionWindow {
    with_temp_target_event_ids(db_path, event_ids_b64, |conn| {
        let recorded_at = conn.query_row(
            "SELECT MIN(re.recorded_at), MAX(re.recorded_at)
             FROM recorded_events re
             INNER JOIN temp.perf_target_event_ids target
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
             INNER JOIN temp.perf_target_event_ids target
                     ON target.event_id = et.event_id",
            [],
            |row| {
                Ok(TimestampWindow {
                    first_at_ms: row.get(0)?,
                    last_at_ms: row.get(1)?,
                })
            },
        )?;
        Ok(ProjectionWindow {
            recorded_at,
            projected_at,
        })
    })
    .expect("query projection window")
}

pub fn total_event_blob_bytes(db_path: &str, event_ids_b64: &[String]) -> u64 {
    with_temp_target_event_ids(db_path, event_ids_b64, |conn| {
        conn.query_row(
            "SELECT COALESCE(SUM(length(e.blob)), 0)
             FROM events e
             INNER JOIN temp.perf_target_event_ids target
                     ON target.event_id = e.event_id",
            [],
            |row| row.get::<_, u64>(0),
        )
    })
    .expect("query total event blob bytes")
}

pub fn min_opt(lhs: Option<i64>, rhs: Option<i64>) -> Option<i64> {
    match (lhs, rhs) {
        (Some(lhs), Some(rhs)) => Some(lhs.min(rhs)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

pub fn max_opt(lhs: Option<i64>, rhs: Option<i64>) -> Option<i64> {
    match (lhs, rhs) {
        (Some(lhs), Some(rhs)) => Some(lhs.max(rhs)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

pub fn delay_from(start_ms: i64, ts: Option<i64>) -> Option<i64> {
    ts.map(|value| value.saturating_sub(start_ms))
}

pub fn estimated_quic_ceiling_mbps(
    bandwidth_mbps_per_direction: f64,
    rtt_ms: u64,
    loss_percent: f64,
) -> f64 {
    const ASSUMED_WIRE_PAYLOAD_BYTES: f64 = 1_450.0;
    const RECOVERY_PENALTY_RTTS_PER_LOSS: f64 = 5.0;

    if loss_percent.abs() <= f64::EPSILON {
        return bandwidth_mbps_per_direction;
    }

    let loss_fraction = (loss_percent / 100.0).max(0.0);
    let rtt_secs = (rtt_ms.max(1) as f64) / 1_000.0;
    let packets_per_sec =
        (bandwidth_mbps_per_direction * 1_000_000.0 / 8.0) / ASSUMED_WIRE_PAYLOAD_BYTES;
    let expected_losses_per_rtt = packets_per_sec * rtt_secs * loss_fraction;
    let recovery_penalty = 1.0 + RECOVERY_PENALTY_RTTS_PER_LOSS * expected_losses_per_rtt;

    bandwidth_mbps_per_direction / recovery_penalty.max(1.0)
}

pub fn bandwidth_summary(
    payload_bytes: u64,
    wall_secs: f64,
    shaped: Option<ShapedNetworkCeiling>,
) -> BandwidthSummary {
    let payload_mib_s = (payload_bytes as f64) / (1024.0 * 1024.0) / wall_secs.max(0.001);
    let payload_mbps = (payload_bytes as f64) * 8.0 / 1_000_000.0 / wall_secs.max(0.001);

    let (perfect_payload_mbps, estimated_quic_ceiling_mbps, bandwidth_saturation_pct) = match shaped
    {
        Some(profile) if profile.loss_percent.abs() <= f64::EPSILON => {
            let perfect = profile.bandwidth_mbps_per_direction;
            let saturation = payload_mbps / perfect.max(f64::EPSILON) * 100.0;
            (Some(perfect), None, Some(saturation))
        }
        Some(profile) => {
            let ceiling = estimated_quic_ceiling_mbps(
                profile.bandwidth_mbps_per_direction,
                profile.rtt_ms,
                profile.loss_percent,
            );
            let saturation = payload_mbps / ceiling.max(f64::EPSILON) * 100.0;
            (None, Some(ceiling), Some(saturation))
        }
        None => (None, None, None),
    };

    BandwidthSummary {
        payload_bytes,
        payload_mib_s,
        payload_mbps,
        perfect_payload_mbps,
        estimated_quic_ceiling_mbps,
        bandwidth_saturation_pct,
    }
}

fn compute_span_stats(values: &mut Vec<i64>) -> Option<SpanStats> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let len = values.len();
    let p50_ms = values[(len - 1) / 2];
    let p95_ms = values[((len - 1) as f64 * 0.95).floor() as usize];
    let max_ms = *values.last().unwrap_or(&0);
    let avg_ms = values.iter().map(|v| *v as f64).sum::<f64>() / len as f64;
    Some(SpanStats {
        avg_ms,
        p50_ms,
        p95_ms,
        max_ms,
    })
}

fn format_span(label: &str, stats: SpanStats) -> String {
    format!(
        "    {label:<20} avg={:.1}ms p50={}ms p95={}ms max={}ms",
        stats.avg_ms, stats.p50_ms, stats.p95_ms, stats.max_ms
    )
}

pub fn joined_one_way_stage_spans_summary(
    sender_db_path: &str,
    receiver_db_path: &str,
    event_ids_b64: &[String],
) -> Option<String> {
    with_temp_target_event_ids(sender_db_path, event_ids_b64, |conn| {
        conn.execute(
            "ATTACH DATABASE ?1 AS receiver",
            rusqlite::params![receiver_db_path],
        )?;
        let result = (|| -> rusqlite::Result<Option<String>> {
            let mut stmt = conn.prepare(
                "SELECT
                     recv.wanted_discovered_at,
                     recv.request_credit_received_at,
                     recv.request_selected_at,
                     recv.request_sent_at,
                     send.request_received_at,
                     send.response_sent_at,
                     recv.response_received_at,
                     recv.persisted_at,
                     recv.projected_at
                 FROM event_timeline send
                 INNER JOIN receiver.event_timeline recv
                         ON recv.event_id = send.event_id
                 INNER JOIN temp.perf_target_event_ids target
                         ON target.event_id = send.event_id",
            )?;

            let mut wanted_to_credit_ms = Vec::new();
            let mut credit_to_select_ms = Vec::new();
            let mut select_to_send_ms = Vec::new();
            let mut req_transit_ms = Vec::new();
            let mut source_queue_send_ms = Vec::new();
            let mut response_transit_ms = Vec::new();
            let mut receive_to_persist_ms = Vec::new();
            let mut persist_to_project_ms = Vec::new();

            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, Option<i64>>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                ))
            })?;

            for row in rows {
                let (
                    wanted_discovered_at,
                    request_credit_received_at,
                    request_selected_at,
                    request_sent_at,
                    request_received_at,
                    response_sent_at,
                    response_received_at,
                    persisted_at,
                    projected_at,
                ) = row?;

                if let (Some(start), Some(end)) = (wanted_discovered_at, request_credit_received_at)
                {
                    wanted_to_credit_ms.push(end.saturating_sub(start));
                }
                if let (Some(start), Some(end)) = (request_credit_received_at, request_selected_at)
                {
                    credit_to_select_ms.push(end.saturating_sub(start));
                }
                if let (Some(start), Some(end)) = (request_selected_at, request_sent_at) {
                    select_to_send_ms.push(end.saturating_sub(start));
                }
                if let (Some(start), Some(end)) = (request_sent_at, request_received_at) {
                    req_transit_ms.push(end.saturating_sub(start));
                }
                if let (Some(start), Some(end)) = (request_received_at, response_sent_at) {
                    source_queue_send_ms.push(end.saturating_sub(start));
                }
                if let (Some(start), Some(end)) = (response_sent_at, response_received_at) {
                    response_transit_ms.push(end.saturating_sub(start));
                }
                if let (Some(start), Some(end)) = (response_received_at, persisted_at) {
                    receive_to_persist_ms.push(end.saturating_sub(start));
                }
                if let (Some(start), Some(end)) = (persisted_at, projected_at) {
                    persist_to_project_ms.push(end.saturating_sub(start));
                }
            }

            let mut lines = Vec::new();
            if let Some(stats) = compute_span_stats(&mut wanted_to_credit_ms) {
                lines.push(format_span("wanted->credit", stats));
            }
            if let Some(stats) = compute_span_stats(&mut credit_to_select_ms) {
                lines.push(format_span("credit->select", stats));
            }
            if let Some(stats) = compute_span_stats(&mut select_to_send_ms) {
                lines.push(format_span("select->send", stats));
            }
            if let Some(stats) = compute_span_stats(&mut req_transit_ms) {
                lines.push(format_span("request transit", stats));
            }
            if let Some(stats) = compute_span_stats(&mut source_queue_send_ms) {
                lines.push(format_span("source queue/send", stats));
            }
            if let Some(stats) = compute_span_stats(&mut response_transit_ms) {
                lines.push(format_span("response transit", stats));
            }
            if let Some(stats) = compute_span_stats(&mut receive_to_persist_ms) {
                lines.push(format_span("receive->persist", stats));
            }
            if let Some(stats) = compute_span_stats(&mut persist_to_project_ms) {
                lines.push(format_span("persist->project", stats));
            }

            if lines.is_empty() {
                Ok(None)
            } else {
                Ok(Some(format!(
                    "  Joined stage spans:\n{}\n",
                    lines.join("\n")
                )))
            }
        })();
        let _ = conn.execute_batch("DETACH DATABASE receiver");
        result
    })
    .expect("query joined one-way stage spans")
}
