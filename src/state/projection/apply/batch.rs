//! Batch projection: projects multiple events in fewer DB round-trips.
//!
//! Batches the infrastructure around pure projectors:
//! - Blob reads: 1 batch query instead of N individual reads
//! - Terminal state checks: 1 batch query instead of N
//! - valid_events + subscription hooks: 1 savepoint instead of N autocommits
//! - Cascade-unblock: runs once at the end of the batch

use std::collections::HashSet;

use rusqlite::Connection;

use crate::crypto::{event_id_from_base64, EventId};
use crate::db::queue::current_timestamp_ms;
use crate::db::timeline::EventTimeline;
use crate::event_modules::{self as events, ParsedEvent};
use crate::state::projection::decision::ProjectionDecision;

use super::cascade::cascade_unblocked;
use super::project_one::project_one;
use super::stages::{record_rejection, run_dep_and_projection_stages};

/// Batch-project a set of events. Returns the number successfully processed.
///
/// Strategy:
/// 1. Batch-check terminal state (already valid/rejected)
/// 2. Batch-read blobs
/// 3. Parse all, reject unparseable
/// 4. For each: run dep/projection stages (writes ops immediately)
/// 5. Batch-insert valid_events + subscription hooks in one savepoint
/// 6. Cascade-unblock all newly valid events
pub fn project_batch(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64s: &[String],
) -> Result<usize, Box<dyn std::error::Error>> {
    if event_id_b64s.is_empty() {
        return Ok(0);
    }

    // 1. Batch-check terminal state
    let already_processed = batch_check_terminal(conn, recorded_by, event_id_b64s)?;
    let pending: Vec<&str> = event_id_b64s
        .iter()
        .filter(|id| !already_processed.contains(id.as_str()))
        .map(String::as_str)
        .collect();

    if pending.is_empty() {
        return Ok(already_processed.len());
    }

    // 2. Batch-read blobs
    let blobs = batch_read_blobs(conn, &pending)?;

    // 3. Parse all blobs
    struct PreparedEvent<'a> {
        event_id_b64: &'a str,
        event_id: EventId,
        blob: Vec<u8>,
        parsed: ParsedEvent,
    }

    let mut prepared = Vec::with_capacity(pending.len());
    let mut terminal_count = already_processed.len();

    for &eid_b64 in &pending {
        let Some(event_id) = event_id_from_base64(eid_b64) else {
            continue;
        };
        let Some(blob) = blobs.get(eid_b64).cloned() else {
            record_rejection(conn, recorded_by, eid_b64, "event not found in events table");
            terminal_count += 1;
            continue;
        };
        match events::parse_event(&blob) {
            Ok(parsed) => {
                prepared.push(PreparedEvent {
                    event_id_b64: eid_b64,
                    event_id,
                    blob,
                    parsed,
                });
            }
            Err(e) => {
                let reason = format!("parse error: {}", e);
                record_rejection(conn, recorded_by, eid_b64, &reason);
                terminal_count += 1;
            }
        }
    }

    // 4. Run dep/projection stages for each event.
    //    WriteOps are executed immediately by run_dep_and_projection_stages.
    //    We collect the valid events for batched valid_events insert.
    struct ValidEvent<'a> {
        event_id_b64: &'a str,
        #[allow(dead_code)]
        event_id: EventId,
        parsed: &'a ParsedEvent,
        inner_parsed: Option<ParsedEvent>,
        semantic_type_code: i64,
    }

    let mut valid_events: Vec<ValidEvent> = Vec::new();

    for ev in &prepared {
        // Encrypted events fall back to project_one (they recurse internally)
        if matches!(ev.parsed, ParsedEvent::Encrypted(_)) {
            let _ = project_one(conn, recorded_by, &ev.event_id);
            terminal_count += 1;
            continue;
        }

        let (decision, inner_parsed) = run_dep_and_projection_stages(
            conn,
            recorded_by,
            ev.event_id_b64,
            &ev.blob,
            &ev.parsed,
            false,
            true,
            None,
        )?;

        match decision {
            ProjectionDecision::Valid => {
                let sub_event = inner_parsed.as_ref().unwrap_or(&ev.parsed);
                let semantic_type_code = i64::from(sub_event.event_type_code());
                valid_events.push(ValidEvent {
                    event_id_b64: ev.event_id_b64,
                    event_id: ev.event_id,
                    parsed: &ev.parsed,
                    inner_parsed,
                    semantic_type_code,
                });
            }
            ProjectionDecision::Reject { ref reason } => {
                record_rejection(conn, recorded_by, ev.event_id_b64, reason);
                terminal_count += 1;
            }
            ProjectionDecision::Block { .. } => {
                let _ = EventTimeline::new(conn)
                    .mark_blocked_b64(ev.event_id_b64, current_timestamp_ms());
            }
            ProjectionDecision::AlreadyProcessed => {
                terminal_count += 1;
            }
        }
    }

    // 5. Batch-insert valid_events + subscription hooks in one savepoint
    if !valid_events.is_empty() {
        conn.execute_batch("SAVEPOINT batch_valid")?;
        let commit_result = (|| -> Result<(), Box<dyn std::error::Error>> {
            let mut stmt = conn.prepare(
                "INSERT OR IGNORE INTO valid_events (peer_id, event_id, semantic_type_code)
                 VALUES (?1, ?2, ?3)",
            )?;
            for ve in &valid_events {
                stmt.execute(rusqlite::params![
                    recorded_by,
                    ve.event_id_b64,
                    ve.semantic_type_code
                ])?;
                let sub_event = ve.inner_parsed.as_ref().unwrap_or(ve.parsed);
                crate::state::subscriptions::on_projected_event(
                    conn,
                    recorded_by,
                    ve.event_id_b64,
                    sub_event,
                )?;
            }
            let now = current_timestamp_ms();
            let timeline = EventTimeline::new(conn);
            for ve in &valid_events {
                let _ = timeline.mark_projected_b64(ve.event_id_b64, now);
            }
            Ok(())
        })();
        match commit_result {
            Ok(()) => conn.execute_batch("RELEASE batch_valid")?,
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK TO batch_valid");
                let _ = conn.execute_batch("RELEASE batch_valid");
                return Err(e);
            }
        }
    }

    // 6. Cascade-unblock for all newly valid events
    for ve in &valid_events {
        cascade_unblocked(conn, recorded_by, ve.event_id_b64, Some(ve.parsed))?;
    }

    terminal_count += valid_events.len();
    Ok(terminal_count)
}

/// Batch-check which event IDs are already in valid_events or rejected_events.
fn batch_check_terminal(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64s: &[String],
) -> Result<HashSet<String>, rusqlite::Error> {
    let mut already = HashSet::new();
    for chunk in event_id_b64s.chunks(900) {
        let placeholders: String = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");

        for table in &["valid_events", "rejected_events"] {
            let sql = format!(
                "SELECT event_id FROM {} WHERE peer_id = ?1 AND event_id IN ({})",
                table, placeholders
            );
            let mut stmt = conn.prepare(&sql)?;
            stmt.raw_bind_parameter(1, recorded_by)?;
            for (i, id) in chunk.iter().enumerate() {
                stmt.raw_bind_parameter(i + 2, id.as_str())?;
            }
            let mut rows = stmt.raw_query();
            while let Some(row) = rows.next()? {
                let id: String = row.get(0)?;
                already.insert(id);
            }
        }
    }
    Ok(already)
}

/// Batch-read blobs from the events table.
fn batch_read_blobs(
    conn: &Connection,
    event_id_b64s: &[&str],
) -> Result<std::collections::HashMap<String, Vec<u8>>, rusqlite::Error> {
    let mut map = std::collections::HashMap::with_capacity(event_id_b64s.len());
    for chunk in event_id_b64s.chunks(900) {
        let placeholders: String = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!(
            "SELECT event_id, blob FROM events WHERE event_id IN ({})",
            placeholders
        );
        let mut stmt = conn.prepare(&sql)?;
        for (i, id) in chunk.iter().enumerate() {
            stmt.raw_bind_parameter(i + 1, *id)?;
        }
        let mut rows = stmt.raw_query();
        while let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            let blob: Vec<u8> = row.get(1)?;
            map.insert(id, blob);
        }
    }
    Ok(map)
}
