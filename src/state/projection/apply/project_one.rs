use super::super::decision::ProjectionDecision;
use crate::crypto::{event_id_to_base64, EventId};
use crate::event_modules::{self as events, ParsedEvent};
use rusqlite::Connection;

use super::cascade::cascade_unblocked;
use super::stages::{record_rejection, run_dep_and_projection_stages};

/// Single-event projection step (no cascade).
///
/// Executes the 7-step projection algorithm for one event:
///   1. Terminal-state check (already valid or rejected → AlreadyProcessed)
///   2. Load blob from events table
///   3. Parse via registry
///   4. Dependency presence check (write block rows if missing)
///   5. Dependency type-code validation
///   6. Signer verification + per-event projector dispatch
///   7. Write valid_events terminal row
///
/// Returns the decision and the parsed event (if available).
///
/// This is an internal helper — it does NOT cascade-unblock dependents.
/// The public entrypoint `project_one` calls this then runs cascade.
/// The Kahn cascade worklist in `cascade_unblocked_inner` also calls this
/// directly to avoid recursive cascade overhead (it manages its own worklist).
pub(crate) fn project_one_step(
    conn: &Connection,
    recorded_by: &str,
    event_id: &EventId,
) -> Result<(ProjectionDecision, Option<ParsedEvent>), Box<dyn std::error::Error>> {
    let event_id_b64 = event_id_to_base64(event_id);

    // 1. Check terminal state — already processed (valid)?
    let already: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![recorded_by, &event_id_b64],
        |row| row.get(0),
    )?;
    if already {
        return Ok((ProjectionDecision::AlreadyProcessed, None));
    }

    // 1b. Check terminal state — already rejected?
    let already_rejected: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM rejected_events WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![recorded_by, &event_id_b64],
        |row| row.get(0),
    )?;
    if already_rejected {
        return Ok((ProjectionDecision::AlreadyProcessed, None));
    }

    // 2. Load blob from events table
    let blob: Vec<u8> = match conn.query_row(
        "SELECT blob FROM events WHERE event_id = ?1",
        rusqlite::params![&event_id_b64],
        |row| row.get(0),
    ) {
        Ok(b) => b,
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            let reason = format!("event {} not found in events table", event_id_b64);
            record_rejection(conn, recorded_by, &event_id_b64, &reason);
            return Ok((ProjectionDecision::Reject { reason }, None));
        }
        Err(e) => return Err(e.into()),
    };

    // 3. Parse via registry
    let parsed = match events::parse_event(&blob) {
        Ok(p) => p,
        Err(e) => {
            let reason = format!("parse error: {}", e);
            record_rejection(conn, recorded_by, &event_id_b64, &reason);
            return Ok((ProjectionDecision::Reject { reason }, None));
        }
    };

    // 4-6. Shared dep/signer/projection stages
    // For encrypted events, inner_parsed contains the decrypted inner event.
    let (decision, inner_parsed) = run_dep_and_projection_stages(
        conn,
        recorded_by,
        &event_id_b64,
        &blob,
        &parsed,
        true, // canonical cleartext flow enforces dep type constraints
    )?;
    match &decision {
        ProjectionDecision::Reject { ref reason } => {
            record_rejection(conn, recorded_by, &event_id_b64, reason);
            return Ok((decision, Some(parsed)));
        }
        ProjectionDecision::Block { ref missing } => {
            // Dependency-stage block rows are written in check_deps_and_block().
            // Projector-level guard blocks (missing == []) rely on emitted commands.
            let _ = missing;
            return Ok((decision, Some(parsed)));
        }
        _ => {}
    }

    // 7. Write terminal state + subscription hook atomically.
    //    Wrapped in a savepoint so that if the subscription hook fails, the
    //    valid_events row is also rolled back. This prevents a crash window
    //    where an event is marked valid but subscriptions never receive it.
    conn.execute_batch("SAVEPOINT project_valid")?;
    let commit_result = (|| -> Result<(), Box<dyn std::error::Error>> {
        conn.execute(
            "INSERT OR IGNORE INTO valid_events (peer_id, event_id) VALUES (?1, ?2)",
            rusqlite::params![recorded_by, &event_id_b64],
        )?;

        // 8. Subscription hook: evaluate active subscriptions for this event.
        //    For encrypted events, use the decrypted inner event for matching.
        let sub_event = inner_parsed.as_ref().unwrap_or(&parsed);
        crate::event_modules::subscription::matcher::on_projected_event(
            conn,
            recorded_by,
            &event_id_b64,
            sub_event,
        )
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

        Ok(())
    })();

    match commit_result {
        Ok(()) => {
            conn.execute_batch("RELEASE project_valid")?;
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK TO project_valid");
            let _ = conn.execute_batch("RELEASE project_valid");
            return Err(e);
        }
    }

    Ok((ProjectionDecision::Valid, Some(parsed)))
}

/// Single canonical projection entrypoint — all ingest paths converge here.
///
/// Given an event_id already stored in the `events` table, this function:
///   1. Runs `project_one_step` (the 7-step single-event algorithm), then
///   2. If the result is Valid, runs `cascade_unblocked` to unblock dependents.
///
/// Callers: `local_create`, `wire_receive` (batch_writer queue drain),
/// `replay`, and guard retries all invoke this function. No alternate
/// projection code path exists for any ingestion source.
///
/// Internal two-layer model: `project_one_step` handles one event without
/// cascade; this function adds cascade orchestration on top. The Kahn
/// cascade worklist calls `project_one_step` directly as an optimization
/// to avoid redundant recursive cascade, while Phase 2 guard retries call
/// back into `project_one` for proper recursive cascade.
pub fn project_one(
    conn: &Connection,
    recorded_by: &str,
    event_id: &EventId,
) -> Result<ProjectionDecision, Box<dyn std::error::Error>> {
    let (decision, parsed) = project_one_step(conn, recorded_by, event_id)?;
    if matches!(decision, ProjectionDecision::Valid) {
        let event_id_b64 = event_id_to_base64(event_id);
        cascade_unblocked(conn, recorded_by, &event_id_b64, parsed.as_ref())?;
    }
    Ok(decision)
}
