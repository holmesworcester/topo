use super::super::decision::ProjectionDecision;
use crate::crypto::event_id_from_base64;
use crate::event_modules::ParsedEvent;
use rusqlite::Connection;

/// After projecting an event, cascade-unblock dependents using Kahn's algorithm.
///
/// Guard retries (InviteAccepted → workspace retries, MessageAttachment →
/// file_slice retries) are now handled by EmitCommand execution in the pure
/// projector apply engine, so this cascade only handles dependency unblocking.
pub(crate) fn cascade_unblocked(
    conn: &Connection,
    recorded_by: &str,
    blocker_b64: &str,
    _initial_parsed: Option<&ParsedEvent>,
) -> Result<(), Box<dyn std::error::Error>> {
    cascade_unblocked_inner(conn, recorded_by, blocker_b64)
}

fn cascade_unblocked_inner(
    conn: &Connection,
    recorded_by: &str,
    blocker_b64: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // --- Kahn's algorithm dep cascade ---
    // blocked_event_deps is READ-ONLY during cascade (no per-step DELETEs).
    // Only blocked_events (small table) gets counter decrements.
    // Bulk cleanup of blocked_event_deps happens once after the loop.
    let mut worklist = vec![blocker_b64.to_string()];
    let mut did_unblock = false;

    while let Some(blocker) = worklist.pop() {
        // 1. Find events blocked on this blocker (covering index lookup, read-only)
        let candidates: Vec<String> = {
            let mut stmt = conn.prepare_cached(
                "SELECT event_id FROM blocked_event_deps
                 WHERE peer_id = ?1 AND blocker_event_id = ?2",
            )?;
            let mut rows = stmt.query(rusqlite::params![recorded_by, &blocker])?;
            let mut result = Vec::new();
            while let Some(row) = rows.next()? {
                result.push(row.get::<_, String>(0)?);
            }
            result
        };

        if candidates.is_empty() {
            continue;
        }

        // 2. Decrement counter for each candidate
        for eid_b64 in &candidates {
            conn.prepare_cached(
                "UPDATE blocked_events SET deps_remaining = deps_remaining - 1
                 WHERE peer_id = ?1 AND event_id = ?2 AND deps_remaining > 0",
            )?
            .execute(rusqlite::params![recorded_by, eid_b64])?;

            let remaining: i64 = match conn
                .prepare_cached(
                    "SELECT deps_remaining FROM blocked_events
                 WHERE peer_id = ?1 AND event_id = ?2",
                )?
                .query_row(rusqlite::params![recorded_by, eid_b64], |row| row.get(0))
            {
                Ok(v) => v,
                Err(rusqlite::Error::QueryReturnedNoRows) => continue, // already processed
                Err(e) => return Err(e.into()),
            };

            if remaining > 0 {
                continue;
            }

            // 3. Ready — clean up header row
            did_unblock = true;
            conn.prepare_cached("DELETE FROM blocked_events WHERE peer_id = ?1 AND event_id = ?2")?
                .execute(rusqlite::params![recorded_by, eid_b64])?;

            // 4. Project this event via project_one_step (no recursive cascade).
            //    apply_projection (called by project_one_step) executes emit_commands,
            //    which handles guard retries (RetryWorkspaceGuards, RetryFileSliceGuards).
            if let Some(event_id) = event_id_from_base64(eid_b64) {
                let (decision, _parsed) =
                    super::project_one::project_one_step(conn, recorded_by, &event_id)?;
                if matches!(decision, ProjectionDecision::Valid) {
                    worklist.push(eid_b64.clone());
                }
            }
        }
    }

    // Bulk cleanup: remove resolved dep edges from blocked_event_deps.
    if did_unblock {
        conn.prepare_cached(
            "DELETE FROM blocked_event_deps WHERE peer_id = ?1
             AND event_id IN (SELECT event_id FROM valid_events WHERE peer_id = ?1)",
        )?
        .execute(rusqlite::params![recorded_by])?;
        conn.prepare_cached(
            "DELETE FROM blocked_event_deps WHERE peer_id = ?1
             AND event_id IN (SELECT event_id FROM rejected_events WHERE peer_id = ?1)",
        )?
        .execute(rusqlite::params![recorded_by])?;
        // Clean up orphaned dep edges for events whose blocked_events header was
        // removed (all deps satisfied) but that didn't reach valid_events — e.g.,
        // file_slices that were dep-unblocked then guard-blocked by the pure projector.
        conn.prepare_cached(
            "DELETE FROM blocked_event_deps WHERE peer_id = ?1
             AND event_id NOT IN (SELECT event_id FROM blocked_events WHERE peer_id = ?1)",
        )?
        .execute(rusqlite::params![recorded_by])?;
    }

    Ok(())
}
