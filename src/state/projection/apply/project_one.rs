use super::super::decision::ProjectionDecision;
use super::backend::{ProjectionApplyResult, ProjectionBackend};
use crate::crypto::{event_id_to_base64, EventId};
use crate::event_modules::{self as events, ParsedEvent};
use rusqlite::Connection;

use super::cascade::{cascade_file_id_if_file, cascade_unblocked, cascade_unblocked_global};
use super::stages::apply_projection_with_backend;

fn event_is_valid_for_peer(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
) -> Result<bool, rusqlite::Error> {
    conn.query_row(
        "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![recorded_by, event_id_b64],
        |row| row.get(0),
    )
}

/// Single-event projection step (no cascade).
///
/// Executes the 7-step projection algorithm for one event:
///   1. Terminal-state check (already valid or rejected → AlreadyProcessed)
///   2. Load blob from events table
///   3. Parse via registry
///   4. Generic tri-state prereq/context load
///   5. Generic signer verification + envelope recursion
///   6. Per-event projector dispatch
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
    project_one_step_with_backend(conn, recorded_by, event_id)
}

pub(crate) fn project_one_step_with_backend<B: ProjectionBackend>(
    backend: &B,
    recorded_by: &str,
    event_id: &EventId,
) -> ProjectionApplyResult<(ProjectionDecision, Option<ParsedEvent>)> {
    let event_id_b64 = event_id_to_base64(event_id);

    if backend.already_processed(recorded_by, &event_id_b64)? {
        return Ok((ProjectionDecision::AlreadyProcessed, None));
    }

    // 2. Load blob from events table
    let blob: Vec<u8> = match backend.load_blob(&event_id_b64)? {
        Some(b) => b,
        None => {
            let reason = format!("event {} not found in events table", event_id_b64);
            backend.record_rejection(recorded_by, &event_id_b64, &reason)?;
            return Ok((ProjectionDecision::Reject { reason }, None));
        }
    };

    // 3. Parse via registry
    let parsed = match events::parse_event(&blob) {
        Ok(p) => p,
        Err(e) => {
            let reason = format!("parse error: {}", e);
            backend.record_rejection(recorded_by, &event_id_b64, &reason)?;
            return Ok((ProjectionDecision::Reject { reason }, None));
        }
    };

    // 4-6. Shared prereq/signer/projection stages
    // For encrypted events, inner_parsed contains the decrypted inner event.
    let (decision, inner_parsed, suppress_sharing) =
        apply_projection_with_backend(backend, recorded_by, &event_id_b64, &blob, &parsed)?;
    match &decision {
        ProjectionDecision::Reject { ref reason } => {
            backend.record_rejection(recorded_by, &event_id_b64, reason)?;
            return Ok((decision, Some(parsed)));
        }
        ProjectionDecision::BlockOnMissingDeps { ref missing } => {
            backend.mark_guard_blocked(&event_id_b64)?;
            let _ = missing;
            return Ok((decision, Some(parsed)));
        }
        _ => {}
    }

    let sub_event = inner_parsed.as_ref().unwrap_or(&parsed);

    // Refinement bridge to the abstract access-control model (see
    // verus-proofs/src/state/access_control.rs). At this point all runtime
    // dep/signer/guard stages have passed, so we pass all-honest flags to the
    // verified checker. The call acts as a live linkage: if a future change
    // to `apply_accepts_primitives_spec` starts rejecting an event kind the
    // runtime still projects, this debug_assert fires. Non-tautological parts
    // (kind-specific recipient matching) can be added as the model grows.
    debug_assert!(
        topo_verus_proofs::state::access_control::abstract_apply_accepts_primitives(
            parsed.event_type_code(),
            /* recipient_is_this_peer */ true,
            /* has_required_dep */ true,
            /* dep_is_valid */ true,
            /* dep_kind_matches */ true,
            /* dep_workspace_matches */ true,
            /* dep_recipient_matches */ true,
        ),
        "abstract access-control model rejected an event the runtime is finalizing as Valid (kind_code={})",
        parsed.event_type_code(),
    );

    backend.finalize_valid_projection(recorded_by, &event_id_b64, sub_event, suppress_sharing)?;

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
    crate::db::queue::with_immediate_tx_result(conn, || {
        let (decision, parsed) = project_one_step(conn, recorded_by, event_id)?;
        if matches!(decision, ProjectionDecision::Valid) {
            let event_id_b64 = event_id_to_base64(event_id);
            if event_is_valid_for_peer(conn, recorded_by, &event_id_b64)? {
                cascade_unblocked(conn, recorded_by, &event_id_b64, parsed.as_ref())?;
                if matches!(parsed.as_ref(), Some(ParsedEvent::EndpointShared(_))) {
                    cascade_unblocked_global(conn, &event_id_b64)?;
                }
                // File events: cascade on file_id to unblock file_slices
                // that were blocked waiting for the descriptor.
                cascade_file_id_if_file(conn, recorded_by, &event_id_b64)?;
            }
        }
        Ok(decision)
    })
}
