use std::time::{SystemTime, UNIX_EPOCH};
use rusqlite::Connection;
use super::decision::ProjectionDecision;
use super::encrypted::project_encrypted;
use super::projectors::{
    project_file_slice, project_message, project_message_attachment, project_message_deletion,
    project_reaction, project_secret_key, project_signed_memo,
};
use super::signer::{resolve_signer_key, verify_ed25519_signature, SignerResolution};
use crate::crypto::{event_id_from_base64, event_id_to_base64, EventId};
use crate::events::{self, registry, ParsedEvent};

/// Check that each dep's type code matches the allowed types for that dep field.
/// Returns Some(reason) if a type mismatch is found, None if all pass.
pub(crate) fn check_dep_types(
    conn: &Connection,
    deps: &[(&str, EventId)],
    type_codes: &[&[u8]],
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    for (i, (field_name, dep_id)) in deps.iter().enumerate() {
        let allowed = type_codes.get(i).copied().unwrap_or(&[]);
        if allowed.is_empty() {
            continue;
        }
        let dep_b64 = event_id_to_base64(dep_id);
        let dep_blob: Vec<u8> = match conn.query_row(
            "SELECT blob FROM events WHERE event_id = ?1",
            rusqlite::params![&dep_b64],
            |row| row.get(0),
        ) {
            Ok(b) => b,
            Err(_) => continue, // dep doesn't exist yet; dep-existence check handles this
        };
        if dep_blob.is_empty() {
            continue;
        }
        let actual_type = dep_blob[0];
        if !allowed.contains(&actual_type) {
            return Ok(Some(format!(
                "dep {} has type code {} but expected one of {:?}",
                field_name, actual_type, allowed
            )));
        }
    }
    Ok(None)
}

/// Record a rejected event durably so it is not re-processed on replay or cascade.
pub(crate) fn record_rejection(conn: &Connection, recorded_by: &str, event_id_b64: &str, reason: &str) {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let _ = conn.execute(
        "INSERT OR IGNORE INTO rejected_events (peer_id, event_id, reason, rejected_at)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![recorded_by, event_id_b64, reason, now_ms],
    );
}

/// Check dep presence against valid_events (tenant-scoped). If any deps are
/// missing, write block rows (blocked_event_deps + blocked_events header) keyed
/// to the caller-provided `event_id_b64` and return `Some(Block { missing })`.
/// Returns `None` if all deps are satisfied.
pub(crate) fn check_deps_and_block(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    deps: &[(&str, EventId)],
) -> Result<Option<ProjectionDecision>, Box<dyn std::error::Error>> {
    let mut missing = Vec::new();
    for (_field_name, dep_id) in deps {
        let dep_b64 = event_id_to_base64(dep_id);
        let dep_valid: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &dep_b64],
            |row| row.get(0),
        )?;
        if !dep_valid {
            missing.push(*dep_id);
        }
    }

    if missing.is_empty() {
        return Ok(None);
    }

    missing.sort_unstable();
    missing.dedup();
    for dep_id in &missing {
        let dep_b64 = event_id_to_base64(dep_id);
        conn.execute(
            "INSERT OR IGNORE INTO blocked_event_deps (peer_id, event_id, blocker_event_id)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![recorded_by, event_id_b64, &dep_b64],
        )?;
    }
    conn.execute(
        "INSERT OR IGNORE INTO blocked_events (peer_id, event_id, deps_remaining)
         VALUES (?1, ?2, ?3)",
        rusqlite::params![recorded_by, event_id_b64, missing.len() as i64],
    )?;

    Ok(Some(ProjectionDecision::Block { missing }))
}

/// Shared projection helper: verify signer (if required), dispatch to per-event
/// projector, return Valid or Reject. Caller is responsible for dep checks.
pub(crate) fn apply_projection(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    blob: &[u8],
    parsed: &ParsedEvent,
) -> Result<ProjectionDecision, Box<dyn std::error::Error>> {
    let meta = registry()
        .lookup(parsed.event_type_code())
        .ok_or_else(|| format!("unknown type code {}", parsed.event_type_code()))?;

    // Signer verification (if required)
    if meta.signer_required {
        let (signer_event_id, signer_type) = parsed
            .signer_fields()
            .ok_or("signer_required but no signer_fields")?;
        let resolution = resolve_signer_key(conn, recorded_by, signer_type, &signer_event_id)?;
        match resolution {
            SignerResolution::NotFound => {
                return Ok(ProjectionDecision::Reject {
                    reason: "signer key not found".to_string(),
                });
            }
            SignerResolution::Invalid(msg) => {
                return Ok(ProjectionDecision::Reject {
                    reason: format!("signer resolution failed: {}", msg),
                });
            }
            SignerResolution::Found(key) => {
                let sig_len = meta.signature_byte_len;
                if blob.len() < sig_len {
                    return Ok(ProjectionDecision::Reject {
                        reason: "blob too short for signature".to_string(),
                    });
                }
                let signing_bytes = &blob[..blob.len() - sig_len];
                let sig_bytes = &blob[blob.len() - sig_len..];
                if !verify_ed25519_signature(&key, signing_bytes, sig_bytes) {
                    return Ok(ProjectionDecision::Reject {
                        reason: "invalid signature".to_string(),
                    });
                }
            }
        }
    }

    // Per-event projector dispatch
    match parsed {
        ParsedEvent::Message(msg) => {
            project_message(conn, recorded_by, event_id_b64, msg)?;
        }
        ParsedEvent::Reaction(rxn) => {
            project_reaction(conn, recorded_by, event_id_b64, rxn)?;
        }
        ParsedEvent::SignedMemo(memo) => {
            project_signed_memo(conn, recorded_by, event_id_b64, memo)?;
        }
        ParsedEvent::Encrypted(enc) => {
            return project_encrypted(conn, recorded_by, event_id_b64, enc);
        }
        ParsedEvent::SecretKey(sk) => {
            project_secret_key(conn, recorded_by, event_id_b64, sk)?;
        }
        ParsedEvent::MessageDeletion(del) => {
            return project_message_deletion(conn, recorded_by, event_id_b64, del);
        }
        ParsedEvent::MessageAttachment(att) => {
            project_message_attachment(conn, recorded_by, event_id_b64, att)?;
        }
        ParsedEvent::FileSlice(fs) => {
            return Ok(project_file_slice(conn, recorded_by, event_id_b64, fs)?);
        }
        ParsedEvent::BenchDep(_) => {
            // No projection table — valid_events tracks completion
        }
        // Identity events: dispatch to identity projectors
        ParsedEvent::Workspace(_)
        | ParsedEvent::InviteAccepted(_)
        | ParsedEvent::UserInviteBoot(_)
        | ParsedEvent::UserInviteOngoing(_)
        | ParsedEvent::DeviceInviteFirst(_)
        | ParsedEvent::DeviceInviteOngoing(_)
        | ParsedEvent::UserBoot(_)
        | ParsedEvent::UserOngoing(_)
        | ParsedEvent::PeerSharedFirst(_)
        | ParsedEvent::PeerSharedOngoing(_)
        | ParsedEvent::AdminBoot(_)
        | ParsedEvent::AdminOngoing(_)
        | ParsedEvent::UserRemoved(_)
        | ParsedEvent::PeerRemoved(_)
        | ParsedEvent::SecretShared(_)
        | ParsedEvent::TransportKey(_) => {
            return super::identity::apply_identity_projection(
                conn,
                recorded_by,
                event_id_b64,
                parsed,
            );
        }
    }

    Ok(ProjectionDecision::Valid)
}

/// Core projection logic: steps 1-7 (terminal check, load, parse, dep check,
/// type check, apply projection, write valid_events). Returns the decision and
/// the parsed event (if available). Does NOT cascade — caller handles that.
fn project_one_core(
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

    // 4-5. Check dep presence and write block rows if missing
    let deps = parsed.dep_field_values();
    if let Some(block) = check_deps_and_block(conn, recorded_by, &event_id_b64, &deps)? {
        return Ok((block, Some(parsed)));
    }

    // 5b. Dep type checking — verify each dep's type code matches expectations
    let meta = registry().lookup(parsed.event_type_code())
        .ok_or_else(|| format!("unknown type code {}", parsed.event_type_code()))?;
    if !meta.dep_field_type_codes.is_empty() {
        if let Some(reason) = check_dep_types(conn, &deps, meta.dep_field_type_codes)? {
            record_rejection(conn, recorded_by, &event_id_b64, &reason);
            return Ok((ProjectionDecision::Reject { reason }, Some(parsed)));
        }
    }

    // 6. Apply projection (signer verification + projector dispatch)
    let decision = apply_projection(conn, recorded_by, &event_id_b64, &blob, &parsed)?;
    match &decision {
        ProjectionDecision::Reject { ref reason } => {
            record_rejection(conn, recorded_by, &event_id_b64, reason);
            return Ok((decision, Some(parsed)));
        }
        ProjectionDecision::Block { ref missing } => {
            // Inner deps missing (encrypted events). Write block records if non-empty.
            if !missing.is_empty() {
                let mut unique_blockers = missing.clone();
                unique_blockers.sort_unstable();
                unique_blockers.dedup();
                for dep_id in &unique_blockers {
                    let dep_b64 = event_id_to_base64(dep_id);
                    conn.execute(
                        "INSERT OR IGNORE INTO blocked_event_deps (peer_id, event_id, blocker_event_id)
                         VALUES (?1, ?2, ?3)",
                        rusqlite::params![recorded_by, &event_id_b64, &dep_b64],
                    )?;
                }
                conn.execute(
                    "INSERT OR IGNORE INTO blocked_events (peer_id, event_id, deps_remaining)
                     VALUES (?1, ?2, ?3)",
                    rusqlite::params![recorded_by, &event_id_b64, unique_blockers.len() as i64],
                )?;
            }
            return Ok((decision, Some(parsed)));
        }
        _ => {}
    }

    // 7. Write terminal state
    conn.execute(
        "INSERT OR IGNORE INTO valid_events (peer_id, event_id) VALUES (?1, ?2)",
        rusqlite::params![recorded_by, &event_id_b64],
    )?;

    Ok((ProjectionDecision::Valid, Some(parsed)))
}

/// Central projection entrypoint. Given an event_id that is already stored in the
/// `events` table, parse it, check dependencies, project into terminal tables,
/// and cascade-unblock any dependents.
pub fn project_one(
    conn: &Connection,
    recorded_by: &str,
    event_id: &EventId,
) -> Result<ProjectionDecision, Box<dyn std::error::Error>> {
    let (decision, parsed) = project_one_core(conn, recorded_by, event_id)?;
    if matches!(decision, ProjectionDecision::Valid) {
        let event_id_b64 = event_id_to_base64(event_id);
        cascade_unblocked(conn, recorded_by, &event_id_b64, parsed.as_ref())?;
    }
    Ok(decision)
}

/// After projecting an event, cascade-unblock dependents using a two-phase approach:
/// Phase 1: Kahn's algorithm dep cascade (using project_one_core).
/// Phase 2: Guard retries (after bulk cleanup so guard queries work correctly).
fn cascade_unblocked(
    conn: &Connection,
    recorded_by: &str,
    blocker_b64: &str,
    initial_parsed: Option<&ParsedEvent>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Run cascade directly so partial blocker/index writes are preserved when
    // transient write contention causes a retry.
    cascade_unblocked_inner(conn, recorded_by, blocker_b64, initial_parsed)
}

fn cascade_unblocked_inner(
    conn: &Connection,
    recorded_by: &str,
    blocker_b64: &str,
    initial_parsed: Option<&ParsedEvent>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Track guard cascade triggers across the entire cascade
    let mut invite_accepted_projected = matches!(initial_parsed, Some(ParsedEvent::InviteAccepted(_)));
    let mut attachment_file_ids: Vec<String> = Vec::new();
    if let Some(ParsedEvent::MessageAttachment(att)) = initial_parsed {
        attachment_file_ids.push(event_id_to_base64(&att.file_id));
    }

    // --- Phase 1: Kahn's algorithm dep cascade ---
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
            )?.execute(rusqlite::params![recorded_by, eid_b64])?;

            let remaining: i64 = match conn.prepare_cached(
                "SELECT deps_remaining FROM blocked_events
                 WHERE peer_id = ?1 AND event_id = ?2",
            )?.query_row(
                rusqlite::params![recorded_by, eid_b64],
                |row| row.get(0),
            ) {
                Ok(v) => v,
                Err(rusqlite::Error::QueryReturnedNoRows) => continue, // already processed
                Err(e) => return Err(e.into()),
            };

            if remaining > 0 {
                continue;
            }

            // 3. Ready — clean up header row
            did_unblock = true;
            conn.prepare_cached(
                "DELETE FROM blocked_events WHERE peer_id = ?1 AND event_id = ?2",
            )?.execute(rusqlite::params![recorded_by, eid_b64])?;

            // 4. Project this event through the canonical single entrypoint
            if let Some(event_id) = event_id_from_base64(eid_b64) {
                let (decision, parsed) = project_one_core(conn, recorded_by, &event_id)?;
                match &decision {
                    ProjectionDecision::Valid => {
                        // Track guard triggers from cascaded events
                        if let Some(ref p) = parsed {
                            if matches!(p, ParsedEvent::InviteAccepted(_)) {
                                invite_accepted_projected = true;
                            }
                            if let ParsedEvent::MessageAttachment(att) = p {
                                attachment_file_ids.push(event_id_to_base64(&att.file_id));
                            }
                        }
                        worklist.push(eid_b64.clone());
                    }
                    ProjectionDecision::Reject { .. } | ProjectionDecision::Block { .. } => {
                        // project_one_core already handled recording rejections
                        // and writing block records for inner deps
                    }
                    ProjectionDecision::AlreadyProcessed => {}
                }
            }
        }
    }

    // Bulk cleanup: remove resolved dep edges from blocked_event_deps.
    // Only needed when events actually transitioned out of blocked state during
    // this cascade. Skipping when did_unblock is false avoids O(N²) cost: these
    // DELETE ... IN (SELECT ...) queries scan valid_events/rejected_events which
    // grow with every projected event, and cascade_unblocked is called for every
    // projection — so running them unconditionally is quadratic in event count.
    //
    // Safety: if no events were unblocked, no new rows moved to valid/rejected
    // during this cascade, so the cleanup is a guaranteed no-op. Previous cascade
    // calls that DID unblock events ran their own cleanup, so no stale rows
    // accumulate across calls.
    if did_unblock {
        conn.prepare_cached(
            "DELETE FROM blocked_event_deps WHERE peer_id = ?1
             AND event_id IN (SELECT event_id FROM valid_events WHERE peer_id = ?1)",
        )?.execute(rusqlite::params![recorded_by])?;
        conn.prepare_cached(
            "DELETE FROM blocked_event_deps WHERE peer_id = ?1
             AND event_id IN (SELECT event_id FROM rejected_events WHERE peer_id = ?1)",
        )?.execute(rusqlite::params![recorded_by])?;
    }

    // --- Phase 2: Guard retries (AFTER bulk cleanup so queries work correctly) ---
    let mut guard_retries_ran = false;

    // Guard cascade: if InviteAccepted projected, retry workspace guard blocks.
    // Only Workspace uses trust-anchor guarding today, so keep the candidate
    // set bounded to workspace events rather than scanning all recorded events.
    if invite_accepted_projected {
        let guard_candidates: Vec<String> = {
            let mut stmt = conn.prepare(
                "SELECT re.event_id
                 FROM recorded_events re
                 INNER JOIN events e ON e.event_id = re.event_id
                 WHERE re.peer_id = ?1
                   AND e.event_type = 'workspace'
                   AND re.event_id NOT IN (SELECT event_id FROM valid_events WHERE peer_id = ?1)
                   AND re.event_id NOT IN (SELECT event_id FROM rejected_events WHERE peer_id = ?1)
                   AND re.event_id NOT IN (SELECT DISTINCT event_id FROM blocked_event_deps WHERE peer_id = ?1)",
            )?;
            let mut rows = stmt.query(rusqlite::params![recorded_by])?;
            let mut result = Vec::new();
            while let Some(row) = rows.next()? {
                result.push(row.get::<_, String>(0)?);
            }
            result
        };
        if !guard_candidates.is_empty() {
            guard_retries_ran = true;
        }
        for eid_b64 in guard_candidates {
            if let Some(event_id) = event_id_from_base64(&eid_b64) {
                // Use project_one (full entrypoint) for proper recursive cascade
                let _ = project_one(conn, recorded_by, &event_id)?;
            }
        }
    }

    // Guard cascade: if MessageAttachment projected, retry file_slice guard blocks
    for file_id_b64 in &attachment_file_ids {
        let fs_candidates: Vec<String> = {
            let mut stmt = conn.prepare(
                "SELECT event_id FROM file_slice_guard_blocks
                 WHERE peer_id = ?1 AND file_id = ?2",
            )?;
            let mut rows = stmt.query(rusqlite::params![recorded_by, file_id_b64])?;
            let mut result = Vec::new();
            while let Some(row) = rows.next()? {
                result.push(row.get::<_, String>(0)?);
            }
            result
        };
        if !fs_candidates.is_empty() {
            guard_retries_ran = true;
        }
        for eid_b64 in fs_candidates {
            if let Some(event_id) = event_id_from_base64(&eid_b64) {
                let _ = project_one(conn, recorded_by, &event_id)?;
            }
            conn.execute(
                "DELETE FROM file_slice_guard_blocks WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &eid_b64],
            )?;
        }
    }

    // Post-phase-2 cleanup: guard retries may have projected events that still
    // had stale dep rows from their earlier dep-blocking phase. For example, a
    // file_slice that was dep-blocked → unblocked → guard-blocked → retried here
    // as Valid still has its original blocked_event_deps rows. Clean them up now.
    // This runs rarely (only when guard retries fire), so no O(N²) concern.
    if guard_retries_ran {
        conn.prepare_cached(
            "DELETE FROM blocked_event_deps WHERE peer_id = ?1
             AND event_id IN (SELECT event_id FROM valid_events WHERE peer_id = ?1)",
        )?.execute(rusqlite::params![recorded_by])?;
        conn.prepare_cached(
            "DELETE FROM blocked_event_deps WHERE peer_id = ?1
             AND event_id IN (SELECT event_id FROM rejected_events WHERE peer_id = ?1)",
        )?.execute(rusqlite::params![recorded_by])?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash_event;
    use crate::db::{
        open_in_memory,
        schema::create_tables,
        store::{insert_event, insert_neg_item_if_shared, insert_recorded_event},
    };
    use crate::events::{
        self, BenchDepEvent, EncryptedEvent, FileSliceEvent, MessageAttachmentEvent,
        MessageDeletionEvent, MessageEvent, ParsedEvent, ReactionEvent, SecretKeyEvent,
        SignedMemoEvent, WorkspaceEvent, EVENT_TYPE_ENCRYPTED, EVENT_TYPE_FILE_SLICE,
        EVENT_TYPE_MESSAGE, EVENT_TYPE_MESSAGE_DELETION, EVENT_TYPE_REACTION,
    };
    use crate::projection::encrypted::encrypt_event_blob;
    use crate::projection::signer::sign_event_bytes;
    use ed25519_dalek::SigningKey;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    /// Insert a blob into events + neg_items + recorded_events (simulating what
    /// batch_writer or create_event_sync does before calling project_one).
    fn insert_event_raw(conn: &Connection, recorded_by: &str, blob: &[u8]) -> EventId {
        let event_id = hash_event(blob);
        let ts = now_ms();
        let type_code = blob[0];
        let type_name = registry()
            .lookup(type_code)
            .map(|m| m.type_name)
            .unwrap_or("unknown");

        insert_event(
            conn,
            &event_id,
            type_name,
            blob,
            crate::events::ShareScope::Shared,
            ts as i64,
            ts as i64,
        )
        .unwrap();
        insert_neg_item_if_shared(
            conn,
            crate::events::ShareScope::Shared,
            ts as i64,
            &event_id,
            "",
        )
        .unwrap();
        insert_recorded_event(conn, recorded_by, &event_id, ts as i64, "test").unwrap();

        event_id
    }

    use crate::events::{
        DeviceInviteFirstEvent, InviteAcceptedEvent, PeerSharedFirstEvent, UserBootEvent,
        UserInviteBootEvent,
    };

    /// Create a Workspace event, insert it, and mark it valid for this tenant.
    /// Returns the event_id suitable for tests that need an existing workspace row.
    fn setup_workspace_event(conn: &Connection, recorded_by: &str) -> EventId {
        let ws = ParsedEvent::Workspace(WorkspaceEvent {
            created_at_ms: now_ms(),
            public_key: [0xAA; 32],
        });
        let blob = events::encode_event(&ws).unwrap();
        let eid = insert_event_raw(conn, recorded_by, &blob);
        let eid_b64 = event_id_to_base64(&eid);
        conn.execute(
            "INSERT OR IGNORE INTO valid_events (peer_id, event_id) VALUES (?1, ?2)",
            rusqlite::params![recorded_by, &eid_b64],
        )
        .unwrap();
        eid
    }

    /// Create a minimal identity chain and return (peer_shared_event_id, signing_key).
    /// Projects all identity events through the pipeline so the signer is in valid_events.
    fn make_identity_chain(conn: &Connection, recorded_by: &str) -> (EventId, SigningKey) {
        let mut rng = rand::thread_rng();

        // 1. Workspace
        let workspace_key = SigningKey::generate(&mut rng);
        let workspace_pub = workspace_key.verifying_key().to_bytes();
        let net_event = ParsedEvent::Workspace(WorkspaceEvent {
            created_at_ms: now_ms(),
            public_key: workspace_pub,
        });
        let net_blob = events::encode_event(&net_event).unwrap();
        let net_eid = insert_event_raw(conn, recorded_by, &net_blob);

        // 2. InviteAccepted (local, binds trust anchor)
        let ia_event = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
            created_at_ms: now_ms(),
            invite_event_id: net_eid,
            workspace_id: net_eid,
        });
        let ia_blob = events::encode_event(&ia_event).unwrap();
        let ia_eid = insert_event_raw(conn, recorded_by, &ia_blob);
        project_one(conn, recorded_by, &ia_eid).unwrap();
        project_one(conn, recorded_by, &net_eid).unwrap();

        // 3. UserInviteBoot (signed by workspace key)
        let invite_key = SigningKey::generate(&mut rng);
        let invite_pub = invite_key.verifying_key().to_bytes();
        let uib = UserInviteBootEvent {
            created_at_ms: now_ms(),
            public_key: invite_pub,
            workspace_id: net_eid,
            signed_by: net_eid,
            signer_type: 1,
            signature: [0u8; 64],
        };
        let uib_event = ParsedEvent::UserInviteBoot(uib);
        let mut uib_blob = events::encode_event(&uib_event).unwrap();
        sign_blob(&workspace_key, &mut uib_blob);
        let uib_eid = insert_event_raw(conn, recorded_by, &uib_blob);
        project_one(conn, recorded_by, &uib_eid).unwrap();

        // 4. UserBoot (signed by invite key)
        let user_key = SigningKey::generate(&mut rng);
        let user_pub = user_key.verifying_key().to_bytes();
        let ub = UserBootEvent {
            created_at_ms: now_ms(),
            public_key: user_pub,
            signed_by: uib_eid,
            signer_type: 2,
            signature: [0u8; 64],
        };
        let ub_event = ParsedEvent::UserBoot(ub);
        let mut ub_blob = events::encode_event(&ub_event).unwrap();
        sign_blob(&invite_key, &mut ub_blob);
        let ub_eid = insert_event_raw(conn, recorded_by, &ub_blob);
        project_one(conn, recorded_by, &ub_eid).unwrap();

        // 5. DeviceInviteFirst (signed by user key)
        let device_invite_key = SigningKey::generate(&mut rng);
        let device_invite_pub = device_invite_key.verifying_key().to_bytes();
        let dif = DeviceInviteFirstEvent {
            created_at_ms: now_ms(),
            public_key: device_invite_pub,
            signed_by: ub_eid,
            signer_type: 4,
            signature: [0u8; 64],
        };
        let dif_event = ParsedEvent::DeviceInviteFirst(dif);
        let mut dif_blob = events::encode_event(&dif_event).unwrap();
        sign_blob(&user_key, &mut dif_blob);
        let dif_eid = insert_event_raw(conn, recorded_by, &dif_blob);
        project_one(conn, recorded_by, &dif_eid).unwrap();

        // 6. PeerSharedFirst (signed by device_invite key)
        let peer_shared_key = SigningKey::generate(&mut rng);
        let peer_shared_pub = peer_shared_key.verifying_key().to_bytes();
        let psf = PeerSharedFirstEvent {
            created_at_ms: now_ms(),
            public_key: peer_shared_pub,
            signed_by: dif_eid,
            signer_type: 3,
            signature: [0u8; 64],
        };
        let psf_event = ParsedEvent::PeerSharedFirst(psf);
        let mut psf_blob = events::encode_event(&psf_event).unwrap();
        sign_blob(&device_invite_key, &mut psf_blob);
        let psf_eid = insert_event_raw(conn, recorded_by, &psf_blob);
        project_one(conn, recorded_by, &psf_eid).unwrap();

        (psf_eid, peer_shared_key)
    }

    /// Build a full identity chain WITHOUT inserting or projecting.
    /// Returns (signer_eid, signing_key, chain_blobs) where chain_blobs
    /// are in dependency order (Network, InviteAccepted, UserInviteBoot, etc.).
    /// Caller must insert_event_raw + project_one each blob in order.
    fn build_identity_chain_deferred(
        recorded_by: &str,
    ) -> (EventId, SigningKey, Vec<(EventId, Vec<u8>)>) {
        let mut rng = rand::thread_rng();

        // 1. Workspace
        let workspace_key = SigningKey::generate(&mut rng);
        let workspace_pub = workspace_key.verifying_key().to_bytes();
        let net_event = ParsedEvent::Workspace(WorkspaceEvent {
            created_at_ms: now_ms(),
            public_key: workspace_pub,
        });
        let net_blob = events::encode_event(&net_event).unwrap();
        let net_eid = hash_event(&net_blob);

        // 2. InviteAccepted
        let ia_event = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
            created_at_ms: now_ms(),
            invite_event_id: net_eid,
            workspace_id: net_eid,
        });
        let ia_blob = events::encode_event(&ia_event).unwrap();
        let ia_eid = hash_event(&ia_blob);

        // 3. UserInviteBoot (signed by workspace key)
        let invite_key = SigningKey::generate(&mut rng);
        let invite_pub = invite_key.verifying_key().to_bytes();
        let uib = UserInviteBootEvent {
            created_at_ms: now_ms(),
            public_key: invite_pub,
            workspace_id: net_eid,
            signed_by: net_eid,
            signer_type: 1,
            signature: [0u8; 64],
        };
        let uib_event = ParsedEvent::UserInviteBoot(uib);
        let mut uib_blob = events::encode_event(&uib_event).unwrap();
        sign_blob(&workspace_key, &mut uib_blob);
        let uib_eid = hash_event(&uib_blob);

        // 4. UserBoot (signed by invite key)
        let user_key = SigningKey::generate(&mut rng);
        let user_pub = user_key.verifying_key().to_bytes();
        let ub = UserBootEvent {
            created_at_ms: now_ms(),
            public_key: user_pub,
            signed_by: uib_eid,
            signer_type: 2,
            signature: [0u8; 64],
        };
        let ub_event = ParsedEvent::UserBoot(ub);
        let mut ub_blob = events::encode_event(&ub_event).unwrap();
        sign_blob(&invite_key, &mut ub_blob);
        let ub_eid = hash_event(&ub_blob);

        // 5. DeviceInviteFirst (signed by user key)
        let device_invite_key = SigningKey::generate(&mut rng);
        let device_invite_pub = device_invite_key.verifying_key().to_bytes();
        let dif = DeviceInviteFirstEvent {
            created_at_ms: now_ms(),
            public_key: device_invite_pub,
            signed_by: ub_eid,
            signer_type: 4,
            signature: [0u8; 64],
        };
        let dif_event = ParsedEvent::DeviceInviteFirst(dif);
        let mut dif_blob = events::encode_event(&dif_event).unwrap();
        sign_blob(&user_key, &mut dif_blob);
        let dif_eid = hash_event(&dif_blob);

        // 6. PeerSharedFirst (signed by device_invite key)
        let peer_shared_key = SigningKey::generate(&mut rng);
        let peer_shared_pub = peer_shared_key.verifying_key().to_bytes();
        let psf = PeerSharedFirstEvent {
            created_at_ms: now_ms(),
            public_key: peer_shared_pub,
            signed_by: dif_eid,
            signer_type: 3,
            signature: [0u8; 64],
        };
        let psf_event = ParsedEvent::PeerSharedFirst(psf);
        let mut psf_blob = events::encode_event(&psf_event).unwrap();
        sign_blob(&device_invite_key, &mut psf_blob);
        let psf_eid = hash_event(&psf_blob);

        // Return blobs in dependency order: IA first (local trust anchor), then Network,
        // then the rest in chain order
        let chain_blobs = vec![
            (ia_eid, ia_blob),
            (net_eid, net_blob),
            (uib_eid, uib_blob),
            (ub_eid, ub_blob),
            (dif_eid, dif_blob),
            (psf_eid, psf_blob),
        ];

        (psf_eid, peer_shared_key, chain_blobs)
    }

    /// Insert and project all events from a deferred identity chain.
    fn insert_and_project_identity_chain(
        conn: &Connection,
        recorded_by: &str,
        chain_blobs: &[(EventId, Vec<u8>)],
    ) {
        for (eid, blob) in chain_blobs {
            insert_event_raw(conn, recorded_by, blob);
            project_one(conn, recorded_by, eid).unwrap();
        }
    }

    /// Helper: sign a blob in-place (overwrite last 64 bytes with Ed25519 signature).
    fn sign_blob(key: &SigningKey, blob: &mut Vec<u8>) {
        let len = blob.len();
        let sig = sign_event_bytes(key, &blob[..len - 64]);
        blob[len - 64..].copy_from_slice(&sig);
    }

    /// Create a signed message event blob. Returns (parsed, blob).
    fn make_message_signed(
        signing_key: &SigningKey,
        signer_eid: &EventId,
        content: &str,
    ) -> (ParsedEvent, Vec<u8>) {
        let msg = MessageEvent {
            created_at_ms: now_ms(),
            workspace_id: [1u8; 32],
            author_id: [2u8; 32],
            content: content.to_string(),
            signed_by: *signer_eid,
            signer_type: 5,
            signature: [0u8; 64],
        };
        let event = ParsedEvent::Message(msg);
        let mut blob = events::encode_event(&event).unwrap();
        sign_blob(signing_key, &mut blob);
        let parsed = events::parse_event(&blob).unwrap();
        (parsed, blob)
    }

    /// Convenience: create identity chain + signed message in one call.
    fn make_message(conn: &Connection, recorded_by: &str, content: &str) -> (ParsedEvent, Vec<u8>) {
        let (signer_eid, signing_key) = make_identity_chain(conn, recorded_by);
        make_message_signed(&signing_key, &signer_eid, content)
    }

    /// Create a signed reaction event blob.
    fn make_reaction_signed(
        signing_key: &SigningKey,
        signer_eid: &EventId,
        target: &EventId,
        emoji: &str,
    ) -> (ParsedEvent, Vec<u8>) {
        let rxn = ReactionEvent {
            created_at_ms: now_ms(),
            target_event_id: *target,
            author_id: [3u8; 32],
            emoji: emoji.to_string(),
            signed_by: *signer_eid,
            signer_type: 5,
            signature: [0u8; 64],
        };
        let event = ParsedEvent::Reaction(rxn);
        let mut blob = events::encode_event(&event).unwrap();
        sign_blob(signing_key, &mut blob);
        let parsed = events::parse_event(&blob).unwrap();
        (parsed, blob)
    }

    /// Convenience: create identity chain + signed reaction.
    fn make_reaction(
        conn: &Connection,
        recorded_by: &str,
        target: &EventId,
        emoji: &str,
    ) -> (ParsedEvent, Vec<u8>) {
        let (signer_eid, signing_key) = make_identity_chain(conn, recorded_by);
        make_reaction_signed(&signing_key, &signer_eid, target, emoji)
    }

    /// Create a signed deletion event blob.
    fn make_deletion_signed(
        signing_key: &SigningKey,
        signer_eid: &EventId,
        target: &EventId,
        author_id: [u8; 32],
    ) -> (ParsedEvent, Vec<u8>) {
        let del = MessageDeletionEvent {
            created_at_ms: now_ms(),
            target_event_id: *target,
            author_id,
            signed_by: *signer_eid,
            signer_type: 5,
            signature: [0u8; 64],
        };
        let event = ParsedEvent::MessageDeletion(del);
        let mut blob = events::encode_event(&event).unwrap();
        sign_blob(signing_key, &mut blob);
        let parsed = events::parse_event(&blob).unwrap();
        (parsed, blob)
    }

    /// Create a signed attachment event blob.
    fn make_attachment_signed(
        signing_key: &SigningKey,
        signer_eid: &EventId,
        message_id: &EventId,
        key_event_id: &EventId,
    ) -> (ParsedEvent, Vec<u8>) {
        let att = MessageAttachmentEvent {
            created_at_ms: now_ms(),
            message_id: *message_id,
            file_id: rand::random(),
            blob_bytes: 204800,
            total_slices: 4,
            slice_bytes: 65536,
            root_hash: [12u8; 32],
            key_event_id: *key_event_id,
            filename: "photo.jpg".to_string(),
            mime_type: "image/jpeg".to_string(),
            signed_by: *signer_eid,
            signer_type: 5,
            signature: [0u8; 64],
        };
        let event = ParsedEvent::MessageAttachment(att);
        let mut blob = events::encode_event(&event).unwrap();
        sign_blob(signing_key, &mut blob);
        let parsed = events::parse_event(&blob).unwrap();
        (parsed, blob)
    }

    fn make_signed_memo(
        signing_key: &SigningKey,
        signer_event_id: &EventId,
        content: &str,
    ) -> (ParsedEvent, Vec<u8>) {
        let memo = SignedMemoEvent {
            created_at_ms: now_ms(),
            signed_by: *signer_event_id,
            signer_type: 5,
            content: content.to_string(),
            signature: [0u8; 64],
        };
        let event = ParsedEvent::SignedMemo(memo);
        let mut blob = events::encode_event(&event).unwrap();
        sign_blob(signing_key, &mut blob);
        let parsed = events::parse_event(&blob).unwrap();
        (parsed, blob)
    }

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    #[test]
    fn test_project_message_valid() {
        let conn = setup();
        let recorded_by = "peer1";
        let (_msg, blob) = make_message(&conn, recorded_by, "hello");
        let eid = insert_event_raw(&conn, recorded_by, &blob);

        let result = project_one(&conn, recorded_by, &eid).unwrap();
        assert_eq!(result, ProjectionDecision::Valid);

        // Verify in messages table
        let eid_b64 = event_id_to_base64(&eid);
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE message_id = ?1 AND recorded_by = ?2",
                rusqlite::params![&eid_b64, recorded_by],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);

        // Verify in valid_events
        let valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &eid_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(valid);
    }

    #[test]
    fn test_project_reaction_valid() {
        let conn = setup();
        let recorded_by = "peer1";
        let net_eid = setup_workspace_event(&conn, recorded_by);

        // Create identity chain once for this tenant
        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        // Create target message first
        let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "target");
        let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
        project_one(&conn, recorded_by, &msg_eid).unwrap();

        // Create reaction targeting it
        let (_rxn, rxn_blob) =
            make_reaction_signed(&signing_key, &signer_eid, &msg_eid, "\u{1f44d}");
        let rxn_eid = insert_event_raw(&conn, recorded_by, &rxn_blob);

        let result = project_one(&conn, recorded_by, &rxn_eid).unwrap();
        assert_eq!(result, ProjectionDecision::Valid);

        let rxn_b64 = event_id_to_base64(&rxn_eid);
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM reactions WHERE event_id = ?1 AND recorded_by = ?2",
                rusqlite::params![&rxn_b64, recorded_by],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_project_reaction_blocked() {
        let conn = setup();
        let recorded_by = "peer1";

        // Create reaction with a target that doesn't exist
        let fake_target = [99u8; 32];
        let (_rxn, rxn_blob) = make_reaction(&conn, recorded_by, &fake_target, "\u{1f44d}");
        let rxn_eid = insert_event_raw(&conn, recorded_by, &rxn_blob);

        let result = project_one(&conn, recorded_by, &rxn_eid).unwrap();
        match result {
            ProjectionDecision::Block { missing } => {
                // May block on fake_target (and possibly signed_by dep)
                assert!(missing.contains(&fake_target));
            }
            other => panic!("expected Block, got {:?}", other),
        }

        // Verify in blocked_event_deps
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM blocked_event_deps WHERE peer_id = ?1",
                rusqlite::params![recorded_by],
                |row| row.get(0),
            )
            .unwrap();
        assert!(count >= 1);

        // Verify NOT in valid_events
        let rxn_b64 = event_id_to_base64(&rxn_eid);
        let valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &rxn_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_project_unblock_cascade() {
        let conn = setup();
        let recorded_by = "peer1";
        let net_eid = setup_workspace_event(&conn, recorded_by);

        // Create identity chain for signing
        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        // Create message blob but don't insert yet
        let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "target");
        let msg_eid = hash_event(&msg_blob);

        // Create reaction targeting it — insert reaction first (out of order)
        let (_rxn, rxn_blob) =
            make_reaction_signed(&signing_key, &signer_eid, &msg_eid, "\u{2764}\u{fe0f}");
        let rxn_eid = insert_event_raw(&conn, recorded_by, &rxn_blob);

        // Project reaction — should block
        let result = project_one(&conn, recorded_by, &rxn_eid).unwrap();
        assert!(matches!(result, ProjectionDecision::Block { .. }));

        // Now insert and project the message
        let msg_eid2 = insert_event_raw(&conn, recorded_by, &msg_blob);
        assert_eq!(msg_eid, msg_eid2);
        let result = project_one(&conn, recorded_by, &msg_eid).unwrap();
        assert_eq!(result, ProjectionDecision::Valid);

        // Reaction should have been auto-unblocked
        let rxn_b64 = event_id_to_base64(&rxn_eid);
        let valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &rxn_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            valid,
            "reaction should be auto-projected after target arrives"
        );

        // No remaining blocked deps
        let blocked: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM blocked_event_deps WHERE peer_id = ?1",
                rusqlite::params![recorded_by],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(blocked, 0);
    }

    #[test]
    fn test_duplicate_dep_ids_unblock_correctly() {
        // Regression: if an event has the same dep_id in multiple dep fields,
        // deps_remaining must reflect the unique blocker count, not the raw
        // vec length, or the event gets permanently stuck.
        let conn = setup();
        let recorded_by = "peer1";

        // E_root: no deps
        let root = ParsedEvent::BenchDep(BenchDepEvent {
            created_at_ms: now_ms(),
            dep_ids: vec![],
            payload: [0xAA; 16],
        });
        let root_blob = events::encode_event(&root).unwrap();
        let root_eid = hash_event(&root_blob);

        // E_dup: depends on E_root TWICE (duplicate dep IDs)
        let dup = ParsedEvent::BenchDep(BenchDepEvent {
            created_at_ms: now_ms(),
            dep_ids: vec![root_eid, root_eid],
            payload: [0xBB; 16],
        });
        let dup_blob = events::encode_event(&dup).unwrap();
        let dup_eid = hash_event(&dup_blob);

        // Insert both, project E_dup first (out of order) — should block
        insert_event_raw(&conn, recorded_by, &root_blob);
        insert_event_raw(&conn, recorded_by, &dup_blob);
        let result = project_one(&conn, recorded_by, &dup_eid).unwrap();
        assert!(matches!(result, ProjectionDecision::Block { .. }));

        // deps_remaining must be 1 (unique), not 2 (raw)
        let dup_b64 = event_id_to_base64(&dup_eid);
        let deps_remaining: i64 = conn
            .query_row(
                "SELECT deps_remaining FROM blocked_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &dup_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(deps_remaining, 1, "deps_remaining should be unique blocker count");

        // Now project E_root — cascade should unblock E_dup
        let result = project_one(&conn, recorded_by, &root_eid).unwrap();
        assert_eq!(result, ProjectionDecision::Valid);

        let valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &dup_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(valid, "event with duplicate deps should be unblocked after blocker resolves");

        // No stuck blocked_events rows
        let stuck: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM blocked_events WHERE peer_id = ?1",
                rusqlite::params![recorded_by],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stuck, 0);
    }

    #[test]
    fn test_already_processed() {
        let conn = setup();
        let recorded_by = "peer1";
        let (_msg, blob) = make_message(&conn, recorded_by, "hello");
        let eid = insert_event_raw(&conn, recorded_by, &blob);

        let r1 = project_one(&conn, recorded_by, &eid).unwrap();
        assert_eq!(r1, ProjectionDecision::Valid);

        let r2 = project_one(&conn, recorded_by, &eid).unwrap();
        assert_eq!(r2, ProjectionDecision::AlreadyProcessed);
    }

    #[test]
    fn test_multi_blocker() {
        let conn = setup();
        let recorded_by = "peer1";
        let net_eid = setup_workspace_event(&conn, recorded_by);

        // Create identity chain for signing
        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        // Create two messages (targets) — pre-compute hashes
        let (_msg1, msg1_blob) = make_message_signed(&signing_key, &signer_eid, "target1");
        let msg1_eid = hash_event(&msg1_blob);
        let (_msg2, msg2_blob) = make_message_signed(&signing_key, &signer_eid, "target2");
        let msg2_eid = hash_event(&msg2_blob);

        // Create reaction targeting msg1 — insert without msg1 in events
        let (_rxn1, rxn1_blob) =
            make_reaction_signed(&signing_key, &signer_eid, &msg1_eid, "\u{1f44d}");
        let rxn1_eid = insert_event_raw(&conn, recorded_by, &rxn1_blob);

        // Create reaction targeting msg2 — insert without msg2 in events
        let (_rxn2, rxn2_blob) =
            make_reaction_signed(&signing_key, &signer_eid, &msg2_eid, "\u{2764}\u{fe0f}");
        let rxn2_eid = insert_event_raw(&conn, recorded_by, &rxn2_blob);

        // Both should block
        assert!(matches!(
            project_one(&conn, recorded_by, &rxn1_eid).unwrap(),
            ProjectionDecision::Block { .. }
        ));
        assert!(matches!(
            project_one(&conn, recorded_by, &rxn2_eid).unwrap(),
            ProjectionDecision::Block { .. }
        ));

        // Insert msg1 — rxn1 unblocks, rxn2 stays blocked
        insert_event_raw(&conn, recorded_by, &msg1_blob);
        project_one(&conn, recorded_by, &msg1_eid).unwrap();

        let rxn1_b64 = event_id_to_base64(&rxn1_eid);
        let rxn2_b64 = event_id_to_base64(&rxn2_eid);
        let r1_valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &rxn1_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(r1_valid);

        let r2_valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &rxn2_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!r2_valid);

        // Insert msg2 — rxn2 unblocks
        insert_event_raw(&conn, recorded_by, &msg2_blob);
        project_one(&conn, recorded_by, &msg2_eid).unwrap();

        let r2_valid2: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &rxn2_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(r2_valid2);
    }

    #[test]
    fn test_legacy_peer_key_blob_rejected() {
        let conn = setup();
        let recorded_by = "peer1";
        // Legacy peer_key wire format: [type=3][created_at][public_key]
        let mut blob = Vec::with_capacity(41);
        blob.push(3);
        blob.extend_from_slice(&now_ms().to_le_bytes());
        blob.extend_from_slice(&[42u8; 32]);
        let eid = insert_event_raw(&conn, recorded_by, &blob);

        let result = project_one(&conn, recorded_by, &eid).unwrap();
        match result {
            ProjectionDecision::Reject { reason } => {
                assert!(reason.contains("unknown event type: 3"), "reason: {}", reason);
            }
            other => panic!("expected Reject, got {:?}", other),
        }
    }

    #[test]
    fn test_project_signed_memo_valid() {
        let conn = setup();
        let recorded_by = "peer1";

        // Create identity chain as signer
        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        // Now create a signed memo referencing the signer
        let (_memo, memo_blob) = make_signed_memo(&signing_key, &signer_eid, "hello signed");
        let memo_eid = insert_event_raw(&conn, recorded_by, &memo_blob);

        let result = project_one(&conn, recorded_by, &memo_eid).unwrap();
        assert_eq!(result, ProjectionDecision::Valid);

        // Verify in signed_memos table
        let memo_b64 = event_id_to_base64(&memo_eid);
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM signed_memos WHERE event_id = ?1 AND recorded_by = ?2",
                rusqlite::params![&memo_b64, recorded_by],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_signed_memo_blocks_on_missing_signer() {
        let conn = setup();
        let recorded_by = "peer1";
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);

        // Create a memo referencing a non-existent signer event
        let fake_signer_id = [99u8; 32];
        let (_memo, memo_blob) = make_signed_memo(&signing_key, &fake_signer_id, "blocked memo");
        let memo_eid = insert_event_raw(&conn, recorded_by, &memo_blob);

        let result = project_one(&conn, recorded_by, &memo_eid).unwrap();
        match result {
            ProjectionDecision::Block { missing } => {
                assert_eq!(missing.len(), 1);
                assert_eq!(missing[0], fake_signer_id);
            }
            other => panic!("expected Block, got {:?}", other),
        }
    }

    #[test]
    fn test_signed_memo_unblocks_when_signer_arrives() {
        let conn = setup();
        let recorded_by = "peer1";

        // Build identity chain without inserting (deferred)
        let (signer_eid, signing_key, chain_blobs) = build_identity_chain_deferred(recorded_by);

        // Create and insert signed memo BEFORE signer exists
        let (_memo, memo_blob) = make_signed_memo(&signing_key, &signer_eid, "out of order");
        let memo_eid = insert_event_raw(&conn, recorded_by, &memo_blob);

        // Project memo — should block on missing signer
        let result = project_one(&conn, recorded_by, &memo_eid).unwrap();
        assert!(matches!(result, ProjectionDecision::Block { .. }));

        // Now insert and project the full identity chain
        insert_and_project_identity_chain(&conn, recorded_by, &chain_blobs);

        // Memo should have been auto-unblocked via cascade
        let memo_b64 = event_id_to_base64(&memo_eid);
        let valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &memo_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            valid,
            "signed memo should be auto-projected after signer key arrives"
        );

        // Verify in signed_memos table
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM signed_memos WHERE event_id = ?1 AND recorded_by = ?2",
                rusqlite::params![&memo_b64, recorded_by],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_signed_memo_invalid_signature_rejects() {
        let conn = setup();
        let recorded_by = "peer1";
        let mut rng = rand::thread_rng();
        let wrong_key = SigningKey::generate(&mut rng);

        // Create identity chain as signer
        let (signer_eid, _signing_key) = make_identity_chain(&conn, recorded_by);

        // Sign the memo with the WRONG key (not the identity chain's key)
        let (_memo, memo_blob) = make_signed_memo(&wrong_key, &signer_eid, "bad signature");
        let memo_eid = insert_event_raw(&conn, recorded_by, &memo_blob);

        let result = project_one(&conn, recorded_by, &memo_eid).unwrap();
        match result {
            ProjectionDecision::Reject { reason } => {
                assert!(reason.contains("invalid signature"), "reason: {}", reason);
            }
            other => panic!("expected Reject, got {:?}", other),
        }
    }

    #[test]
    fn test_signed_content_events_project_with_identity_chain() {
        // Verify that signed messages and reactions project correctly through
        // the pipeline with proper identity chains.
        let conn = setup();
        let recorded_by = "peer1";
        let net_eid = setup_workspace_event(&conn, recorded_by);

        // Create identity chain once for this tenant
        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "signed message");
        let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
        let r1 = project_one(&conn, recorded_by, &msg_eid).unwrap();
        assert_eq!(r1, ProjectionDecision::Valid);

        let (_rxn, rxn_blob) =
            make_reaction_signed(&signing_key, &signer_eid, &msg_eid, "\u{1f44d}");
        let rxn_eid = insert_event_raw(&conn, recorded_by, &rxn_blob);
        let r2 = project_one(&conn, recorded_by, &rxn_eid).unwrap();
        assert_eq!(r2, ProjectionDecision::Valid);
    }

    #[test]
    fn test_dep_global_existence_not_sufficient() {
        // A dep existing globally (for tenant_a) must NOT satisfy tenant_b's dep check
        let conn = setup();
        let tenant_a = "tenant_a";
        let tenant_b = "tenant_b";
        let net_eid_a = setup_workspace_event(&conn, tenant_a);

        // Tenant A creates and projects a message
        let (_msg, msg_blob) = make_message(&conn, tenant_a, "target for A");
        let msg_eid = insert_event_raw(&conn, tenant_a, &msg_blob);
        let r = project_one(&conn, tenant_a, &msg_eid).unwrap();
        assert_eq!(r, ProjectionDecision::Valid);

        // Tenant B creates a reaction targeting A's message (with B's own identity chain)
        let (_rxn, rxn_blob) = make_reaction(&conn, tenant_b, &msg_eid, "\u{1f44d}");
        let rxn_eid = insert_event_raw(&conn, tenant_b, &rxn_blob);

        // Tenant B projects the reaction — should BLOCK because the message is not
        // in valid_events for tenant_b, even though the blob exists in global events table
        let r2 = project_one(&conn, tenant_b, &rxn_eid).unwrap();
        match r2 {
            ProjectionDecision::Block { missing } => {
                assert!(missing.contains(&msg_eid));
            }
            other => panic!("expected Block, got {:?}", other),
        }
    }

    #[test]
    fn test_cross_tenant_projection_isolation() {
        // Both tenants project the same message blob — each gets independent valid_events
        let conn = setup();
        let tenant_a = "tenant_a";
        let tenant_b = "tenant_b";
        let net_eid_a = setup_workspace_event(&conn, tenant_a);
        // Same workspace event must be valid for tenant_b too since they share the blob
        setup_workspace_event(&conn, tenant_b);
        // Use tenant_a's net_eid so both share the same message blob
        // But we need the SAME workspace_id in both tenants' valid_events.
        // Since setup_workspace_event creates different workspace events per tenant,
        // we must manually mark tenant_a's workspace event valid for tenant_b too.
        let net_b64 = event_id_to_base64(&net_eid_a);
        insert_recorded_event(&conn, tenant_b, &net_eid_a, now_ms() as i64, "test").unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO valid_events (peer_id, event_id) VALUES (?1, ?2)",
            rusqlite::params![tenant_b, &net_b64],
        ).unwrap();

        // Create identity chain for tenant_a, then replicate identity events for tenant_b
        let (signer_eid, signing_key) = make_identity_chain(&conn, tenant_a);

        // Replicate the identity chain events for tenant_b so the signer is valid for both
        // We need to record and project the same identity events for tenant_b.
        // The simplest approach: also create an identity chain for tenant_b.
        // But since the message's signed_by references tenant_a's signer, tenant_b needs
        // that same signer projected. Let's record the signer event for tenant_b and
        // project the entire chain for tenant_b.
        // Actually, the identity chain events are already in the events table.
        // We need to record+project them for tenant_b. The signer_eid (PeerSharedFirst)
        // and all its ancestors need to be valid for tenant_b.
        // The simplest approach: create a separate identity chain for tenant_b that produces
        // a different signer, but then the message would reference tenant_a's signer, not tenant_b's.
        // So let's use separate messages for each tenant.
        let (_msg_a, msg_a_blob) = make_message_signed(&signing_key, &signer_eid, "shared message");
        let msg_eid = insert_event_raw(&conn, tenant_a, &msg_a_blob);
        let r_a = project_one(&conn, tenant_a, &msg_eid).unwrap();
        assert_eq!(r_a, ProjectionDecision::Valid);

        // For tenant_b, create its own identity chain and message
        let (signer_eid_b, signing_key_b) = make_identity_chain(&conn, tenant_b);
        let (_msg_b, msg_b_blob) =
            make_message_signed(&signing_key_b, &signer_eid_b, "shared message b");
        let msg_b_eid = insert_event_raw(&conn, tenant_b, &msg_b_blob);
        let r_b = project_one(&conn, tenant_b, &msg_b_eid).unwrap();
        assert_eq!(r_b, ProjectionDecision::Valid);

        // Each tenant has a message in the messages table
        let msg_a_b64 = event_id_to_base64(&msg_eid);
        let msg_a_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE message_id = ?1",
                rusqlite::params![&msg_a_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(msg_a_count, 1);

        let msg_b_b64 = event_id_to_base64(&msg_b_eid);
        let msg_b_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE message_id = ?1",
                rusqlite::params![&msg_b_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(msg_b_count, 1);

        // Each tenant has independent valid_events entries
        let a_valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![tenant_a, &msg_a_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(a_valid, "tenant_a should have valid_events entry");

        let b_valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![tenant_b, &msg_b_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(b_valid, "tenant_b should have valid_events entry");
    }

    #[test]
    fn test_cross_tenant_signer_isolation() {
        // Identity chain projected for tenant_a only; signed memo should block for tenant_b
        let conn = setup();
        let tenant_a = "tenant_a";
        let tenant_b = "tenant_b";

        // Create identity chain for tenant_a
        let (signer_eid, signing_key) = make_identity_chain(&conn, tenant_a);

        // Create signed memo (correct signature)
        let (_memo, memo_blob) =
            make_signed_memo(&signing_key, &signer_eid, "tenant isolation test");
        let memo_eid = insert_event_raw(&conn, tenant_a, &memo_blob);

        // Project for tenant_a — should be Valid
        let r_a = project_one(&conn, tenant_a, &memo_eid).unwrap();
        assert_eq!(r_a, ProjectionDecision::Valid);

        // Also record the memo + signer for tenant_b
        insert_recorded_event(&conn, tenant_b, &memo_eid, now_ms() as i64, "test").unwrap();
        insert_recorded_event(&conn, tenant_b, &signer_eid, now_ms() as i64, "test").unwrap();

        // Project memo for tenant_b — should BLOCK (signer dep not valid for B)
        let r_b = project_one(&conn, tenant_b, &memo_eid).unwrap();
        match r_b {
            ProjectionDecision::Block { missing } => {
                assert_eq!(missing.len(), 1);
                assert_eq!(missing[0], signer_eid);
            }
            other => panic!("expected Block for tenant_b, got {:?}", other),
        }

        // Verify: signed_memos has 1 row for A, 0 for B
        let sm_a: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM signed_memos WHERE recorded_by = ?1",
                rusqlite::params![tenant_a],
                |row| row.get(0),
            )
            .unwrap();
        let sm_b: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM signed_memos WHERE recorded_by = ?1",
                rusqlite::params![tenant_b],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(sm_a, 1);
        assert_eq!(sm_b, 0);
    }

    #[test]
    fn test_rejection_recorded_durably() {
        let conn = setup();
        let recorded_by = "peer1";
        let mut rng = rand::thread_rng();
        let wrong_key = SigningKey::generate(&mut rng);

        // Create identity chain as signer
        let (signer_eid, _signing_key) = make_identity_chain(&conn, recorded_by);

        // Sign memo with wrong key
        let (_memo, memo_blob) = make_signed_memo(&wrong_key, &signer_eid, "bad sig");
        let memo_eid = insert_event_raw(&conn, recorded_by, &memo_blob);

        let result = project_one(&conn, recorded_by, &memo_eid).unwrap();
        match result {
            ProjectionDecision::Reject { ref reason } => {
                assert!(reason.contains("invalid signature"), "reason: {}", reason);
            }
            other => panic!("expected Reject, got {:?}", other),
        }

        // Verify row exists in rejected_events
        let memo_b64 = event_id_to_base64(&memo_eid);
        let rej_reason: String = conn
            .query_row(
                "SELECT reason FROM rejected_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &memo_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(rej_reason.contains("invalid signature"));
    }

    #[test]
    fn test_rejected_event_not_retried() {
        let conn = setup();
        let recorded_by = "peer1";
        let mut rng = rand::thread_rng();
        let wrong_key = SigningKey::generate(&mut rng);

        // Sign memo with wrong key against existing identity-chain signer.
        let (real_signer_eid, _real_signing_key) = make_identity_chain(&conn, recorded_by);
        let (_memo, memo_blob) = make_signed_memo(&wrong_key, &real_signer_eid, "bad sig again");
        let memo_eid = insert_event_raw(&conn, recorded_by, &memo_blob);

        // First call: Reject
        let r1 = project_one(&conn, recorded_by, &memo_eid).unwrap();
        assert!(matches!(r1, ProjectionDecision::Reject { .. }));

        // Second call: AlreadyProcessed (not Reject again)
        let r2 = project_one(&conn, recorded_by, &memo_eid).unwrap();
        assert_eq!(r2, ProjectionDecision::AlreadyProcessed);
    }

    #[test]
    fn test_two_tenant_contexts_single_db() {
        let conn = setup();
        let tenant_a = "tenant_a";
        let tenant_b = "tenant_b";
        let net_eid_a = setup_workspace_event(&conn, tenant_a);
        let net_eid_b = setup_workspace_event(&conn, tenant_b);

        // Each tenant creates a message with its own identity chain
        let (_msg_a, msg_a_blob) = make_message(&conn, tenant_a, "hello from A");
        let msg_a_eid = insert_event_raw(&conn, tenant_a, &msg_a_blob);
        let (_msg_b, msg_b_blob) = make_message(&conn, tenant_b, "hello from B");
        let msg_b_eid = insert_event_raw(&conn, tenant_b, &msg_b_blob);

        // Project each for their tenant
        let r_a = project_one(&conn, tenant_a, &msg_a_eid).unwrap();
        assert_eq!(r_a, ProjectionDecision::Valid);
        let r_b = project_one(&conn, tenant_b, &msg_b_eid).unwrap();
        assert_eq!(r_b, ProjectionDecision::Valid);

        // Each sees only 1 message (isolated)
        let count_a: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
                rusqlite::params![tenant_a],
                |row| row.get(0),
            )
            .unwrap();
        let count_b: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
                rusqlite::params![tenant_b],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count_a, 1);
        assert_eq!(count_b, 1);

        // Tenant B reacts to tenant A's message — blocks (dep not valid for B)
        let (_rxn, rxn_blob) = make_reaction(&conn, tenant_b, &msg_a_eid, "\u{1f44d}");
        let rxn_eid = insert_event_raw(&conn, tenant_b, &rxn_blob);
        let r_rxn = project_one(&conn, tenant_b, &rxn_eid).unwrap();
        assert!(matches!(r_rxn, ProjectionDecision::Block { .. }));

        // Now record and project tenant_a's message for tenant_b.
        // The message's signed_by references tenant_a's signer, so tenant_b also needs
        // that signer projected. We need to project the message's signer chain for tenant_b.
        // Since the message blob references a signer that belongs to tenant_a, projecting
        // the message for tenant_b will block on the signer dep. Let's project tenant_a's
        // message signer chain for tenant_b by recording+projecting those identity events.
        // For simplicity, we just record+project the message for tenant_b.
        // The message will block on its signed_by dep for tenant_b. So we accept a Block.
        insert_recorded_event(&conn, tenant_b, &msg_a_eid, now_ms() as i64, "test").unwrap();
        let r_msg_for_b = project_one(&conn, tenant_b, &msg_a_eid).unwrap();
        // The message's signed_by references tenant_a's identity chain which is not valid for tenant_b.
        // So it will block. This is correct cross-tenant isolation behavior.
        assert!(
            matches!(r_msg_for_b, ProjectionDecision::Block { .. }),
            "message should block for tenant_b due to missing signer, got {:?}",
            r_msg_for_b
        );

        // Reaction also still blocked (its target is not valid for tenant_b)
        let rxn_b64 = event_id_to_base64(&rxn_eid);
        let rxn_valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![tenant_b, &rxn_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !rxn_valid,
            "reaction should remain blocked since message is not valid for tenant_b"
        );

        // Tenant B has 1 message (its own)
        let count_b_msgs: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
                rusqlite::params![tenant_b],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count_b_msgs, 1);
    }

    // ===== Encrypted event helpers =====

    fn make_secret_key(key_bytes: [u8; 32]) -> (ParsedEvent, Vec<u8>) {
        let sk = ParsedEvent::SecretKey(SecretKeyEvent {
            created_at_ms: now_ms(),
            key_bytes,
        });
        let blob = events::encode_event(&sk).unwrap();
        (sk, blob)
    }

    fn make_encrypted_event(
        key_bytes: &[u8; 32],
        inner_blob: &[u8],
        inner_type_code: u8,
        key_event_id: &EventId,
    ) -> (ParsedEvent, Vec<u8>) {
        let (nonce, ciphertext, auth_tag) = encrypt_event_blob(key_bytes, inner_blob).unwrap();
        let enc = ParsedEvent::Encrypted(EncryptedEvent {
            created_at_ms: now_ms(),
            key_event_id: *key_event_id,
            inner_type_code,
            nonce,
            ciphertext,
            auth_tag,
        });
        let blob = events::encode_event(&enc).unwrap();
        (enc, blob)
    }

    #[test]
    fn test_project_secret_key_valid() {
        let conn = setup();
        let recorded_by = "peer1";
        let key_bytes: [u8; 32] = rand::random();
        let (_sk, blob) = make_secret_key(key_bytes);
        let eid = insert_event_raw(&conn, recorded_by, &blob);

        let result = project_one(&conn, recorded_by, &eid).unwrap();
        assert_eq!(result, ProjectionDecision::Valid);

        // Verify in secret_keys table
        let eid_b64 = event_id_to_base64(&eid);
        let stored_key: Vec<u8> = conn
            .query_row(
                "SELECT key_bytes FROM secret_keys WHERE event_id = ?1 AND recorded_by = ?2",
                rusqlite::params![&eid_b64, recorded_by],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored_key, key_bytes.as_slice());
    }

    #[test]
    fn test_encrypted_message_valid() {
        let conn = setup();
        let recorded_by = "peer1";
        let net_eid = setup_workspace_event(&conn, recorded_by);
        let key_bytes: [u8; 32] = rand::random();

        // Create and project secret key
        let (_sk, sk_blob) = make_secret_key(key_bytes);
        let sk_eid = insert_event_raw(&conn, recorded_by, &sk_blob);
        let r = project_one(&conn, recorded_by, &sk_eid).unwrap();
        assert_eq!(r, ProjectionDecision::Valid);

        // Create identity chain for signing the inner message
        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        // Create signed inner message
        let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "encrypted hello");

        // Encrypt it
        let (_enc, enc_blob) =
            make_encrypted_event(&key_bytes, &msg_blob, EVENT_TYPE_MESSAGE, &sk_eid);
        let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);

        let result = project_one(&conn, recorded_by, &enc_eid).unwrap();
        assert_eq!(result, ProjectionDecision::Valid);

        // Verify inner message is in messages table (using encrypted event_id)
        let enc_b64 = event_id_to_base64(&enc_eid);
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE message_id = ?1 AND recorded_by = ?2",
                rusqlite::params![&enc_b64, recorded_by],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_encrypted_blocks_on_missing_key() {
        let conn = setup();
        let recorded_by = "peer1";
        let key_bytes: [u8; 32] = rand::random();

        // Pre-compute key event_id without inserting
        let (_sk, sk_blob) = make_secret_key(key_bytes);
        let sk_eid = hash_event(&sk_blob);

        // Create identity chain for signing the inner message
        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        // Create encrypted event referencing the missing key
        let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "blocked encrypted");
        let (_enc, enc_blob) =
            make_encrypted_event(&key_bytes, &msg_blob, EVENT_TYPE_MESSAGE, &sk_eid);
        let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);

        let result = project_one(&conn, recorded_by, &enc_eid).unwrap();
        match result {
            ProjectionDecision::Block { missing } => {
                assert_eq!(missing.len(), 1);
                assert_eq!(missing[0], sk_eid);
            }
            other => panic!("expected Block, got {:?}", other),
        }
    }

    #[test]
    fn test_encrypted_unblocks_when_key_arrives() {
        let conn = setup();
        let recorded_by = "peer1";
        let net_eid = setup_workspace_event(&conn, recorded_by);
        let key_bytes: [u8; 32] = rand::random();

        // Pre-compute key event_id
        let (_sk, sk_blob) = make_secret_key(key_bytes);
        let sk_eid = hash_event(&sk_blob);

        // Create identity chain for signing the inner message
        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        // Insert encrypted event first (before key)
        let (_msg, msg_blob) =
            make_message_signed(&signing_key, &signer_eid, "out of order encrypted");
        let (_enc, enc_blob) =
            make_encrypted_event(&key_bytes, &msg_blob, EVENT_TYPE_MESSAGE, &sk_eid);
        let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);

        // Project → Block
        let result = project_one(&conn, recorded_by, &enc_eid).unwrap();
        assert!(matches!(result, ProjectionDecision::Block { .. }));

        // Now insert and project the secret key
        insert_event_raw(&conn, recorded_by, &sk_blob);
        let r = project_one(&conn, recorded_by, &sk_eid).unwrap();
        assert_eq!(r, ProjectionDecision::Valid);

        // Encrypted event should have been cascade-unblocked
        let enc_b64 = event_id_to_base64(&enc_eid);
        let valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &enc_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            valid,
            "encrypted event should be auto-projected after key arrives"
        );

        // Verify inner message was projected
        let msg_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE message_id = ?1 AND recorded_by = ?2",
                rusqlite::params![&enc_b64, recorded_by],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(msg_count, 1);
    }

    #[test]
    fn test_encrypted_wrong_key_rejects() {
        let conn = setup();
        let recorded_by = "peer1";
        let key_a: [u8; 32] = rand::random();
        let key_b: [u8; 32] = rand::random();

        // Create and project key B
        let (_sk_b, sk_b_blob) = make_secret_key(key_b);
        let sk_b_eid = insert_event_raw(&conn, recorded_by, &sk_b_blob);
        project_one(&conn, recorded_by, &sk_b_eid).unwrap();

        // Create identity chain for signing the inner message
        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        // Encrypt with key A but reference key B
        let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "wrong key test");
        let (_enc, enc_blob) =
            make_encrypted_event(&key_a, &msg_blob, EVENT_TYPE_MESSAGE, &sk_b_eid);
        let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);

        let result = project_one(&conn, recorded_by, &enc_eid).unwrap();
        match result {
            ProjectionDecision::Reject { reason } => {
                assert!(reason.contains("decryption failed"), "reason: {}", reason);
            }
            other => panic!("expected Reject, got {:?}", other),
        }
    }

    #[test]
    fn test_encrypted_inner_type_mismatch_rejects() {
        use crate::events::fixed_layout;

        let conn = setup();
        let recorded_by = "peer1";
        let key_bytes: [u8; 32] = rand::random();

        // Create and project key
        let (_sk, sk_blob) = make_secret_key(key_bytes);
        let sk_eid = insert_event_raw(&conn, recorded_by, &sk_blob);
        project_one(&conn, recorded_by, &sk_eid).unwrap();

        // Craft a reaction-sized blob whose first byte is MESSAGE type (1)
        // to trigger inner type mismatch at the pipeline level.
        let reaction_wire_size = fixed_layout::REACTION_WIRE_SIZE;
        let mut fake_inner = vec![0u8; reaction_wire_size];
        fake_inner[0] = EVENT_TYPE_MESSAGE; // wrong: says message, envelope says reaction

        let (nonce, ciphertext, auth_tag) = encrypt_event_blob(&key_bytes, &fake_inner).unwrap();
        let enc = ParsedEvent::Encrypted(EncryptedEvent {
            created_at_ms: now_ms(),
            key_event_id: sk_eid,
            inner_type_code: EVENT_TYPE_REACTION, // declares reaction
            nonce,
            ciphertext, // 234 bytes, matches reaction wire size
            auth_tag,
        });
        let enc_blob = events::encode_event(&enc).unwrap();
        let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);

        let result = project_one(&conn, recorded_by, &enc_eid).unwrap();
        match result {
            ProjectionDecision::Reject { reason } => {
                // In fixed-size world, type mismatch manifests as parse error:
                // the 234-byte ciphertext decrypts but can't parse as type 1 (1194 bytes)
                assert!(
                    reason.contains("inner type mismatch") || reason.contains("inner event parse error"),
                    "reason: {}", reason
                );
            }
            other => panic!("expected Reject, got {:?}", other),
        }
    }

    #[test]
    fn test_encrypted_nested_rejects() {
        use crate::events::fixed_layout;

        let conn = setup();
        let recorded_by = "peer1";
        let key_bytes: [u8; 32] = rand::random();

        // Create and project key
        let (_sk, sk_blob) = make_secret_key(key_bytes);
        let sk_eid = insert_event_raw(&conn, recorded_by, &sk_blob);
        project_one(&conn, recorded_by, &sk_eid).unwrap();

        // inner_type_code=5 (encrypted) is now rejected at parser level
        // (encrypted_inner_wire_size returns None). Construct raw blob manually.
        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);
        let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "nested inner");
        let (_inner_enc, inner_enc_blob) =
            make_encrypted_event(&key_bytes, &msg_blob, EVENT_TYPE_MESSAGE, &sk_eid);

        // Manually build an outer encrypted blob with inner_type_code=5
        let (nonce, raw_ct, auth_tag) = encrypt_event_blob(&key_bytes, &inner_enc_blob).unwrap();
        let total = fixed_layout::ENCRYPTED_HEADER_BYTES + raw_ct.len() + fixed_layout::ENCRYPTED_AUTH_TAG_BYTES;
        let mut buf = vec![0u8; total];
        buf[0] = EVENT_TYPE_ENCRYPTED;
        buf[1..9].copy_from_slice(&now_ms().to_le_bytes());
        buf[9..41].copy_from_slice(&sk_eid);
        buf[41] = EVENT_TYPE_ENCRYPTED; // inner_type_code = 5 (nested)
        buf[42..54].copy_from_slice(&nonce);
        buf[54..54 + raw_ct.len()].copy_from_slice(&raw_ct);
        buf[54 + raw_ct.len()..].copy_from_slice(&auth_tag);

        let outer_eid = insert_event_raw(&conn, recorded_by, &buf);
        let result = project_one(&conn, recorded_by, &outer_eid).unwrap();
        match result {
            ProjectionDecision::Reject { reason } => {
                // Parser rejects unknown inner_type_code=5 before pipeline even runs
                assert!(reason.contains("parse error"), "reason: {}", reason);
            }
            other => panic!("expected Reject, got {:?}", other),
        }
    }

    #[test]
    fn test_encrypted_inner_dep_blocks() {
        let conn = setup();
        let recorded_by = "peer1";
        let key_bytes: [u8; 32] = rand::random();

        // Create and project key
        let (_sk, sk_blob) = make_secret_key(key_bytes);
        let sk_eid = insert_event_raw(&conn, recorded_by, &sk_blob);
        project_one(&conn, recorded_by, &sk_eid).unwrap();

        // Create identity chain for signing the inner reaction
        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        // Create encrypted reaction with missing target
        let fake_target = [88u8; 32];
        let (_rxn, rxn_blob) =
            make_reaction_signed(&signing_key, &signer_eid, &fake_target, "\u{1f44d}");
        let (_enc, enc_blob) = make_encrypted_event(&key_bytes, &rxn_blob, 2, &sk_eid);
        let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);

        let result = project_one(&conn, recorded_by, &enc_eid).unwrap();
        match result {
            ProjectionDecision::Block { missing } => {
                assert!(missing.contains(&fake_target));
            }
            other => panic!("expected Block on inner dep, got {:?}", other),
        }

        // Verify NOT in valid_events
        let enc_b64 = event_id_to_base64(&enc_eid);
        let valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &enc_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_encrypted_inner_dep_unblocks() {
        let conn = setup();
        let recorded_by = "peer1";
        let net_eid = setup_workspace_event(&conn, recorded_by);
        let key_bytes: [u8; 32] = rand::random();

        // Create and project key
        let (_sk, sk_blob) = make_secret_key(key_bytes);
        let sk_eid = insert_event_raw(&conn, recorded_by, &sk_blob);
        project_one(&conn, recorded_by, &sk_eid).unwrap();

        // Create identity chain for signing inner events
        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        // Create target message (pre-compute but don't insert yet)
        let (_msg, msg_blob) =
            make_message_signed(&signing_key, &signer_eid, "target for encrypted rxn");
        let msg_eid = hash_event(&msg_blob);

        // Create encrypted reaction targeting the message
        let (_rxn, rxn_blob) =
            make_reaction_signed(&signing_key, &signer_eid, &msg_eid, "\u{2764}\u{fe0f}");
        let (_enc, enc_blob) = make_encrypted_event(&key_bytes, &rxn_blob, 2, &sk_eid);
        let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);

        // Project → Block on inner dep (message)
        let result = project_one(&conn, recorded_by, &enc_eid).unwrap();
        assert!(matches!(result, ProjectionDecision::Block { .. }));

        // Now insert and project the message
        insert_event_raw(&conn, recorded_by, &msg_blob);
        let r = project_one(&conn, recorded_by, &msg_eid).unwrap();
        assert_eq!(r, ProjectionDecision::Valid);

        // Encrypted reaction should have been cascade-unblocked
        let enc_b64 = event_id_to_base64(&enc_eid);
        let valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &enc_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            valid,
            "encrypted reaction should be auto-projected after target message arrives"
        );
    }

    #[test]
    fn test_encrypted_rejection_recorded_durably() {
        let conn = setup();
        let recorded_by = "peer1";
        let key_a: [u8; 32] = rand::random();
        let key_b: [u8; 32] = rand::random();

        // Create and project key B
        let (_sk_b, sk_b_blob) = make_secret_key(key_b);
        let sk_b_eid = insert_event_raw(&conn, recorded_by, &sk_b_blob);
        project_one(&conn, recorded_by, &sk_b_eid).unwrap();

        // Create identity chain for signing the inner message
        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        // Encrypt with key A, reference key B → decryption fails
        let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "will be rejected");
        let (_enc, enc_blob) =
            make_encrypted_event(&key_a, &msg_blob, EVENT_TYPE_MESSAGE, &sk_b_eid);
        let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);

        let result = project_one(&conn, recorded_by, &enc_eid).unwrap();
        assert!(matches!(result, ProjectionDecision::Reject { .. }));

        // Verify in rejected_events
        let enc_b64 = event_id_to_base64(&enc_eid);
        let reason: String = conn
            .query_row(
                "SELECT reason FROM rejected_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &enc_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(reason.contains("decryption failed"));
    }

    #[test]
    fn test_encrypted_cross_tenant_isolation() {
        let conn = setup();
        let tenant_a = "tenant_a";
        let tenant_b = "tenant_b";
        let net_eid_a = setup_workspace_event(&conn, tenant_a);
        let key_bytes: [u8; 32] = rand::random();

        // Create and project key for tenant_a only
        let (_sk, sk_blob) = make_secret_key(key_bytes);
        let sk_eid = insert_event_raw(&conn, tenant_a, &sk_blob);
        let r = project_one(&conn, tenant_a, &sk_eid).unwrap();
        assert_eq!(r, ProjectionDecision::Valid);

        // Create identity chain for signing the inner message (for tenant_a)
        let (signer_eid, signing_key) = make_identity_chain(&conn, tenant_a);

        // Create encrypted message referencing that key
        let (_msg, msg_blob) =
            make_message_signed(&signing_key, &signer_eid, "tenant-scoped encryption");
        let (_enc, enc_blob) =
            make_encrypted_event(&key_bytes, &msg_blob, EVENT_TYPE_MESSAGE, &sk_eid);
        let enc_eid = insert_event_raw(&conn, tenant_a, &enc_blob);

        // Project for tenant_a → Valid
        let r_a = project_one(&conn, tenant_a, &enc_eid).unwrap();
        assert_eq!(r_a, ProjectionDecision::Valid);

        // Record for tenant_b (also record the sk_blob event)
        insert_recorded_event(&conn, tenant_b, &enc_eid, now_ms() as i64, "test").unwrap();
        insert_recorded_event(&conn, tenant_b, &sk_eid, now_ms() as i64, "test").unwrap();

        // Project encrypted event for tenant_b → Block (key not valid for B)
        let r_b = project_one(&conn, tenant_b, &enc_eid).unwrap();
        match r_b {
            ProjectionDecision::Block { missing } => {
                assert_eq!(missing.len(), 1);
                assert_eq!(missing[0], sk_eid);
            }
            other => panic!("expected Block for tenant_b, got {:?}", other),
        }
    }

    // ===== Encrypted-inner parity characterization tests (Phase 1) =====
    //
    // These tests lock the behavioral equivalence boundaries between direct
    // event projection and encrypted-inner projection. They must remain green
    // through the refactor (Phases 2-3) to prove no semantic drift.

    /// Helper: set up a shared encryption context (identity chain + secret key).
    /// Returns (signer_eid, signing_key, key_bytes, sk_eid).
    fn setup_encryption_ctx(
        conn: &Connection,
        recorded_by: &str,
    ) -> (EventId, SigningKey, [u8; 32], EventId) {
        let (signer_eid, signing_key) = make_identity_chain(conn, recorded_by);
        let key_bytes: [u8; 32] = rand::random();
        let (_sk, sk_blob) = make_secret_key(key_bytes);
        let sk_eid = insert_event_raw(conn, recorded_by, &sk_blob);
        let r = project_one(conn, recorded_by, &sk_eid).unwrap();
        assert_eq!(r, ProjectionDecision::Valid);
        (signer_eid, signing_key, key_bytes, sk_eid)
    }

    // --- Message parity ---

    #[test]
    fn test_encrypted_parity_message_projected_state() {
        // Verify that an encrypted message produces the same projected row
        // (in `messages`) as a directly projected message, using the
        // *outer* encrypted event_id as the message_id.
        let conn = setup();
        let recorded_by = "peer1";
        let _ws = setup_workspace_event(&conn, recorded_by);
        let (signer_eid, signing_key, key_bytes, sk_eid) =
            setup_encryption_ctx(&conn, recorded_by);

        // Direct message
        let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "direct hello");
        let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
        let r_direct = project_one(&conn, recorded_by, &msg_eid).unwrap();
        assert_eq!(r_direct, ProjectionDecision::Valid);

        // Encrypted message with same content
        let (_msg2, msg2_blob) = make_message_signed(&signing_key, &signer_eid, "encrypted hello");
        let (_enc, enc_blob) =
            make_encrypted_event(&key_bytes, &msg2_blob, EVENT_TYPE_MESSAGE, &sk_eid);
        let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);
        let r_enc = project_one(&conn, recorded_by, &enc_eid).unwrap();
        assert_eq!(r_enc, ProjectionDecision::Valid);

        // Both should be in messages table
        let msg_b64 = event_id_to_base64(&msg_eid);
        let enc_b64 = event_id_to_base64(&enc_eid);

        let direct_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1 AND message_id = ?2",
                rusqlite::params![recorded_by, &msg_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(direct_count, 1, "direct message should be in messages table");

        let enc_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1 AND message_id = ?2",
                rusqlite::params![recorded_by, &enc_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(enc_count, 1, "encrypted message should be in messages table with outer event_id");

        // Both in valid_events
        let direct_valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &msg_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(direct_valid);

        let enc_valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &enc_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(enc_valid);
    }

    // --- Reaction parity ---

    #[test]
    fn test_encrypted_parity_reaction_projected_state() {
        // Verify encrypted reaction produces the same projected row (in `reactions`)
        // as a direct reaction, anchored to outer encrypted event_id.
        let conn = setup();
        let recorded_by = "peer1";
        let _ws = setup_workspace_event(&conn, recorded_by);
        let (signer_eid, signing_key, key_bytes, sk_eid) =
            setup_encryption_ctx(&conn, recorded_by);

        // Create a target message
        let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "reaction target");
        let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
        project_one(&conn, recorded_by, &msg_eid).unwrap();

        // Direct reaction
        let (_rxn, rxn_blob) =
            make_reaction_signed(&signing_key, &signer_eid, &msg_eid, "\u{1f44d}");
        let rxn_eid = insert_event_raw(&conn, recorded_by, &rxn_blob);
        let r_direct = project_one(&conn, recorded_by, &rxn_eid).unwrap();
        assert_eq!(r_direct, ProjectionDecision::Valid);

        // Encrypted reaction
        let (_rxn2, rxn2_blob) =
            make_reaction_signed(&signing_key, &signer_eid, &msg_eid, "\u{2764}\u{fe0f}");
        let (_enc, enc_blob) =
            make_encrypted_event(&key_bytes, &rxn2_blob, EVENT_TYPE_REACTION, &sk_eid);
        let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);
        let r_enc = project_one(&conn, recorded_by, &enc_eid).unwrap();
        assert_eq!(r_enc, ProjectionDecision::Valid);

        // Both should be in reactions table
        let rxn_b64 = event_id_to_base64(&rxn_eid);
        let enc_b64 = event_id_to_base64(&enc_eid);

        let direct_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &rxn_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(direct_count, 1, "direct reaction should be in reactions table");

        let enc_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &enc_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(enc_count, 1, "encrypted reaction should be in reactions table with outer event_id");
    }

    // --- Message deletion parity ---

    #[test]
    fn test_encrypted_parity_deletion_valid() {
        // Verify encrypted message deletion produces the same tombstone state
        // as direct deletion, with the encrypted wrapper event_id in valid_events.
        let conn = setup();
        let recorded_by = "peer1";
        let _ws = setup_workspace_event(&conn, recorded_by);
        let (signer_eid, signing_key, key_bytes, sk_eid) =
            setup_encryption_ctx(&conn, recorded_by);

        // Create and project a message (will be deleted by encrypted deletion)
        let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "to be deleted via encrypted");
        let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
        project_one(&conn, recorded_by, &msg_eid).unwrap();

        // Create deletion event (author_id = [2;32] matches message author)
        let (_del, del_blob) =
            make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [2u8; 32]);

        // Encrypt the deletion
        let (_enc, enc_blob) =
            make_encrypted_event(&key_bytes, &del_blob, EVENT_TYPE_MESSAGE_DELETION, &sk_eid);
        let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);
        let result = project_one(&conn, recorded_by, &enc_eid).unwrap();
        assert_eq!(result, ProjectionDecision::Valid);

        // Message should be deleted
        let msg_b64 = event_id_to_base64(&msg_eid);
        let msg_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1 AND message_id = ?2",
                rusqlite::params![recorded_by, &msg_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(msg_count, 0, "message should be deleted");

        // Tombstone should exist
        let tomb_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM deleted_messages WHERE recorded_by = ?1 AND message_id = ?2",
                rusqlite::params![recorded_by, &msg_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tomb_count, 1, "tombstone should exist");

        // Encrypted wrapper event should be in valid_events (outer event anchoring)
        let enc_b64 = event_id_to_base64(&enc_eid);
        let enc_valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &enc_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(enc_valid, "encrypted wrapper should be in valid_events");
    }

    #[test]
    fn test_encrypted_parity_deletion_inner_dep_blocks() {
        // Encrypted deletion where the target message doesn't exist yet.
        // Should block, with block rows anchored to outer encrypted event_id.
        let conn = setup();
        let recorded_by = "peer1";
        let _ws = setup_workspace_event(&conn, recorded_by);
        let (signer_eid, signing_key, key_bytes, sk_eid) =
            setup_encryption_ctx(&conn, recorded_by);

        // Create deletion targeting a non-existent message
        let fake_target = [77u8; 32];
        let (_del, del_blob) =
            make_deletion_signed(&signing_key, &signer_eid, &fake_target, [2u8; 32]);
        let (_enc, enc_blob) =
            make_encrypted_event(&key_bytes, &del_blob, EVENT_TYPE_MESSAGE_DELETION, &sk_eid);
        let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);
        let result = project_one(&conn, recorded_by, &enc_eid).unwrap();

        match result {
            ProjectionDecision::Block { missing } => {
                assert!(missing.contains(&fake_target), "should block on missing target");
            }
            other => panic!("expected Block, got {:?}", other),
        }

        // Block rows should be keyed to outer encrypted event_id
        let enc_b64 = event_id_to_base64(&enc_eid);
        let blocked: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM blocked_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &enc_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(blocked, "blocked_events row should use outer encrypted event_id");

        let dep_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM blocked_event_deps WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &enc_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(dep_count > 0, "blocked_event_deps should use outer encrypted event_id");
    }

    // --- File slice parity ---

    #[test]
    fn test_encrypted_parity_file_slice_valid() {
        // Verify encrypted file_slice produces the same projected row as direct,
        // with outer encrypted event_id in file_slices and valid_events.
        let conn = setup();
        let recorded_by = "peer1";
        let _ws = setup_workspace_event(&conn, recorded_by);
        let (signer_eid, signing_key, key_bytes, sk_eid) =
            setup_encryption_ctx(&conn, recorded_by);

        // Create descriptor (required for file_slice projection)
        let file_id = [99u8; 32];
        setup_descriptor_for_file(&conn, recorded_by, &signing_key, &signer_eid, file_id);

        // Create and encrypt file_slice
        let (_fs, fs_blob) =
            make_file_slice(&signing_key, &signer_eid, file_id, 0, b"encrypted slice data");
        let (_enc, enc_blob) =
            make_encrypted_event(&key_bytes, &fs_blob, EVENT_TYPE_FILE_SLICE, &sk_eid);
        let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);
        let result = project_one(&conn, recorded_by, &enc_eid).unwrap();
        assert_eq!(result, ProjectionDecision::Valid);

        // File slice should be in file_slices table with outer event_id
        let enc_b64 = event_id_to_base64(&enc_eid);
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM file_slices WHERE recorded_by = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &enc_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "encrypted file_slice should be in file_slices with outer event_id");

        // Outer event should be in valid_events
        let enc_valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &enc_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(enc_valid, "encrypted wrapper should be in valid_events");
    }

    #[test]
    fn test_encrypted_parity_file_slice_guard_blocks() {
        // Encrypted file_slice without a descriptor should guard-block,
        // with block state anchored to outer encrypted event_id.
        let conn = setup();
        let recorded_by = "peer1";
        let _ws = setup_workspace_event(&conn, recorded_by);
        let (signer_eid, signing_key, key_bytes, sk_eid) =
            setup_encryption_ctx(&conn, recorded_by);

        // No descriptor — file_slice should guard-block
        let file_id = [88u8; 32];
        let (_fs, fs_blob) =
            make_file_slice(&signing_key, &signer_eid, file_id, 0, b"no descriptor");
        let (_enc, enc_blob) =
            make_encrypted_event(&key_bytes, &fs_blob, EVENT_TYPE_FILE_SLICE, &sk_eid);
        let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);
        let result = project_one(&conn, recorded_by, &enc_eid).unwrap();

        // Should block (guard-block returns Block with empty missing)
        assert!(
            matches!(result, ProjectionDecision::Block { .. }),
            "encrypted file_slice should block without descriptor, got {:?}",
            result
        );

        // Should NOT be in valid_events
        let enc_b64 = event_id_to_base64(&enc_eid);
        let enc_valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &enc_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!enc_valid, "encrypted file_slice should not be valid without descriptor");
    }

    // --- Inner signer failure parity ---

    #[test]
    fn test_encrypted_inner_signer_dep_missing_blocks() {
        // Encrypted message where the inner event references a signer that
        // doesn't exist. Should reject (not block) since signer resolution
        // fails after deps are satisfied.
        let conn = setup();
        let recorded_by = "peer1";
        let _ws = setup_workspace_event(&conn, recorded_by);
        let key_bytes: [u8; 32] = rand::random();

        // Create and project key
        let (_sk, sk_blob) = make_secret_key(key_bytes);
        let sk_eid = insert_event_raw(&conn, recorded_by, &sk_blob);
        project_one(&conn, recorded_by, &sk_eid).unwrap();

        // Create message signed with a key whose signer event doesn't exist
        // in valid_events (using a fabricated signer_eid)
        let mut rng = rand::thread_rng();
        let orphan_key = SigningKey::generate(&mut rng);
        let fake_signer_eid = [0xDD; 32];
        let msg = MessageEvent {
            created_at_ms: now_ms(),
            workspace_id: [1u8; 32],
            author_id: [2u8; 32],
            content: "orphan signer".to_string(),
            signed_by: fake_signer_eid,
            signer_type: 5,
            signature: [0u8; 64],
        };
        let event = ParsedEvent::Message(msg);
        let mut msg_blob = events::encode_event(&event).unwrap();
        sign_blob(&orphan_key, &mut msg_blob);

        // Encrypt it
        let (_enc, enc_blob) =
            make_encrypted_event(&key_bytes, &msg_blob, EVENT_TYPE_MESSAGE, &sk_eid);
        let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);

        // The inner message deps include signer_eid as a dep. Since that dep
        // doesn't exist in valid_events, this should block on the missing dep.
        let result = project_one(&conn, recorded_by, &enc_eid).unwrap();
        match result {
            ProjectionDecision::Block { missing } => {
                assert!(
                    missing.contains(&fake_signer_eid),
                    "should block on missing signer dep"
                );
            }
            other => panic!("expected Block on missing signer dep, got {:?}", other),
        }

        // Block anchored to outer event_id
        let enc_b64 = event_id_to_base64(&enc_eid);
        let blocked: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM blocked_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &enc_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(blocked, "block should be anchored to outer encrypted event_id");
    }

    #[test]
    fn test_encrypted_inner_invalid_signature_rejects() {
        // Encrypted message with a valid signer key but wrong signature bytes.
        // Should reject via the signer verification stage.
        let conn = setup();
        let recorded_by = "peer1";
        let _ws = setup_workspace_event(&conn, recorded_by);
        let (signer_eid, _signing_key, key_bytes, sk_eid) =
            setup_encryption_ctx(&conn, recorded_by);

        // Create message but sign with a DIFFERENT key
        let mut rng = rand::thread_rng();
        let wrong_key = SigningKey::generate(&mut rng);
        let msg = MessageEvent {
            created_at_ms: now_ms(),
            workspace_id: [1u8; 32],
            author_id: [2u8; 32],
            content: "bad sig".to_string(),
            signed_by: signer_eid,
            signer_type: 5,
            signature: [0u8; 64],
        };
        let event = ParsedEvent::Message(msg);
        let mut msg_blob = events::encode_event(&event).unwrap();
        sign_blob(&wrong_key, &mut msg_blob);

        let (_enc, enc_blob) =
            make_encrypted_event(&key_bytes, &msg_blob, EVENT_TYPE_MESSAGE, &sk_eid);
        let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);
        let result = project_one(&conn, recorded_by, &enc_eid).unwrap();

        match result {
            ProjectionDecision::Reject { reason } => {
                assert!(
                    reason.contains("invalid signature") || reason.contains("inner event invalid signature"),
                    "expected signature rejection, got: {}",
                    reason
                );
            }
            other => panic!("expected Reject for bad inner signature, got {:?}", other),
        }

        // Rejection anchored to outer event_id
        let enc_b64 = event_id_to_base64(&enc_eid);
        let rejected: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM rejected_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &enc_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(rejected, "rejection should be recorded for outer encrypted event_id");
    }

    // --- Identity-inside-encrypted rejection ---

    #[test]
    fn test_encrypted_identity_event_rejects() {
        // An identity event (e.g. Workspace) wrapped in encrypted should reject
        // with a clear reason about disallowed inner families.
        let conn = setup();
        let recorded_by = "peer1";
        let key_bytes: [u8; 32] = rand::random();

        let (_sk, sk_blob) = make_secret_key(key_bytes);
        let sk_eid = insert_event_raw(&conn, recorded_by, &sk_blob);
        project_one(&conn, recorded_by, &sk_eid).unwrap();

        // Create a workspace event and encrypt it
        let ws = ParsedEvent::Workspace(WorkspaceEvent {
            created_at_ms: now_ms(),
            public_key: [0xBB; 32],
        });
        let ws_blob = events::encode_event(&ws).unwrap();
        let (_enc, enc_blob) = make_encrypted_event(
            &key_bytes,
            &ws_blob,
            crate::events::EVENT_TYPE_WORKSPACE,
            &sk_eid,
        );
        let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);
        let result = project_one(&conn, recorded_by, &enc_eid).unwrap();

        match result {
            ProjectionDecision::Reject { reason } => {
                assert!(
                    reason.contains("not admissible inside encrypted wrappers"),
                    "reason: {}",
                    reason
                );
            }
            other => panic!("expected Reject for identity inside encrypted, got {:?}", other),
        }
    }

    // ===== Message deletion helpers =====

    /// Convenience: create identity chain + signed deletion.
    fn make_deletion(
        conn: &Connection,
        recorded_by: &str,
        target: &EventId,
        author_id: [u8; 32],
    ) -> (ParsedEvent, Vec<u8>) {
        let (signer_eid, signing_key) = make_identity_chain(conn, recorded_by);
        make_deletion_signed(&signing_key, &signer_eid, target, author_id)
    }

    #[test]
    fn test_project_message_deletion_valid() {
        let conn = setup();
        let recorded_by = "peer1";
        let net_eid = setup_workspace_event(&conn, recorded_by);

        // Create identity chain once for this tenant
        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        // Create and project a message
        let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "to be deleted");
        let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
        let r = project_one(&conn, recorded_by, &msg_eid).unwrap();
        assert_eq!(r, ProjectionDecision::Valid);

        // Create and project the deletion
        let (_del, del_blob) = make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [2u8; 32]); // author_id matches message
        let del_eid = insert_event_raw(&conn, recorded_by, &del_blob);
        let result = project_one(&conn, recorded_by, &del_eid).unwrap();
        assert_eq!(result, ProjectionDecision::Valid);

        // Message should be removed
        let msg_b64 = event_id_to_base64(&msg_eid);
        let msg_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1 AND message_id = ?2",
                rusqlite::params![recorded_by, &msg_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(msg_count, 0);

        // Tombstone should exist
        let del_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM deleted_messages WHERE recorded_by = ?1 AND message_id = ?2",
                rusqlite::params![recorded_by, &msg_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(del_count, 1);

        // Deletion event should be in valid_events
        let del_b64 = event_id_to_base64(&del_eid);
        let valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &del_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(valid);
    }

    #[test]
    fn test_deletion_cascades_reactions() {
        let conn = setup();
        let recorded_by = "peer1";
        let net_eid = setup_workspace_event(&conn, recorded_by);

        // Create identity chain once for this tenant
        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        // Create message + 2 reactions
        let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "with reactions");
        let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
        project_one(&conn, recorded_by, &msg_eid).unwrap();

        let (_rxn1, rxn1_blob) =
            make_reaction_signed(&signing_key, &signer_eid, &msg_eid, "\u{1f44d}");
        let rxn1_eid = insert_event_raw(&conn, recorded_by, &rxn1_blob);
        project_one(&conn, recorded_by, &rxn1_eid).unwrap();

        let (_rxn2, rxn2_blob) =
            make_reaction_signed(&signing_key, &signer_eid, &msg_eid, "\u{2764}\u{fe0f}");
        let rxn2_eid = insert_event_raw(&conn, recorded_by, &rxn2_blob);
        project_one(&conn, recorded_by, &rxn2_eid).unwrap();

        // Verify 2 reactions exist
        let rxn_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1",
                rusqlite::params![recorded_by],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rxn_count, 2);

        // Delete the message
        let (_del, del_blob) = make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [2u8; 32]);
        let del_eid = insert_event_raw(&conn, recorded_by, &del_blob);
        let result = project_one(&conn, recorded_by, &del_eid).unwrap();
        assert_eq!(result, ProjectionDecision::Valid);

        // Reactions should be cascaded away
        let rxn_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1",
                rusqlite::params![recorded_by],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rxn_count, 0);

        // Tombstone exists
        let del_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM deleted_messages WHERE recorded_by = ?1",
                rusqlite::params![recorded_by],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(del_count, 1);
    }

    #[test]
    fn test_deletion_blocks_on_missing_target() {
        let conn = setup();
        let recorded_by = "peer1";

        let fake_target = [77u8; 32];
        let (_del, del_blob) = make_deletion(&conn, recorded_by, &fake_target, [2u8; 32]);
        let del_eid = insert_event_raw(&conn, recorded_by, &del_blob);

        let result = project_one(&conn, recorded_by, &del_eid).unwrap();
        match result {
            ProjectionDecision::Block { missing } => {
                assert!(missing.contains(&fake_target));
            }
            other => panic!("expected Block, got {:?}", other),
        }
    }

    #[test]
    fn test_deletion_unblocks_when_target_arrives() {
        let conn = setup();
        let recorded_by = "peer1";
        let net_eid = setup_workspace_event(&conn, recorded_by);

        // Create identity chain for signing
        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        // Pre-compute message blob and eid
        let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "will arrive later");
        let msg_eid = hash_event(&msg_blob);

        // Create deletion first (before message exists)
        let (_del, del_blob) = make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [2u8; 32]);
        let del_eid = insert_event_raw(&conn, recorded_by, &del_blob);

        // Project deletion — should block
        let result = project_one(&conn, recorded_by, &del_eid).unwrap();
        assert!(matches!(result, ProjectionDecision::Block { .. }));

        // Now insert and project the message
        insert_event_raw(&conn, recorded_by, &msg_blob);
        let r = project_one(&conn, recorded_by, &msg_eid).unwrap();
        assert_eq!(r, ProjectionDecision::Valid);

        // Deletion should have been cascade-unblocked and executed
        let del_b64 = event_id_to_base64(&del_eid);
        let valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &del_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            valid,
            "deletion should be auto-projected after target arrives"
        );

        // Message should be deleted (tombstoned)
        let msg_b64 = event_id_to_base64(&msg_eid);
        let msg_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1 AND message_id = ?2",
                rusqlite::params![recorded_by, &msg_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(msg_count, 0);

        let tombstone: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM deleted_messages WHERE recorded_by = ?1 AND message_id = ?2",
                rusqlite::params![recorded_by, &msg_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tombstone, 1);
    }

    #[test]
    fn test_deletion_wrong_author_rejects() {
        let conn = setup();
        let recorded_by = "peer1";
        let net_eid = setup_workspace_event(&conn, recorded_by);

        // Create identity chain once for this tenant
        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        // Create message with author_id = [2u8; 32]
        let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "wrong author test");
        let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
        project_one(&conn, recorded_by, &msg_eid).unwrap();

        // Create deletion with different author_id
        let (_del, del_blob) =
            make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [99u8; 32]); // wrong author
        let del_eid = insert_event_raw(&conn, recorded_by, &del_blob);

        let result = project_one(&conn, recorded_by, &del_eid).unwrap();
        match result {
            ProjectionDecision::Reject { reason } => {
                assert!(
                    reason.contains("deletion author does not match"),
                    "reason: {}",
                    reason
                );
            }
            other => panic!("expected Reject, got {:?}", other),
        }
    }

    #[test]
    fn test_deletion_idempotent() {
        let conn = setup();
        let recorded_by = "peer1";
        let net_eid = setup_workspace_event(&conn, recorded_by);

        // Create identity chain for signing
        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        // Create and project message
        let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "delete me twice");
        let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
        project_one(&conn, recorded_by, &msg_eid).unwrap();

        // First deletion
        let (_del1, del1_blob) =
            make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [2u8; 32]);
        let del1_eid = insert_event_raw(&conn, recorded_by, &del1_blob);
        let r1 = project_one(&conn, recorded_by, &del1_eid).unwrap();
        assert_eq!(r1, ProjectionDecision::Valid);

        // Second deletion (same target, different event) — also signed
        let (_del2, del2_blob) =
            make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [2u8; 32]);
        let del2_eid = insert_event_raw(&conn, recorded_by, &del2_blob);
        let r2 = project_one(&conn, recorded_by, &del2_eid).unwrap();
        // Second deletion finds tombstone already exists → AlreadyProcessed from projector,
        // which means apply_projection returns AlreadyProcessed, pipeline treats it as Valid
        assert!(matches!(r2, ProjectionDecision::Valid));

        // Only one tombstone
        let del_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM deleted_messages WHERE recorded_by = ?1",
                rusqlite::params![recorded_by],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(del_count, 1);
    }

    #[test]
    fn test_reaction_after_deletion_skipped() {
        let conn = setup();
        let recorded_by = "peer1";
        let net_eid = setup_workspace_event(&conn, recorded_by);

        // Create identity chain once for this tenant
        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        // Create and project message
        let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "will be deleted");
        let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
        project_one(&conn, recorded_by, &msg_eid).unwrap();

        // Delete message
        let (_del, del_blob) = make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [2u8; 32]);
        let del_eid = insert_event_raw(&conn, recorded_by, &del_blob);
        project_one(&conn, recorded_by, &del_eid).unwrap();

        // Now create a reaction targeting the deleted message
        let (_rxn, rxn_blob) =
            make_reaction_signed(&signing_key, &signer_eid, &msg_eid, "\u{1f44d}");
        let rxn_eid = insert_event_raw(&conn, recorded_by, &rxn_blob);
        let result = project_one(&conn, recorded_by, &rxn_eid).unwrap();

        // The reaction is structurally valid (target dep exists in valid_events),
        // but project_reaction skips it because the message is deleted
        assert_eq!(result, ProjectionDecision::Valid);

        // No reactions in the table
        let rxn_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1",
                rusqlite::params![recorded_by],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rxn_count, 0);
    }

    #[test]
    fn test_deletion_convergence() {
        let conn = setup();
        let recorded_by = "peer1";
        let net_eid = setup_workspace_event(&conn, recorded_by);

        // Create identity chain for signing (used across both orderings)
        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        // === Forward order: msg → rxn → del ===
        let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "convergence test");
        let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
        project_one(&conn, recorded_by, &msg_eid).unwrap();

        let (_rxn, rxn_blob) =
            make_reaction_signed(&signing_key, &signer_eid, &msg_eid, "\u{1f44d}");
        let rxn_eid = insert_event_raw(&conn, recorded_by, &rxn_blob);
        project_one(&conn, recorded_by, &rxn_eid).unwrap();

        let (_del, del_blob) = make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [2u8; 32]);
        let del_eid = insert_event_raw(&conn, recorded_by, &del_blob);
        project_one(&conn, recorded_by, &del_eid).unwrap();

        // Capture forward state
        let fwd_msg: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
                rusqlite::params![recorded_by],
                |row| row.get(0),
            )
            .unwrap();
        let fwd_rxn: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1",
                rusqlite::params![recorded_by],
                |row| row.get(0),
            )
            .unwrap();
        let fwd_del: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM deleted_messages WHERE recorded_by = ?1",
                rusqlite::params![recorded_by],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(fwd_msg, 0, "message should be deleted");
        assert_eq!(fwd_rxn, 0, "reactions should be cascaded");
        assert_eq!(fwd_del, 1, "tombstone should exist");

        // === Reverse order: clear content tables and replay del → rxn → msg ===
        // Only clear the 3 content events from valid_events, keeping identity chain intact
        let msg_b64 = event_id_to_base64(&msg_eid);
        let rxn_b64 = event_id_to_base64(&rxn_eid);
        let del_b64 = event_id_to_base64(&del_eid);
        conn.execute(
            "DELETE FROM messages WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
        )
        .unwrap();
        conn.execute(
            "DELETE FROM reactions WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
        )
        .unwrap();
        conn.execute(
            "DELETE FROM deleted_messages WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
        )
        .unwrap();
        for eid_b64 in [&msg_b64, &rxn_b64, &del_b64] {
            conn.execute(
                "DELETE FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, eid_b64],
            )
            .unwrap();
        }
        conn.execute(
            "DELETE FROM blocked_event_deps WHERE peer_id = ?1",
            rusqlite::params![recorded_by],
        )
        .unwrap();
        conn.execute(
            "DELETE FROM rejected_events WHERE peer_id = ?1",
            rusqlite::params![recorded_by],
        )
        .unwrap();

        // Re-insert workspace event as valid (it was cleared above)
        let net_b64 = event_id_to_base64(&net_eid);
        conn.execute(
            "INSERT OR IGNORE INTO valid_events (peer_id, event_id) VALUES (?1, ?2)",
            rusqlite::params![recorded_by, &net_b64],
        ).unwrap();

        // Project in reverse order: del first (blocks), then rxn (blocks), then msg (unblocks all)
        project_one(&conn, recorded_by, &del_eid).unwrap();
        project_one(&conn, recorded_by, &rxn_eid).unwrap();
        project_one(&conn, recorded_by, &msg_eid).unwrap();

        // Capture reverse state
        let rev_msg: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
                rusqlite::params![recorded_by],
                |row| row.get(0),
            )
            .unwrap();
        let rev_rxn: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1",
                rusqlite::params![recorded_by],
                |row| row.get(0),
            )
            .unwrap();
        let rev_del: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM deleted_messages WHERE recorded_by = ?1",
                rusqlite::params![recorded_by],
                |row| row.get(0),
            )
            .unwrap();

        // Both orders produce the same result
        assert_eq!(
            rev_msg, fwd_msg,
            "message count mismatch: fwd={}, rev={}",
            fwd_msg, rev_msg
        );
        assert_eq!(
            rev_rxn, fwd_rxn,
            "reaction count mismatch: fwd={}, rev={}",
            fwd_rxn, rev_rxn
        );
        assert_eq!(
            rev_del, fwd_del,
            "tombstone count mismatch: fwd={}, rev={}",
            fwd_del, rev_del
        );
    }

    #[test]
    fn test_unsupported_signer_type_rejects() {
        let conn = setup();
        let recorded_by = "peer1";
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let (signer_eid, _signing_key) = make_identity_chain(&conn, recorded_by);

        // Create a signed memo but mutate signer_type byte to 255
        let (_memo, mut memo_blob) = make_signed_memo(&signing_key, &signer_eid, "bad signer type");
        // signer_type is at byte offset 41 in the wire format
        memo_blob[41] = 255;
        // Re-hash since blob changed
        let memo_eid = insert_event_raw(&conn, recorded_by, &memo_blob);

        let result = project_one(&conn, recorded_by, &memo_eid).unwrap();
        match result {
            ProjectionDecision::Reject { reason } => {
                assert!(
                    reason.contains("unsupported signer_type"),
                    "reason: {}",
                    reason
                );
            }
            other => panic!("expected Reject, got {:?}", other),
        }

        // Verify rejected_events row exists
        let memo_b64 = event_id_to_base64(&memo_eid);
        let rej_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM rejected_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &memo_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rej_count, 1);
    }

    #[test]
    fn test_emit_cross_tenant_records_and_projects() {
        use crate::projection::emit::emit_deterministic_event;

        let conn = setup();
        let tenant_a = "tenant_a";
        let tenant_b = "tenant_b";
        let net_eid = setup_workspace_event(&conn, tenant_a);
        // Also mark valid for tenant_b
        let net_b64 = event_id_to_base64(&net_eid);
        insert_recorded_event(&conn, tenant_b, &net_eid, now_ms() as i64, "test").unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO valid_events (peer_id, event_id) VALUES (?1, ?2)",
            rusqlite::params![tenant_b, &net_b64],
        ).unwrap();

        // Use a SecretKey event (unsigned, no signer_required) for the cross-tenant
        // emit test. This avoids needing to set up identity chains for emit_deterministic_event.
        let sk = ParsedEvent::SecretKey(SecretKeyEvent {
            created_at_ms: 1000,
            key_bytes: [42u8; 32],
        });

        // Tenant A emits it
        let eid_a = emit_deterministic_event(&conn, tenant_a, &sk).unwrap();
        let eid_b64 = event_id_to_base64(&eid_a);

        // Tenant B emits the same deterministic event
        let eid_b = emit_deterministic_event(&conn, tenant_b, &sk).unwrap();
        assert_eq!(
            eid_a, eid_b,
            "same deterministic event should produce same event_id"
        );

        // Global events table: 1 row
        let event_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE event_id = ?1",
                rusqlite::params![&eid_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(event_count, 1);

        // recorded_events: 2 rows (one per tenant)
        let rec_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM recorded_events WHERE event_id = ?1",
                rusqlite::params![&eid_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rec_count, 2);

        // valid_events: 2 rows (one per tenant)
        for tenant in [tenant_a, tenant_b] {
            let valid: bool = conn
                .query_row(
                    "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                    rusqlite::params![tenant, &eid_b64],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(valid, "tenant {} should have valid_events entry", tenant);
        }

        // secret_keys: 2 rows (one per tenant)
        let sk_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM secret_keys WHERE event_id = ?1",
                rusqlite::params![&eid_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(sk_count, 2, "both tenants should have projected secret_key");
    }

    #[test]
    fn test_emit_local_share_scope_no_neg_items() {
        use crate::projection::emit::emit_deterministic_event;

        let conn = setup();
        let recorded_by = "peer1";

        // SecretKeyEvent has ShareScope::Local
        let sk = ParsedEvent::SecretKey(SecretKeyEvent {
            created_at_ms: 2000,
            key_bytes: [42u8; 32],
        });

        let eid = emit_deterministic_event(&conn, recorded_by, &sk).unwrap();
        let eid_b64 = event_id_to_base64(&eid);

        // events table should have the event
        let event_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE event_id = ?1",
                rusqlite::params![&eid_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(event_count, 1);

        // recorded_events should have the entry
        let rec_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM recorded_events WHERE event_id = ?1 AND peer_id = ?2",
                rusqlite::params![&eid_b64, recorded_by],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rec_count, 1);

        // neg_items should have 0 rows (ShareScope::Local)
        let neg_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM neg_items", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            neg_count, 0,
            "local-scope events must not be inserted into neg_items"
        );
    }

    #[test]
    fn test_post_tombstone_wrong_author_deletion_rejects() {
        let conn = setup();
        let recorded_by = "peer1";
        let net_eid = setup_workspace_event(&conn, recorded_by);

        // Create identity chain for signing
        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        // Create and project a message (author_id = [2u8; 32])
        let (_msg, msg_blob) =
            make_message_signed(&signing_key, &signer_eid, "post-tombstone auth test");
        let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
        project_one(&conn, recorded_by, &msg_eid).unwrap();

        // Delete with correct author → Valid
        let (_del1, del1_blob) =
            make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [2u8; 32]);
        let del1_eid = insert_event_raw(&conn, recorded_by, &del1_blob);
        let r1 = project_one(&conn, recorded_by, &del1_eid).unwrap();
        assert_eq!(r1, ProjectionDecision::Valid);

        // Second deletion with wrong author_id = [99u8; 32] — also signed
        let (_del2, del2_blob) =
            make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [99u8; 32]);
        let del2_eid = insert_event_raw(&conn, recorded_by, &del2_blob);
        let r2 = project_one(&conn, recorded_by, &del2_eid).unwrap();

        // Should be Reject, NOT AlreadyProcessed or Valid
        match r2 {
            ProjectionDecision::Reject { reason } => {
                assert!(
                    reason.contains("deletion author does not match"),
                    "reason: {}",
                    reason
                );
            }
            other => panic!(
                "expected Reject for wrong-author post-tombstone deletion, got {:?}",
                other
            ),
        }

        // rejected_events should have an entry for the wrong-author deletion
        let del2_b64 = event_id_to_base64(&del2_eid);
        let rej_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM rejected_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &del2_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rej_count, 1);
    }

    #[test]
    fn test_rejected_events_recorded_for_invalid_sig() {
        let conn = setup();
        let recorded_by = "peer1";
        let mut rng = rand::thread_rng();
        let wrong_key = SigningKey::generate(&mut rng);

        // Create identity chain as signer
        let (signer_eid, _signing_key) = make_identity_chain(&conn, recorded_by);

        // Sign the memo with the WRONG key
        let (_memo, memo_blob) = make_signed_memo(&wrong_key, &signer_eid, "bad sig memo");
        let memo_eid = insert_event_raw(&conn, recorded_by, &memo_blob);

        let result = project_one(&conn, recorded_by, &memo_eid).unwrap();
        assert!(matches!(result, ProjectionDecision::Reject { .. }));

        // Verify rejected_events row exists with correct reason
        let memo_b64 = event_id_to_base64(&memo_eid);
        let rej_reason: String = conn
            .query_row(
                "SELECT reason FROM rejected_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &memo_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            rej_reason.contains("invalid signature"),
            "reason: {}",
            rej_reason
        );
    }

    // === File attachment helpers ===

    fn make_file_slice(
        signing_key: &SigningKey,
        signer_event_id: &EventId,
        file_id: [u8; 32],
        slice_number: u32,
        ciphertext_seed: &[u8],
    ) -> (ParsedEvent, Vec<u8>) {
        use crate::events::fixed_layout::FILE_SLICE_CIPHERTEXT_BYTES;
        // Pad to canonical fixed size (short seeds are zero-extended)
        let mut ciphertext = vec![0u8; FILE_SLICE_CIPHERTEXT_BYTES];
        let len = ciphertext_seed.len().min(FILE_SLICE_CIPHERTEXT_BYTES);
        ciphertext[..len].copy_from_slice(&ciphertext_seed[..len]);
        let fs = FileSliceEvent {
            created_at_ms: now_ms(),
            file_id,
            slice_number,
            ciphertext,
            signed_by: *signer_event_id,
            signer_type: 5,
            signature: [0u8; 64],
        };
        let event = ParsedEvent::FileSlice(fs);
        let mut blob = events::encode_event(&event).unwrap();
        sign_blob(signing_key, &mut blob);
        let parsed = events::parse_event(&blob).unwrap();
        (parsed, blob)
    }

    /// Convenience: create identity chain + signed attachment.
    fn make_message_attachment(
        conn: &Connection,
        recorded_by: &str,
        message_id: &EventId,
        key_event_id: &EventId,
    ) -> (ParsedEvent, Vec<u8>) {
        let (signer_eid, signing_key) = make_identity_chain(conn, recorded_by);
        let att = MessageAttachmentEvent {
            created_at_ms: now_ms(),
            message_id: *message_id,
            file_id: [42u8; 32],
            blob_bytes: 1024,
            total_slices: 1,
            slice_bytes: 1024,
            root_hash: [0xABu8; 32],
            key_event_id: *key_event_id,
            filename: "test.bin".to_string(),
            mime_type: "application/octet-stream".to_string(),
            signed_by: signer_eid,
            signer_type: 5,
            signature: [0u8; 64],
        };
        let event = ParsedEvent::MessageAttachment(att);
        let mut blob = events::encode_event(&event).unwrap();
        sign_blob(&signing_key, &mut blob);
        let parsed = events::parse_event(&blob).unwrap();
        (parsed, blob)
    }

    /// Helper: create a MessageAttachment descriptor with a specific file_id and signer,
    /// along with its required deps (Message + SecretKey). Insert and project all of them.
    /// Returns the attachment event_id.
    fn setup_descriptor_for_file(
        conn: &Connection,
        recorded_by: &str,
        signing_key: &SigningKey,
        signer_eid: &EventId,
        file_id: [u8; 32],
    ) -> EventId {
        // Create message (dep for attachment)
        let (_msg, msg_blob) =
            make_message_signed(signing_key, signer_eid, "parent msg for descriptor");
        let msg_eid = insert_event_raw(conn, recorded_by, &msg_blob);
        project_one(conn, recorded_by, &msg_eid).unwrap();

        // Create SecretKey (dep for attachment)
        let sk = ParsedEvent::SecretKey(SecretKeyEvent {
            created_at_ms: now_ms(),
            key_bytes: [0xBB; 32],
        });
        let sk_blob = events::encode_event(&sk).unwrap();
        let sk_eid = insert_event_raw(conn, recorded_by, &sk_blob);
        project_one(conn, recorded_by, &sk_eid).unwrap();

        // Create MessageAttachment descriptor with the specific file_id
        let att = MessageAttachmentEvent {
            created_at_ms: now_ms(),
            message_id: msg_eid,
            file_id,
            blob_bytes: 204800,
            total_slices: 4,
            slice_bytes: 65536,
            root_hash: [12u8; 32],
            key_event_id: sk_eid,
            filename: "test.bin".to_string(),
            mime_type: "application/octet-stream".to_string(),
            signed_by: *signer_eid,
            signer_type: 5,
            signature: [0u8; 64],
        };
        let event = ParsedEvent::MessageAttachment(att);
        let mut blob = events::encode_event(&event).unwrap();
        sign_blob(signing_key, &mut blob);
        let att_blob = blob;
        let att_eid = insert_event_raw(conn, recorded_by, &att_blob);
        let result = project_one(conn, recorded_by, &att_eid).unwrap();
        assert_eq!(
            result,
            ProjectionDecision::Valid,
            "descriptor should project Valid"
        );
        att_eid
    }

    #[test]
    fn test_file_slice_valid() {
        let conn = setup();
        let recorded_by = "peer1";

        // Create identity chain as signer
        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        // Create descriptor (MessageAttachment) for this file_id
        let file_id = [99u8; 32];
        setup_descriptor_for_file(&conn, recorded_by, &signing_key, &signer_eid, file_id);

        // Create FileSlice
        let (_fs, fs_blob) =
            make_file_slice(&signing_key, &signer_eid, file_id, 0, b"encrypted data");
        let fs_eid = insert_event_raw(&conn, recorded_by, &fs_blob);
        let result = project_one(&conn, recorded_by, &fs_eid).unwrap();
        assert_eq!(result, ProjectionDecision::Valid);

        // Verify in file_slices table
        let fs_b64 = event_id_to_base64(&fs_eid);
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM file_slices WHERE recorded_by = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &fs_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_file_slice_blocks_on_missing_signer() {
        let conn = setup();
        let recorded_by = "peer1";
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);

        // Use a fake signer event_id that doesn't exist
        let fake_signer = [77u8; 32];
        let file_id = [99u8; 32];
        let (_fs, fs_blob) = make_file_slice(&signing_key, &fake_signer, file_id, 0, b"data");
        let fs_eid = insert_event_raw(&conn, recorded_by, &fs_blob);
        let result = project_one(&conn, recorded_by, &fs_eid).unwrap();
        assert!(matches!(result, ProjectionDecision::Block { .. }));
    }

    #[test]
    fn test_file_slice_unblocks_when_signer_arrives() {
        let conn = setup();
        let recorded_by = "peer1";

        // Build identity chain without inserting (deferred)
        let (signer_eid, signing_key, chain_blobs) = build_identity_chain_deferred(recorded_by);

        // Create FileSlice referencing the not-yet-existing signer
        let file_id = [99u8; 32];
        let (_fs, fs_blob) = make_file_slice(&signing_key, &signer_eid, file_id, 0, b"data");
        let fs_eid = insert_event_raw(&conn, recorded_by, &fs_blob);

        // Should block on missing signer dep
        let result = project_one(&conn, recorded_by, &fs_eid).unwrap();
        assert!(matches!(result, ProjectionDecision::Block { .. }));

        // Insert and project the full identity chain — signer dep resolves,
        // but file_slice will now guard-block on missing descriptor
        insert_and_project_identity_chain(&conn, recorded_by, &chain_blobs);

        // File slice should NOT yet be valid (guard-blocked on missing descriptor)
        let fs_b64 = event_id_to_base64(&fs_eid);
        let valid_before_descriptor: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &fs_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !valid_before_descriptor,
            "file_slice should still be guard-blocked before descriptor"
        );

        // Now create the descriptor — this should cascade-unblock the file_slice
        setup_descriptor_for_file(&conn, recorded_by, &signing_key, &signer_eid, file_id);

        // FileSlice should now be cascade-unblocked
        let valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &fs_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            valid,
            "file_slice should have been cascade-unblocked after descriptor"
        );
    }

    #[test]
    fn test_file_slice_invalid_signature_rejects() {
        let conn = setup();
        let recorded_by = "peer1";
        let mut rng = rand::thread_rng();
        let wrong_key = SigningKey::generate(&mut rng);
        let (signer_eid, signer_key) = make_identity_chain(&conn, recorded_by);

        // Sign file_slice with the WRONG key
        let file_id = [99u8; 32];
        let (_fs, fs_blob) = make_file_slice(&wrong_key, &signer_eid, file_id, 0, b"data");
        setup_descriptor_for_file(&conn, recorded_by, &signer_key, &signer_eid, file_id);
        let fs_eid = insert_event_raw(&conn, recorded_by, &fs_blob);
        let result = project_one(&conn, recorded_by, &fs_eid).unwrap();
        assert!(matches!(result, ProjectionDecision::Reject { .. }));
    }

    #[test]
    fn test_multiple_slices_same_file() {
        let conn = setup();
        let recorded_by = "peer1";

        // Create identity chain as signer
        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        // Create descriptor for this file_id
        let file_id = [99u8; 32];
        setup_descriptor_for_file(&conn, recorded_by, &signing_key, &signer_eid, file_id);

        for i in 0..5u32 {
            let (_fs, fs_blob) = make_file_slice(
                &signing_key,
                &signer_eid,
                file_id,
                i,
                format!("slice {}", i).as_bytes(),
            );
            let fs_eid = insert_event_raw(&conn, recorded_by, &fs_blob);
            let result = project_one(&conn, recorded_by, &fs_eid).unwrap();
            assert_eq!(
                result,
                ProjectionDecision::Valid,
                "slice {} should be valid",
                i
            );
        }

        // Verify all 5 slices in table
        let file_id_b64 = crate::crypto::event_id_to_base64(&file_id);
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM file_slices WHERE recorded_by = ?1 AND file_id = ?2",
                rusqlite::params![recorded_by, &file_id_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 5);
    }

    #[test]
    fn test_file_slice_tenant_isolation() {
        let conn = setup();
        let (signer_eid_a, signing_key_a) = make_identity_chain(&conn, "tenant_a");
        let (_signer_eid_b, _signing_key_b) = make_identity_chain(&conn, "tenant_b");

        let file_id = [99u8; 32];
        setup_descriptor_for_file(&conn, "tenant_a", &signing_key_a, &signer_eid_a, file_id);
        let (_fs, fs_blob) = make_file_slice(&signing_key_a, &signer_eid_a, file_id, 0, b"data");
        let fs_eid = insert_event_raw(&conn, "tenant_a", &fs_blob);
        project_one(&conn, "tenant_a", &fs_eid).unwrap();

        // Tenant B should not see tenant A's slice
        let file_id_b64 = crate::crypto::event_id_to_base64(&file_id);
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM file_slices WHERE recorded_by = 'tenant_b' AND file_id = ?1",
                rusqlite::params![&file_id_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_project_attachment_valid() {
        let conn = setup();
        let recorded_by = "peer1";
        let net_eid = setup_workspace_event(&conn, recorded_by);

        // Create identity chain once for this tenant
        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        // Create message (dep)
        let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "hello attachment");
        let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
        project_one(&conn, recorded_by, &msg_eid).unwrap();

        // Create SecretKey (dep)
        let sk = ParsedEvent::SecretKey(SecretKeyEvent {
            created_at_ms: now_ms(),
            key_bytes: [0xAA; 32],
        });
        let sk_blob = events::encode_event(&sk).unwrap();
        let sk_eid = insert_event_raw(&conn, recorded_by, &sk_blob);
        project_one(&conn, recorded_by, &sk_eid).unwrap();

        // Create attachment referencing both deps
        let (_att, att_blob) = make_attachment_signed(&signing_key, &signer_eid, &msg_eid, &sk_eid);
        let att_eid = insert_event_raw(&conn, recorded_by, &att_blob);
        let result = project_one(&conn, recorded_by, &att_eid).unwrap();
        assert_eq!(result, ProjectionDecision::Valid);

        // Verify in table
        let att_b64 = event_id_to_base64(&att_eid);
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM message_attachments WHERE recorded_by = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &att_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_attachment_blocks_on_missing_message() {
        let conn = setup();
        let recorded_by = "peer1";

        // Create SecretKey but NOT message
        let sk = ParsedEvent::SecretKey(SecretKeyEvent {
            created_at_ms: now_ms(),
            key_bytes: [0xAA; 32],
        });
        let sk_blob = events::encode_event(&sk).unwrap();
        let sk_eid = insert_event_raw(&conn, recorded_by, &sk_blob);
        project_one(&conn, recorded_by, &sk_eid).unwrap();

        let fake_msg_id = [88u8; 32];
        let (_att, att_blob) = make_message_attachment(&conn, recorded_by, &fake_msg_id, &sk_eid);
        let att_eid = insert_event_raw(&conn, recorded_by, &att_blob);
        let result = project_one(&conn, recorded_by, &att_eid).unwrap();
        assert!(matches!(result, ProjectionDecision::Block { .. }));
    }

    #[test]
    fn test_attachment_blocks_on_missing_key() {
        let conn = setup();
        let recorded_by = "peer1";

        // Create identity chain once for this tenant
        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        // Create message but NOT secret key
        let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "hello");
        let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
        project_one(&conn, recorded_by, &msg_eid).unwrap();

        let fake_key_id = [77u8; 32];
        let (_att, att_blob) =
            make_attachment_signed(&signing_key, &signer_eid, &msg_eid, &fake_key_id);
        let att_eid = insert_event_raw(&conn, recorded_by, &att_blob);
        let result = project_one(&conn, recorded_by, &att_eid).unwrap();
        assert!(matches!(result, ProjectionDecision::Block { .. }));
    }

    #[test]
    fn test_attachment_blocks_on_both_missing() {
        let conn = setup();
        let recorded_by = "peer1";

        let fake_msg_id = [88u8; 32];
        let fake_key_id = [77u8; 32];
        let (_att, att_blob) =
            make_message_attachment(&conn, recorded_by, &fake_msg_id, &fake_key_id);
        let att_eid = insert_event_raw(&conn, recorded_by, &att_blob);
        let result = project_one(&conn, recorded_by, &att_eid).unwrap();
        match result {
            ProjectionDecision::Block { ref missing } => {
                // Should block on at least the 2 fake deps (message_id + key_event_id)
                assert!(
                    missing.contains(&fake_msg_id),
                    "should block on missing message_id"
                );
                assert!(
                    missing.contains(&fake_key_id),
                    "should block on missing key_event_id"
                );
            }
            _ => panic!("expected Block, got {:?}", result),
        }
    }

    #[test]
    fn test_attachment_cascade_unblock() {
        let conn = setup();
        let recorded_by = "peer1";
        let net_eid = setup_workspace_event(&conn, recorded_by);

        // Create identity chain for signing
        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        // Pre-compute the message and key event IDs
        let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "hello cascade");
        let msg_eid = crate::crypto::hash_event(&msg_blob);

        let sk = ParsedEvent::SecretKey(SecretKeyEvent {
            created_at_ms: now_ms(),
            key_bytes: [0xBB; 32],
        });
        let sk_blob = events::encode_event(&sk).unwrap();
        let sk_eid = crate::crypto::hash_event(&sk_blob);

        // Insert attachment first (both deps missing → blocks)
        let (_att, att_blob) = make_attachment_signed(&signing_key, &signer_eid, &msg_eid, &sk_eid);
        let att_eid = insert_event_raw(&conn, recorded_by, &att_blob);
        let result = project_one(&conn, recorded_by, &att_eid).unwrap();
        assert!(matches!(result, ProjectionDecision::Block { .. }));

        // Insert message dep — still blocked (key missing)
        let msg_eid2 = insert_event_raw(&conn, recorded_by, &msg_blob);
        assert_eq!(msg_eid, msg_eid2);
        project_one(&conn, recorded_by, &msg_eid).unwrap();

        // Attachment still not valid
        let att_b64 = event_id_to_base64(&att_eid);
        let valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &att_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!valid, "attachment should still be blocked");

        // Insert key dep — should cascade-unblock attachment
        let sk_eid2 = insert_event_raw(&conn, recorded_by, &sk_blob);
        assert_eq!(sk_eid, sk_eid2);
        project_one(&conn, recorded_by, &sk_eid).unwrap();

        // Attachment should now be valid
        let valid2: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &att_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(valid2, "attachment should have been cascade-unblocked");
    }

    #[test]
    fn test_file_slice_idempotent_replay() {
        let conn = setup();
        let recorded_by = "peer1";

        // Create identity chain as signer
        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        // Create descriptor for this file_id
        let file_id = [99u8; 32];
        setup_descriptor_for_file(&conn, recorded_by, &signing_key, &signer_eid, file_id);

        let (_fs, fs_blob) = make_file_slice(&signing_key, &signer_eid, file_id, 0, b"data");
        let fs_eid = insert_event_raw(&conn, recorded_by, &fs_blob);

        // First projection
        let result = project_one(&conn, recorded_by, &fs_eid).unwrap();
        assert_eq!(result, ProjectionDecision::Valid);

        // Replay — should return AlreadyProcessed (already in valid_events)
        let result2 = project_one(&conn, recorded_by, &fs_eid).unwrap();
        assert_eq!(result2, ProjectionDecision::AlreadyProcessed);
    }

    #[test]
    fn test_file_slice_duplicate_slot_conflict_rejects() {
        let conn = setup();
        let recorded_by = "peer1";

        // Create identity chain as signer
        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        // Create descriptor for this file_id
        let file_id = [99u8; 32];
        setup_descriptor_for_file(&conn, recorded_by, &signing_key, &signer_eid, file_id);

        // First slice at slot 0
        let (_fs1, fs1_blob) = make_file_slice(&signing_key, &signer_eid, file_id, 0, b"first");
        let fs1_eid = insert_event_raw(&conn, recorded_by, &fs1_blob);
        let result = project_one(&conn, recorded_by, &fs1_eid).unwrap();
        assert_eq!(result, ProjectionDecision::Valid);

        // Second, DIFFERENT slice at same slot 0 — should reject
        let (_fs2, fs2_blob) = make_file_slice(&signing_key, &signer_eid, file_id, 0, b"second");
        let fs2_eid = insert_event_raw(&conn, recorded_by, &fs2_blob);
        let result2 = project_one(&conn, recorded_by, &fs2_eid).unwrap();
        assert!(
            matches!(result2, ProjectionDecision::Reject { .. }),
            "duplicate slot with different event_id should reject, got {:?}",
            result2
        );
    }

    #[test]
    fn test_file_slice_wrong_signer_rejected() {
        let conn = setup();
        let recorded_by = "peer1";
        let mut rng = rand::thread_rng();

        // Build a shared identity chain up through UserBoot, then branch
        // into two separate PeerSharedFirst signers (A and B).

        // 1. Workspace
        let workspace_key = SigningKey::generate(&mut rng);
        let workspace_pub = workspace_key.verifying_key().to_bytes();
        let net_event = ParsedEvent::Workspace(WorkspaceEvent {
            created_at_ms: now_ms(),
            public_key: workspace_pub,
        });
        let net_blob = events::encode_event(&net_event).unwrap();
        let net_eid = insert_event_raw(&conn, recorded_by, &net_blob);

        // 2. InviteAccepted
        let ia_event = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
            created_at_ms: now_ms(),
            invite_event_id: net_eid,
            workspace_id: net_eid,
        });
        let ia_blob = events::encode_event(&ia_event).unwrap();
        let ia_eid = insert_event_raw(&conn, recorded_by, &ia_blob);
        project_one(&conn, recorded_by, &ia_eid).unwrap();
        project_one(&conn, recorded_by, &net_eid).unwrap();

        // 3. UserInviteBoot (signed by workspace key)
        let invite_key = SigningKey::generate(&mut rng);
        let invite_pub = invite_key.verifying_key().to_bytes();
        let uib = UserInviteBootEvent {
            created_at_ms: now_ms(),
            public_key: invite_pub,
            workspace_id: net_eid,
            signed_by: net_eid,
            signer_type: 1,
            signature: [0u8; 64],
        };
        let uib_event = ParsedEvent::UserInviteBoot(uib);
        let mut uib_blob = events::encode_event(&uib_event).unwrap();
        sign_blob(&workspace_key, &mut uib_blob);
        let uib_eid = insert_event_raw(&conn, recorded_by, &uib_blob);
        project_one(&conn, recorded_by, &uib_eid).unwrap();

        // 4. UserBoot (signed by invite key)
        let user_key = SigningKey::generate(&mut rng);
        let user_pub = user_key.verifying_key().to_bytes();
        let ub = UserBootEvent {
            created_at_ms: now_ms(),
            public_key: user_pub,
            signed_by: uib_eid,
            signer_type: 2,
            signature: [0u8; 64],
        };
        let ub_event = ParsedEvent::UserBoot(ub);
        let mut ub_blob = events::encode_event(&ub_event).unwrap();
        sign_blob(&invite_key, &mut ub_blob);
        let ub_eid = insert_event_raw(&conn, recorded_by, &ub_blob);
        project_one(&conn, recorded_by, &ub_eid).unwrap();

        // 5a. DeviceInviteFirst A (signed by user key)
        let device_invite_key_a = SigningKey::generate(&mut rng);
        let device_invite_pub_a = device_invite_key_a.verifying_key().to_bytes();
        let dif_a = DeviceInviteFirstEvent {
            created_at_ms: now_ms(),
            public_key: device_invite_pub_a,
            signed_by: ub_eid,
            signer_type: 4,
            signature: [0u8; 64],
        };
        let dif_a_event = ParsedEvent::DeviceInviteFirst(dif_a);
        let mut dif_a_blob = events::encode_event(&dif_a_event).unwrap();
        sign_blob(&user_key, &mut dif_a_blob);
        let dif_a_eid = insert_event_raw(&conn, recorded_by, &dif_a_blob);
        project_one(&conn, recorded_by, &dif_a_eid).unwrap();

        // 6a. PeerSharedFirst A (signed by device_invite_a)
        let signer_key_a = SigningKey::generate(&mut rng);
        let peer_pub_a = signer_key_a.verifying_key().to_bytes();
        let psf_a = PeerSharedFirstEvent {
            created_at_ms: now_ms(),
            public_key: peer_pub_a,
            signed_by: dif_a_eid,
            signer_type: 3,
            signature: [0u8; 64],
        };
        let psf_a_event = ParsedEvent::PeerSharedFirst(psf_a);
        let mut psf_a_blob = events::encode_event(&psf_a_event).unwrap();
        sign_blob(&device_invite_key_a, &mut psf_a_blob);
        let signer_a_eid = insert_event_raw(&conn, recorded_by, &psf_a_blob);
        project_one(&conn, recorded_by, &signer_a_eid).unwrap();

        // 5b. DeviceInviteFirst B (signed by user key — branching from same UserBoot)
        let device_invite_key_b = SigningKey::generate(&mut rng);
        let device_invite_pub_b = device_invite_key_b.verifying_key().to_bytes();
        let dif_b = DeviceInviteFirstEvent {
            created_at_ms: now_ms(),
            public_key: device_invite_pub_b,
            signed_by: ub_eid,
            signer_type: 4,
            signature: [0u8; 64],
        };
        let dif_b_event = ParsedEvent::DeviceInviteFirst(dif_b);
        let mut dif_b_blob = events::encode_event(&dif_b_event).unwrap();
        sign_blob(&user_key, &mut dif_b_blob);
        let dif_b_eid = insert_event_raw(&conn, recorded_by, &dif_b_blob);
        project_one(&conn, recorded_by, &dif_b_eid).unwrap();

        // 6b. PeerSharedFirst B (signed by device_invite_b)
        let signer_key_b = SigningKey::generate(&mut rng);
        let peer_pub_b = signer_key_b.verifying_key().to_bytes();
        let psf_b = PeerSharedFirstEvent {
            created_at_ms: now_ms(),
            public_key: peer_pub_b,
            signed_by: dif_b_eid,
            signer_type: 3,
            signature: [0u8; 64],
        };
        let psf_b_event = ParsedEvent::PeerSharedFirst(psf_b);
        let mut psf_b_blob = events::encode_event(&psf_b_event).unwrap();
        sign_blob(&device_invite_key_b, &mut psf_b_blob);
        let signer_b_eid = insert_event_raw(&conn, recorded_by, &psf_b_blob);
        project_one(&conn, recorded_by, &signer_b_eid).unwrap();

        // Create descriptor with signer A
        let file_id = [99u8; 32];
        setup_descriptor_for_file(&conn, recorded_by, &signer_key_a, &signer_a_eid, file_id);

        // Create file_slice signed by signer B (different from descriptor's signer A)
        let (_fs, fs_blob) =
            make_file_slice(&signer_key_b, &signer_b_eid, file_id, 0, b"unauthorized data");
        let fs_eid = insert_event_raw(&conn, recorded_by, &fs_blob);
        let result = project_one(&conn, recorded_by, &fs_eid).unwrap();
        assert!(
            matches!(result, ProjectionDecision::Reject { .. }),
            "file_slice with wrong signer should be rejected, got {:?}",
            result
        );
    }

    // ========================================================================
    // New tests for single-entrypoint cascade refactor (Issue 1)
    // ========================================================================

    #[test]
    fn test_multi_dep_event_projects_only_when_all_resolve() {
        // BenchDepEvent with 2 deps: verify it only projects when both deps are valid.
        let conn = setup();
        let recorded_by = "peer1";

        // Create two SecretKey events as deps (no deps of their own)
        let sk_a = ParsedEvent::SecretKey(SecretKeyEvent {
            created_at_ms: now_ms(),
            key_bytes: [0xAA; 32],
        });
        let sk_a_blob = events::encode_event(&sk_a).unwrap();
        let sk_a_eid = insert_event_raw(&conn, recorded_by, &sk_a_blob);

        let sk_b = ParsedEvent::SecretKey(SecretKeyEvent {
            created_at_ms: now_ms(),
            key_bytes: [0xBB; 32],
        });
        let sk_b_blob = events::encode_event(&sk_b).unwrap();
        let sk_b_eid = insert_event_raw(&conn, recorded_by, &sk_b_blob);

        // Create BenchDepEvent depending on both
        let bench = ParsedEvent::BenchDep(BenchDepEvent {
            created_at_ms: now_ms(),
            dep_ids: vec![sk_a_eid, sk_b_eid],
            payload: [0x42; 16],
        });
        let bench_blob = events::encode_event(&bench).unwrap();
        let bench_eid = insert_event_raw(&conn, recorded_by, &bench_blob);

        // Project bench first — should block on both deps
        let result = project_one(&conn, recorded_by, &bench_eid).unwrap();
        assert!(
            matches!(result, ProjectionDecision::Block { ref missing } if missing.len() == 2),
            "should block on 2 missing deps, got {:?}",
            result
        );

        // Project dep A only — bench should still be blocked
        project_one(&conn, recorded_by, &sk_a_eid).unwrap();
        let bench_b64 = event_id_to_base64(&bench_eid);
        let still_blocked: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM blocked_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &bench_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(still_blocked, "bench should still be blocked after only one dep resolves");

        // Project dep B — now bench should cascade to valid
        project_one(&conn, recorded_by, &sk_b_eid).unwrap();
        let bench_valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &bench_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(bench_valid, "bench should be valid after both deps resolve via cascade");
    }

    #[test]
    fn test_cascade_and_direct_produce_same_state() {
        // Compare direct (in-order) projection vs out-of-order cascade.
        // Both should produce identical valid_events sets.
        let recorded_by = "peer1";

        // --- Direct path (in dependency order) ---
        let conn_direct = setup();
        let (signer_eid, signing_key) = make_identity_chain(&conn_direct, recorded_by);
        let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "hello");
        let msg_eid = insert_event_raw(&conn_direct, recorded_by, &msg_blob);
        project_one(&conn_direct, recorded_by, &msg_eid).unwrap();

        let (_rxn, rxn_blob) = make_reaction_signed(&signing_key, &signer_eid, &msg_eid, "thumbs_up");
        let rxn_eid = insert_event_raw(&conn_direct, recorded_by, &rxn_blob);
        project_one(&conn_direct, recorded_by, &rxn_eid).unwrap();

        // --- Cascade path (reaction before message) ---
        let conn_cascade = setup();
        // Same identity chain
        let (signer_eid_c, signing_key_c) = make_identity_chain(&conn_cascade, recorded_by);
        let (_msg_c, msg_blob_c) = make_message_signed(&signing_key_c, &signer_eid_c, "hello");
        let msg_eid_c = insert_event_raw(&conn_cascade, recorded_by, &msg_blob_c);
        // DON'T project message yet

        let (_rxn_c, rxn_blob_c) = make_reaction_signed(&signing_key_c, &signer_eid_c, &msg_eid_c, "thumbs_up");
        let rxn_eid_c = insert_event_raw(&conn_cascade, recorded_by, &rxn_blob_c);
        // Reaction should block (message not valid yet)
        let r = project_one(&conn_cascade, recorded_by, &rxn_eid_c).unwrap();
        assert!(matches!(r, ProjectionDecision::Block { .. }));

        // Now project message — should cascade and unblock reaction
        project_one(&conn_cascade, recorded_by, &msg_eid_c).unwrap();

        // Both should have the reaction as valid
        let rxn_b64 = event_id_to_base64(&rxn_eid);
        let rxn_valid_direct: bool = conn_direct
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &rxn_b64],
                |row| row.get(0),
            )
            .unwrap();

        let rxn_b64_c = event_id_to_base64(&rxn_eid_c);
        let rxn_valid_cascade: bool = conn_cascade
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &rxn_b64_c],
                |row| row.get(0),
            )
            .unwrap();

        assert!(rxn_valid_direct, "reaction should be valid via direct path");
        assert!(rxn_valid_cascade, "reaction should be valid via cascade path");
    }

    #[test]
    fn test_encrypted_inner_dep_cascade_unblock() {
        // Encrypted event whose inner event (a Reaction) depends on a message.
        // Insert encrypted event first (blocks on key), then provide key (cascades
        // to decrypt, but inner reaction blocks on message), then provide message
        // (cascades to unblock inner reaction -> encrypted becomes valid).
        let conn = setup();
        let recorded_by = "peer1";
        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        // Create the message that the inner reaction will target
        let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "target msg");
        let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
        // DON'T project message yet

        // Create the secret key for encryption
        let key_bytes: [u8; 32] = rand::random();
        let (_sk, sk_blob) = make_secret_key(key_bytes);
        let sk_eid = insert_event_raw(&conn, recorded_by, &sk_blob);
        // DON'T project key yet

        // Create inner event: a Reaction targeting the message
        let rxn = ReactionEvent {
            created_at_ms: now_ms(),
            target_event_id: msg_eid,
            author_id: [3u8; 32],
            emoji: "heart".to_string(),
            signed_by: signer_eid,
            signer_type: 5,
            signature: [0u8; 64],
        };
        let rxn_event = ParsedEvent::Reaction(rxn);
        let mut inner_blob = events::encode_event(&rxn_event).unwrap();
        sign_blob(&signing_key, &mut inner_blob);

        // Wrap in encrypted envelope
        let (_enc, enc_blob) = make_encrypted_event(&key_bytes, &inner_blob, EVENT_TYPE_REACTION, &sk_eid);
        let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);

        // Project encrypted event — should block on missing key_event_id dep
        let r1 = project_one(&conn, recorded_by, &enc_eid).unwrap();
        assert!(
            matches!(r1, ProjectionDecision::Block { .. }),
            "encrypted should block on missing key, got {:?}",
            r1
        );

        // Project key — encrypted event cascades, decrypts, but inner reaction
        // blocks on missing message. Encrypted event should NOT be valid yet.
        project_one(&conn, recorded_by, &sk_eid).unwrap();
        let enc_b64 = event_id_to_base64(&enc_eid);
        let enc_valid_after_key: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &enc_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !enc_valid_after_key,
            "encrypted event should NOT be valid yet (inner dep missing)"
        );

        // Project message — inner reaction unblocks, encrypted event should cascade to valid
        project_one(&conn, recorded_by, &msg_eid).unwrap();
        let enc_valid_final: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &enc_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            enc_valid_final,
            "encrypted event should be valid after all inner deps resolve"
        );
    }

    #[test]
    fn test_invite_accepted_guard_retry_on_workspace() {
        // Workspace events are guard-blocked (not dep-blocked) until InviteAccepted
        // sets the trust anchor. Verify that projecting InviteAccepted triggers
        // guard retry and unblocks the Workspace event.
        let conn = setup();
        let recorded_by = "peer1";
        let mut rng = rand::thread_rng();

        // Create workspace event
        let workspace_key = SigningKey::generate(&mut rng);
        let workspace_pub = workspace_key.verifying_key().to_bytes();
        let ws_event = ParsedEvent::Workspace(WorkspaceEvent {
            created_at_ms: now_ms(),
            public_key: workspace_pub,
        });
        let ws_blob = events::encode_event(&ws_event).unwrap();
        let ws_eid = insert_event_raw(&conn, recorded_by, &ws_blob);

        // Project workspace first — should be guard-blocked (no trust anchor yet)
        let r1 = project_one(&conn, recorded_by, &ws_eid).unwrap();
        assert!(
            matches!(r1, ProjectionDecision::Block { ref missing } if missing.is_empty()),
            "workspace should be guard-blocked with empty missing, got {:?}",
            r1
        );

        // Create and project InviteAccepted — should set trust anchor and trigger guard retry
        let ia_event = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
            created_at_ms: now_ms(),
            invite_event_id: ws_eid,
            workspace_id: ws_eid,
        });
        let ia_blob = events::encode_event(&ia_event).unwrap();
        let ia_eid = insert_event_raw(&conn, recorded_by, &ia_blob);
        let r2 = project_one(&conn, recorded_by, &ia_eid).unwrap();
        assert_eq!(r2, ProjectionDecision::Valid, "invite_accepted should project Valid");

        // Workspace should now be valid via guard retry cascade
        let ws_b64 = event_id_to_base64(&ws_eid);
        let ws_valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &ws_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(ws_valid, "workspace should be valid after invite_accepted guard retry");
    }

    #[test]
    fn test_file_slice_guard_retry_after_cascaded_attachment() {
        // FileSlice is guard-blocked waiting for descriptor (MessageAttachment).
        // MessageAttachment is dep-blocked on a message. When the message projects,
        // it cascades the attachment, which triggers guard retry on the file_slice.
        let conn = setup();
        let recorded_by = "peer1";
        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        let file_id = [77u8; 32];

        // Create message (dep for attachment) but DON'T project yet
        let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "parent msg");
        let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);

        // Create SecretKey (dep for attachment) and project it
        let sk = ParsedEvent::SecretKey(SecretKeyEvent {
            created_at_ms: now_ms(),
            key_bytes: [0xDD; 32],
        });
        let sk_blob = events::encode_event(&sk).unwrap();
        let sk_eid = insert_event_raw(&conn, recorded_by, &sk_blob);
        project_one(&conn, recorded_by, &sk_eid).unwrap();

        // Create attachment (descriptor) — dep-blocked on message
        let att = MessageAttachmentEvent {
            created_at_ms: now_ms(),
            message_id: msg_eid,
            file_id,
            blob_bytes: 204800,
            total_slices: 4,
            slice_bytes: 65536,
            root_hash: [12u8; 32],
            key_event_id: sk_eid,
            filename: "test.bin".to_string(),
            mime_type: "application/octet-stream".to_string(),
            signed_by: signer_eid,
            signer_type: 5,
            signature: [0u8; 64],
        };
        let att_event = ParsedEvent::MessageAttachment(att);
        let mut att_blob = events::encode_event(&att_event).unwrap();
        sign_blob(&signing_key, &mut att_blob);
        let att_eid = insert_event_raw(&conn, recorded_by, &att_blob);
        let r1 = project_one(&conn, recorded_by, &att_eid).unwrap();
        assert!(
            matches!(r1, ProjectionDecision::Block { .. }),
            "attachment should block on missing message dep, got {:?}",
            r1
        );

        // Create file_slice — guard-blocked (no descriptor yet)
        let (_fs, fs_blob) = make_file_slice(&signing_key, &signer_eid, file_id, 0, b"slice data");
        let fs_eid = insert_event_raw(&conn, recorded_by, &fs_blob);
        let r2 = project_one(&conn, recorded_by, &fs_eid).unwrap();
        // file_slice returns Block with empty missing (guard block) because no descriptor exists
        assert!(
            matches!(r2, ProjectionDecision::Block { ref missing } if missing.is_empty()),
            "file_slice should be guard-blocked, got {:?}",
            r2
        );

        // Verify file_slice is in guard block table
        let fs_b64 = event_id_to_base64(&fs_eid);
        let guard_blocked: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM file_slice_guard_blocks WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &fs_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(guard_blocked, "file_slice should be in guard_blocks table");

        // Now project message — should cascade: attachment unblocks, then guard retry unblocks file_slice
        project_one(&conn, recorded_by, &msg_eid).unwrap();

        // Attachment should be valid
        let att_b64 = event_id_to_base64(&att_eid);
        let att_valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &att_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(att_valid, "attachment should be valid after message cascade");

        // File slice should be valid (guard retry triggered by attachment cascade)
        let fs_valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &fs_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(fs_valid, "file_slice should be valid after cascaded guard retry");
    }
}
