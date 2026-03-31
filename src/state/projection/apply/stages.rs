use super::super::decision::ProjectionDecision;
use super::super::signer::{verify_ed25519_signature, SignerResolution};
use super::backend::{ProjectionApplyResult, ProjectionBackend};
use crate::crypto::{event_id_to_base64, EventId};
use crate::db::queue::current_timestamp_ms;
use crate::db::timeline::EventTimeline;
use crate::event_modules::{registry, ParsedEvent, TransportPrivacy};
use crate::projection::queries::ContextLoadResult;
use crate::state::{dependency_fetch, live_hints::source_peer_id_from_source_tag};
use rusqlite::{Connection, OptionalExtension};

use super::dispatch::dispatch_pure_projector;

fn semantic_type_code_for_parsed(parsed: &ParsedEvent) -> u8 {
    match parsed {
        ParsedEvent::Encrypted(enc) => enc.inner_type_code,
        _ => parsed.event_type_code(),
    }
}

fn derive_semantic_type_code_from_blob(
    blob: &[u8],
) -> Result<Option<u8>, Box<dyn std::error::Error>> {
    let parsed = match crate::event_modules::parse_event(blob) {
        Ok(parsed) => parsed,
        Err(_) => return Ok(crate::event_modules::outer_semantic_type_code(blob)),
    };
    Ok(Some(semantic_type_code_for_parsed(&parsed)))
}

fn check_transport_privacy(
    parsed: &ParsedEvent,
    is_encrypted_transport: bool,
) -> Result<(), String> {
    let meta = registry()
        .lookup(parsed.event_type_code())
        .ok_or_else(|| format!("unknown type code {}", parsed.event_type_code()))?;

    match (meta.transport_privacy(), is_encrypted_transport) {
        (TransportPrivacy::RequireEncrypted, false) => Err(format!(
            "{} events must be carried inside encrypted wrappers",
            meta.type_name
        )),
        (TransportPrivacy::PlaintextOnly, true) => Err(format!(
            "{} events may not be carried inside encrypted wrappers",
            meta.type_name
        )),
        _ => Ok(()),
    }
}

fn load_valid_semantic_type_code(
    conn: &Connection,
    recorded_by: &str,
    dep_b64: &str,
) -> Result<Option<u8>, Box<dyn std::error::Error>> {
    let stored: Option<Option<i64>> = conn
        .query_row(
            "SELECT semantic_type_code
             FROM valid_events
             WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, dep_b64],
            |row| row.get(0),
        )
        .optional()?;

    match stored {
        Some(Some(code)) => {
            let code = u8::try_from(code).map_err(|_| {
                format!(
                    "semantic_type_code {} out of range for event {}",
                    code, dep_b64
                )
            })?;
            Ok(Some(code))
        }
        Some(None) => {
            let blob: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT blob FROM events WHERE event_id = ?1",
                    rusqlite::params![dep_b64],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(blob) = blob else {
                return Ok(None);
            };
            let Some(code) = derive_semantic_type_code_from_blob(&blob)? else {
                return Ok(None);
            };
            conn.execute(
                "UPDATE valid_events
                 SET semantic_type_code = ?3
                 WHERE peer_id = ?1 AND event_id = ?2 AND semantic_type_code IS NULL",
                rusqlite::params![recorded_by, dep_b64, i64::from(code)],
            )?;
            Ok(Some(code))
        }
        None => {
            if global_endpoint_shared_is_valid(conn, dep_b64)? {
                return Ok(Some(crate::event_modules::EVENT_TYPE_ENDPOINT_SHARED));
            }
            Ok(None)
        }
    }
}

fn global_endpoint_shared_is_valid(
    conn: &Connection,
    dep_b64: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let present: bool = conn.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM endpoints_shared
             WHERE event_id = ?1
         )",
        rusqlite::params![dep_b64],
        |row| row.get(0),
    )?;
    Ok(present)
}

fn dep_is_satisfied_for_scope(
    conn: &Connection,
    recorded_by: &str,
    dep_b64: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let dep_valid: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![recorded_by, dep_b64],
        |row| row.get(0),
    )?;
    if dep_valid {
        return Ok(true);
    }
    global_endpoint_shared_is_valid(conn, dep_b64)
}

fn load_recorded_source_peer_id(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let source_tag: Option<String> = conn
        .query_row(
            "SELECT source
             FROM recorded_events
             WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, event_id_b64],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    Ok(source_tag.and_then(|source_tag| source_peer_id_from_source_tag(&source_tag)))
}

fn tombstone_satisfies_message_dep(
    conn: &Connection,
    recorded_by: &str,
    parsed: &ParsedEvent,
    field_name: &str,
    dep_b64: &str,
) -> Result<bool, rusqlite::Error> {
    let is_deleted_message_target = matches!(
        (parsed, field_name),
        (ParsedEvent::Reaction(_), "target_event_id") | (ParsedEvent::File(_), "message_id")
    );
    if !is_deleted_message_target {
        return Ok(false);
    }
    conn.query_row(
        "SELECT COUNT(*) > 0
         FROM deleted_messages
         WHERE recorded_by = ?1 AND message_id = ?2",
        rusqlite::params![recorded_by, dep_b64],
        |row| row.get(0),
    )
}

/// Check that each dep's type code matches the allowed types for that dep field.
/// Returns Some(reason) if a type mismatch is found, None if all pass.
pub(crate) fn check_dep_types(
    conn: &Connection,
    recorded_by: &str,
    parsed: &ParsedEvent,
    deps: &[(&str, EventId)],
    type_codes: &[&[u8]],
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    for (i, (field_name, dep_id)) in deps.iter().enumerate() {
        let allowed = type_codes.get(i).copied().unwrap_or(&[]);
        if allowed.is_empty() {
            continue;
        }
        let dep_b64 = event_id_to_base64(dep_id);
        let actual_type = match load_valid_semantic_type_code(conn, recorded_by, &dep_b64) {
            Ok(Some(code)) => code,
            Ok(None) => {
                let tombstone_satisfies_dep_type = tombstone_satisfies_message_dep(
                    conn,
                    recorded_by,
                    parsed,
                    field_name,
                    &dep_b64,
                )?;
                if tombstone_satisfies_dep_type {
                    continue;
                }
                return Ok(Some(format!(
                    "dep {} missing tenant-scoped semantic type record",
                    field_name
                )));
            }
            Err(e) => return Err(e),
        };
        if !allowed.contains(&actual_type) {
            return Ok(Some(format!(
                "dep {} has semantic type code {} but expected one of {:?}",
                field_name, actual_type, allowed
            )));
        }
    }
    Ok(None)
}

/// Record a rejected event durably so it is not re-processed on replay or cascade.
pub(crate) fn record_rejection(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    reason: &str,
) {
    let now_ms = current_timestamp_ms();
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
    parsed: &ParsedEvent,
    deps: &[(&str, EventId)],
) -> Result<Option<ProjectionDecision>, Box<dyn std::error::Error>> {
    let mut missing = Vec::new();
    for (field_name, dep_id) in deps {
        let dep_b64 = event_id_to_base64(dep_id);
        let dep_valid = dep_is_satisfied_for_scope(conn, recorded_by, &dep_b64)?;
        if !dep_valid {
            let tombstone_satisfies_dep =
                tombstone_satisfies_message_dep(conn, recorded_by, parsed, field_name, &dep_b64)?;
            if tombstone_satisfies_dep {
                continue;
            }
            missing.push(*dep_id);
        }
    }

    if missing.is_empty() {
        return Ok(None);
    }

    record_block_rows(conn, recorded_by, event_id_b64, &missing)?;
    if let Some(source_peer_id) = load_recorded_source_peer_id(conn, recorded_by, event_id_b64)? {
        dependency_fetch::publish_from_connection(conn, recorded_by, &source_peer_id, &missing);
    }

    Ok(Some(ProjectionDecision::Block { missing }))
}

pub(crate) fn record_block_rows(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    missing: &[EventId],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut missing = missing.to_vec();
    missing.sort_unstable();
    missing.dedup();

    // Clean stale dep edges from prior blocks before recording new ones.
    // This prevents deps_remaining from desyncing with the actual edge set
    // when an event is re-blocked with a different set of missing deps
    // (e.g., dep-unblock → guard-block → re-dep-block via retry command).
    conn.execute(
        "DELETE FROM blocked_event_deps WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![recorded_by, event_id_b64],
    )?;

    for dep_id in &missing {
        let dep_b64 = event_id_to_base64(dep_id);
        conn.execute(
            "INSERT OR IGNORE INTO blocked_event_deps (peer_id, event_id, blocker_event_id)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![recorded_by, event_id_b64, &dep_b64],
        )?;
    }

    // Use INSERT OR REPLACE so deps_remaining is always updated to match
    // the current missing set, even if a prior blocked_events row exists
    // with a stale counter from an earlier block.
    conn.execute(
        "INSERT OR REPLACE INTO blocked_events (peer_id, event_id, deps_remaining)
         VALUES (?1, ?2, ?3)",
        rusqlite::params![recorded_by, event_id_b64, missing.len() as i64],
    )?;
    let _ = EventTimeline::new(conn).mark_blocked_b64(event_id_b64, current_timestamp_ms());
    Ok(())
}

/// Shared projection helper: verify signer (if required), build context snapshot,
/// dispatch to pure projector, execute write_ops, return decision.
///
/// This is the core of the pure functional projector architecture: projectors
/// are pure functions over (event, context snapshot) that return deterministic
/// write_ops and emit_commands. The apply engine executes them.
#[allow(dead_code)]
pub(crate) fn apply_projection(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    blob: &[u8],
    parsed: &ParsedEvent,
    current_transport_key_event_id: Option<&str>,
) -> Result<(ProjectionDecision, Option<ParsedEvent>), Box<dyn std::error::Error>> {
    apply_projection_with_backend(
        conn,
        recorded_by,
        event_id_b64,
        blob,
        parsed,
        current_transport_key_event_id,
    )
}

pub(crate) fn apply_projection_with_backend<B: ProjectionBackend>(
    backend: &B,
    recorded_by: &str,
    event_id_b64: &str,
    blob: &[u8],
    parsed: &ParsedEvent,
    current_transport_key_event_id: Option<&str>,
) -> ProjectionApplyResult<(ProjectionDecision, Option<ParsedEvent>)> {
    let meta = registry()
        .lookup(parsed.event_type_code())
        .ok_or_else(|| format!("unknown type code {}", parsed.event_type_code()))?;

    // Signer verification (if required) — this stays in the pipeline
    // because it requires blob bytes and is uniform across all signed events.
    if meta.signer_required {
        let (signer_event_id, signer_type) = parsed
            .signer_fields()
            .ok_or("signer_required but no signer_fields")?;
        let resolution = backend.resolve_signer_key(recorded_by, signer_type, &signer_event_id)?;
        match resolution {
            SignerResolution::NotFound => {
                return Ok((
                    ProjectionDecision::Reject {
                        reason: "signer key not found".to_string(),
                    },
                    None,
                ));
            }
            SignerResolution::Invalid(msg) => {
                return Ok((
                    ProjectionDecision::Reject {
                        reason: format!("signer resolution failed: {}", msg),
                    },
                    None,
                ));
            }
            SignerResolution::Found(key) => {
                let sig_len = meta.signature_byte_len;
                if blob.len() < sig_len {
                    return Ok((
                        ProjectionDecision::Reject {
                            reason: "blob too short for signature".to_string(),
                        },
                        None,
                    ));
                }
                let signing_bytes = &blob[..blob.len() - sig_len];
                let sig_bytes = &blob[blob.len() - sig_len..];
                if !verify_ed25519_signature(&key, signing_bytes, sig_bytes) {
                    return Ok((
                        ProjectionDecision::Reject {
                            reason: "invalid signature".to_string(),
                        },
                        None,
                    ));
                }
            }
        }
    }

    // Encrypted events still use the old flow (they decrypt and recurse
    // through run_dep_and_projection_stages for the inner event).
    // Returns (decision, Some(inner_parsed)) so the caller can fire the
    // subscription hook after the valid_events write.
    if let ParsedEvent::Encrypted(enc) = parsed {
        let (decision, inner) = backend.project_encrypted(recorded_by, event_id_b64, enc)?;
        return Ok((decision, inner));
    }

    // Build projector context via event-module-owned loader.
    let mut ctx = match (meta.context_loader)(backend, recorded_by, event_id_b64, parsed)? {
        ContextLoadResult::Ready(ctx) => ctx,
        ContextLoadResult::Block { missing } => {
            if !missing.is_empty() {
                backend.record_block(recorded_by, event_id_b64, &missing)?;
            }
            return Ok((ProjectionDecision::Block { missing }, None));
        }
        ContextLoadResult::Reject { reason } => {
            return Ok((ProjectionDecision::Reject { reason }, None));
        }
    };
    ctx.current_transport_key_event_id = current_transport_key_event_id.map(ToOwned::to_owned);

    // Dispatch to pure projector
    let result = dispatch_pure_projector(recorded_by, event_id_b64, parsed, &ctx);

    // Explicit per-decision side-effect policy:
    // - Valid: apply write_ops and emitted commands.
    // - Block: apply emitted commands only (for block-side effects).
    // - Reject / AlreadyProcessed: no side effects.
    match result.decision {
        ProjectionDecision::Valid => {
            backend.execute_write_ops(&result.write_ops)?;
            backend.execute_emit_commands(recorded_by, &result.emit_commands)?;
        }
        ProjectionDecision::Block { .. } => {
            backend.execute_emit_commands(recorded_by, &result.emit_commands)?;
        }
        ProjectionDecision::Reject { .. } | ProjectionDecision::AlreadyProcessed => {}
    }

    Ok((result.decision, None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_connection, schema::create_tables};
    use crate::event_modules::BenchDepEvent;

    fn setup_file_db() -> (tempfile::TempDir, String, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("stages.db").to_string_lossy().to_string();
        let conn = open_connection(&db_path).unwrap();
        create_tables(&conn).unwrap();
        (dir, db_path, conn)
    }

    fn event_id(byte: u8) -> EventId {
        let mut id = [0u8; 32];
        id[0] = byte;
        id
    }

    fn unrelated_parsed() -> ParsedEvent {
        ParsedEvent::BenchDep(BenchDepEvent {
            created_at_ms: 1,
            dep_ids: vec![],
            payload: [0u8; 16],
        })
    }

    #[tokio::test]
    async fn blocked_quic_event_emits_dependency_fetch_for_source_peer() {
        let (_dir, db_path, conn) = setup_file_db();
        let blocked = event_id(1);
        let missing = event_id(2);
        let blocked_b64 = event_id_to_base64(&blocked);
        conn.execute(
            "INSERT INTO recorded_events (peer_id, event_id, recorded_at, source)
             VALUES (?1, ?2, 1, ?3)",
            rusqlite::params!["tenant-a", &blocked_b64, "quic_recv:peer-z@127.0.0.1:7777"],
        )
        .unwrap();

        let (mut rx, _guard) = dependency_fetch::register(&db_path, "tenant-a", "peer-z");
        let decision = check_deps_and_block(
            &conn,
            "tenant-a",
            &blocked_b64,
            &unrelated_parsed(),
            &[("dep", missing)],
        )
        .unwrap();
        assert!(matches!(decision, Some(ProjectionDecision::Block { .. })));
        assert_eq!(rx.recv().await, Some(vec![missing]));
    }

    #[tokio::test]
    async fn local_only_blocked_event_does_not_emit_dependency_fetch() {
        let (_dir, db_path, conn) = setup_file_db();
        let blocked = event_id(3);
        let missing = event_id(4);
        let blocked_b64 = event_id_to_base64(&blocked);
        conn.execute(
            "INSERT INTO recorded_events (peer_id, event_id, recorded_at, source)
             VALUES (?1, ?2, 1, ?3)",
            rusqlite::params!["tenant-a", &blocked_b64, "local_create"],
        )
        .unwrap();

        let (mut rx, _guard) = dependency_fetch::register(&db_path, "tenant-a", "peer-z");
        let decision = check_deps_and_block(
            &conn,
            "tenant-a",
            &blocked_b64,
            &unrelated_parsed(),
            &[("dep", missing)],
        )
        .unwrap();
        assert!(matches!(decision, Some(ProjectionDecision::Block { .. })));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), rx.recv())
                .await
                .is_err()
        );
    }
}

/// Shared dependency/signer/projection stage bundle used by cleartext and
/// decrypted-inner flows.
///
/// Returns `(decision, Option<inner_parsed>)` where `inner_parsed` is `Some`
/// only for encrypted events that decrypted successfully — used by
/// `project_one_step` to fire the subscription hook with the inner event.
///
/// Stages:
/// 1. Dependency presence check + block row writes
/// 2. Optional dependency type enforcement
/// 3. Signer verification + projector dispatch
pub(crate) fn run_dep_and_projection_stages(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    blob: &[u8],
    parsed: &ParsedEvent,
    is_encrypted_transport: bool,
    enforce_dep_types: bool,
    current_transport_key_event_id: Option<&str>,
) -> Result<(ProjectionDecision, Option<ParsedEvent>), Box<dyn std::error::Error>> {
    run_dep_and_projection_stages_with_backend(
        conn,
        recorded_by,
        event_id_b64,
        blob,
        parsed,
        is_encrypted_transport,
        enforce_dep_types,
        current_transport_key_event_id,
    )
}

pub(crate) fn run_dep_and_projection_stages_with_backend<B: ProjectionBackend>(
    backend: &B,
    recorded_by: &str,
    event_id_b64: &str,
    blob: &[u8],
    parsed: &ParsedEvent,
    is_encrypted_transport: bool,
    enforce_dep_types: bool,
    current_transport_key_event_id: Option<&str>,
) -> ProjectionApplyResult<(ProjectionDecision, Option<ParsedEvent>)> {
    if let Err(reason) = check_transport_privacy(parsed, is_encrypted_transport) {
        return Ok((ProjectionDecision::Reject { reason }, None));
    }

    let deps = parsed.dep_field_values();
    if let Some(block) = backend.check_deps_and_block(recorded_by, event_id_b64, parsed, &deps)? {
        return Ok((block, None));
    }

    if enforce_dep_types {
        let meta = registry()
            .lookup(parsed.event_type_code())
            .ok_or_else(|| format!("unknown type code {}", parsed.event_type_code()))?;
        if !meta.dep_field_type_codes.is_empty() {
            if let Some(reason) =
                backend.check_dep_types(recorded_by, parsed, &deps, meta.dep_field_type_codes)?
            {
                return Ok((ProjectionDecision::Reject { reason }, None));
            }
        }
    }

    apply_projection_with_backend(
        backend,
        recorded_by,
        event_id_b64,
        blob,
        parsed,
        current_transport_key_event_id,
    )
}
