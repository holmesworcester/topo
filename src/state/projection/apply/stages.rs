use super::super::decision::ProjectionDecision;
use super::super::encrypted::project_encrypted;
use super::super::signer::{resolve_signer_key, verify_ed25519_signature, SignerResolution};
use crate::crypto::{event_id_to_base64, EventId};
use crate::db::timeline::EventTimeline;
use crate::db::wanted::WantedEvents;
use crate::event_modules::{registry, ParsedEvent, TransportPrivacy};
use rusqlite::{Connection, OptionalExtension};
use std::time::{SystemTime, UNIX_EPOCH};

use super::dispatch::dispatch_pure_projector;
use super::write_exec::{execute_emit_commands, execute_write_ops};

fn semantic_type_code_for_parsed(parsed: &ParsedEvent) -> u8 {
    match parsed {
        ParsedEvent::Encrypted(enc) => enc.inner_type_code,
        _ => parsed.event_type_code(),
    }
}

fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
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
        None => Ok(None),
    }
}

/// Check that each dep's type code matches the allowed types for that dep field.
/// Returns Some(reason) if a type mismatch is found, None if all pass.
pub(crate) fn check_dep_types(
    conn: &Connection,
    recorded_by: &str,
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
                return Ok(Some(format!(
                    "dep {} missing tenant-scoped semantic type record",
                    field_name
                )))
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
    let _ = WantedEvents::new(conn).insert_many_for_local(recorded_by, &missing);
    let _ = EventTimeline::new(conn).mark_blocked_b64(event_id_b64, current_timestamp_ms());

    Ok(Some(ProjectionDecision::Block { missing }))
}

/// Shared projection helper: verify signer (if required), build context snapshot,
/// dispatch to pure projector, execute write_ops, return decision.
///
/// This is the core of the pure functional projector architecture: projectors
/// are pure functions over (event, context snapshot) that return deterministic
/// write_ops and emit_commands. The apply engine executes them.
pub(crate) fn apply_projection(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    blob: &[u8],
    parsed: &ParsedEvent,
    current_transport_key_event_id: Option<&str>,
) -> Result<(ProjectionDecision, Option<ParsedEvent>), Box<dyn std::error::Error>> {
    let meta = registry()
        .lookup(parsed.event_type_code())
        .ok_or_else(|| format!("unknown type code {}", parsed.event_type_code()))?;

    // Signer verification (if required) — this stays in the pipeline
    // because it requires blob bytes and is uniform across all signed events.
    if meta.signer_required {
        let (signer_event_id, signer_type) = parsed
            .signer_fields()
            .ok_or("signer_required but no signer_fields")?;
        let resolution = resolve_signer_key(conn, recorded_by, signer_type, &signer_event_id)?;
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
        let (decision, inner) = project_encrypted(conn, recorded_by, event_id_b64, enc)?;
        return Ok((decision, inner));
    }

    // Build projector context via event-module-owned loader.
    let mut ctx = (meta.context_loader)(conn, recorded_by, event_id_b64, parsed)?;
    ctx.current_transport_key_event_id = current_transport_key_event_id.map(ToOwned::to_owned);

    // Dispatch to pure projector
    let result = dispatch_pure_projector(recorded_by, event_id_b64, parsed, &ctx);

    // Explicit per-decision side-effect policy:
    // - Valid: apply write_ops and emitted commands.
    // - Block: apply emitted commands only (for block-side effects).
    // - Reject / AlreadyProcessed: no side effects.
    match result.decision {
        ProjectionDecision::Valid => {
            execute_write_ops(conn, &result.write_ops)?;
            execute_emit_commands(conn, recorded_by, &result.emit_commands)?;
        }
        ProjectionDecision::Block { .. } => {
            execute_emit_commands(conn, recorded_by, &result.emit_commands)?;
        }
        ProjectionDecision::Reject { .. } | ProjectionDecision::AlreadyProcessed => {}
    }

    Ok((result.decision, None))
}

/// Like `apply_projection` but returns the `ProjectorResult` without executing
/// writes. Used by batch projection to collect WriteOps across many events and
/// execute them in one transaction.
///
/// Returns `None` for encrypted events (they need the old recursive path).
pub(crate) fn prepare_projection(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    blob: &[u8],
    parsed: &ParsedEvent,
) -> Result<Option<crate::state::projection::contract::ProjectorResult>, Box<dyn std::error::Error>>
{
    let meta = registry()
        .lookup(parsed.event_type_code())
        .ok_or_else(|| format!("unknown type code {}", parsed.event_type_code()))?;

    // Signer verification
    if meta.signer_required {
        let (signer_event_id, signer_type) = parsed
            .signer_fields()
            .ok_or("signer_required but no signer_fields")?;
        let resolution = resolve_signer_key(conn, recorded_by, signer_type, &signer_event_id)?;
        match resolution {
            SignerResolution::NotFound => {
                return Ok(Some(crate::state::projection::contract::ProjectorResult::reject(
                    "signer key not found".to_string(),
                )));
            }
            SignerResolution::Invalid(msg) => {
                return Ok(Some(crate::state::projection::contract::ProjectorResult::reject(
                    format!("signer resolution failed: {}", msg),
                )));
            }
            SignerResolution::Found(key) => {
                let sig_len = meta.signature_byte_len;
                if blob.len() < sig_len {
                    return Ok(Some(crate::state::projection::contract::ProjectorResult::reject(
                        "blob too short for signature".to_string(),
                    )));
                }
                let signing_bytes = &blob[..blob.len() - sig_len];
                let sig_bytes = &blob[blob.len() - sig_len..];
                if !verify_ed25519_signature(&key, signing_bytes, sig_bytes) {
                    return Ok(Some(crate::state::projection::contract::ProjectorResult::reject(
                        "invalid signature".to_string(),
                    )));
                }
            }
        }
    }

    // Encrypted events cannot be prepared — they recurse internally
    if matches!(parsed, ParsedEvent::Encrypted(_)) {
        return Ok(None);
    }

    // Build context and dispatch to pure projector
    let mut ctx = (meta.context_loader)(conn, recorded_by, event_id_b64, parsed)?;
    ctx.current_transport_key_event_id = None;

    let result = dispatch_pure_projector(recorded_by, event_id_b64, parsed, &ctx);
    Ok(Some(result))
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
    if let Err(reason) = check_transport_privacy(parsed, is_encrypted_transport) {
        return Ok((ProjectionDecision::Reject { reason }, None));
    }

    let deps = parsed.dep_field_values();
    if let Some(block) = check_deps_and_block(conn, recorded_by, event_id_b64, &deps)? {
        return Ok((block, None));
    }

    if enforce_dep_types {
        let meta = registry()
            .lookup(parsed.event_type_code())
            .ok_or_else(|| format!("unknown type code {}", parsed.event_type_code()))?;
        if !meta.dep_field_type_codes.is_empty() {
            if let Some(reason) =
                check_dep_types(conn, recorded_by, &deps, meta.dep_field_type_codes)?
            {
                return Ok((ProjectionDecision::Reject { reason }, None));
            }
        }
    }

    apply_projection(
        conn,
        recorded_by,
        event_id_b64,
        blob,
        parsed,
        current_transport_key_event_id,
    )
}
