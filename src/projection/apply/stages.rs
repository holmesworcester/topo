use super::super::decision::ProjectionDecision;
use super::super::encrypted::project_encrypted;
use super::super::result::EmitCommand;
use super::super::signer::{resolve_signer_key, verify_ed25519_signature, SignerResolution};
use crate::crypto::{event_id_to_base64, EventId};
use crate::event_modules::{registry, ParsedEvent};
use rusqlite::Connection;
use std::time::{SystemTime, UNIX_EPOCH};

use super::context::build_context_snapshot;
use super::dispatch::dispatch_pure_projector;
use super::write_exec::{execute_emit_commands, execute_write_ops};

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
pub(crate) fn record_rejection(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    reason: &str,
) {
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
) -> Result<ProjectionDecision, Box<dyn std::error::Error>> {
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

    // Encrypted events still use the old flow (they decrypt and recurse
    // through run_dep_and_projection_stages for the inner event).
    if let ParsedEvent::Encrypted(enc) = parsed {
        return project_encrypted(conn, recorded_by, event_id_b64, enc);
    }

    // Build context snapshot — the only DB reads the projector needs
    let ctx = build_context_snapshot(conn, recorded_by, event_id_b64, parsed)?;

    // Dispatch to pure projector
    let result = dispatch_pure_projector(recorded_by, event_id_b64, parsed, &ctx);

    // Apply: execute write_ops transactionally
    if matches!(result.decision, ProjectionDecision::Valid)
        || matches!(result.decision, ProjectionDecision::AlreadyProcessed)
    {
        execute_write_ops(conn, &result.write_ops)?;
    }

    // Execute emitted commands (only on Valid)
    if matches!(result.decision, ProjectionDecision::Valid) {
        execute_emit_commands(conn, recorded_by, &result.emit_commands)?;
    }

    // Handle guard-block commands even on Block decisions (e.g., file_slice guard blocks)
    if matches!(result.decision, ProjectionDecision::Block { .. }) {
        for cmd in &result.emit_commands {
            if let EmitCommand::RecordFileSliceGuardBlock { file_id, event_id } = cmd {
                conn.execute(
                    "INSERT OR IGNORE INTO file_slice_guard_blocks (peer_id, file_id, event_id)
                     VALUES (?1, ?2, ?3)",
                    rusqlite::params![recorded_by, file_id, event_id],
                )?;
            }
        }
    }

    Ok(result.decision)
}

/// Shared dependency/signer/projection stage bundle used by cleartext and
/// decrypted-inner flows.
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
    enforce_dep_types: bool,
) -> Result<ProjectionDecision, Box<dyn std::error::Error>> {
    let deps = parsed.dep_field_values();
    if let Some(block) = check_deps_and_block(conn, recorded_by, event_id_b64, &deps)? {
        return Ok(block);
    }

    if enforce_dep_types {
        let meta = registry()
            .lookup(parsed.event_type_code())
            .ok_or_else(|| format!("unknown type code {}", parsed.event_type_code()))?;
        if !meta.dep_field_type_codes.is_empty() {
            if let Some(reason) = check_dep_types(conn, &deps, meta.dep_field_type_codes)? {
                return Ok(ProjectionDecision::Reject { reason });
            }
        }
    }

    apply_projection(conn, recorded_by, event_id_b64, blob, parsed)
}
