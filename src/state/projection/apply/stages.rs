use super::super::decision::ProjectionDecision;
use super::super::signer::{verify_ed25519_signature, SignerResolution};
use super::backend::{ProjectionApplyResult, ProjectionBackend};
use crate::crypto::{event_id_to_base64, EventId};
use crate::db::queue::current_timestamp_ms;
use crate::db::timeline::EventTimeline;
use crate::event_modules::encrypted::NO_OWNER_EVENT_ID;
use crate::event_modules::{
    registry, ParsedEvent, TransportPrivacy, EVENT_TYPE_FILE, EVENT_TYPE_FILE_SLICE,
    EVENT_TYPE_REACTION,
};
use crate::projection::contract::EmitCommand;
use crate::projection::queries::{ContextLoadResult, DepLoadResult, ProjectionFrameContext};
use crate::state::live_hints::source_peer_id_from_source_tag;
use rusqlite::{Connection, OptionalExtension};

use super::dispatch::dispatch_pure_projector;

const MAX_PROJECTION_ENVELOPE_DEPTH: usize = 4;

fn encrypted_owner_deleted_fast_path<B: ProjectionBackend>(
    backend: &B,
    recorded_by: &str,
    parsed: &ParsedEvent,
) -> ProjectionApplyResult<Option<String>> {
    let ParsedEvent::Encrypted(enc) = parsed else {
        return Ok(None);
    };
    if enc.owner_event_id == NO_OWNER_EVENT_ID {
        return Ok(None);
    }
    if !matches!(
        enc.inner_type_code,
        EVENT_TYPE_REACTION | EVENT_TYPE_FILE | EVENT_TYPE_FILE_SLICE
    ) {
        return Ok(None);
    }
    let owner_event_id_b64 = event_id_to_base64(&enc.owner_event_id);
    if backend.message_is_deleted(recorded_by, &owner_event_id_b64)? {
        return Ok(Some(owner_event_id_b64));
    }
    Ok(None)
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

pub(crate) fn load_recorded_source_peer_id(
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
    // after projector context changes.
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

fn load_context_with_prereqs<B: ProjectionBackend>(
    backend: &B,
    frame: &ProjectionFrameContext,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> ProjectionApplyResult<ContextLoadResult> {
    let meta = registry()
        .lookup(parsed.event_type_code())
        .ok_or_else(|| format!("unknown type code {}", parsed.event_type_code()))?;

    let deps = parsed.dep_field_values();
    let mut missing = Vec::new();
    for (idx, (field_name, dep_id)) in deps.iter().enumerate() {
        match backend.load_dep_result(recorded_by, parsed, field_name, dep_id)? {
            DepLoadResult::Missing => missing.push(*dep_id),
            DepLoadResult::Ready { semantic_type_code } => {
                let allowed = meta.dep_field_type_codes.get(idx).copied().unwrap_or(&[]);
                if allowed.is_empty() {
                    continue;
                }
                let Some(actual) = semantic_type_code else {
                    return Ok(ContextLoadResult::reject(format!(
                        "dep {} missing tenant-scoped semantic type record",
                        field_name
                    )));
                };
                if !allowed.contains(&actual) {
                    return Ok(ContextLoadResult::reject(format!(
                        "dep {} has semantic type code {} but expected one of {:?}",
                        field_name, actual, allowed
                    )));
                }
            }
        }
    }

    if !missing.is_empty() {
        missing.sort_unstable();
        missing.dedup();
        return Ok(ContextLoadResult::block(missing));
    }

    (meta.context_loader)(backend, frame, recorded_by, event_id_b64, parsed)
}

/// Shared projection helper: verify signer (if required), build context snapshot,
/// dispatch to pure projector, execute write_ops, return decision.
///
/// This is the core of the pure functional projector architecture: projectors
/// are pure functions over (event, context snapshot) that return deterministic
/// write_ops and emit_commands. The apply engine executes them.
pub(crate) fn apply_projection_with_backend<B: ProjectionBackend>(
    backend: &B,
    recorded_by: &str,
    event_id_b64: &str,
    blob: &[u8],
    parsed: &ParsedEvent,
) -> ProjectionApplyResult<(ProjectionDecision, Option<ParsedEvent>)> {
    apply_projection_frame(
        backend,
        recorded_by,
        event_id_b64,
        blob,
        parsed,
        false,
        ProjectionFrameContext::default(),
        0,
    )
}

pub(crate) fn run_dep_and_projection_stages(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    blob: &[u8],
    parsed: &ParsedEvent,
    is_encrypted_transport: bool,
    _allow_envelope_recursion: bool,
    current_transport_key_event_id: Option<&str>,
) -> ProjectionApplyResult<(ProjectionDecision, Option<ParsedEvent>)> {
    run_dep_and_projection_stages_with_backend(
        conn,
        recorded_by,
        event_id_b64,
        blob,
        parsed,
        is_encrypted_transport,
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
    current_transport_key_event_id: Option<&str>,
) -> ProjectionApplyResult<(ProjectionDecision, Option<ParsedEvent>)> {
    let mut frame = ProjectionFrameContext::default();
    frame.current_transport_key_event_id = current_transport_key_event_id.map(ToOwned::to_owned);
    apply_projection_frame(
        backend,
        recorded_by,
        event_id_b64,
        blob,
        parsed,
        is_encrypted_transport,
        frame,
        0,
    )
}

fn apply_projection_frame<B: ProjectionBackend>(
    backend: &B,
    recorded_by: &str,
    event_id_b64: &str,
    blob: &[u8],
    parsed: &ParsedEvent,
    is_encrypted_transport: bool,
    frame: ProjectionFrameContext,
    envelope_depth: usize,
) -> ProjectionApplyResult<(ProjectionDecision, Option<ParsedEvent>)> {
    let meta = registry()
        .lookup(parsed.event_type_code())
        .ok_or_else(|| format!("unknown type code {}", parsed.event_type_code()))?;

    if meta.signer_required && frame.current_signer.is_none() {
        return Ok((
            ProjectionDecision::Reject {
                reason: format!("{} missing current signer envelope", meta.type_name),
            },
            None,
        ));
    }

    if let Err(reason) = check_transport_privacy(parsed, is_encrypted_transport) {
        return Ok((ProjectionDecision::Reject { reason }, None));
    }

    if let Some(owner_event_id_b64) =
        encrypted_owner_deleted_fast_path(backend, recorded_by, parsed)?
    {
        backend.execute_emit_commands(
            recorded_by,
            &[EmitCommand::HardPurgeMessageGraph {
                message_event_id: owner_event_id_b64,
            }],
        )?;
        return Ok((ProjectionDecision::Valid, None));
    }

    // Generic prerequisite reads now live at the context-load boundary:
    // declared deps, dep semantic types, and module-local context all return
    // through the same tri-state result.
    let mut ctx =
        match load_context_with_prereqs(backend, &frame, recorded_by, event_id_b64, parsed)? {
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
    ctx.current_transport_key_event_id = frame.current_transport_key_event_id.clone();
    ctx.current_owner_event_id = frame.current_owner_event_id.clone();
    ctx.current_signer = frame.current_signer.clone();

    if let ParsedEvent::Signed(signed) = parsed {
        if envelope_depth >= MAX_PROJECTION_ENVELOPE_DEPTH {
            return Ok((
                ProjectionDecision::Reject {
                    reason: "projection envelope depth exceeded".to_string(),
                },
                None,
            ));
        }

        let resolution = backend.resolve_signer_key(recorded_by, &signed.signer_event_id)?;
        let resolved = match resolution {
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
            SignerResolution::Found(resolved) => resolved,
        };

        if blob.len() < 64 {
            return Ok((
                ProjectionDecision::Reject {
                    reason: "blob too short for signature".to_string(),
                },
                None,
            ));
        }
        let signing_bytes = &blob[..blob.len() - 64];
        if !verify_ed25519_signature(&resolved.public_key, signing_bytes, &signed.signature) {
            return Ok((
                ProjectionDecision::Reject {
                    reason: "invalid signature".to_string(),
                },
                None,
            ));
        }

        let inner_parsed = match crate::event_modules::parse_event(&signed.payload) {
            Ok(v) => v,
            Err(err) => {
                return Ok((
                    ProjectionDecision::Reject {
                        reason: format!("inner event parse error: {}", err),
                    },
                    None,
                ))
            }
        };
        if inner_parsed.event_type_code() != signed.inner_type_code {
            return Ok((
                ProjectionDecision::Reject {
                    reason: format!(
                        "inner type mismatch: signed wrapper declares {}, inner is {}",
                        signed.inner_type_code,
                        inner_parsed.event_type_code()
                    ),
                },
                None,
            ));
        }
        if matches!(inner_parsed, ParsedEvent::Signed(_)) {
            return Ok((
                ProjectionDecision::Reject {
                    reason: "nested signed wrappers are not allowed".to_string(),
                },
                None,
            ));
        }

        let mut next_frame = frame.clone();
        next_frame.current_signer = Some(resolved.info.clone());
        let (decision, inner) = apply_projection_frame(
            backend,
            recorded_by,
            event_id_b64,
            &signed.payload,
            &inner_parsed,
            is_encrypted_transport,
            next_frame,
            envelope_depth + 1,
        )?;
        return Ok((decision, inner.or(Some(inner_parsed))));
    }

    if let ParsedEvent::Encrypted(enc) = parsed {
        if envelope_depth >= MAX_PROJECTION_ENVELOPE_DEPTH {
            return Ok((
                ProjectionDecision::Reject {
                    reason: "projection envelope depth exceeded".to_string(),
                },
                None,
            ));
        }
        let Some(key_bytes) = backend.load_key_secret_bytes(recorded_by, &enc.key_event_id)? else {
            return Ok((
                ProjectionDecision::Reject {
                    reason: "secret key not found in key_secrets table".to_string(),
                },
                None,
            ));
        };
        let plaintext = match crate::projection::encrypted::decrypt_event_blob(
            &key_bytes,
            &enc.nonce,
            &enc.ciphertext,
            &enc.auth_tag,
        ) {
            Ok(v) => v,
            Err(_) => {
                return Ok((
                    ProjectionDecision::Reject {
                        reason: "decryption failed (wrong key or corrupted)".to_string(),
                    },
                    None,
                ))
            }
        };
        let inner_parsed = match crate::event_modules::parse_event(&plaintext) {
            Ok(v) => v,
            Err(err) => {
                return Ok((
                    ProjectionDecision::Reject {
                        reason: format!("inner event parse error: {}", err),
                    },
                    None,
                ))
            }
        };
        if inner_parsed.event_type_code() != enc.inner_type_code {
            return Ok((
                ProjectionDecision::Reject {
                    reason: format!(
                        "inner type mismatch: outer declares {}, inner is {}",
                        enc.inner_type_code,
                        inner_parsed.event_type_code()
                    ),
                },
                None,
            ));
        }
        let Some(inner_meta) = registry().lookup(inner_parsed.event_type_code()) else {
            return Ok((
                ProjectionDecision::Reject {
                    reason: format!(
                        "event type {} is not admissible inside encrypted wrappers",
                        inner_parsed.event_type_code()
                    ),
                },
                None,
            ));
        };
        if !inner_meta.encryptable {
            return Ok((
                ProjectionDecision::Reject {
                    reason: format!(
                        "event type {} is not admissible inside encrypted wrappers",
                        inner_parsed.event_type_code()
                    ),
                },
                None,
            ));
        }
        let transport_key_event_id_b64 = event_id_to_base64(&enc.key_event_id);
        let mut next_frame = frame.clone();
        next_frame.current_transport_key_event_id = Some(transport_key_event_id_b64.clone());
        if enc.owner_event_id != NO_OWNER_EVENT_ID {
            next_frame.current_owner_event_id = Some(event_id_to_base64(&enc.owner_event_id));
        } else {
            next_frame.current_owner_event_id = None;
        }
        let (decision, _) = apply_projection_frame(
            backend,
            recorded_by,
            event_id_b64,
            &plaintext,
            &inner_parsed,
            true,
            next_frame,
            envelope_depth + 1,
        )?;
        let inner = matches!(decision, ProjectionDecision::Valid).then_some(inner_parsed);
        return Ok((decision, inner));
    }

    ctx.current_transport_key_event_id = frame.current_transport_key_event_id.clone();
    ctx.current_owner_event_id = frame.current_owner_event_id.clone();
    ctx.current_signer = frame.current_signer.clone();

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
        ProjectionDecision::Block { ref missing } => {
            if !missing.is_empty() {
                backend.record_block(recorded_by, event_id_b64, missing)?;
            }
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
    use crate::projection::apply::backend::ProjectionBackend;
    use crate::state::dependency_fetch;

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

        let (mut rx, _guard): (tokio::sync::mpsc::UnboundedReceiver<Vec<EventId>>, _) =
            dependency_fetch::register(&db_path, "tenant-a", "peer-z");
        ProjectionBackend::record_block(&conn, "tenant-a", &blocked_b64, &[missing]).unwrap();
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

        let (mut rx, _guard): (tokio::sync::mpsc::UnboundedReceiver<Vec<EventId>>, _) =
            dependency_fetch::register(&db_path, "tenant-a", "peer-z");
        ProjectionBackend::record_block(&conn, "tenant-a", &blocked_b64, &[missing]).unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), rx.recv())
                .await
                .is_err()
        );
    }
}
