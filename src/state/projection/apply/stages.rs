use super::super::decision::ProjectionDecision;
use super::super::signer::{SignerResolution, verify_ed25519_signature};
use super::backend::{ProjectionApplyResult, ProjectionBackend};
use crate::crypto::{EventId, event_id_to_base64};
use crate::db::queue::current_timestamp_ms;
use crate::db::timeline::EventTimeline;
use crate::event_modules::encrypted::NO_OWNER_EVENT_ID;
use crate::event_modules::{ParsedEvent, TransportPrivacy, registry};
use crate::projection::contract::EmitCommand;
use crate::projection::queries::{
    ContextLoadResult, DepLoadResult, ProjectionFrameContext, SemanticTypePlan,
    decide_semantic_type_plan, normalize_semantic_type,
};
use rusqlite::Connection;

use super::dispatch::dispatch_pure_projector;

const MAX_PROJECTION_ENVELOPE_DEPTH: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
enum ContextLoadDispositionRawRows {
    Ready,
    Block { missing: Vec<EventId> },
    Reject { reason: String },
    Purge { message_event_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ContextLoadDispositionDecisionContext {
    Ready,
    Block { missing: Vec<EventId> },
    Reject { reason: String },
    Purge { message_event_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ContextLoadDispositionPlan {
    Continue,
    RecordBlockAndReturn { missing: Vec<EventId> },
    Reject { reason: String },
    EmitHardPurgeAndReturn { message_event_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProjectionDecisionEffectRawRows {
    Valid,
    Block { missing: Vec<EventId> },
    Reject,
    AlreadyProcessed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProjectionDecisionEffectDecisionContext {
    Valid,
    Block { missing: Vec<EventId> },
    Reject,
    AlreadyProcessed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProjectionDecisionEffectPlan {
    ApplyWriteOpsAndEmitCommands,
    EmitCommandsOnly { missing: Vec<EventId> },
    NoEffects,
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
    let mut ready_deps = Vec::new();
    let mut purge_message_event_id = None;
    for (idx, (field_name, dep_id)) in deps.iter().enumerate() {
        match backend.load_dep_result(recorded_by, parsed, field_name, dep_id)? {
            DepLoadResult::Missing => missing.push(*dep_id),
            DepLoadResult::Ready { semantic_type_rows } => {
                ready_deps.push((idx, *field_name, *dep_id, semantic_type_rows))
            }
            DepLoadResult::Reject { reason } => {
                return Ok(ContextLoadResult::reject(reason));
            }
            DepLoadResult::Purge { message_event_id } => {
                purge_message_event_id.get_or_insert(message_event_id);
            }
        }
    }

    if let Some(message_event_id) = purge_message_event_id {
        return Ok(ContextLoadResult::purge(message_event_id));
    }

    for (idx, field_name, dep_id, semantic_type_rows) in ready_deps {
        let allowed = meta.dep_field_type_codes.get(idx).copied().unwrap_or(&[]);
        let context = normalize_semantic_type(&semantic_type_rows, allowed);
        match decide_semantic_type_plan(&context, field_name) {
            SemanticTypePlan::DepMissing => missing.push(dep_id),
            SemanticTypePlan::DepReady { .. } => {}
            SemanticTypePlan::Reject { reason } => {
                return Ok(ContextLoadResult::reject(reason));
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

fn load_context_load_disposition_raw_rows(
    result: &ContextLoadResult,
) -> ContextLoadDispositionRawRows {
    match result {
        ContextLoadResult::Ready(_) => ContextLoadDispositionRawRows::Ready,
        ContextLoadResult::Block { missing } => ContextLoadDispositionRawRows::Block {
            missing: missing.clone(),
        },
        ContextLoadResult::Reject { reason } => ContextLoadDispositionRawRows::Reject {
            reason: reason.clone(),
        },
        ContextLoadResult::Purge { message_event_id } => ContextLoadDispositionRawRows::Purge {
            message_event_id: message_event_id.clone(),
        },
    }
}

fn normalize_context_load_disposition(
    raw_rows: ContextLoadDispositionRawRows,
) -> ContextLoadDispositionDecisionContext {
    match raw_rows {
        ContextLoadDispositionRawRows::Ready => ContextLoadDispositionDecisionContext::Ready,
        ContextLoadDispositionRawRows::Block { missing } => {
            ContextLoadDispositionDecisionContext::Block { missing }
        }
        ContextLoadDispositionRawRows::Reject { reason } => {
            ContextLoadDispositionDecisionContext::Reject { reason }
        }
        ContextLoadDispositionRawRows::Purge { message_event_id } => {
            ContextLoadDispositionDecisionContext::Purge { message_event_id }
        }
    }
}

fn decide_context_load_disposition(
    context: &ContextLoadDispositionDecisionContext,
) -> ContextLoadDispositionPlan {
    match context {
        ContextLoadDispositionDecisionContext::Ready => ContextLoadDispositionPlan::Continue,
        ContextLoadDispositionDecisionContext::Block { missing } => {
            ContextLoadDispositionPlan::RecordBlockAndReturn {
                missing: missing.clone(),
            }
        }
        ContextLoadDispositionDecisionContext::Reject { reason } => {
            ContextLoadDispositionPlan::Reject {
                reason: reason.clone(),
            }
        }
        ContextLoadDispositionDecisionContext::Purge { message_event_id } => {
            ContextLoadDispositionPlan::EmitHardPurgeAndReturn {
                message_event_id: message_event_id.clone(),
            }
        }
    }
}

fn decide_projection_decision_effect_plan(
    context: &ProjectionDecisionEffectDecisionContext,
) -> ProjectionDecisionEffectPlan {
    match context {
        ProjectionDecisionEffectDecisionContext::Valid => {
            ProjectionDecisionEffectPlan::ApplyWriteOpsAndEmitCommands
        }
        ProjectionDecisionEffectDecisionContext::Block { missing } => {
            ProjectionDecisionEffectPlan::EmitCommandsOnly {
                missing: missing.clone(),
            }
        }
        ProjectionDecisionEffectDecisionContext::Reject
        | ProjectionDecisionEffectDecisionContext::AlreadyProcessed => {
            ProjectionDecisionEffectPlan::NoEffects
        }
    }
}

fn load_projection_decision_effect_raw_rows(
    decision: &ProjectionDecision,
) -> ProjectionDecisionEffectRawRows {
    match decision {
        ProjectionDecision::Valid => ProjectionDecisionEffectRawRows::Valid,
        ProjectionDecision::Block { missing } => ProjectionDecisionEffectRawRows::Block {
            missing: missing.clone(),
        },
        ProjectionDecision::Reject { .. } => ProjectionDecisionEffectRawRows::Reject,
        ProjectionDecision::AlreadyProcessed => ProjectionDecisionEffectRawRows::AlreadyProcessed,
    }
}

fn normalize_projection_decision_effect_context(
    raw_rows: ProjectionDecisionEffectRawRows,
) -> ProjectionDecisionEffectDecisionContext {
    match raw_rows {
        ProjectionDecisionEffectRawRows::Valid => ProjectionDecisionEffectDecisionContext::Valid,
        ProjectionDecisionEffectRawRows::Block { missing } => {
            ProjectionDecisionEffectDecisionContext::Block { missing }
        }
        ProjectionDecisionEffectRawRows::Reject => ProjectionDecisionEffectDecisionContext::Reject,
        ProjectionDecisionEffectRawRows::AlreadyProcessed => {
            ProjectionDecisionEffectDecisionContext::AlreadyProcessed
        }
    }
}

/// Shared projection helper: verify signer (if required), build decision context,
/// dispatch to pure projector, execute write_ops, return decision.
///
/// This is the core of the pure functional projector architecture: projectors
/// are pure functions over (event, decision context) that return deterministic
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

    // Generic prerequisite reads now live at the context-load boundary:
    // declared deps, dep semantic types, and module-local context all return
    // through the same tri-state result.
    let context_result =
        load_context_with_prereqs(backend, &frame, recorded_by, event_id_b64, parsed)?;
    let context_load_disposition_context =
        normalize_context_load_disposition(load_context_load_disposition_raw_rows(&context_result));
    let mut ctx = match decide_context_load_disposition(&context_load_disposition_context) {
        ContextLoadDispositionPlan::Continue => match context_result {
            ContextLoadResult::Ready(ctx) => ctx,
            _ => unreachable!("continue plan requires ready context"),
        },
        ContextLoadDispositionPlan::RecordBlockAndReturn { missing } => {
            if !missing.is_empty() {
                backend.record_block(recorded_by, event_id_b64, &missing)?;
            }
            return Ok((ProjectionDecision::Block { missing }, None));
        }
        ContextLoadDispositionPlan::Reject { reason } => {
            return Ok((ProjectionDecision::Reject { reason }, None));
        }
        ContextLoadDispositionPlan::EmitHardPurgeAndReturn { message_event_id } => {
            backend.execute_emit_commands(
                recorded_by,
                &[EmitCommand::HardPurgeMessageGraph { message_event_id }],
            )?;
            return Ok((ProjectionDecision::Valid, None));
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
                ));
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
                ));
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
                ));
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
    let projection_decision_effect_context = normalize_projection_decision_effect_context(
        load_projection_decision_effect_raw_rows(&result.decision),
    );
    match decide_projection_decision_effect_plan(&projection_decision_effect_context) {
        ProjectionDecisionEffectPlan::ApplyWriteOpsAndEmitCommands => {
            backend.execute_write_ops(&result.write_ops)?;
            backend.execute_emit_commands(recorded_by, &result.emit_commands)?;
        }
        ProjectionDecisionEffectPlan::EmitCommandsOnly { missing } => {
            if !missing.is_empty() {
                backend.record_block(recorded_by, event_id_b64, &missing)?;
            }
            backend.execute_emit_commands(recorded_by, &result.emit_commands)?;
        }
        ProjectionDecisionEffectPlan::NoEffects => {}
    }

    Ok((result.decision, None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_connection, schema::create_tables};

    #[test]
    fn creates_blocked_event_tables() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("stages.db").to_string_lossy().to_string();
        let conn = open_connection(&db_path).unwrap();
        create_tables(&conn).unwrap();

        let blocked_events_exists: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type = 'table' AND name = 'blocked_events'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let blocked_event_deps_exists: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type = 'table' AND name = 'blocked_event_deps'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert!(blocked_events_exists);
        assert!(blocked_event_deps_exists);
    }

    #[test]
    fn context_load_disposition_maps_block_to_block_recording_plan() {
        let missing = vec![[0x11; 32]];
        let context = normalize_context_load_disposition(load_context_load_disposition_raw_rows(
            &ContextLoadResult::block(missing.clone()),
        ));
        assert_eq!(
            context,
            ContextLoadDispositionDecisionContext::Block {
                missing: missing.clone(),
            }
        );
        assert_eq!(
            decide_context_load_disposition(&context),
            ContextLoadDispositionPlan::RecordBlockAndReturn { missing }
        );
    }

    #[test]
    fn context_load_disposition_maps_purge_to_hard_purge_plan() {
        let message_event_id = "deleted-message".to_string();
        let context = normalize_context_load_disposition(load_context_load_disposition_raw_rows(
            &ContextLoadResult::purge(message_event_id.clone()),
        ));
        assert_eq!(
            context,
            ContextLoadDispositionDecisionContext::Purge {
                message_event_id: message_event_id.clone(),
            }
        );
        assert_eq!(
            decide_context_load_disposition(&context),
            ContextLoadDispositionPlan::EmitHardPurgeAndReturn { message_event_id }
        );
    }

    #[test]
    fn projection_decision_effect_plan_disables_effects_for_rejects() {
        let context = normalize_projection_decision_effect_context(
            load_projection_decision_effect_raw_rows(&ProjectionDecision::Reject {
                reason: "nope".to_string(),
            }),
        );
        assert_eq!(context, ProjectionDecisionEffectDecisionContext::Reject);
        assert_eq!(
            decide_projection_decision_effect_plan(&context),
            ProjectionDecisionEffectPlan::NoEffects
        );
    }

    #[test]
    fn projection_decision_effect_plan_disables_effects_for_already_processed() {
        let context = normalize_projection_decision_effect_context(
            load_projection_decision_effect_raw_rows(&ProjectionDecision::AlreadyProcessed),
        );
        assert_eq!(
            context,
            ProjectionDecisionEffectDecisionContext::AlreadyProcessed
        );
        assert_eq!(
            decide_projection_decision_effect_plan(&context),
            ProjectionDecisionEffectPlan::NoEffects
        );
    }

    #[test]
    fn projection_decision_effect_plan_does_not_apply_writes_for_blocks() {
        let missing = vec![[0x22; 32]];
        let context = normalize_projection_decision_effect_context(
            load_projection_decision_effect_raw_rows(&ProjectionDecision::Block {
                missing: missing.clone(),
            }),
        );
        assert_eq!(
            context,
            ProjectionDecisionEffectDecisionContext::Block {
                missing: missing.clone(),
            }
        );
        assert_eq!(
            decide_projection_decision_effect_plan(&context),
            ProjectionDecisionEffectPlan::EmitCommandsOnly { missing }
        );
    }
}
