use super::super::ParsedEvent;
use crate::crypto::event_id_to_base64;
use crate::projection::contract::{
    EmitCommand, ProjectorDecisionContext, ProjectorResult, SqlVal, WriteOp,
};
use crate::projection::queries::{ContextLoadResult, ProjectionFrameContext, ProjectionQueries};

pub fn build_projector_context(
    queries: &dyn ProjectionQueries,
    frame: &ProjectionFrameContext,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextLoadResult, Box<dyn std::error::Error>> {
    let message_deletion = match parsed {
        ParsedEvent::MessageDeletion(message_deletion) => message_deletion,
        _ => {
            return Err(
                "message_deletion context loader called for non-message_deletion event".into(),
            )
        }
    };

    let ctx = queries.load_message_deletion_context(
        frame,
        recorded_by,
        event_id_b64,
        message_deletion,
    )?;
    if let Some(reason) = &ctx.deletion_signer_reject_reason {
        return Ok(ContextLoadResult::reject(reason.clone()));
    }
    Ok(ContextLoadResult::ready(ctx))
}

/// Pure projector: MessageDeletion -> two-stage deletion intent + tombstone model.
///
/// 1. Always emits an idempotent deletion_intent write keyed by (recorded_by, target_id).
/// 2. If target exists in projected state (ctx.target_message_author is Some), verifies
///    author match and emits tombstone + cascade writes.
/// 3. If target doesn't exist yet (None), only records intent - the message projector
///    will tombstone on first materialization when it checks deletion_intents.
/// 4. If already tombstoned, verifies author and returns AlreadyProcessed.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ProjectorDecisionContext,
) -> ProjectorResult {
    let del = match parsed {
        ParsedEvent::MessageDeletion(d) => d,
        _ => return ProjectorResult::reject("not a message_deletion event".to_string()),
    };
    if ctx.current_owner_event_id.is_some() {
        return ProjectorResult::reject(
            "message_deletion events must not carry outer owner_event_id".to_string(),
        );
    }

    let target_b64 = event_id_to_base64(&del.target_event_id);
    let signer_user_b64 = ctx.deletion_signer_user_id.as_deref();
    let is_admin = ctx.deletion_signer_is_admin;
    let (intent_author_id, intent_authorized_by_admin) = if is_admin {
        ("".to_string(), 1i64)
    } else if let Some(user_id) = signer_user_b64 {
        (user_id.to_string(), 0i64)
    } else {
        return ProjectorResult::reject(
            "message_deletion signer authorization missing".to_string(),
        );
    };

    // Type validation: reject if target is a known non-message event.
    if ctx.target_is_non_message {
        return ProjectorResult::reject("deletion target is a non-message event".to_string());
    }

    // Already tombstoned - verify author, return AlreadyProcessed
    if let Some(ref stored_author) = ctx.target_tombstone_author {
        if !is_admin && Some(stored_author.as_str()) != signer_user_b64 {
            return ProjectorResult::reject(
                "deletion signer does not match message author".to_string(),
            );
        }
        // Deletion intent should still be recorded for idempotence,
        // but it's a no-op if already exists.
        let ops = vec![WriteOp::InsertOrIgnore {
            table: "deletion_intents",
            columns: vec![
                "recorded_by",
                "target_id",
                "deletion_event_id",
                "author_id",
                "authorized_by_admin",
                "created_at",
            ],
            values: vec![
                SqlVal::Text(recorded_by.to_string()),
                SqlVal::Text(target_b64.clone()),
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Text(intent_author_id),
                SqlVal::Int(intent_authorized_by_admin),
                SqlVal::Int(del.created_at_ms as i64),
            ],
        }];
        return ProjectorResult::valid_with_commands(
            ops,
            vec![EmitCommand::HardPurgeMessageGraph {
                message_event_id: target_b64,
            }],
        );
    }

    // Always record deletion intent (idempotent via INSERT OR IGNORE)
    let mut ops = vec![WriteOp::InsertOrIgnore {
        table: "deletion_intents",
        columns: vec![
            "recorded_by",
            "target_id",
            "deletion_event_id",
            "author_id",
            "authorized_by_admin",
            "created_at",
        ],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(target_b64.clone()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(intent_author_id.clone()),
            SqlVal::Int(intent_authorized_by_admin),
            SqlVal::Int(del.created_at_ms as i64),
        ],
    }];

    // Target exists - verify author, emit tombstone + cascade
    if let Some(ref msg_author) = ctx.target_message_author {
        if !is_admin && Some(msg_author.as_str()) != signer_user_b64 {
            return ProjectorResult::reject(
                "deletion signer does not match message author".to_string(),
            );
        }

        // Tombstone
        ops.push(WriteOp::InsertOrIgnore {
            table: "deleted_messages",
            columns: vec![
                "recorded_by",
                "message_id",
                "deletion_event_id",
                "author_id",
                "deleted_at",
            ],
            values: vec![
                SqlVal::Text(recorded_by.to_string()),
                SqlVal::Text(target_b64.clone()),
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Text(msg_author.clone()),
                SqlVal::Int(del.created_at_ms as i64),
            ],
        });

        return ProjectorResult::valid_with_commands(
            ops,
            vec![EmitCommand::HardPurgeMessageGraph {
                message_event_id: target_b64,
            }],
        );
    }

    // Target doesn't exist yet - only record intent.
    // When the message arrives, message::project_pure will check deletion_intents
    // and tombstone immediately (delete-before-create convergence).
    ProjectorResult::valid(ops)
}
