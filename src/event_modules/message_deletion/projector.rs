use super::super::ParsedEvent;
use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

/// Pure projector: MessageDeletion -> two-stage deletion intent + tombstone model.
///
/// 1. Always emits an idempotent deletion_intent write keyed by (recorded_by, "message", target_id).
/// 2. If target exists in projected state (ctx.target_message_author is Some), verifies
///    author match and emits tombstone + cascade writes.
/// 3. If target doesn't exist yet (None), only records intent - the message projector
///    will tombstone on first materialization when it checks deletion_intents.
/// 4. If already tombstoned, verifies author and returns AlreadyProcessed.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let del = match parsed {
        ParsedEvent::MessageDeletion(d) => d,
        _ => return ProjectorResult::reject("not a message_deletion event".to_string()),
    };

    if let Some(reason) = &ctx.signer_user_mismatch_reason {
        return ProjectorResult::reject(reason.clone());
    }

    let target_b64 = event_id_to_base64(&del.target_event_id);
    let del_author_b64 = event_id_to_base64(&del.author_id);

    // Type validation: reject if target is a known non-message event.
    if ctx.target_is_non_message {
        return ProjectorResult::reject("deletion target is a non-message event".to_string());
    }

    // Already tombstoned - verify author, return AlreadyProcessed
    if let Some(ref stored_author) = ctx.target_tombstone_author {
        if stored_author != &del_author_b64 {
            return ProjectorResult::reject(
                "deletion author does not match message author".to_string(),
            );
        }
        // Deletion intent should still be recorded for idempotence,
        // but it's a no-op if already exists.
        let ops = vec![WriteOp::InsertOrIgnore {
            table: "deletion_intents",
            columns: vec![
                "recorded_by",
                "target_kind",
                "target_id",
                "deletion_event_id",
                "author_id",
                "created_at",
            ],
            values: vec![
                SqlVal::Text(recorded_by.to_string()),
                SqlVal::Text("message".to_string()),
                SqlVal::Text(target_b64),
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Text(del_author_b64),
                SqlVal::Int(del.created_at_ms as i64),
            ],
        }];
        return ProjectorResult::valid(ops);
    }

    // Always record deletion intent (idempotent via INSERT OR IGNORE)
    let mut ops = vec![WriteOp::InsertOrIgnore {
        table: "deletion_intents",
        columns: vec![
            "recorded_by",
            "target_kind",
            "target_id",
            "deletion_event_id",
            "author_id",
            "created_at",
        ],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text("message".to_string()),
            SqlVal::Text(target_b64.clone()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(del_author_b64.clone()),
            SqlVal::Int(del.created_at_ms as i64),
        ],
    }];

    // Target exists - verify author, emit tombstone + cascade
    if let Some(ref msg_author) = ctx.target_message_author {
        if msg_author != &del_author_b64 {
            return ProjectorResult::reject(
                "deletion author does not match message author".to_string(),
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
                SqlVal::Text(del_author_b64),
                SqlVal::Int(del.created_at_ms as i64),
            ],
        });

        // Cascade: delete message and its reactions (explicit write ops, not hidden side effects)
        ops.push(WriteOp::Delete {
            table: "messages",
            where_clause: vec![
                ("recorded_by", SqlVal::Text(recorded_by.to_string())),
                ("message_id", SqlVal::Text(target_b64.clone())),
            ],
        });
        ops.push(WriteOp::Delete {
            table: "reactions",
            where_clause: vec![
                ("recorded_by", SqlVal::Text(recorded_by.to_string())),
                ("target_event_id", SqlVal::Text(target_b64)),
            ],
        });

        return ProjectorResult::valid(ops);
    }

    // Target doesn't exist yet - only record intent.
    // When the message arrives, message::project_pure will check deletion_intents
    // and tombstone immediately (delete-before-create convergence).
    ProjectorResult::valid(ops)
}
