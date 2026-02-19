use super::super::ParsedEvent;
use crate::crypto::event_id_to_base64;
use crate::projection::result::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

/// Pure projector: Message -> messages table insert.
///
/// Also checks the context snapshot for a matching deletion_intent. If the
/// message target already has a deletion intent recorded, the message is
/// projected as tombstoned on first materialization.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let msg = match parsed {
        ParsedEvent::Message(m) => m,
        _ => return ProjectorResult::reject("not a message event".to_string()),
    };

    if let Some(reason) = &ctx.signer_user_mismatch_reason {
        return ProjectorResult::reject(reason.clone());
    }

    let workspace_id_b64 = event_id_to_base64(&msg.workspace_id);
    let author_id_b64 = event_id_to_base64(&msg.author_id);

    // Check for pre-existing deletion intents (delete-before-create convergence).
    // Multiple intents may exist (different deletion events targeting this message).
    // Find the first one whose author matches the message author.
    if let Some(intent) = ctx.deletion_intents.iter().find(|i| i.author_id == author_id_b64) {
        // Message was already targeted for deletion before it arrived.
        // Record the tombstone immediately using the original deletion event ID
        // for replay invariance.
        let ops = vec![WriteOp::InsertOrIgnore {
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
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Text(intent.deletion_event_id.clone()),
                SqlVal::Text(intent.author_id.clone()),
                SqlVal::Int(intent.created_at),
            ],
        }];
        // Structurally valid (the event itself is fine), but tombstoned.
        return ProjectorResult::valid(ops);
    }
    // No matching-author intent found - materialize the message normally.
    // Any wrong-author intents are stale and ignored.

    let ops = vec![WriteOp::InsertOrIgnore {
        table: "messages",
        columns: vec![
            "message_id",
            "workspace_id",
            "author_id",
            "content",
            "created_at",
            "recorded_by",
        ],
        values: vec![
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(workspace_id_b64),
            SqlVal::Text(author_id_b64),
            SqlVal::Text(msg.content.clone()),
            SqlVal::Int(msg.created_at_ms as i64),
            SqlVal::Text(recorded_by.to_string()),
        ],
    }];
    ProjectorResult::valid(ops)
}
