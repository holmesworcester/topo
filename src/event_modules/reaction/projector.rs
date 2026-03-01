use super::super::ParsedEvent;
use crate::crypto::event_id_to_base64;
use crate::projection::result::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

/// Pure projector: Reaction → reactions table insert.
///
/// If the target message has been deleted, the
/// reaction is structurally valid but no row is written.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let rxn = match parsed {
        ParsedEvent::Reaction(r) => r,
        _ => return ProjectorResult::reject("not a reaction event".to_string()),
    };

    if let Some(reason) = &ctx.signer_user_mismatch_reason {
        return ProjectorResult::reject(reason.clone());
    }

    let target_id_b64 = event_id_to_base64(&rxn.target_event_id);

    // Check deletion state — skip if target is tombstoned or has deletion intent
    if ctx.target_message_deleted {
        return ProjectorResult::valid(vec![]); // valid event, no row written
    }

    let author_id_b64 = event_id_to_base64(&rxn.author_id);
    let ops = vec![WriteOp::InsertOrIgnore {
        table: "reactions",
        columns: vec![
            "event_id",
            "target_event_id",
            "author_id",
            "emoji",
            "created_at",
            "recorded_by",
        ],
        values: vec![
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(target_id_b64),
            SqlVal::Text(author_id_b64),
            SqlVal::Text(rxn.emoji.clone()),
            SqlVal::Int(rxn.created_at_ms as i64),
            SqlVal::Text(recorded_by.to_string()),
        ],
    }];
    ProjectorResult::valid(ops)
}
