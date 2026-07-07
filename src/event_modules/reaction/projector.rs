use super::super::ParsedEvent;
use crate::crypto::event_id_to_base64;
use crate::projection::decision_context::{
    ContextLoadResult, ProjectionFrameContext, ProjectionQueries,
};
use crate::projection::projector::{ProjectorDecisionContext, ProjectorResult, SqlVal, WriteOp};

pub fn build_projector_context(
    queries: &dyn ProjectionQueries,
    frame: &ProjectionFrameContext,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextLoadResult, Box<dyn std::error::Error>> {
    let reaction = match parsed {
        ParsedEvent::Reaction(reaction) => reaction,
        _ => return Err("reaction context loader called for non-reaction event".into()),
    };

    let ctx = queries.load_reaction_context(frame, recorded_by, event_id_b64, reaction)?;
    if let Some(reason) = &ctx.signer_user_mismatch_reason {
        return Ok(ContextLoadResult::reject(reason.clone()));
    }
    Ok(ContextLoadResult::ready(ctx))
}

/// Pure projector: Reaction → reactions table insert.
///
/// Tombstoned targets are handled by dependency context loading before this
/// projector runs; the resulting hard purge is valid but writes no reaction row.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ProjectorDecisionContext,
) -> ProjectorResult {
    let rxn = match parsed {
        ParsedEvent::Reaction(r) => r,
        _ => return ProjectorResult::reject("not a reaction event".to_string()),
    };

    if rxn.emoji.trim().is_empty() {
        return ProjectorResult::reject("reaction content must not be empty".to_string());
    }

    let target_id_b64 = event_id_to_base64(&rxn.target_event_id);
    if let Some(owner_event_id_b64) = ctx.current_owner_event_id.as_deref() {
        if owner_event_id_b64 != target_id_b64 {
            return ProjectorResult::reject(format!(
                "reaction owner_event_id {} does not match target_event_id {}",
                owner_event_id_b64, target_id_b64
            ));
        }
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
