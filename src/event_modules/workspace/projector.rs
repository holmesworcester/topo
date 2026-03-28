use crate::event_modules::ParsedEvent;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use crate::projection::queries::{ContextLoadResult, ProjectionQueries};

pub fn build_projector_context(
    queries: &dyn ProjectionQueries,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextLoadResult, Box<dyn std::error::Error>> {
    let workspace = match parsed {
        ParsedEvent::Workspace(workspace) => workspace,
        _ => return Err("workspace context loader called for non-workspace event".into()),
    };

    let ctx = queries.load_workspace_context(recorded_by, event_id_b64, workspace)?;
    match &ctx.accepted_workspace_id {
        None => Ok(ContextLoadResult::block(vec![])),
        Some(anchor_wid) if anchor_wid == event_id_b64 => Ok(ContextLoadResult::ready(ctx)),
        Some(_) => Ok(ContextLoadResult::reject(
            "workspace_id does not match accepted invite binding",
        )),
    }
}

/// Pure projector: Workspace guard — accepted-invite binding must match workspace event_id.
/// Returns Block if no accepted binding yet, Reject if mismatch.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let ws = match parsed {
        ParsedEvent::Workspace(w) => w,
        _ => return ProjectorResult::reject("not a workspace event".to_string()),
    };

    let ops = vec![WriteOp::InsertOrIgnore {
        table: "workspaces",
        columns: vec![
            "recorded_by",
            "event_id",
            "workspace_id",
            "public_key",
            "name",
        ],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Blob(ws.public_key.to_vec()),
            SqlVal::Text(ws.name.clone()),
        ],
    }];
    ProjectorResult::valid(ops)
}
