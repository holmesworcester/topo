use crate::event_modules::ParsedEvent;
use crate::projection::decision_context::{
    decide_workspace_context_plan, workspace_context_plan_to_load_result, ContextLoadResult,
    ProjectionFrameContext, ProjectionQueries,
};
use crate::projection::projector::{ProjectorDecisionContext, ProjectorResult, SqlVal, WriteOp};

pub fn build_projector_context(
    queries: &dyn ProjectionQueries,
    frame: &ProjectionFrameContext,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextLoadResult, Box<dyn std::error::Error>> {
    let workspace = match parsed {
        ParsedEvent::Workspace(workspace) => workspace,
        _ => return Err("workspace context loader called for non-workspace event".into()),
    };

    let context =
        queries.load_workspace_decision_context(frame, recorded_by, event_id_b64, workspace)?;
    let plan = decide_workspace_context_plan(&context, event_id_b64);
    Ok(workspace_context_plan_to_load_result(plan))
}

/// Pure projector: Workspace guard — accepted-invite binding must match workspace event_id.
/// Returns Block if no accepted binding yet, Reject if mismatch.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ProjectorDecisionContext,
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
