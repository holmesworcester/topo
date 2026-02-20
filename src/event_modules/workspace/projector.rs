use crate::event_modules::ParsedEvent;
use crate::projection::result::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

/// Pure projector: Workspace guard — trust_anchors must match workspace event_id.
/// Returns Block if no trust anchor yet, Reject if mismatch.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let ws = match parsed {
        ParsedEvent::Workspace(w) => w,
        _ => return ProjectorResult::reject("not a workspace event".to_string()),
    };

    let workspace_id_b64 = event_id_b64.to_string();

    match &ctx.trust_anchor_workspace_id {
        None => {
            // Guard-block: no trust anchor yet. Returns Block with empty
            // missing vec because the blocker is the trust anchor (set by
            // invite_accepted), not a specific event dep. Recovery:
            // invite_accepted emits RetryWorkspaceEvent { workspace_id }
            // which re-projects this event after the anchor is written.
            ProjectorResult::block(vec![])
        }
        Some(anchor_wid) if anchor_wid == &workspace_id_b64 => {
            // Trust anchor matches — project
            let ops = vec![
                WriteOp::InsertOrIgnore {
                    table: "workspaces",
                    columns: vec!["recorded_by", "event_id", "workspace_id", "public_key", "name"],
                    values: vec![
                        SqlVal::Text(recorded_by.to_string()),
                        SqlVal::Text(event_id_b64.to_string()),
                        SqlVal::Text(workspace_id_b64),
                        SqlVal::Blob(ws.public_key.to_vec()),
                        SqlVal::Text(ws.name.clone()),
                    ],
                },
            ];
            ProjectorResult::valid(ops)
        }
        Some(_) => {
            // Foreign workspace — reject
            ProjectorResult::reject("workspace_id does not match trust anchor".to_string())
        }
    }
}
