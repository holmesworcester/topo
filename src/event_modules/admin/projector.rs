use super::super::ParsedEvent;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

/// Pure projector: Admin (Boot or Ongoing) → admins table.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let public_key = match parsed {
        ParsedEvent::AdminBoot(a) => &a.public_key,
        ParsedEvent::AdminOngoing(a) => &a.public_key,
        _ => return ProjectorResult::reject("not an admin event".to_string()),
    };

    let ops = vec![WriteOp::InsertOrIgnore {
        table: "admins",
        columns: vec!["recorded_by", "event_id", "public_key"],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Blob(public_key.to_vec()),
        ],
    }];
    ProjectorResult::valid(ops)
}
