use super::super::ParsedEvent;
use crate::projection::result::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

/// Pure projector: UserInvite (Boot or Ongoing) → user_invites table.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let public_key = match parsed {
        ParsedEvent::UserInviteBoot(ui) => &ui.public_key,
        ParsedEvent::UserInviteOngoing(ui) => &ui.public_key,
        _ => return ProjectorResult::reject("not a user_invite event".to_string()),
    };

    let ops = vec![WriteOp::InsertOrIgnore {
        table: "user_invites",
        columns: vec!["recorded_by", "event_id", "public_key"],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Blob(public_key.to_vec()),
        ],
    }];
    ProjectorResult::valid(ops)
}
