use super::super::ParsedEvent;
use crate::projection::result::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

/// Pure projector: User (Boot or Ongoing) → users table.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let (public_key, username) = match parsed {
        ParsedEvent::UserBoot(u) => (&u.public_key, &u.username),
        ParsedEvent::UserOngoing(u) => (&u.public_key, &u.username),
        _ => return ProjectorResult::reject("not a user event".to_string()),
    };

    let ops = vec![WriteOp::InsertOrIgnore {
        table: "users",
        columns: vec!["recorded_by", "event_id", "public_key", "username"],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Blob(public_key.to_vec()),
            SqlVal::Text(username.to_string()),
        ],
    }];
    ProjectorResult::valid(ops)
}
