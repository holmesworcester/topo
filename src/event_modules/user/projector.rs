use super::super::ParsedEvent;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

/// Pure projector: User -> users table.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let (public_key, username) = match parsed {
        ParsedEvent::User(u) => (&u.public_key, &u.username),
        _ => return ProjectorResult::reject("not a user event".to_string()),
    };

    if username.trim().is_empty() {
        return ProjectorResult::reject("username must not be empty".to_string());
    }

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

#[cfg(test)]
mod projector_tests {
    use super::*;
    use crate::event_modules::{ParsedEvent, UserEvent, WorkspaceEvent};

    fn user_event() -> ParsedEvent {
        ParsedEvent::User(UserEvent {
            created_at_ms: 1,
            public_key: [7u8; 32],
            username: "alice".to_string(),
        })
    }

    #[test]
    fn test_user_valid() {
        let result = project_pure(
            "peer1",
            "user-event",
            &user_event(),
            &ContextSnapshot::default(),
        );
        assert!(matches!(
            result.decision,
            crate::projection::decision::ProjectionDecision::Valid
        ));
        assert_eq!(result.write_ops.len(), 1);
    }

    #[test]
    fn test_user_rejects_non_user_event() {
        let other = ParsedEvent::Workspace(WorkspaceEvent {
            created_at_ms: 1,
            public_key: [0u8; 32],
            name: "ws".to_string(),
        });
        let result = project_pure(
            "peer1",
            "workspace-event",
            &other,
            &ContextSnapshot::default(),
        );
        assert!(matches!(
            result.decision,
            crate::projection::decision::ProjectionDecision::Reject { .. }
        ));
    }
}
