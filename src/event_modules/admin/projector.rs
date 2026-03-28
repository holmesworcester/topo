use super::super::ParsedEvent;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use crate::projection::queries::define_query_context_loader;

define_query_context_loader!(build_projector_context, Admin, load_admin_context, "admin");

/// Pure projector: Admin -> admins table.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let public_key = match parsed {
        ParsedEvent::Admin(a) => &a.public_key,
        _ => return ProjectorResult::reject("not an admin event".to_string()),
    };
    if let Some(reason) = &ctx.admin_user_key_mismatch_reason {
        return ProjectorResult::reject(reason.clone());
    }

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

#[cfg(test)]
mod projector_tests {
    use super::*;
    use crate::event_modules::{AdminEvent, ParsedEvent, WorkspaceEvent};

    fn admin_event() -> ParsedEvent {
        ParsedEvent::Admin(AdminEvent {
            created_at_ms: 1,
            public_key: [9u8; 32],
            user_event_id: [7u8; 32],
            signed_by: [8u8; 32],
            signer_type: 1,
            signature: [0u8; 64],
        })
    }

    #[test]
    fn test_admin_valid_with_matching_user_binding() {
        let result = project_pure(
            "peer1",
            "admin-event",
            &admin_event(),
            &ContextSnapshot::default(),
        );
        assert!(matches!(
            result.decision,
            crate::projection::decision::ProjectionDecision::Valid
        ));
        assert_eq!(result.write_ops.len(), 1);
    }

    #[test]
    fn test_admin_rejects_user_key_mismatch() {
        let result = project_pure(
            "peer1",
            "admin-event",
            &admin_event(),
            &ContextSnapshot {
                admin_user_key_mismatch_reason: Some(
                    "admin public_key does not match user public_key".to_string(),
                ),
                ..ContextSnapshot::default()
            },
        );
        assert!(matches!(
            result.decision,
            crate::projection::decision::ProjectionDecision::Reject { .. }
        ));
    }

    #[test]
    fn test_admin_rejects_non_admin_event() {
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
