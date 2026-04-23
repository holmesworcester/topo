use super::super::ParsedEvent;
use crate::event_modules::EVENT_TYPE_USER_INVITE;
use crate::projection::decision_context::{
    ContextLoadResult, ProjectionFrameContext, ProjectionQueries,
};
use crate::projection::projector::{ProjectorDecisionContext, ProjectorResult, SqlVal, WriteOp};

pub fn build_projector_context(
    _queries: &dyn ProjectionQueries,
    frame: &ProjectionFrameContext,
    _recorded_by: &str,
    _event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextLoadResult, Box<dyn std::error::Error>> {
    if !matches!(parsed, ParsedEvent::User(_)) {
        return Err("user context loader called for non-user event".into());
    }

    use topo_verus_proofs::event_modules::user::{
        decide_user_signer_plan_core, UserSignerKindCore, UserSignerPlanCore,
    };

    let signer_kind = match frame.current_signer.as_ref() {
        None => UserSignerKindCore::Missing,
        Some(current_signer) if current_signer.semantic_type_code == EVENT_TYPE_USER_INVITE => {
            UserSignerKindCore::UserInvite
        }
        Some(_) => UserSignerKindCore::Other,
    };

    let plan = decide_user_signer_plan_core(signer_kind);
    Ok(match plan {
        UserSignerPlanCore::Ready => ContextLoadResult::ready(ProjectorDecisionContext::default()),
        UserSignerPlanCore::RejectMissingSigner => {
            ContextLoadResult::reject("missing current signer envelope for user")
        }
        UserSignerPlanCore::RejectWrongSignerType => {
            ContextLoadResult::reject("user signer must be user_invite")
        }
    })
}

/// Pure projector: User -> users table.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ProjectorDecisionContext,
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
    use crate::db::{open_in_memory, schema::create_tables};
    use crate::event_modules::{ParsedEvent, UserEvent, WorkspaceEvent};
    use crate::projection::decision_context::ProjectionFrameContext;
    use crate::projection::projector::CurrentSignerInfo;

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
            &ProjectorDecisionContext::default(),
        );
        assert!(matches!(
            result.decision,
            crate::projection::decision::ProjectionDecision::Valid
        ));
        assert_eq!(result.write_ops.len(), 1);
    }

    #[test]
    fn test_user_accepts_user_invite_signer() {
        let conn = open_in_memory().expect("open db");
        create_tables(&conn).expect("create tables");

        let result = build_projector_context(
            &conn,
            &ProjectionFrameContext {
                current_signer: Some(CurrentSignerInfo {
                    event_id: crate::crypto::event_id_to_base64(&[3u8; 32]),
                    semantic_type_code: EVENT_TYPE_USER_INVITE,
                }),
                ..ProjectionFrameContext::default()
            },
            "peer1",
            "user-event",
            &user_event(),
        )
        .expect("context load");

        assert!(matches!(result, ContextLoadResult::Ready { .. }));
    }

    #[test]
    fn test_user_rejects_workspace_signer() {
        let conn = open_in_memory().expect("open db");
        create_tables(&conn).expect("create tables");

        let result = build_projector_context(
            &conn,
            &ProjectionFrameContext {
                current_signer: Some(CurrentSignerInfo {
                    event_id: crate::crypto::event_id_to_base64(&[2u8; 32]),
                    semantic_type_code: crate::event_modules::EVENT_TYPE_WORKSPACE,
                }),
                ..ProjectionFrameContext::default()
            },
            "peer1",
            "user-event",
            &user_event(),
        )
        .expect("context load");

        assert!(matches!(
            result,
            ContextLoadResult::Reject { ref reason }
                if reason.contains("user signer must be user_invite")
        ));
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
            &ProjectorDecisionContext::default(),
        );
        assert!(matches!(
            result.decision,
            crate::projection::decision::ProjectionDecision::Reject { .. }
        ));
    }

    #[test]
    fn test_user_rejects_missing_signer() {
        let conn = open_in_memory().expect("open db");
        create_tables(&conn).expect("create tables");

        let result = build_projector_context(
            &conn,
            &ProjectionFrameContext::default(),
            "peer1",
            "user-event",
            &user_event(),
        )
        .expect("context load");

        assert!(matches!(
            result,
            ContextLoadResult::Reject { ref reason }
                if reason.contains("missing current signer envelope for user")
        ));
    }
}
