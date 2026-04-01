use super::super::ParsedEvent;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use crate::projection::queries::{ContextLoadResult, ProjectionQueries};

pub fn build_projector_context(
    queries: &dyn ProjectionQueries,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextLoadResult, Box<dyn std::error::Error>> {
    let admin = match parsed {
        ParsedEvent::Admin(admin) => admin,
        _ => return Err("admin context loader called for non-admin event".into()),
    };

    let ctx = queries.load_admin_context(recorded_by, event_id_b64, admin)?;
    if let Some(reason) = &ctx.admin_user_key_mismatch_reason {
        return Ok(ContextLoadResult::reject(reason.clone()));
    }
    Ok(ContextLoadResult::ready(ctx))
}

/// Pure projector: Admin -> admins table.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let public_key = match parsed {
        ParsedEvent::Admin(a) => &a.public_key,
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

#[cfg(test)]
mod projector_tests {
    use super::*;
    use crate::db::{open_in_memory, schema::create_tables};
    use crate::event_modules::{AdminEvent, ParsedEvent, WorkspaceEvent};
    use crate::projection::queries::ContextLoadResult;

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

    #[test]
    fn test_admin_rejects_user_key_mismatch() {
        let conn = open_in_memory().expect("open in-memory db");
        create_tables(&conn).expect("create tables");

        let recorded_by = "peer1";
        let user_event_id_b64 = crate::crypto::event_id_to_base64(&[7u8; 32]);
        conn.execute(
            "INSERT INTO users (recorded_by, event_id, public_key, username)
             VALUES (?1, ?2, ?3, 'alice')",
            rusqlite::params![recorded_by, &user_event_id_b64, vec![1u8; 32]],
        )
        .expect("insert users row");

        let ParsedEvent::Admin(admin) = admin_event() else {
            unreachable!();
        };
        let loaded = build_projector_context(
            &conn,
            recorded_by,
            "admin-event",
            &ParsedEvent::Admin(admin),
        )
        .expect("load admin context");
        match loaded {
            ContextLoadResult::Reject { reason } => {
                assert!(reason.contains("does not match user public_key"));
            }
            other => panic!("expected reject, got {other:?}"),
        }
    }
}
