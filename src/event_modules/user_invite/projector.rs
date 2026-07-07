use super::super::ParsedEvent;
use crate::crypto::event_id_to_base64;
use crate::event_modules::{EVENT_TYPE_PEER_SHARED, EVENT_TYPE_WORKSPACE};
use crate::projection::decision_context::{
    ContextLoadResult, ProjectionFrameContext, ProjectionQueries,
};
use crate::projection::projector::{ProjectorDecisionContext, ProjectorResult, SqlVal, WriteOp};

pub fn build_projector_context(
    queries: &dyn ProjectionQueries,
    frame: &ProjectionFrameContext,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextLoadResult, Box<dyn std::error::Error>> {
    let user_invite = match parsed {
        ParsedEvent::UserInvite(user_invite) => user_invite,
        _ => return Err("user_invite context loader called for non-user_invite event".into()),
    };

    let ctx = queries.load_user_invite_context(frame, recorded_by, event_id_b64, user_invite)?;
    let Some(current_signer) = frame.current_signer.as_ref() else {
        return Ok(ContextLoadResult::reject(
            "missing current signer envelope for user_invite",
        ));
    };
    let workspace_b64 = event_id_to_base64(&user_invite.workspace_id);
    match current_signer.semantic_type_code {
        EVENT_TYPE_WORKSPACE
            if current_signer.event_id != workspace_b64
                || user_invite.authority_event_id != user_invite.workspace_id =>
        {
            Ok(ContextLoadResult::reject(
                "bootstrap user_invite must use workspace as signer and authority",
            ))
        }
        EVENT_TYPE_PEER_SHARED if ctx.invite_authority_matches_signer != Some(true) => {
            Ok(ContextLoadResult::reject(
                "peer-signed user_invite authority does not match signer admin identity",
            ))
        }
        EVENT_TYPE_WORKSPACE | EVENT_TYPE_PEER_SHARED => Ok(ContextLoadResult::ready(ctx)),
        _ => Ok(ContextLoadResult::reject(
            "user_invite signer must be workspace or peer_shared",
        )),
    }
}

/// Pure projector: UserInvite -> user_invites table.
/// When bootstrap_context is available and this event is locally created,
/// also write pending_invite_bootstrap_trust.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ProjectorDecisionContext,
) -> ProjectorResult {
    let (public_key, created_at_ms, key_history_event_id) = match parsed {
        ParsedEvent::UserInvite(ui) => (
            &ui.public_key,
            ui.created_at_ms as i64,
            event_id_to_base64(&ui.key_history_event_id),
        ),
        _ => return ProjectorResult::reject("not a user_invite event".to_string()),
    };

    let mut ops = vec![WriteOp::InsertOrIgnore {
        table: "user_invites",
        columns: vec![
            "recorded_by",
            "event_id",
            "public_key",
            "key_history_event_id",
        ],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Blob(public_key.to_vec()),
            SqlVal::Text(key_history_event_id),
        ],
    }];

    if ctx.is_local_create {
        if let Some(ref bc) = ctx.bootstrap_context {
            let expected_spki =
                crate::transport::cert::spki_fingerprint_from_ed25519_pubkey(public_key);
            ops.push(WriteOp::InsertOrIgnore {
                table: "pending_invite_bootstrap_trust",
                columns: vec![
                    "recorded_by",
                    "invite_event_id",
                    "workspace_id",
                    "expected_bootstrap_spki_fingerprint",
                    "created_at",
                    "expires_at",
                ],
                values: vec![
                    SqlVal::Text(recorded_by.to_string()),
                    SqlVal::Text(event_id_b64.to_string()),
                    SqlVal::Text(bc.workspace_id.clone()),
                    SqlVal::Blob(expected_spki.to_vec()),
                    SqlVal::Int(created_at_ms),
                    SqlVal::Int(
                        created_at_ms + crate::db::transport_trust::PENDING_INVITE_BOOTSTRAP_TTL_MS,
                    ),
                ],
            });
        }
    }

    ProjectorResult::valid(ops)
}

#[cfg(test)]
mod user_invite_projector_tests {
    use super::*;
    use crate::crypto::event_id_to_base64;
    use crate::db::{open_in_memory, schema::create_tables};
    use crate::event_modules::{ParsedEvent, UserInviteEvent, WorkspaceEvent};
    use crate::projection::decision::ProjectionDecision;
    use crate::projection::decision_context::ProjectionFrameContext;
    use crate::projection::projector::{
        BootstrapDecisionContext, CurrentSignerInfo, ProjectorDecisionContext, WriteOp,
    };

    fn bootstrap_user_invite() -> ParsedEvent {
        ParsedEvent::UserInvite(UserInviteEvent {
            created_at_ms: 1,
            public_key: [9u8; 32],
            workspace_id: [2u8; 32],
            authority_event_id: [2u8; 32],
            key_history_event_id: crate::event_modules::key_history::NO_KEY_HISTORY_EVENT_ID,
        })
    }

    fn peer_signed_user_invite() -> ParsedEvent {
        ParsedEvent::UserInvite(UserInviteEvent {
            created_at_ms: 1,
            public_key: [9u8; 32],
            workspace_id: [2u8; 32],
            authority_event_id: [4u8; 32],
            key_history_event_id: crate::event_modules::key_history::NO_KEY_HISTORY_EVENT_ID,
        })
    }

    fn local_bootstrap_ctx() -> ProjectorDecisionContext {
        ProjectorDecisionContext {
            bootstrap_context: Some(BootstrapDecisionContext {
                workspace_id: "workspace".to_string(),
                bootstrap_addrs: vec!["tcp://127.0.0.1:7777".to_string()],
                bootstrap_spki_fingerprint: [7u8; 32],
            }),
            is_local_create: true,
            ..ProjectorDecisionContext::default()
        }
    }

    fn assert_valid(result: &ProjectorResult, expected_writes: usize) {
        assert!(matches!(result.decision, ProjectionDecision::Valid));
        assert_eq!(result.write_ops.len(), expected_writes);
    }

    #[test]
    fn test_user_invite_basic_valid() {
        let result = project_pure(
            "peer1",
            "invite-event",
            &bootstrap_user_invite(),
            &ProjectorDecisionContext::default(),
        );
        assert_valid(&result, 1);
    }

    #[test]
    fn test_user_invite_writes_pending_trust() {
        let result = project_pure(
            "peer1",
            "invite-event",
            &bootstrap_user_invite(),
            &local_bootstrap_ctx(),
        );
        assert_valid(&result, 2);
        assert!(matches!(
            &result.write_ops[1],
            WriteOp::InsertOrIgnore { table, .. } if *table == "pending_invite_bootstrap_trust"
        ));
    }

    #[test]
    fn test_user_invite_no_pending_when_not_local() {
        let mut ctx = local_bootstrap_ctx();
        ctx.is_local_create = false;

        let result = project_pure("peer1", "invite-event", &bootstrap_user_invite(), &ctx);
        assert_valid(&result, 1);
    }

    #[test]
    fn test_user_invite_rejects_bootstrap_signer_mismatch() {
        let event = ParsedEvent::UserInvite(UserInviteEvent {
            created_at_ms: 1,
            public_key: [9u8; 32],
            workspace_id: [2u8; 32],
            authority_event_id: [2u8; 32],
            key_history_event_id: crate::event_modules::key_history::NO_KEY_HISTORY_EVENT_ID,
        });
        let conn = open_in_memory().expect("open db");
        create_tables(&conn).expect("create tables");
        let result = build_projector_context(
            &conn,
            &ProjectionFrameContext {
                current_signer: Some(CurrentSignerInfo {
                    event_id: event_id_to_base64(&[7u8; 32]),
                    semantic_type_code: EVENT_TYPE_WORKSPACE,
                }),
                ..ProjectionFrameContext::default()
            },
            "peer1",
            "invite-event",
            &event,
        )
        .expect("context load");
        assert!(matches!(
            result,
            ContextLoadResult::Reject { ref reason }
                if reason.contains("bootstrap user_invite must use workspace as signer and authority")
        ));
    }

    #[test]
    fn test_user_invite_rejects_bootstrap_authority_mismatch() {
        let event = ParsedEvent::UserInvite(UserInviteEvent {
            created_at_ms: 1,
            public_key: [9u8; 32],
            workspace_id: [2u8; 32],
            authority_event_id: [6u8; 32],
            key_history_event_id: crate::event_modules::key_history::NO_KEY_HISTORY_EVENT_ID,
        });
        let conn = open_in_memory().expect("open db");
        create_tables(&conn).expect("create tables");
        let result = build_projector_context(
            &conn,
            &ProjectionFrameContext {
                current_signer: Some(CurrentSignerInfo {
                    event_id: event_id_to_base64(&[2u8; 32]),
                    semantic_type_code: EVENT_TYPE_WORKSPACE,
                }),
                ..ProjectionFrameContext::default()
            },
            "peer1",
            "invite-event",
            &event,
        )
        .expect("context load");
        assert!(matches!(
            result,
            ContextLoadResult::Reject { ref reason }
                if reason.contains("bootstrap user_invite must use workspace as signer and authority")
        ));
    }

    #[test]
    fn test_user_invite_rejects_peer_signed_authority_mismatch() {
        let conn = open_in_memory().expect("open db");
        create_tables(&conn).expect("create tables");
        let result = build_projector_context(
            &conn,
            &ProjectionFrameContext {
                current_signer: Some(CurrentSignerInfo {
                    event_id: "peer-shared-signer".to_string(),
                    semantic_type_code: EVENT_TYPE_PEER_SHARED,
                }),
                ..ProjectionFrameContext::default()
            },
            "peer1",
            "invite-event",
            &peer_signed_user_invite(),
        )
        .expect("context load");
        assert!(matches!(
            result,
            ContextLoadResult::Reject { ref reason }
                if reason.contains("peer-signed user_invite authority does not match signer admin identity")
        ));
    }

    #[test]
    fn test_user_invite_rejects_non_user_invite_event() {
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
        assert!(matches!(result.decision, ProjectionDecision::Reject { .. }));
    }
}
