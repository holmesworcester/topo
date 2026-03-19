use super::super::ParsedEvent;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

/// Pure projector: UserInvite -> user_invites table.
/// When bootstrap_context is available and this event is locally created,
/// also write pending_invite_bootstrap_trust.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let (public_key, created_at_ms, signed_by, signer_type, workspace_id, authority_event_id) =
        match parsed {
            ParsedEvent::UserInvite(ui) => (
                &ui.public_key,
                ui.created_at_ms as i64,
                ui.signed_by,
                ui.signer_type,
                ui.workspace_id,
                ui.authority_event_id,
            ),
            _ => return ProjectorResult::reject("not a user_invite event".to_string()),
        };

    if signer_type == 1 {
        if signed_by != workspace_id || authority_event_id != workspace_id {
            return ProjectorResult::reject(
                "bootstrap user_invite must use workspace as signer and authority".to_string(),
            );
        }
    } else if signer_type == 5 {
        if ctx.invite_authority_matches_signer != Some(true) {
            return ProjectorResult::reject(
                "peer-signed user_invite authority does not match signer admin identity"
                    .to_string(),
            );
        }
    } else {
        return ProjectorResult::reject("unsupported user_invite signer_type".to_string());
    }

    let mut ops = vec![WriteOp::InsertOrIgnore {
        table: "user_invites",
        columns: vec!["recorded_by", "event_id", "public_key"],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Blob(public_key.to_vec()),
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
    use crate::event_modules::{ParsedEvent, UserInviteEvent, WorkspaceEvent};
    use crate::projection::contract::{BootstrapContextSnapshot, ContextSnapshot, WriteOp};
    use crate::projection::decision::ProjectionDecision;

    fn bootstrap_user_invite() -> ParsedEvent {
        ParsedEvent::UserInvite(UserInviteEvent {
            created_at_ms: 1,
            public_key: [9u8; 32],
            workspace_id: [2u8; 32],
            authority_event_id: [2u8; 32],
            signed_by: [2u8; 32],
            signer_type: 1,
            signature: [0u8; 64],
        })
    }

    fn peer_signed_user_invite() -> ParsedEvent {
        ParsedEvent::UserInvite(UserInviteEvent {
            created_at_ms: 1,
            public_key: [9u8; 32],
            workspace_id: [2u8; 32],
            authority_event_id: [4u8; 32],
            signed_by: [3u8; 32],
            signer_type: 5,
            signature: [0u8; 64],
        })
    }

    fn local_bootstrap_ctx() -> ContextSnapshot {
        ContextSnapshot {
            bootstrap_context: Some(BootstrapContextSnapshot {
                workspace_id: "workspace".to_string(),
                bootstrap_addrs: vec!["tcp://127.0.0.1:7777".to_string()],
                bootstrap_spki_fingerprint: [7u8; 32],
            }),
            is_local_create: true,
            ..ContextSnapshot::default()
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
            &ContextSnapshot::default(),
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
            signed_by: [5u8; 32],
            signer_type: 1,
            signature: [0u8; 64],
        });
        let result = project_pure("peer1", "invite-event", &event, &ContextSnapshot::default());
        assert!(matches!(
            result.decision,
            ProjectionDecision::Reject { ref reason }
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
            signed_by: [2u8; 32],
            signer_type: 1,
            signature: [0u8; 64],
        });
        let result = project_pure("peer1", "invite-event", &event, &ContextSnapshot::default());
        assert!(matches!(
            result.decision,
            ProjectionDecision::Reject { ref reason }
                if reason.contains("bootstrap user_invite must use workspace as signer and authority")
        ));
    }

    #[test]
    fn test_user_invite_rejects_peer_signed_authority_mismatch() {
        let result = project_pure(
            "peer1",
            "invite-event",
            &peer_signed_user_invite(),
            &ContextSnapshot {
                invite_authority_matches_signer: Some(false),
                ..ContextSnapshot::default()
            },
        );
        assert!(matches!(
            result.decision,
            ProjectionDecision::Reject { ref reason }
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
            &ContextSnapshot::default(),
        );
        assert!(matches!(result.decision, ProjectionDecision::Reject { .. }));
    }
}
