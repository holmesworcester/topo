use super::super::ParsedEvent;
use crate::crypto::event_id_to_base64;
use crate::event_modules::{EVENT_TYPE_PEER_SHARED, EVENT_TYPE_USER};
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use crate::projection::queries::{ContextLoadResult, ProjectionFrameContext, ProjectionQueries};

pub fn build_projector_context(
    queries: &dyn ProjectionQueries,
    frame: &ProjectionFrameContext,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextLoadResult, Box<dyn std::error::Error>> {
    let device_invite = match parsed {
        ParsedEvent::DeviceInvite(device_invite) => device_invite,
        _ => return Err("device_invite context loader called for non-device_invite event".into()),
    };

    let ctx =
        queries.load_device_invite_context(frame, recorded_by, event_id_b64, device_invite)?;
    let Some(current_signer) = frame.current_signer.as_ref() else {
        return Ok(ContextLoadResult::reject(
            "missing current signer envelope for device_invite",
        ));
    };
    match current_signer.semantic_type_code {
        EVENT_TYPE_USER
            if event_id_to_base64(&device_invite.authority_event_id) != current_signer.event_id =>
        {
            Ok(ContextLoadResult::reject(
                "bootstrap device_invite authority must match signer user event",
            ))
        }
        EVENT_TYPE_PEER_SHARED if ctx.invite_authority_matches_signer != Some(true) => {
            Ok(ContextLoadResult::reject(
                "peer-signed device_invite authority does not match signer user identity",
            ))
        }
        EVENT_TYPE_USER | EVENT_TYPE_PEER_SHARED => Ok(ContextLoadResult::ready(ctx)),
        _ => Ok(ContextLoadResult::reject(
            "device_invite signer must be user or peer_shared",
        )),
    }
}

/// Pure projector: DeviceInvite -> device_invites table.
/// When bootstrap_context is available and this event is locally created,
/// also write pending_invite_bootstrap_trust.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let (public_key, created_at_ms) = match parsed {
        ParsedEvent::DeviceInvite(di) => (&di.public_key, di.created_at_ms as i64),
        _ => return ProjectorResult::reject("not a device_invite event".to_string()),
    };

    let mut ops = vec![WriteOp::InsertOrIgnore {
        table: "device_invites",
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
mod device_invite_projector_tests {
    use super::*;
    use crate::crypto::event_id_to_base64;
    use crate::db::{open_in_memory, schema::create_tables};
    use crate::event_modules::{DeviceInviteEvent, ParsedEvent, WorkspaceEvent};
    use crate::projection::contract::{
        BootstrapContextSnapshot, ContextSnapshot, CurrentSignerInfo, WriteOp,
    };
    use crate::projection::decision::ProjectionDecision;
    use crate::projection::queries::ProjectionFrameContext;

    fn bootstrap_device_invite() -> ParsedEvent {
        ParsedEvent::DeviceInvite(DeviceInviteEvent {
            created_at_ms: 1,
            public_key: [9u8; 32],
            authority_event_id: [2u8; 32],
        })
    }

    fn peer_signed_device_invite() -> ParsedEvent {
        ParsedEvent::DeviceInvite(DeviceInviteEvent {
            created_at_ms: 1,
            public_key: [9u8; 32],
            authority_event_id: [4u8; 32],
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
    fn test_device_invite_writes_pending_trust() {
        let result = project_pure(
            "peer1",
            "invite-event",
            &bootstrap_device_invite(),
            &local_bootstrap_ctx(),
        );
        assert_valid(&result, 2);
        assert!(matches!(
            &result.write_ops[1],
            WriteOp::InsertOrIgnore { table, .. } if *table == "pending_invite_bootstrap_trust"
        ));
    }

    #[test]
    fn test_device_invite_no_pending_when_not_local() {
        let mut ctx = local_bootstrap_ctx();
        ctx.is_local_create = false;

        let result = project_pure("peer1", "invite-event", &bootstrap_device_invite(), &ctx);
        assert_valid(&result, 1);
    }

    #[test]
    fn test_device_invite_rejects_bootstrap_authority_mismatch() {
        let event = ParsedEvent::DeviceInvite(DeviceInviteEvent {
            created_at_ms: 1,
            public_key: [9u8; 32],
            authority_event_id: [6u8; 32],
        });
        let conn = open_in_memory().expect("open db");
        create_tables(&conn).expect("create tables");
        let result = build_projector_context(
            &conn,
            &ProjectionFrameContext {
                current_signer: Some(CurrentSignerInfo {
                    event_id: event_id_to_base64(&[2u8; 32]),
                    semantic_type_code: EVENT_TYPE_USER,
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
                if reason.contains("bootstrap device_invite authority must match signer user event")
        ));
    }

    #[test]
    fn test_device_invite_rejects_peer_signed_authority_mismatch() {
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
            &peer_signed_device_invite(),
        )
        .expect("context load");
        assert!(matches!(
            result,
            ContextLoadResult::Reject { ref reason }
                if reason.contains("peer-signed device_invite authority does not match signer user identity")
        ));
    }

    #[test]
    fn test_device_invite_rejects_non_device_invite_event() {
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
