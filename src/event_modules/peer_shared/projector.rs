use super::super::ParsedEvent;
use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use crate::projection::queries::{ContextLoadResult, ProjectionFrameContext, ProjectionQueries};

pub fn build_projector_context(
    queries: &dyn ProjectionQueries,
    frame: &ProjectionFrameContext,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextLoadResult, Box<dyn std::error::Error>> {
    let peer_shared = match parsed {
        ParsedEvent::PeerShared(peer_shared) => peer_shared,
        _ => return Err("peer_shared context loader called for non-peer_shared event".into()),
    };

    let ctx = queries.load_peer_shared_context(frame, recorded_by, event_id_b64, peer_shared)?;
    if let Some(reason) = &ctx.peer_shared_user_mismatch_reason {
        return Ok(ContextLoadResult::reject(reason.clone()));
    }
    if ctx.peer_shared_endpoint_id.is_none() {
        return Ok(ContextLoadResult::reject(
            ctx.peer_shared_endpoint_binding_reason
                .clone()
                .unwrap_or_else(|| "peer_shared missing endpoint_shared binding".to_string()),
        ));
    }
    Ok(ContextLoadResult::ready(ctx))
}

/// Pure projector: PeerShared -> peers_shared table.
///
/// We intentionally do NOT delete `invite_bootstrap_trust` here.  The
/// bootstrap trust row doubles as an autodial address record: keeping it alive
/// ensures the leaf can re-dial the hub via the Bootstrap source after its
/// runtime restarts on identity transition, regardless of which side wins the
/// hex-ordered preferred-connection-direction check for ObservedPeer sources.
/// The row expires naturally after its 24-hour TTL; by that time the first
/// successful permanent-cert reconnect will have established a durable
/// observed-endpoint record that takes over for future reconnects.
///
/// Similarly, we do NOT delete `pending_invite_bootstrap_trust` here because
/// the DELETE WHERE clause matches the permanent fingerprint, which never
/// equals the invite fingerprint stored in that table, so the DELETE was
/// always a no-op in practice.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let (public_key, user_event_id, device_name) = match parsed {
        ParsedEvent::PeerShared(p) => (&p.public_key, &p.user_event_id, &p.device_name),
        _ => return ProjectorResult::reject("not a peer_shared event".to_string()),
    };
    let endpoint_id = ctx
        .peer_shared_endpoint_id
        .as_ref()
        .expect("peer_shared context loader guarantees endpoint binding");

    let user_event_id_b64 = event_id_to_base64(user_event_id);
    let transport_fingerprint = crate::crypto::spki_fingerprint_from_ed25519_pubkey(public_key);
    let endpoint_shared_event_id_b64 = match parsed {
        ParsedEvent::PeerShared(p) => event_id_to_base64(&p.endpoint_shared_event_id),
        _ => unreachable!(),
    };
    let ops = vec![WriteOp::InsertOrIgnore {
        table: "peers_shared",
        columns: vec![
            "recorded_by",
            "event_id",
            "public_key",
            "transport_fingerprint",
            "endpoint_shared_event_id",
            "endpoint_id",
            "user_event_id",
            "device_name",
        ],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Blob(public_key.to_vec()),
            SqlVal::Blob(transport_fingerprint.to_vec()),
            SqlVal::Text(endpoint_shared_event_id_b64),
            SqlVal::Text(endpoint_id.clone()),
            SqlVal::Text(user_event_id_b64),
            SqlVal::Text(device_name.to_string()),
        ],
    }];

    ProjectorResult::valid(ops)
}

#[cfg(test)]
mod projector_tests {
    use super::*;
    use crate::db::{open_in_memory, schema::create_tables};
    use crate::event_modules::ShareScope;
    use crate::event_modules::EVENT_TYPE_DEVICE_INVITE;
    use crate::event_modules::{encode_event, DeviceInviteEvent};
    use crate::event_modules::{ParsedEvent, PeerSharedEvent, WorkspaceEvent};
    use crate::projection::contract::CurrentSignerInfo;
    use crate::projection::queries::ContextLoadResult;
    use crate::projection::queries::ProjectionFrameContext;

    fn peer_shared_event() -> ParsedEvent {
        ParsedEvent::PeerShared(PeerSharedEvent {
            created_at_ms: 1,
            public_key: [5u8; 32],
            user_event_id: [6u8; 32],
            endpoint_shared_event_id: [8u8; 32],
            device_name: "phone".to_string(),
        })
    }

    #[test]
    fn test_peer_shared_valid() {
        let result = project_pure(
            "peer1",
            "peer-shared-event",
            &peer_shared_event(),
            &ContextSnapshot {
                peer_shared_endpoint_id: Some("endpoint-1".to_string()),
                ..ContextSnapshot::default()
            },
        );
        assert!(matches!(
            result.decision,
            crate::projection::decision::ProjectionDecision::Valid
        ));
        assert_eq!(result.write_ops.len(), 1);
    }

    #[test]
    fn test_peer_shared_rejects_non_peer_shared_event() {
        let other = ParsedEvent::Workspace(WorkspaceEvent {
            created_at_ms: 1,
            public_key: [0u8; 32],
            name: "ws".to_string(),
        });
        let result = project_pure(
            "peer1",
            "workspace-event",
            &other,
            &ContextSnapshot {
                peer_shared_endpoint_id: Some("endpoint-1".to_string()),
                ..ContextSnapshot::default()
            },
        );
        assert!(matches!(
            result.decision,
            crate::projection::decision::ProjectionDecision::Reject { .. }
        ));
    }

    #[test]
    fn test_peer_shared_rejects_authorized_user_mismatch() {
        let conn = open_in_memory().expect("open in-memory db");
        create_tables(&conn).expect("create tables");

        let recorded_by = "peer1";
        let signer_event_id = [7u8; 32];
        let signer_event_id_b64 = crate::crypto::event_id_to_base64(&signer_event_id);
        let event = ParsedEvent::DeviceInvite(DeviceInviteEvent {
            created_at_ms: 1,
            public_key: [4u8; 32],
            authority_event_id: [6u8; 32],
        });
        let blob = encode_event(&event).expect("encode device invite");
        conn.execute(
            "INSERT INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, 'device_invite', ?2, ?3, 1, 1)",
            rusqlite::params![&signer_event_id_b64, blob, ShareScope::Shared.as_str()],
        )
        .expect("insert event blob");
        conn.execute(
            "INSERT INTO valid_events (peer_id, event_id)
             VALUES (?1, ?2)",
            rusqlite::params![recorded_by, &signer_event_id_b64],
        )
        .expect("insert valid event");
        let endpoint_shared_event_id_b64 = crate::crypto::event_id_to_base64(&[8u8; 32]);
        conn.execute(
            "INSERT INTO endpoints_shared (recorded_by, event_id, endpoint_id, public_key, created_at)
             VALUES (?1, ?2, 'endpoint-1', ?3, 1)",
            rusqlite::params![recorded_by, &endpoint_shared_event_id_b64, vec![9u8; 32]],
        )
        .expect("insert endpoint_shared row");
        let parsed = ParsedEvent::PeerShared(PeerSharedEvent {
            user_event_id: [5u8; 32],
            ..match peer_shared_event() {
                ParsedEvent::PeerShared(event) => event,
                _ => unreachable!(),
            }
        });

        let frame = ProjectionFrameContext {
            current_transport_key_event_id: None,
            current_signer: Some(CurrentSignerInfo {
                event_id: signer_event_id_b64.clone(),
                semantic_type_code: EVENT_TYPE_DEVICE_INVITE,
            }),
        };
        let loaded =
            build_projector_context(&conn, &frame, recorded_by, "peer-shared-event", &parsed)
                .expect("load peer_shared context");
        match loaded {
            ContextLoadResult::Reject { reason } => {
                assert!(reason.contains("authorizes user"));
                assert!(reason.contains("event claims"));
            }
            other => panic!("expected reject, got {other:?}"),
        }
    }
}
