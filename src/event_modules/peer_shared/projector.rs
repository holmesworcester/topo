use super::super::ParsedEvent;
use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

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
    if let Some(reason) = &ctx.peer_shared_user_mismatch_reason {
        return ProjectorResult::reject(reason.clone());
    }

    let user_event_id_b64 = event_id_to_base64(user_event_id);
    let transport_fingerprint = crate::crypto::spki_fingerprint_from_ed25519_pubkey(public_key);
    let ops = vec![WriteOp::InsertOrIgnore {
        table: "peers_shared",
        columns: vec![
            "recorded_by",
            "event_id",
            "public_key",
            "transport_fingerprint",
            "user_event_id",
            "device_name",
        ],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Blob(public_key.to_vec()),
            SqlVal::Blob(transport_fingerprint.to_vec()),
            SqlVal::Text(user_event_id_b64),
            SqlVal::Text(device_name.to_string()),
        ],
    }];

    ProjectorResult::valid(ops)
}

#[cfg(test)]
mod projector_tests {
    use super::*;
    use crate::event_modules::{ParsedEvent, PeerSharedEvent, WorkspaceEvent};

    fn peer_shared_event() -> ParsedEvent {
        ParsedEvent::PeerShared(PeerSharedEvent {
            created_at_ms: 1,
            public_key: [5u8; 32],
            user_event_id: [6u8; 32],
            device_name: "phone".to_string(),
            signed_by: [7u8; 32],
            signer_type: 3,
            signature: [0u8; 64],
        })
    }

    #[test]
    fn test_peer_shared_valid() {
        let result = project_pure(
            "peer1",
            "peer-shared-event",
            &peer_shared_event(),
            &ContextSnapshot::default(),
        );
        assert!(matches!(
            result.decision,
            crate::projection::decision::ProjectionDecision::Valid
        ));
        assert_eq!(result.write_ops.len(), 1);
    }

    #[test]
    fn test_peer_shared_rejects_authorized_user_mismatch() {
        let result = project_pure(
            "peer1",
            "peer-shared-event",
            &peer_shared_event(),
            &ContextSnapshot {
                peer_shared_user_mismatch_reason: Some(
                    "peer_shared signer authorizes user a but event claims b".to_string(),
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
            &ContextSnapshot::default(),
        );
        assert!(matches!(
            result.decision,
            crate::projection::decision::ProjectionDecision::Reject { .. }
        ));
    }
}
