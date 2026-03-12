use super::super::ParsedEvent;
use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

/// Pure projector: PeerShared -> peers_shared table.
/// Also consumes accepted bootstrap trust rows matching this peer's transport
/// fingerprint, so steady-state peer trust naturally supersedes joiner-side
/// bootstrap trust without revoking inviter-side pending trust for reusable
/// invites.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let (public_key, user_event_id, device_name) = match parsed {
        ParsedEvent::PeerShared(p) => (&p.public_key, &p.user_event_id, &p.device_name),
        _ => return ProjectorResult::reject("not a peer_shared event".to_string()),
    };

    let user_event_id_b64 = event_id_to_base64(user_event_id);
    let transport_fingerprint = crate::crypto::spki_fingerprint_from_ed25519_pubkey(public_key);
    let ops = vec![
        WriteOp::InsertOrIgnore {
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
        },
        WriteOp::Delete {
            table: "invite_bootstrap_trust",
            where_clause: vec![
                ("recorded_by", SqlVal::Text(recorded_by.to_string())),
                (
                    "bootstrap_spki_fingerprint",
                    SqlVal::Blob(transport_fingerprint.to_vec()),
                ),
            ],
        },
    ];

    ProjectorResult::valid(ops)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::peer_shared::PeerSharedEvent;
    use crate::state::projection::contract::{SqlVal, WriteOp};

    #[test]
    fn peer_shared_projection_keeps_pending_inviter_bootstrap_trust() {
        let public_key = [0x55; 32];
        let parsed = ParsedEvent::PeerShared(PeerSharedEvent {
            created_at_ms: 1,
            public_key,
            user_event_id: [0x11; 32],
            device_name: "device".to_string(),
            signed_by: [0x22; 32],
            signer_type: 3,
            signature: [0u8; 64],
        });

        let result = project_pure(
            "recorded-by",
            "event-b64",
            &parsed,
            &ContextSnapshot::default(),
        );

        assert!(
            !result.write_ops.iter().any(|op| matches!(
                op,
                WriteOp::Delete {
                    table: "pending_invite_bootstrap_trust",
                    ..
                }
            )),
            "PeerShared projection should not delete inviter-side pending bootstrap trust"
        );
        assert!(
            result.write_ops.iter().any(|op| matches!(
                op,
                WriteOp::Delete {
                    table: "invite_bootstrap_trust",
                    where_clause,
                } if where_clause.iter().any(|(column, value)| {
                    *column == "bootstrap_spki_fingerprint"
                        && matches!(value, SqlVal::Blob(_))
                })
            )),
            "PeerShared projection should still consume accepted bootstrap trust"
        );
    }
}
