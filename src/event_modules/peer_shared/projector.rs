use super::super::ParsedEvent;
use crate::crypto::event_id_to_base64;
use crate::projection::result::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

/// Pure projector: PeerShared (First or Ongoing) → peers_shared table.
/// Also consumes bootstrap trust rows matching this peer's transport fingerprint,
/// so steady-state peer trust naturally supersedes bootstrap trust.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let (public_key, user_event_id, device_name) = match parsed {
        ParsedEvent::PeerSharedFirst(p) => (&p.public_key, &p.user_event_id, &p.device_name),
        ParsedEvent::PeerSharedOngoing(p) => (&p.public_key, &p.user_event_id, &p.device_name),
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
            table: "pending_invite_bootstrap_trust",
            where_clause: vec![
                ("recorded_by", SqlVal::Text(recorded_by.to_string())),
                (
                    "expected_bootstrap_spki_fingerprint",
                    SqlVal::Blob(transport_fingerprint.to_vec()),
                ),
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
