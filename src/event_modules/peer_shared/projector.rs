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
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let (public_key, user_event_id, device_name) = match parsed {
        ParsedEvent::PeerShared(p) => (&p.public_key, &p.user_event_id, &p.device_name),
        _ => return ProjectorResult::reject("not a peer_shared event".to_string()),
    };

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
