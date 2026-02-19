use super::super::ParsedEvent;
use crate::crypto::event_id_to_base64;
use crate::projection::result::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

/// Pure projector: PeerShared (First or Ongoing) → peers_shared table.
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
    let ops = vec![WriteOp::InsertOrIgnore {
        table: "peers_shared",
        columns: vec!["recorded_by", "event_id", "public_key", "user_event_id", "device_name"],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Blob(public_key.to_vec()),
            SqlVal::Text(user_event_id_b64),
            SqlVal::Text(device_name.to_string()),
        ],
    }];
    ProjectorResult::valid(ops)
}
