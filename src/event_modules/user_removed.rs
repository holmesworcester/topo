use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_USER_REMOVED};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRemovedEvent {
    pub created_at_ms: u64,
    pub target_event_id: [u8; 32],  // User event being removed
    pub signed_by: [u8; 32],        // signer event_id (PeerShared event — admin)
    pub signer_type: u8,            // 5 = peer_shared
    pub signature: [u8; 64],
}

/// Wire format (138 bytes fixed):
/// [0]        type_code = 20
/// [1..9]     created_at_ms (u64 LE)
/// [9..41]    target_event_id (32 bytes)
/// [41..73]   signed_by (32 bytes)
/// [73]       signer_type (1 byte)
/// [74..138]  signature (64 bytes)
pub fn parse_user_removed(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < 138 {
        return Err(EventError::TooShort { expected: 138, actual: blob.len() });
    }
    if blob.len() > 138 {
        return Err(EventError::TrailingData { expected: 138, actual: blob.len() });
    }
    if blob[0] != EVENT_TYPE_USER_REMOVED {
        return Err(EventError::WrongType { expected: EVENT_TYPE_USER_REMOVED, actual: blob[0] });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());
    let mut target_event_id = [0u8; 32];
    target_event_id.copy_from_slice(&blob[9..41]);
    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[41..73]);
    let signer_type = blob[73];
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[74..138]);

    Ok(ParsedEvent::UserRemoved(UserRemovedEvent {
        created_at_ms,
        target_event_id,
        signed_by,
        signer_type,
        signature,
    }))
}

pub fn encode_user_removed(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::UserRemoved(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    let mut buf = Vec::with_capacity(138);
    buf.push(EVENT_TYPE_USER_REMOVED);
    buf.extend_from_slice(&e.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&e.target_event_id);
    buf.extend_from_slice(&e.signed_by);
    buf.push(e.signer_type);
    buf.extend_from_slice(&e.signature);
    Ok(buf)
}

// === Projector (event-module locality) ===

use crate::crypto::event_id_to_base64;
use crate::projection::result::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

/// Pure projector: UserRemoved → removed_entities table.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let r = match parsed {
        ParsedEvent::UserRemoved(r) => r,
        _ => return ProjectorResult::reject("not a user_removed event".to_string()),
    };

    let target_b64 = event_id_to_base64(&r.target_event_id);
    let ops = vec![WriteOp::InsertOrIgnore {
        table: "removed_entities",
        columns: vec!["recorded_by", "event_id", "target_event_id", "removal_type"],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(target_b64),
            SqlVal::Text("user".to_string()),
        ],
    }];
    ProjectorResult::valid(ops)
}

pub static USER_REMOVED_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_USER_REMOVED,
    type_name: "user_removed",
    projection_table: "removed_entities",
    share_scope: ShareScope::Shared,
    dep_fields: &["target_event_id", "signed_by"],
    dep_field_type_codes: &[&[14, 15], &[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: false,
    parse: parse_user_removed,
    encode: encode_user_removed,
    projector: project_pure,
};

// === Command/Query APIs (event-module locality) ===

use crate::crypto::EventId;
use crate::projection::create::create_signed_event_sync;
use ed25519_dalek::SigningKey;
use rusqlite::Connection;

pub struct CreateUserRemovedCmd {
    pub target_event_id: [u8; 32],
}

pub fn create(
    db: &Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
    created_at_ms: u64,
    cmd: CreateUserRemovedCmd,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let ur = ParsedEvent::UserRemoved(UserRemovedEvent {
        created_at_ms,
        target_event_id: cmd.target_event_id,
        signed_by: *signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let eid = create_signed_event_sync(db, recorded_by, &ur, signing_key)?;
    Ok(eid)
}
