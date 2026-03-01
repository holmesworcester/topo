use super::layout::common::IDENTITY_PUBKEY_SIGNED_WIRE_SIZE;
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_PEER_REMOVED};

// ─── Layout (owned by this module) ───

pub const PEER_REMOVED_WIRE_SIZE: usize = IDENTITY_PUBKEY_SIGNED_WIRE_SIZE;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRemovedEvent {
    pub created_at_ms: u64,
    pub target_event_id: [u8; 32], // PeerShared event being removed
    pub signed_by: [u8; 32],       // signer event_id (PeerShared event — admin)
    pub signer_type: u8,           // 5 = peer_shared
    pub signature: [u8; 64],
}

/// Wire format (138 bytes fixed):
/// [0]        type_code = 21
/// [1..9]     created_at_ms (u64 LE)
/// [9..41]    target_event_id (32 bytes)
/// [41..73]   signed_by (32 bytes)
/// [73]       signer_type (1 byte)
/// [74..138]  signature (64 bytes)
pub fn parse_peer_removed(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < IDENTITY_PUBKEY_SIGNED_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: IDENTITY_PUBKEY_SIGNED_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > IDENTITY_PUBKEY_SIGNED_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: IDENTITY_PUBKEY_SIGNED_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_PEER_REMOVED {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_PEER_REMOVED,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());
    let mut target_event_id = [0u8; 32];
    target_event_id.copy_from_slice(&blob[9..41]);
    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[41..73]);
    let signer_type = blob[73];
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[74..138]);

    Ok(ParsedEvent::PeerRemoved(PeerRemovedEvent {
        created_at_ms,
        target_event_id,
        signed_by,
        signer_type,
        signature,
    }))
}

pub fn encode_peer_removed(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::PeerRemoved(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    let mut buf = Vec::with_capacity(IDENTITY_PUBKEY_SIGNED_WIRE_SIZE);
    buf.push(EVENT_TYPE_PEER_REMOVED);
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
use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS removed_entities (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            target_event_id TEXT NOT NULL,
            removal_type TEXT NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        ",
    )?;
    Ok(())
}

/// Pure projector: PeerRemoved → removed_entities table.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let r = match parsed {
        ParsedEvent::PeerRemoved(r) => r,
        _ => return ProjectorResult::reject("not a peer_removed event".to_string()),
    };

    let target_b64 = event_id_to_base64(&r.target_event_id);
    let ops = vec![WriteOp::InsertOrIgnore {
        table: "removed_entities",
        columns: vec!["recorded_by", "event_id", "target_event_id", "removal_type"],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(target_b64),
            SqlVal::Text("peer".to_string()),
        ],
    }];
    ProjectorResult::valid(ops)
}

pub static PEER_REMOVED_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_PEER_REMOVED,
    type_name: "peer_removed",
    projection_table: "removed_entities",
    share_scope: ShareScope::Shared,
    dep_fields: &["target_event_id", "signed_by"],
    dep_field_type_codes: &[&[16, 17], &[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: false,
    parse: parse_peer_removed,
    encode: encode_peer_removed,
    projector: project_pure,
};
