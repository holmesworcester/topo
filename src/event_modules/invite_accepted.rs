use super::layout::common::COMMON_HEADER_BYTES;
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_INVITE_ACCEPTED};

// ─── Layout (owned by this module) ───

/// InviteAccepted (type 9): type(1) + created_at(8) + invite_event_id(32) + workspace_id(32) = 73
pub const INVITE_ACCEPTED_WIRE_SIZE: usize = COMMON_HEADER_BYTES + 32 + 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteAcceptedEvent {
    pub created_at_ms: u64,
    pub invite_event_id: [u8; 32],  // the invite event being accepted
    pub workspace_id: [u8; 32],       // workspace being joined
}

/// Wire format (73 bytes fixed):
/// [0]      type_code = 9
/// [1..9]   created_at_ms (u64 LE)
/// [9..41]  invite_event_id (32 bytes)
/// [41..73] workspace_id (32 bytes)
pub fn parse_invite_accepted(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < INVITE_ACCEPTED_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: INVITE_ACCEPTED_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > INVITE_ACCEPTED_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: INVITE_ACCEPTED_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_INVITE_ACCEPTED {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_INVITE_ACCEPTED,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());

    let mut invite_event_id = [0u8; 32];
    invite_event_id.copy_from_slice(&blob[9..41]);

    let mut workspace_id = [0u8; 32];
    workspace_id.copy_from_slice(&blob[41..73]);

    Ok(ParsedEvent::InviteAccepted(InviteAcceptedEvent {
        created_at_ms,
        invite_event_id,
        workspace_id,
    }))
}

pub fn encode_invite_accepted(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let ia = match event {
        ParsedEvent::InviteAccepted(a) => a,
        _ => return Err(EventError::WrongVariant),
    };

    let mut buf = Vec::with_capacity(INVITE_ACCEPTED_WIRE_SIZE);
    buf.push(EVENT_TYPE_INVITE_ACCEPTED);
    buf.extend_from_slice(&ia.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&ia.invite_event_id);
    buf.extend_from_slice(&ia.workspace_id);
    Ok(buf)
}

// === Projector (event-module locality) ===

use crate::crypto::event_id_to_base64;
use crate::projection::result::{ContextSnapshot, EmitCommand, ProjectorResult, SqlVal, WriteOp};

/// Pure projector: InviteAccepted — local trust-anchor binding.
///
/// Binds directly from InviteAcceptedEvent fields. Uses first-write-wins
/// (INSERT OR IGNORE) for trust anchor immutability; rejects on mismatch.
/// Emits RetryWorkspaceGuards command so blocked workspace events can unblock.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let ia = match parsed {
        ParsedEvent::InviteAccepted(a) => a,
        _ => return ProjectorResult::reject("not an invite_accepted event".to_string()),
    };

    let invite_eid_b64 = event_id_to_base64(&ia.invite_event_id);
    let workspace_id_b64 = event_id_to_base64(&ia.workspace_id);

    // Check existing trust anchor — reject on mismatch.
    if let Some(ref stored) = ctx.trust_anchor_workspace_id {
        if stored != &workspace_id_b64 {
            return ProjectorResult::reject(format!(
                "invite_accepted workspace_id {} conflicts with existing trust anchor {}",
                workspace_id_b64, stored
            ));
        }
    }

    let ops = vec![
        // Projection table
        WriteOp::InsertOrIgnore {
            table: "invite_accepted",
            columns: vec!["recorded_by", "event_id", "invite_event_id", "workspace_id"],
            values: vec![
                SqlVal::Text(recorded_by.to_string()),
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Text(invite_eid_b64),
                SqlVal::Text(workspace_id_b64.clone()),
            ],
        },
        // Trust anchor (first-write-wins)
        WriteOp::InsertOrIgnore {
            table: "trust_anchors",
            columns: vec!["peer_id", "workspace_id"],
            values: vec![
                SqlVal::Text(recorded_by.to_string()),
                SqlVal::Text(workspace_id_b64),
            ],
        },
    ];

    ProjectorResult::valid_with_commands(ops, vec![EmitCommand::RetryWorkspaceGuards])
}

pub static INVITE_ACCEPTED_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_INVITE_ACCEPTED,
    type_name: "invite_accepted",
    projection_table: "invite_accepted",
    share_scope: ShareScope::Local,
    dep_fields: &[],
    dep_field_type_codes: &[],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_invite_accepted,
    encode: encode_invite_accepted,
    projector: project_pure,
};
