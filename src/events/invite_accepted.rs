use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_INVITE_ACCEPTED};

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
    if blob.len() < 73 {
        return Err(EventError::TooShort {
            expected: 73,
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

    let mut buf = Vec::with_capacity(73);
    buf.push(EVENT_TYPE_INVITE_ACCEPTED);
    buf.extend_from_slice(&ia.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&ia.invite_event_id);
    buf.extend_from_slice(&ia.workspace_id);
    Ok(buf)
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
    parse: parse_invite_accepted,
    encode: encode_invite_accepted,
};
