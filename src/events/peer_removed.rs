use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_PEER_REMOVED};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRemovedEvent {
    pub created_at_ms: u64,
    pub target_event_id: [u8; 32],  // PeerShared event being removed
    pub signed_by: [u8; 32],        // signer event_id (PeerShared event — admin)
    pub signer_type: u8,            // 5 = peer_shared
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
    if blob.len() < 138 {
        return Err(EventError::TooShort { expected: 138, actual: blob.len() });
    }
    if blob[0] != EVENT_TYPE_PEER_REMOVED {
        return Err(EventError::WrongType { expected: EVENT_TYPE_PEER_REMOVED, actual: blob[0] });
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
    let mut buf = Vec::with_capacity(138);
    buf.push(EVENT_TYPE_PEER_REMOVED);
    buf.extend_from_slice(&e.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&e.target_event_id);
    buf.extend_from_slice(&e.signed_by);
    buf.push(e.signer_type);
    buf.extend_from_slice(&e.signature);
    Ok(buf)
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
    parse: parse_peer_removed,
    encode: encode_peer_removed,
};
