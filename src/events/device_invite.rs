use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_DEVICE_INVITE_FIRST, EVENT_TYPE_DEVICE_INVITE_ONGOING};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInviteFirstEvent {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],
    pub signed_by: [u8; 32],     // signer event_id (User event)
    pub signer_type: u8,         // 4 = user
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInviteOngoingEvent {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],
    pub signed_by: [u8; 32],     // signer event_id (PeerShared event)
    pub signer_type: u8,         // 5 = peer_shared
    pub signature: [u8; 64],
}

/// Wire format (138 bytes fixed):
/// [0]        type_code = 12
/// [1..9]     created_at_ms (u64 LE)
/// [9..41]    public_key (32 bytes)
/// [41..73]   signed_by (32 bytes)
/// [73]       signer_type (1 byte)
/// [74..138]  signature (64 bytes)
pub fn parse_device_invite_first(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < 138 {
        return Err(EventError::TooShort { expected: 138, actual: blob.len() });
    }
    if blob.len() > 138 {
        return Err(EventError::TrailingData { expected: 138, actual: blob.len() });
    }
    if blob[0] != EVENT_TYPE_DEVICE_INVITE_FIRST {
        return Err(EventError::WrongType { expected: EVENT_TYPE_DEVICE_INVITE_FIRST, actual: blob[0] });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&blob[9..41]);
    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[41..73]);
    let signer_type = blob[73];
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[74..138]);

    Ok(ParsedEvent::DeviceInviteFirst(DeviceInviteFirstEvent {
        created_at_ms,
        public_key,
        signed_by,
        signer_type,
        signature,
    }))
}

pub fn encode_device_invite_first(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::DeviceInviteFirst(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    let mut buf = Vec::with_capacity(138);
    buf.push(EVENT_TYPE_DEVICE_INVITE_FIRST);
    buf.extend_from_slice(&e.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&e.public_key);
    buf.extend_from_slice(&e.signed_by);
    buf.push(e.signer_type);
    buf.extend_from_slice(&e.signature);
    Ok(buf)
}

/// Wire format (138 bytes fixed):
/// [0]        type_code = 13
/// [1..9]     created_at_ms (u64 LE)
/// [9..41]    public_key (32 bytes)
/// [41..73]   signed_by (32 bytes)
/// [73]       signer_type (1 byte)
/// [74..138]  signature (64 bytes)
pub fn parse_device_invite_ongoing(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < 138 {
        return Err(EventError::TooShort { expected: 138, actual: blob.len() });
    }
    if blob.len() > 138 {
        return Err(EventError::TrailingData { expected: 138, actual: blob.len() });
    }
    if blob[0] != EVENT_TYPE_DEVICE_INVITE_ONGOING {
        return Err(EventError::WrongType { expected: EVENT_TYPE_DEVICE_INVITE_ONGOING, actual: blob[0] });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&blob[9..41]);
    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[41..73]);
    let signer_type = blob[73];
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[74..138]);

    Ok(ParsedEvent::DeviceInviteOngoing(DeviceInviteOngoingEvent {
        created_at_ms,
        public_key,
        signed_by,
        signer_type,
        signature,
    }))
}

pub fn encode_device_invite_ongoing(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::DeviceInviteOngoing(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    let mut buf = Vec::with_capacity(138);
    buf.push(EVENT_TYPE_DEVICE_INVITE_ONGOING);
    buf.extend_from_slice(&e.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&e.public_key);
    buf.extend_from_slice(&e.signed_by);
    buf.push(e.signer_type);
    buf.extend_from_slice(&e.signature);
    Ok(buf)
}

pub static DEVICE_INVITE_FIRST_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_DEVICE_INVITE_FIRST,
    type_name: "device_invite_first",
    projection_table: "device_invites",
    share_scope: ShareScope::Shared,
    dep_fields: &["signed_by"],
    dep_field_type_codes: &[&[]],
    signer_required: true,
    signature_byte_len: 64,
    parse: parse_device_invite_first,
    encode: encode_device_invite_first,
};

pub static DEVICE_INVITE_ONGOING_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_DEVICE_INVITE_ONGOING,
    type_name: "device_invite_ongoing",
    projection_table: "device_invites",
    share_scope: ShareScope::Shared,
    dep_fields: &["signed_by"],
    dep_field_type_codes: &[&[]],
    signer_required: true,
    signature_byte_len: 64,
    parse: parse_device_invite_ongoing,
    encode: encode_device_invite_ongoing,
};
