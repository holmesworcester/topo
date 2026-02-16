use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_ADMIN_BOOT, EVENT_TYPE_ADMIN_ONGOING};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminBootEvent {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],
    pub user_event_id: [u8; 32],  // dep: User event
    pub signed_by: [u8; 32],      // signer event_id (Workspace event)
    pub signer_type: u8,          // 1 = workspace
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminOngoingEvent {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],
    pub admin_boot_event_id: [u8; 32],  // dep: AdminBoot event
    pub signed_by: [u8; 32],            // signer event_id (PeerShared event)
    pub signer_type: u8,                // 5 = peer_shared
    pub signature: [u8; 64],
}

/// Wire format for AdminBoot (170 bytes fixed):
/// [0]        type_code = 18
/// [1..9]     created_at_ms (u64 LE)
/// [9..41]    public_key (32 bytes)
/// [41..73]   user_event_id (32 bytes) — dep
/// [73..105]  signed_by (32 bytes)
/// [105]      signer_type (1 byte)
/// [106..170] signature (64 bytes)
pub fn parse_admin_boot(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < 170 {
        return Err(EventError::TooShort { expected: 170, actual: blob.len() });
    }
    if blob.len() > 170 {
        return Err(EventError::TrailingData { expected: 170, actual: blob.len() });
    }
    if blob[0] != EVENT_TYPE_ADMIN_BOOT {
        return Err(EventError::WrongType { expected: EVENT_TYPE_ADMIN_BOOT, actual: blob[0] });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&blob[9..41]);
    let mut user_event_id = [0u8; 32];
    user_event_id.copy_from_slice(&blob[41..73]);
    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[73..105]);
    let signer_type = blob[105];
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[106..170]);

    Ok(ParsedEvent::AdminBoot(AdminBootEvent {
        created_at_ms,
        public_key,
        user_event_id,
        signed_by,
        signer_type,
        signature,
    }))
}

pub fn encode_admin_boot(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::AdminBoot(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    let mut buf = Vec::with_capacity(170);
    buf.push(EVENT_TYPE_ADMIN_BOOT);
    buf.extend_from_slice(&e.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&e.public_key);
    buf.extend_from_slice(&e.user_event_id);
    buf.extend_from_slice(&e.signed_by);
    buf.push(e.signer_type);
    buf.extend_from_slice(&e.signature);
    Ok(buf)
}

/// Wire format for AdminOngoing (170 bytes fixed):
/// [0]        type_code = 19
/// [1..9]     created_at_ms (u64 LE)
/// [9..41]    public_key (32 bytes)
/// [41..73]   admin_boot_event_id (32 bytes) — dep
/// [73..105]  signed_by (32 bytes)
/// [105]      signer_type (1 byte)
/// [106..170] signature (64 bytes)
pub fn parse_admin_ongoing(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < 170 {
        return Err(EventError::TooShort { expected: 170, actual: blob.len() });
    }
    if blob.len() > 170 {
        return Err(EventError::TrailingData { expected: 170, actual: blob.len() });
    }
    if blob[0] != EVENT_TYPE_ADMIN_ONGOING {
        return Err(EventError::WrongType { expected: EVENT_TYPE_ADMIN_ONGOING, actual: blob[0] });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&blob[9..41]);
    let mut admin_boot_event_id = [0u8; 32];
    admin_boot_event_id.copy_from_slice(&blob[41..73]);
    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[73..105]);
    let signer_type = blob[105];
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[106..170]);

    Ok(ParsedEvent::AdminOngoing(AdminOngoingEvent {
        created_at_ms,
        public_key,
        admin_boot_event_id,
        signed_by,
        signer_type,
        signature,
    }))
}

pub fn encode_admin_ongoing(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::AdminOngoing(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    let mut buf = Vec::with_capacity(170);
    buf.push(EVENT_TYPE_ADMIN_ONGOING);
    buf.extend_from_slice(&e.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&e.public_key);
    buf.extend_from_slice(&e.admin_boot_event_id);
    buf.extend_from_slice(&e.signed_by);
    buf.push(e.signer_type);
    buf.extend_from_slice(&e.signature);
    Ok(buf)
}

pub static ADMIN_BOOT_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_ADMIN_BOOT,
    type_name: "admin_boot",
    projection_table: "admins",
    share_scope: ShareScope::Shared,
    dep_fields: &["user_event_id", "signed_by"],
    dep_field_type_codes: &[&[14, 15], &[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: false,
    parse: parse_admin_boot,
    encode: encode_admin_boot,
};

pub static ADMIN_ONGOING_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_ADMIN_ONGOING,
    type_name: "admin_ongoing",
    projection_table: "admins",
    share_scope: ShareScope::Shared,
    dep_fields: &["admin_boot_event_id", "signed_by"],
    dep_field_type_codes: &[&[18], &[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: false,
    parse: parse_admin_ongoing,
    encode: encode_admin_ongoing,
};
