use super::super::layout::common::{COMMON_HEADER_BYTES, SIGNATURE_TRAILER_BYTES};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{
    EventError, ParsedEvent, EVENT_TYPE_USER_INVITE_BOOT, EVENT_TYPE_USER_INVITE_ONGOING,
};

// ─── Layout (owned by this module) ───

/// UserInviteBoot (type 10): type(1) + created_at(8) + public_key(32) + workspace_id(32)
///                          + signed_by(32) + signer_type(1) + signature(64) = 170
pub const USER_INVITE_BOOT_WIRE_SIZE: usize =
    COMMON_HEADER_BYTES + 32 + 32 + SIGNATURE_TRAILER_BYTES;

/// UserInviteOngoing (type 11): same layout as UserInviteBoot = 170
pub const USER_INVITE_ONGOING_WIRE_SIZE: usize = USER_INVITE_BOOT_WIRE_SIZE;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserInviteBootEvent {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],   // Ed25519 key for this invite
    pub workspace_id: [u8; 32], // reference (for workspace capture), NOT a dep
    pub signed_by: [u8; 32],    // signer event_id (Workspace event)
    pub signer_type: u8,        // 1 = workspace
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserInviteOngoingEvent {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],     // Ed25519 key for this invite
    pub admin_event_id: [u8; 32], // dep: admin event authorizing this invite
    pub signed_by: [u8; 32],      // signer event_id (PeerShared event)
    pub signer_type: u8,          // 5 = peer_shared
    pub signature: [u8; 64],
}

/// Wire format for UserInviteBoot (170 bytes fixed):
/// [0]        type_code = 10
/// [1..9]     created_at_ms (u64 LE)
/// [9..41]    public_key (32 bytes)
/// [41..73]   workspace_id (32 bytes) — reference, not dep
/// [73..105]  signed_by (32 bytes)
/// [105]      signer_type (1 byte)
/// [106..170] signature (64 bytes)
pub fn parse_user_invite_boot(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < USER_INVITE_BOOT_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: USER_INVITE_BOOT_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > USER_INVITE_BOOT_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: USER_INVITE_BOOT_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_USER_INVITE_BOOT {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_USER_INVITE_BOOT,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&blob[9..41]);
    let mut workspace_id = [0u8; 32];
    workspace_id.copy_from_slice(&blob[41..73]);
    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[73..105]);
    let signer_type = blob[105];
    if signer_type != 1 {
        return Err(EventError::InvalidMetadata(
            "user_invite_boot signer_type must be 1 (workspace)",
        ));
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[106..170]);

    Ok(ParsedEvent::UserInviteBoot(UserInviteBootEvent {
        created_at_ms,
        public_key,
        workspace_id,
        signed_by,
        signer_type,
        signature,
    }))
}

pub fn encode_user_invite_boot(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::UserInviteBoot(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    let mut buf = Vec::with_capacity(USER_INVITE_BOOT_WIRE_SIZE);
    buf.push(EVENT_TYPE_USER_INVITE_BOOT);
    buf.extend_from_slice(&e.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&e.public_key);
    buf.extend_from_slice(&e.workspace_id);
    buf.extend_from_slice(&e.signed_by);
    buf.push(e.signer_type);
    buf.extend_from_slice(&e.signature);
    Ok(buf)
}

/// Wire format for UserInviteOngoing (170 bytes fixed):
/// [0]        type_code = 11
/// [1..9]     created_at_ms (u64 LE)
/// [9..41]    public_key (32 bytes)
/// [41..73]   admin_event_id (32 bytes) — dep
/// [73..105]  signed_by (32 bytes)
/// [105]      signer_type (1 byte)
/// [106..170] signature (64 bytes)
pub fn parse_user_invite_ongoing(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < USER_INVITE_ONGOING_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: USER_INVITE_ONGOING_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > USER_INVITE_ONGOING_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: USER_INVITE_ONGOING_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_USER_INVITE_ONGOING {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_USER_INVITE_ONGOING,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&blob[9..41]);
    let mut admin_event_id = [0u8; 32];
    admin_event_id.copy_from_slice(&blob[41..73]);
    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[73..105]);
    let signer_type = blob[105];
    if signer_type != 5 {
        return Err(EventError::InvalidMetadata(
            "user_invite_ongoing signer_type must be 5 (peer_shared)",
        ));
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[106..170]);

    Ok(ParsedEvent::UserInviteOngoing(UserInviteOngoingEvent {
        created_at_ms,
        public_key,
        admin_event_id,
        signed_by,
        signer_type,
        signature,
    }))
}

pub fn encode_user_invite_ongoing(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::UserInviteOngoing(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    let mut buf = Vec::with_capacity(USER_INVITE_ONGOING_WIRE_SIZE);
    buf.push(EVENT_TYPE_USER_INVITE_ONGOING);
    buf.extend_from_slice(&e.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&e.public_key);
    buf.extend_from_slice(&e.admin_event_id);
    buf.extend_from_slice(&e.signed_by);
    buf.push(e.signer_type);
    buf.extend_from_slice(&e.signature);
    Ok(buf)
}

pub static USER_INVITE_BOOT_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_USER_INVITE_BOOT,
    type_name: "user_invite_boot",
    projection_table: "user_invites",
    share_scope: ShareScope::Shared,
    dep_fields: &["signed_by"],
    dep_field_type_codes: &[&[8]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: false,
    parse: parse_user_invite_boot,
    encode: encode_user_invite_boot,
    projector: super::projector::project_pure,
    context_loader: super::projection_context::build_projector_context,
};

pub static USER_INVITE_ONGOING_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_USER_INVITE_ONGOING,
    type_name: "user_invite_ongoing",
    projection_table: "user_invites",
    share_scope: ShareScope::Shared,
    dep_fields: &["admin_event_id", "signed_by"],
    dep_field_type_codes: &[&[18, 19], &[16, 17]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: false,
    parse: parse_user_invite_ongoing,
    encode: encode_user_invite_ongoing,
    projector: super::projector::project_pure,
    context_loader: super::projection_context::build_projector_context,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_user_invite_boot_rejects_wrong_signer_type() {
        let mut blob = vec![0u8; USER_INVITE_BOOT_WIRE_SIZE];
        blob[0] = EVENT_TYPE_USER_INVITE_BOOT;
        blob[105] = 5;

        let err = parse_user_invite_boot(&blob).expect_err("should reject wrong signer type");
        assert!(matches!(err, EventError::InvalidMetadata(_)));
    }

    #[test]
    fn parse_user_invite_ongoing_rejects_wrong_signer_type() {
        let mut blob = vec![0u8; USER_INVITE_ONGOING_WIRE_SIZE];
        blob[0] = EVENT_TYPE_USER_INVITE_ONGOING;
        blob[105] = 1;

        let err = parse_user_invite_ongoing(&blob).expect_err("should reject wrong signer type");
        assert!(matches!(err, EventError::InvalidMetadata(_)));
    }
}
