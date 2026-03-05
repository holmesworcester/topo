use super::super::layout::common::{COMMON_HEADER_BYTES, SIGNATURE_TRAILER_BYTES};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_USER_INVITE};

/// UserInvite (type 10): type(1) + created_at(8) + public_key(32) + workspace_id(32)
/// + signed_by(32) + signer_type(1) + signature(64) = 170
pub const USER_INVITE_WIRE_SIZE: usize = COMMON_HEADER_BYTES + 32 + 32 + SIGNATURE_TRAILER_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserInviteEvent {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],
    pub workspace_id: [u8; 32],
    pub signed_by: [u8; 32],
    pub signer_type: u8,
    pub signature: [u8; 64],
}

impl super::super::Describe for UserInviteEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("public_key", super::super::trunc_hex(&self.public_key, 16)),
            (
                "workspace_id",
                super::super::short_id_b64(&self.workspace_id),
            ),
        ]
    }
}

pub fn parse_user_invite(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < USER_INVITE_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: USER_INVITE_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > USER_INVITE_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: USER_INVITE_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_USER_INVITE {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_USER_INVITE,
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
            "user_invite signer_type must be 1 (workspace)",
        ));
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[106..170]);

    Ok(ParsedEvent::UserInvite(UserInviteEvent {
        created_at_ms,
        public_key,
        workspace_id,
        signed_by,
        signer_type,
        signature,
    }))
}

pub fn encode_user_invite(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::UserInvite(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    let mut buf = Vec::with_capacity(USER_INVITE_WIRE_SIZE);
    buf.push(EVENT_TYPE_USER_INVITE);
    buf.extend_from_slice(&e.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&e.public_key);
    buf.extend_from_slice(&e.workspace_id);
    buf.extend_from_slice(&e.signed_by);
    buf.push(e.signer_type);
    buf.extend_from_slice(&e.signature);
    Ok(buf)
}

pub static USER_INVITE_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_USER_INVITE,
    type_name: "user_invite",
    projection_table: "user_invites",
    share_scope: ShareScope::Shared,
    dep_fields: &["signed_by"],
    dep_field_type_codes: &[&[8]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: false,
    parse: parse_user_invite,
    encode: encode_user_invite,
    projector: super::projector::project_pure,
    context_loader: super::projection_context::build_projector_context,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_user_invite_rejects_wrong_signer_type() {
        let mut blob = vec![0u8; USER_INVITE_WIRE_SIZE];
        blob[0] = EVENT_TYPE_USER_INVITE;
        blob[105] = 5;

        let err = parse_user_invite(&blob).expect_err("should reject wrong signer type");
        assert!(matches!(err, EventError::InvalidMetadata(_)));
    }
}
