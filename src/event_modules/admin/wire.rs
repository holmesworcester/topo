use super::super::layout::common::{COMMON_HEADER_BYTES, SIGNATURE_TRAILER_BYTES};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_ADMIN};

/// Admin (type 18): type(1) + created_at(8) + public_key(32) + user_event_id(32)
/// + signed_by(32) + signer_type(1) + signature(64) = 170
pub const ADMIN_WIRE_SIZE: usize = COMMON_HEADER_BYTES + 32 + 32 + SIGNATURE_TRAILER_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminEvent {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],
    pub user_event_id: [u8; 32],
    pub signed_by: [u8; 32],
    pub signer_type: u8,
    pub signature: [u8; 64],
}

impl super::super::Describe for AdminEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![("public_key", super::super::trunc_hex(&self.public_key, 16))]
    }
}

pub fn parse_admin(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < ADMIN_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: ADMIN_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > ADMIN_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: ADMIN_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_ADMIN {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_ADMIN,
            actual: blob[0],
        });
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

    Ok(ParsedEvent::Admin(AdminEvent {
        created_at_ms,
        public_key,
        user_event_id,
        signed_by,
        signer_type,
        signature,
    }))
}

pub fn encode_admin(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::Admin(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    let mut buf = Vec::with_capacity(ADMIN_WIRE_SIZE);
    buf.push(EVENT_TYPE_ADMIN);
    buf.extend_from_slice(&e.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&e.public_key);
    buf.extend_from_slice(&e.user_event_id);
    buf.extend_from_slice(&e.signed_by);
    buf.push(e.signer_type);
    buf.extend_from_slice(&e.signature);
    Ok(buf)
}

pub static ADMIN_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_ADMIN,
    type_name: "admin",
    projection_table: "admins",
    share_scope: ShareScope::Shared,
    dep_fields: &["user_event_id", "signed_by"],
    dep_field_type_codes: &[&[14], &[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: false,
    parse: parse_admin,
    encode: encode_admin,
    projector: super::projector::project_pure,
    context_loader: crate::event_modules::registry::load_empty_context,
};
