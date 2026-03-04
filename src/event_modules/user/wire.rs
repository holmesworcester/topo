use super::super::layout::common::{
    read_text_slot, write_text_slot, COMMON_HEADER_BYTES, NAME_BYTES, SIGNATURE_TRAILER_BYTES,
};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_USER};

/// User (type 14):
/// type(1) + created_at(8) + public_key(32) + username(64)
/// + signed_by(32) + signer_type(1) + signature(64) = 202
pub const USER_WIRE_SIZE: usize = COMMON_HEADER_BYTES + 32 + NAME_BYTES + SIGNATURE_TRAILER_BYTES;

mod user_offsets {
    use super::super::super::layout::common::NAME_BYTES;
    pub const TYPE_CODE: usize = 0;
    pub const CREATED_AT: usize = 1;
    pub const PUBLIC_KEY: usize = 9;
    pub const USERNAME: usize = 41;
    pub const SIGNED_BY: usize = 41 + NAME_BYTES;
    pub const SIGNER_TYPE: usize = SIGNED_BY + 32;
    pub const SIGNATURE: usize = SIGNER_TYPE + 1;
}

use user_offsets as off;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserEvent {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],
    pub username: String,
    pub signed_by: [u8; 32],
    pub signer_type: u8,
    pub signature: [u8; 64],
}

pub fn parse_user(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < USER_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: USER_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > USER_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: USER_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_USER {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_USER,
            actual: blob[0],
        });
    }

    let created_at_ms =
        u64::from_le_bytes(blob[off::CREATED_AT..off::PUBLIC_KEY].try_into().unwrap());
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&blob[off::PUBLIC_KEY..off::USERNAME]);

    let username = read_text_slot(&blob[off::USERNAME..off::USERNAME + NAME_BYTES])
        .map_err(EventError::TextSlot)?;

    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[off::SIGNED_BY..off::SIGNER_TYPE]);
    let signer_type = blob[off::SIGNER_TYPE];
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[off::SIGNATURE..off::SIGNATURE + 64]);

    Ok(ParsedEvent::User(UserEvent {
        created_at_ms,
        public_key,
        username,
        signed_by,
        signer_type,
        signature,
    }))
}

pub fn encode_user(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::User(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    let mut buf = vec![0u8; USER_WIRE_SIZE];
    buf[off::TYPE_CODE] = EVENT_TYPE_USER;
    buf[off::CREATED_AT..off::PUBLIC_KEY].copy_from_slice(&e.created_at_ms.to_le_bytes());
    buf[off::PUBLIC_KEY..off::USERNAME].copy_from_slice(&e.public_key);
    write_text_slot(
        &e.username,
        &mut buf[off::USERNAME..off::USERNAME + NAME_BYTES],
    )
    .map_err(EventError::TextSlot)?;
    buf[off::SIGNED_BY..off::SIGNER_TYPE].copy_from_slice(&e.signed_by);
    buf[off::SIGNER_TYPE] = e.signer_type;
    buf[off::SIGNATURE..off::SIGNATURE + 64].copy_from_slice(&e.signature);
    Ok(buf)
}

pub static USER_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_USER,
    type_name: "user",
    projection_table: "users",
    share_scope: ShareScope::Shared,
    dep_fields: &["signed_by"],
    dep_field_type_codes: &[&[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: false,
    parse: parse_user,
    encode: encode_user,
    projector: super::projector::project_pure,
    context_loader: crate::event_modules::registry::load_empty_context,
};

#[cfg(test)]
mod layout_tests {
    use super::*;

    #[test]
    fn offsets_consistent() {
        assert_eq!(user_offsets::SIGNATURE + 64, USER_WIRE_SIZE);
    }
}
