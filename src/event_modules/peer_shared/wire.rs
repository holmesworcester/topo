use super::super::layout::common::{
    read_text_slot, write_text_slot, COMMON_HEADER_BYTES, NAME_BYTES, SIGNATURE_TRAILER_BYTES,
};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{
    EventError, ParsedEvent, EVENT_TYPE_PEER_SHARED_FIRST, EVENT_TYPE_PEER_SHARED_ONGOING,
};

// --- Layout (owned by this module) ---

/// PeerShared (types 16, 17): type(1) + created_at(8) + public_key(32) + user_event_id(32)
///                           + device_name(64) + signed_by(32) + signer_type(1) + signature(64) = 234
pub const PEER_SHARED_WIRE_SIZE: usize =
    COMMON_HEADER_BYTES + 32 + 32 + NAME_BYTES + SIGNATURE_TRAILER_BYTES;

mod peer_shared_offsets {
    use super::super::super::layout::common::NAME_BYTES;
    pub const TYPE_CODE: usize = 0;
    pub const CREATED_AT: usize = 1;
    pub const PUBLIC_KEY: usize = 9;
    pub const USER_EVENT_ID: usize = 41;
    pub const DEVICE_NAME: usize = 73;
    pub const SIGNED_BY: usize = 73 + NAME_BYTES; // 137
    pub const SIGNER_TYPE: usize = SIGNED_BY + 32; // 169
    pub const SIGNATURE: usize = SIGNER_TYPE + 1; // 170
}

use peer_shared_offsets as off;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSharedFirstEvent {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],
    pub user_event_id: [u8; 32],
    pub device_name: String,
    pub signed_by: [u8; 32],
    pub signer_type: u8,
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSharedOngoingEvent {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],
    pub user_event_id: [u8; 32],
    pub device_name: String,
    pub signed_by: [u8; 32],
    pub signer_type: u8,
    pub signature: [u8; 64],
}

pub fn parse_peer_shared_first(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < PEER_SHARED_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: PEER_SHARED_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > PEER_SHARED_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: PEER_SHARED_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_PEER_SHARED_FIRST {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_PEER_SHARED_FIRST,
            actual: blob[0],
        });
    }

    let created_at_ms =
        u64::from_le_bytes(blob[off::CREATED_AT..off::PUBLIC_KEY].try_into().unwrap());
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&blob[off::PUBLIC_KEY..off::USER_EVENT_ID]);
    let mut user_event_id = [0u8; 32];
    user_event_id.copy_from_slice(&blob[off::USER_EVENT_ID..off::DEVICE_NAME]);

    let device_name = read_text_slot(&blob[off::DEVICE_NAME..off::DEVICE_NAME + NAME_BYTES])
        .map_err(EventError::TextSlot)?;

    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[off::SIGNED_BY..off::SIGNER_TYPE]);
    let signer_type = blob[off::SIGNER_TYPE];
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[off::SIGNATURE..off::SIGNATURE + 64]);

    Ok(ParsedEvent::PeerSharedFirst(PeerSharedFirstEvent {
        created_at_ms,
        public_key,
        user_event_id,
        device_name,
        signed_by,
        signer_type,
        signature,
    }))
}

pub fn encode_peer_shared_first(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::PeerSharedFirst(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    let mut buf = vec![0u8; PEER_SHARED_WIRE_SIZE];
    buf[off::TYPE_CODE] = EVENT_TYPE_PEER_SHARED_FIRST;
    buf[off::CREATED_AT..off::PUBLIC_KEY].copy_from_slice(&e.created_at_ms.to_le_bytes());
    buf[off::PUBLIC_KEY..off::USER_EVENT_ID].copy_from_slice(&e.public_key);
    buf[off::USER_EVENT_ID..off::DEVICE_NAME].copy_from_slice(&e.user_event_id);
    write_text_slot(
        &e.device_name,
        &mut buf[off::DEVICE_NAME..off::DEVICE_NAME + NAME_BYTES],
    )
    .map_err(EventError::TextSlot)?;
    buf[off::SIGNED_BY..off::SIGNER_TYPE].copy_from_slice(&e.signed_by);
    buf[off::SIGNER_TYPE] = e.signer_type;
    buf[off::SIGNATURE..off::SIGNATURE + 64].copy_from_slice(&e.signature);
    Ok(buf)
}

pub fn parse_peer_shared_ongoing(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < PEER_SHARED_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: PEER_SHARED_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > PEER_SHARED_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: PEER_SHARED_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_PEER_SHARED_ONGOING {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_PEER_SHARED_ONGOING,
            actual: blob[0],
        });
    }

    let created_at_ms =
        u64::from_le_bytes(blob[off::CREATED_AT..off::PUBLIC_KEY].try_into().unwrap());
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&blob[off::PUBLIC_KEY..off::USER_EVENT_ID]);
    let mut user_event_id = [0u8; 32];
    user_event_id.copy_from_slice(&blob[off::USER_EVENT_ID..off::DEVICE_NAME]);

    let device_name = read_text_slot(&blob[off::DEVICE_NAME..off::DEVICE_NAME + NAME_BYTES])
        .map_err(EventError::TextSlot)?;

    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[off::SIGNED_BY..off::SIGNER_TYPE]);
    let signer_type = blob[off::SIGNER_TYPE];
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[off::SIGNATURE..off::SIGNATURE + 64]);

    Ok(ParsedEvent::PeerSharedOngoing(PeerSharedOngoingEvent {
        created_at_ms,
        public_key,
        user_event_id,
        device_name,
        signed_by,
        signer_type,
        signature,
    }))
}

pub fn encode_peer_shared_ongoing(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::PeerSharedOngoing(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    let mut buf = vec![0u8; PEER_SHARED_WIRE_SIZE];
    buf[off::TYPE_CODE] = EVENT_TYPE_PEER_SHARED_ONGOING;
    buf[off::CREATED_AT..off::PUBLIC_KEY].copy_from_slice(&e.created_at_ms.to_le_bytes());
    buf[off::PUBLIC_KEY..off::USER_EVENT_ID].copy_from_slice(&e.public_key);
    buf[off::USER_EVENT_ID..off::DEVICE_NAME].copy_from_slice(&e.user_event_id);
    write_text_slot(
        &e.device_name,
        &mut buf[off::DEVICE_NAME..off::DEVICE_NAME + NAME_BYTES],
    )
    .map_err(EventError::TextSlot)?;
    buf[off::SIGNED_BY..off::SIGNER_TYPE].copy_from_slice(&e.signed_by);
    buf[off::SIGNER_TYPE] = e.signer_type;
    buf[off::SIGNATURE..off::SIGNATURE + 64].copy_from_slice(&e.signature);
    Ok(buf)
}

pub static PEER_SHARED_FIRST_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_PEER_SHARED_FIRST,
    type_name: "peer_shared_first",
    projection_table: "peers_shared",
    share_scope: ShareScope::Shared,
    dep_fields: &["user_event_id", "signed_by"],
    dep_field_type_codes: &[&[14, 15], &[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: false,
    parse: parse_peer_shared_first,
    encode: encode_peer_shared_first,
    projector: super::projector::project_pure,
    context_loader: crate::event_modules::registry::load_empty_context,
};

pub static PEER_SHARED_ONGOING_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_PEER_SHARED_ONGOING,
    type_name: "peer_shared_ongoing",
    projection_table: "peers_shared",
    share_scope: ShareScope::Shared,
    dep_fields: &["user_event_id", "signed_by"],
    dep_field_type_codes: &[&[14, 15], &[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: false,
    parse: parse_peer_shared_ongoing,
    encode: encode_peer_shared_ongoing,
    projector: super::projector::project_pure,
    context_loader: crate::event_modules::registry::load_empty_context,
};

#[cfg(test)]
mod layout_tests {
    use super::*;

    #[test]
    fn offsets_consistent() {
        assert_eq!(peer_shared_offsets::SIGNATURE + 64, PEER_SHARED_WIRE_SIZE);
    }
}
