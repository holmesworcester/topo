use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_TRANSPORT_KEY};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportKeyEvent {
    pub created_at_ms: u64,
    pub spki_fingerprint: [u8; 32],  // BLAKE2b-256 of cert SPKI
    pub signed_by: [u8; 32],         // signer event_id (PeerShared event)
    pub signer_type: u8,             // 5 = peer_shared
    pub signature: [u8; 64],
}

/// Wire format (138 bytes fixed):
/// [0]        type_code = 23
/// [1..9]     created_at_ms (u64 LE)
/// [9..41]    spki_fingerprint (32 bytes)
/// [41..73]   signed_by (32 bytes)
/// [73]       signer_type (1 byte)
/// [74..138]  signature (64 bytes)
pub fn parse_transport_key(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < 138 {
        return Err(EventError::TooShort { expected: 138, actual: blob.len() });
    }
    if blob.len() > 138 {
        return Err(EventError::TrailingData { expected: 138, actual: blob.len() });
    }
    if blob[0] != EVENT_TYPE_TRANSPORT_KEY {
        return Err(EventError::WrongType { expected: EVENT_TYPE_TRANSPORT_KEY, actual: blob[0] });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());
    let mut spki_fingerprint = [0u8; 32];
    spki_fingerprint.copy_from_slice(&blob[9..41]);
    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[41..73]);
    let signer_type = blob[73];
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[74..138]);

    Ok(ParsedEvent::TransportKey(TransportKeyEvent {
        created_at_ms,
        spki_fingerprint,
        signed_by,
        signer_type,
        signature,
    }))
}

pub fn encode_transport_key(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::TransportKey(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    let mut buf = Vec::with_capacity(138);
    buf.push(EVENT_TYPE_TRANSPORT_KEY);
    buf.extend_from_slice(&e.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&e.spki_fingerprint);
    buf.extend_from_slice(&e.signed_by);
    buf.push(e.signer_type);
    buf.extend_from_slice(&e.signature);
    Ok(buf)
}

pub static TRANSPORT_KEY_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_TRANSPORT_KEY,
    type_name: "transport_key",
    projection_table: "transport_keys",
    share_scope: ShareScope::Shared,
    dep_fields: &["signed_by"],
    dep_field_type_codes: &[&[]],
    signer_required: true,
    signature_byte_len: 64,
    parse: parse_transport_key,
    encode: encode_transport_key,
};
