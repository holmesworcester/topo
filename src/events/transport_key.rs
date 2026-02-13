use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_TRANSPORT_KEY};

/// TransportKey is an unsigned deterministic emitted event.
/// It binds an SPKI fingerprint to a PeerShared identity event.
/// Because it is deterministic (bytes fully determined by inputs),
/// it does not carry a signature — validation uses deterministic-derivation
/// checks instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportKeyEvent {
    pub created_at_ms: u64,
    pub spki_fingerprint: [u8; 32],      // BLAKE2b-256 of cert SPKI
    pub peer_shared_event_id: [u8; 32],  // dependency: PeerShared event
}

/// Wire format (73 bytes fixed):
/// [0]        type_code = 23
/// [1..9]     created_at_ms (u64 LE)
/// [9..41]    spki_fingerprint (32 bytes)
/// [41..73]   peer_shared_event_id (32 bytes)
pub fn parse_transport_key(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < 73 {
        return Err(EventError::TooShort { expected: 73, actual: blob.len() });
    }
    if blob[0] != EVENT_TYPE_TRANSPORT_KEY {
        return Err(EventError::WrongType { expected: EVENT_TYPE_TRANSPORT_KEY, actual: blob[0] });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());
    let mut spki_fingerprint = [0u8; 32];
    spki_fingerprint.copy_from_slice(&blob[9..41]);
    let mut peer_shared_event_id = [0u8; 32];
    peer_shared_event_id.copy_from_slice(&blob[41..73]);

    Ok(ParsedEvent::TransportKey(TransportKeyEvent {
        created_at_ms,
        spki_fingerprint,
        peer_shared_event_id,
    }))
}

pub fn encode_transport_key(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::TransportKey(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    let mut buf = Vec::with_capacity(73);
    buf.push(EVENT_TYPE_TRANSPORT_KEY);
    buf.extend_from_slice(&e.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&e.spki_fingerprint);
    buf.extend_from_slice(&e.peer_shared_event_id);
    Ok(buf)
}

pub static TRANSPORT_KEY_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_TRANSPORT_KEY,
    type_name: "transport_key",
    projection_table: "transport_keys",
    share_scope: ShareScope::Shared,
    dep_fields: &["peer_shared_event_id"],
    dep_field_type_codes: &[&[]],
    signer_required: false,
    signature_byte_len: 0,
    parse: parse_transport_key,
    encode: encode_transport_key,
};
