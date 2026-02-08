use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_NETWORK};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkEvent {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],  // Ed25519 verifying key for the network
    pub network_id: [u8; 32],  // unique network identifier
}

/// Wire format (73 bytes fixed):
/// [0]      type_code = 8
/// [1..9]   created_at_ms (u64 LE)
/// [9..41]  public_key (32 bytes)
/// [41..73] network_id (32 bytes)
pub fn parse_network(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < 73 {
        return Err(EventError::TooShort {
            expected: 73,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_NETWORK {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_NETWORK,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());

    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&blob[9..41]);

    let mut network_id = [0u8; 32];
    network_id.copy_from_slice(&blob[41..73]);

    Ok(ParsedEvent::Network(NetworkEvent {
        created_at_ms,
        public_key,
        network_id,
    }))
}

pub fn encode_network(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let net = match event {
        ParsedEvent::Network(n) => n,
        _ => return Err(EventError::WrongVariant),
    };

    let mut buf = Vec::with_capacity(73);
    buf.push(EVENT_TYPE_NETWORK);
    buf.extend_from_slice(&net.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&net.public_key);
    buf.extend_from_slice(&net.network_id);
    Ok(buf)
}

pub static NETWORK_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_NETWORK,
    type_name: "network",
    projection_table: "networks",
    share_scope: ShareScope::Shared,
    dep_fields: &[],
    signer_required: false,
    signature_byte_len: 0,
    parse: parse_network,
    encode: encode_network,
};
