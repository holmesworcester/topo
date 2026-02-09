use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_PEER_KEY};

/// DEPRECATED: PeerKey (signer_type 0) is superseded by PeerShared identity chain keys
/// (signer_type 5). New events should use PeerSharedFirst/PeerSharedOngoing as signers.
/// PeerKey is retained for parsing old events and backward compatibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerKeyEvent {
    pub created_at_ms: u64,
    pub public_key: [u8; 32], // Ed25519 verifying key
}

/// Wire format (41 bytes fixed):
/// [0]      type_code = 3
/// [1..9]   created_at_ms (u64 LE)
/// [9..41]  public_key (32 bytes)
pub fn parse_peer_key(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < 41 {
        return Err(EventError::TooShort {
            expected: 41,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_PEER_KEY {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_PEER_KEY,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());

    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&blob[9..41]);

    Ok(ParsedEvent::PeerKey(PeerKeyEvent {
        created_at_ms,
        public_key,
    }))
}

pub fn encode_peer_key(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let pk = match event {
        ParsedEvent::PeerKey(p) => p,
        _ => return Err(EventError::WrongVariant),
    };

    let mut buf = Vec::with_capacity(41);
    buf.push(EVENT_TYPE_PEER_KEY);
    buf.extend_from_slice(&pk.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&pk.public_key);
    Ok(buf)
}

pub static PEER_KEY_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_PEER_KEY,
    type_name: "peer_key",
    projection_table: "peer_keys",
    share_scope: ShareScope::Shared,
    dep_fields: &[],
    signer_required: false,
    signature_byte_len: 0,
    parse: parse_peer_key,
    encode: encode_peer_key,
};
