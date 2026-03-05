use super::layout::common::COMMON_HEADER_BYTES;
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_PEER};

pub const PEER_WIRE_SIZE: usize = COMMON_HEADER_BYTES + 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerEvent {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],
}

impl super::Describe for PeerEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("public_key", super::trunc_hex(&self.public_key, 16)),
            (
                "peer_id",
                hex::encode(crate::crypto::spki_fingerprint_from_ed25519_pubkey(
                    &self.public_key,
                )),
            ),
        ]
    }
}

pub fn parse_peer(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < PEER_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: PEER_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > PEER_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: PEER_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_PEER {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_PEER,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&blob[9..41]);

    Ok(ParsedEvent::Peer(PeerEvent {
        created_at_ms,
        public_key,
    }))
}

pub fn encode_peer(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::Peer(v) => v,
        _ => return Err(EventError::WrongVariant),
    };

    let mut buf = Vec::with_capacity(PEER_WIRE_SIZE);
    buf.push(EVENT_TYPE_PEER);
    buf.extend_from_slice(&e.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&e.public_key);
    Ok(buf)
}

use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS peers_local (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            public_key BLOB NOT NULL,
            peer_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        ",
    )?;
    Ok(())
}

pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let e = match parsed {
        ParsedEvent::Peer(v) => v,
        _ => return ProjectorResult::reject("not a peer event".to_string()),
    };

    let peer_id = hex::encode(crate::crypto::spki_fingerprint_from_ed25519_pubkey(
        &e.public_key,
    ));

    ProjectorResult::valid(vec![WriteOp::InsertOrIgnore {
        table: "peers_local",
        columns: vec![
            "recorded_by",
            "event_id",
            "public_key",
            "peer_id",
            "created_at",
        ],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Blob(e.public_key.to_vec()),
            SqlVal::Text(peer_id),
            SqlVal::Int(e.created_at_ms as i64),
        ],
    }])
}

pub static PEER_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_PEER,
    type_name: "peer",
    projection_table: "peers_local",
    share_scope: ShareScope::Local,
    dep_fields: &[],
    dep_field_type_codes: &[],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_peer,
    encode: encode_peer,
    projector: project_pure,
    context_loader: crate::event_modules::registry::load_empty_context,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::{encode_event, parse_event};

    #[test]
    fn test_roundtrip_peer() {
        let e = ParsedEvent::Peer(PeerEvent {
            created_at_ms: 12345,
            public_key: [7u8; 32],
        });
        let blob = encode_event(&e).unwrap();
        assert_eq!(blob.len(), PEER_WIRE_SIZE);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, e);
    }
}
