use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_PEER_SECRET};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSecretEvent {
    pub created_at_ms: u64,
    pub signer_event_id: [u8; 32],
    pub private_key_bytes: [u8; 32],
}

impl super::Describe for PeerSecretEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![(
            "signer_event_id",
            super::short_id_b64(&self.signer_event_id),
        )]
    }
}

/// Wire format (73 bytes fixed):
/// [0]      type_code = 27
/// [1..9]   created_at_ms (u64 LE)
/// [9..41]  signer_event_id (32 bytes, dep: peer_shared)
/// [41..73] private_key_bytes (32 bytes)
pub const PEER_SECRET_WIRE_SIZE: usize = 73;

pub fn parse_peer_secret(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < PEER_SECRET_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: PEER_SECRET_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > PEER_SECRET_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: PEER_SECRET_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_PEER_SECRET {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_PEER_SECRET,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());

    let mut signer_event_id = [0u8; 32];
    signer_event_id.copy_from_slice(&blob[9..41]);

    let mut private_key_bytes = [0u8; 32];
    private_key_bytes.copy_from_slice(&blob[41..73]);

    Ok(ParsedEvent::PeerSecret(PeerSecretEvent {
        created_at_ms,
        signer_event_id,
        private_key_bytes,
    }))
}

pub fn encode_peer_secret(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::PeerSecret(v) => v,
        _ => return Err(EventError::WrongVariant),
    };

    let mut buf = Vec::with_capacity(PEER_SECRET_WIRE_SIZE);
    buf.push(EVENT_TYPE_PEER_SECRET);
    buf.extend_from_slice(&e.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&e.signer_event_id);
    buf.extend_from_slice(&e.private_key_bytes);
    Ok(buf)
}

// === Projector (event-module locality) ===

use crate::contracts::transport_identity_contract::TransportIdentityIntent;
use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ContextSnapshot, EmitCommand, ProjectorResult, SqlVal, WriteOp};
use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS peer_secrets (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            signer_event_id TEXT NOT NULL,
            private_key BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_peer_secrets_signer
            ON peer_secrets(recorded_by, signer_event_id, created_at DESC, event_id DESC);

        -- Legacy bootstrap-fallback cache table (non-event path).
        -- Kept for compatibility with existing transport fallback behavior.
        CREATE TABLE IF NOT EXISTS local_signer_material (
            recorded_by TEXT NOT NULL,
            signer_event_id TEXT NOT NULL,
            signer_kind INTEGER NOT NULL,
            private_key BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (recorded_by, signer_event_id)
        );
        ",
    )?;
    Ok(())
}

/// Pure projector: PeerSecret -> peer_secrets table (one row per event).
/// Always emits ApplyTransportIdentityIntent(InstallPeerSharedIdentityFromSigner).
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let e = match parsed {
        ParsedEvent::PeerSecret(v) => v,
        _ => return ProjectorResult::reject("not a peer_secret event".to_string()),
    };

    let signer_eid_b64 = event_id_to_base64(&e.signer_event_id);

    ProjectorResult::valid_with_commands(
        vec![WriteOp::InsertOrIgnore {
            table: "peer_secrets",
            columns: vec![
                "recorded_by",
                "event_id",
                "signer_event_id",
                "private_key",
                "created_at",
            ],
            values: vec![
                SqlVal::Text(recorded_by.to_string()),
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Text(signer_eid_b64),
                SqlVal::Blob(e.private_key_bytes.to_vec()),
                SqlVal::Int(e.created_at_ms as i64),
            ],
        }],
        vec![EmitCommand::ApplyTransportIdentityIntent {
            intent: TransportIdentityIntent::InstallPeerSharedIdentityFromSigner {
                recorded_by: recorded_by.to_string(),
                signer_event_id: e.signer_event_id,
            },
        }],
    )
}

pub static PEER_SECRET_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_PEER_SECRET,
    type_name: "peer_secret",
    projection_table: "peer_secrets",
    share_scope: ShareScope::Local,
    dep_fields: &["signer_event_id"],
    dep_field_type_codes: &[&[16]],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_peer_secret,
    encode: encode_peer_secret,
    projector: project_pure,
    context_loader: crate::event_modules::registry::load_empty_context,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::{encode_event, parse_event};

    #[test]
    fn test_roundtrip_peer_secret() {
        let e = PeerSecretEvent {
            created_at_ms: 1234567890123,
            signer_event_id: [1u8; 32],
            private_key_bytes: [2u8; 32],
        };
        let event = ParsedEvent::PeerSecret(e);
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), PEER_SECRET_WIRE_SIZE);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_reject_trailing_data() {
        let e = PeerSecretEvent {
            created_at_ms: 100,
            signer_event_id: [0u8; 32],
            private_key_bytes: [0u8; 32],
        };
        let event = ParsedEvent::PeerSecret(e);
        let mut blob = encode_event(&event).unwrap();
        blob.push(0xFF);
        let err = parse_event(&blob).unwrap_err();
        assert!(matches!(
            err,
            EventError::TrailingData {
                expected: PEER_SECRET_WIRE_SIZE,
                actual: 74
            }
        ));
    }

    #[test]
    fn test_reject_short_data() {
        let blob = vec![EVENT_TYPE_PEER_SECRET; 10];
        let err = parse_event(&blob).unwrap_err();
        assert!(matches!(
            err,
            EventError::TooShort {
                expected: PEER_SECRET_WIRE_SIZE,
                ..
            }
        ));
    }
}
