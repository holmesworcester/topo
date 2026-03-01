use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_LOCAL_SIGNER_SECRET};

pub const SIGNER_KIND_WORKSPACE: u8 = 1;
pub const SIGNER_KIND_USER: u8 = 2;
pub const SIGNER_KIND_PEER_SHARED: u8 = 3;
pub const SIGNER_KIND_PENDING_INVITE_UNWRAP: u8 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSignerSecretEvent {
    pub created_at_ms: u64,
    pub signer_event_id: [u8; 32],
    pub signer_kind: u8,
    pub private_key_bytes: [u8; 32],
}

/// Wire format (74 bytes fixed):
/// [0]      type_code = 27
/// [1..9]   created_at_ms (u64 LE)
/// [9..41]  signer_event_id (32 bytes)
/// [41]     signer_kind (u8: 1=workspace, 2=user, 3=peer_shared, 4=pending invite unwrap)
/// [42..74] private_key_bytes (32 bytes)
pub fn parse_local_signer_secret(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < 74 {
        return Err(EventError::TooShort {
            expected: 74,
            actual: blob.len(),
        });
    }
    if blob.len() > 74 {
        return Err(EventError::TrailingData {
            expected: 74,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_LOCAL_SIGNER_SECRET {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_LOCAL_SIGNER_SECRET,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());

    let mut signer_event_id = [0u8; 32];
    signer_event_id.copy_from_slice(&blob[9..41]);

    let signer_kind = blob[41];
    if signer_kind < 1 || signer_kind > 4 {
        return Err(EventError::InvalidMetadata(
            "signer_kind must be 1, 2, 3, or 4",
        ));
    }

    let mut private_key_bytes = [0u8; 32];
    private_key_bytes.copy_from_slice(&blob[42..74]);

    Ok(ParsedEvent::LocalSignerSecret(LocalSignerSecretEvent {
        created_at_ms,
        signer_event_id,
        signer_kind,
        private_key_bytes,
    }))
}

pub fn encode_local_signer_secret(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::LocalSignerSecret(v) => v,
        _ => return Err(EventError::WrongVariant),
    };

    if e.signer_kind < 1 || e.signer_kind > 4 {
        return Err(EventError::InvalidMetadata(
            "signer_kind must be 1, 2, 3, or 4",
        ));
    }

    let mut buf = Vec::with_capacity(74);
    buf.push(EVENT_TYPE_LOCAL_SIGNER_SECRET);
    buf.extend_from_slice(&e.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&e.signer_event_id);
    buf.push(e.signer_kind);
    buf.extend_from_slice(&e.private_key_bytes);
    Ok(buf)
}

// === Projector (event-module locality) ===

use crate::contracts::transport_identity_contract::TransportIdentityIntent;
use crate::crypto::event_id_to_base64;
use crate::projection::result::{ContextSnapshot, EmitCommand, ProjectorResult, SqlVal, WriteOp};
use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
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

/// Pure projector: LocalSignerSecret → local_signer_material table.
/// UPSERT by (recorded_by, signer_event_id): Delete existing + InsertOrIgnore.
/// Emits `ApplyTransportIdentityIntent(InstallPeerSharedIdentityFromSigner)`
/// when signer_kind == SIGNER_KIND_PEER_SHARED.
pub fn project_pure(
    recorded_by: &str,
    _event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let e = match parsed {
        ParsedEvent::LocalSignerSecret(v) => v,
        _ => return ProjectorResult::reject("not a local_signer_secret event".to_string()),
    };

    let signer_eid_b64 = event_id_to_base64(&e.signer_event_id);

    let mut ops = vec![WriteOp::Delete {
        table: "local_signer_material",
        where_clause: vec![
            ("recorded_by", SqlVal::Text(recorded_by.to_string())),
            ("signer_event_id", SqlVal::Text(signer_eid_b64.clone())),
        ],
    }];
    // signer_kind=4 with all-zero key bytes is a delete tombstone.
    let is_pending_tombstone =
        e.signer_kind == SIGNER_KIND_PENDING_INVITE_UNWRAP && e.private_key_bytes == [0u8; 32];
    if !is_pending_tombstone {
        ops.push(WriteOp::InsertOrIgnore {
            table: "local_signer_material",
            columns: vec![
                "recorded_by",
                "signer_event_id",
                "signer_kind",
                "private_key",
                "created_at",
            ],
            values: vec![
                SqlVal::Text(recorded_by.to_string()),
                SqlVal::Text(signer_eid_b64),
                SqlVal::Int(e.signer_kind as i64),
                SqlVal::Blob(e.private_key_bytes.to_vec()),
                SqlVal::Int(e.created_at_ms as i64),
            ],
        });
    }

    if e.signer_kind == SIGNER_KIND_PEER_SHARED {
        ProjectorResult::valid_with_commands(
            ops,
            vec![EmitCommand::ApplyTransportIdentityIntent {
                intent: TransportIdentityIntent::InstallPeerSharedIdentityFromSigner {
                    recorded_by: recorded_by.to_string(),
                    signer_event_id: e.signer_event_id,
                },
            }],
        )
    } else {
        ProjectorResult::valid(ops)
    }
}

pub static LOCAL_SIGNER_SECRET_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_LOCAL_SIGNER_SECRET,
    type_name: "local_signer_secret",
    projection_table: "local_signer_material",
    share_scope: ShareScope::Local,
    // No static dep gate: pending-invite unwrap keys (signer_kind=4) may refer
    // to invite event IDs not yet synced locally.
    dep_fields: &[],
    dep_field_type_codes: &[],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_local_signer_secret,
    encode: encode_local_signer_secret,
    projector: project_pure,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::{encode_event, parse_event};

    #[test]
    fn test_roundtrip_workspace() {
        let e = LocalSignerSecretEvent {
            created_at_ms: 1234567890123,
            signer_event_id: [1u8; 32],
            signer_kind: SIGNER_KIND_WORKSPACE,
            private_key_bytes: [2u8; 32],
        };
        let event = ParsedEvent::LocalSignerSecret(e);
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), 74);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_roundtrip_user() {
        let e = LocalSignerSecretEvent {
            created_at_ms: 9876543210000,
            signer_event_id: [3u8; 32],
            signer_kind: SIGNER_KIND_USER,
            private_key_bytes: [4u8; 32],
        };
        let event = ParsedEvent::LocalSignerSecret(e);
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), 74);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_roundtrip_peer_shared() {
        let e = LocalSignerSecretEvent {
            created_at_ms: 5555555555555,
            signer_event_id: [5u8; 32],
            signer_kind: SIGNER_KIND_PEER_SHARED,
            private_key_bytes: [6u8; 32],
        };
        let event = ParsedEvent::LocalSignerSecret(e);
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), 74);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_roundtrip_pending_invite_unwrap() {
        let e = LocalSignerSecretEvent {
            created_at_ms: 6666666666666,
            signer_event_id: [7u8; 32],
            signer_kind: SIGNER_KIND_PENDING_INVITE_UNWRAP,
            private_key_bytes: [8u8; 32],
        };
        let event = ParsedEvent::LocalSignerSecret(e);
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), 74);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_reject_invalid_signer_kind() {
        let mut blob = vec![EVENT_TYPE_LOCAL_SIGNER_SECRET];
        blob.extend_from_slice(&0u64.to_le_bytes());
        blob.extend_from_slice(&[0u8; 32]); // signer_event_id
        blob.push(0); // invalid signer_kind
        blob.extend_from_slice(&[0u8; 32]); // private_key_bytes
        assert!(parse_event(&blob).is_err());

        let mut blob2 = vec![EVENT_TYPE_LOCAL_SIGNER_SECRET];
        blob2.extend_from_slice(&0u64.to_le_bytes());
        blob2.extend_from_slice(&[0u8; 32]);
        blob2.push(5); // invalid signer_kind
        blob2.extend_from_slice(&[0u8; 32]);
        assert!(parse_event(&blob2).is_err());
    }

    #[test]
    fn test_reject_trailing_data() {
        let e = LocalSignerSecretEvent {
            created_at_ms: 100,
            signer_event_id: [0u8; 32],
            signer_kind: SIGNER_KIND_WORKSPACE,
            private_key_bytes: [0u8; 32],
        };
        let event = ParsedEvent::LocalSignerSecret(e);
        let mut blob = encode_event(&event).unwrap();
        blob.push(0xFF);
        let err = parse_event(&blob).unwrap_err();
        assert!(matches!(
            err,
            EventError::TrailingData {
                expected: 74,
                actual: 75
            }
        ));
    }

    #[test]
    fn test_reject_short_data() {
        let blob = vec![EVENT_TYPE_LOCAL_SIGNER_SECRET; 10];
        let err = parse_event(&blob).unwrap_err();
        assert!(matches!(err, EventError::TooShort { expected: 74, .. }));
    }
}
