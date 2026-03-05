use super::layout::common::COMMON_HEADER_BYTES;
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_INVITE_PRIVKEY};

pub const INVITE_PRIVKEY_WIRE_SIZE: usize = COMMON_HEADER_BYTES + 32 + 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitePrivkeyEvent {
    pub created_at_ms: u64,
    pub invite_event_id: [u8; 32],
    pub private_key_bytes: [u8; 32],
}

impl super::Describe for InvitePrivkeyEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "invite_event_id",
                super::short_id_b64(&self.invite_event_id),
            ),
            ("private_key", super::trunc_hex(&self.private_key_bytes, 16)),
        ]
    }
}

pub fn parse_invite_privkey(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < INVITE_PRIVKEY_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: INVITE_PRIVKEY_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > INVITE_PRIVKEY_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: INVITE_PRIVKEY_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_INVITE_PRIVKEY {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_INVITE_PRIVKEY,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());
    let mut invite_event_id = [0u8; 32];
    invite_event_id.copy_from_slice(&blob[9..41]);
    let mut private_key_bytes = [0u8; 32];
    private_key_bytes.copy_from_slice(&blob[41..73]);

    Ok(ParsedEvent::InvitePrivkey(InvitePrivkeyEvent {
        created_at_ms,
        invite_event_id,
        private_key_bytes,
    }))
}

pub fn encode_invite_privkey(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::InvitePrivkey(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    let mut buf = Vec::with_capacity(INVITE_PRIVKEY_WIRE_SIZE);
    buf.push(EVENT_TYPE_INVITE_PRIVKEY);
    buf.extend_from_slice(&e.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&e.invite_event_id);
    buf.extend_from_slice(&e.private_key_bytes);
    Ok(buf)
}

pub fn deterministic_invite_privkey_created_at_ms(
    invite_event_id: &[u8; 32],
    private_key_bytes: &[u8; 32],
) -> u64 {
    use blake2::digest::consts::U8;
    use blake2::{Blake2b, Digest};

    let mut hasher = Blake2b::<U8>::new();
    hasher.update(b"poc7-invite-privkey-created-at-v1");
    hasher.update(invite_event_id);
    hasher.update(private_key_bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(out)
}

pub fn deterministic_invite_privkey_event(
    invite_event_id: [u8; 32],
    private_key_bytes: [u8; 32],
) -> ParsedEvent {
    ParsedEvent::InvitePrivkey(InvitePrivkeyEvent {
        created_at_ms: deterministic_invite_privkey_created_at_ms(
            &invite_event_id,
            &private_key_bytes,
        ),
        invite_event_id,
        private_key_bytes,
    })
}

pub fn deterministic_invite_privkey_event_id(
    invite_event_id: &[u8; 32],
    private_key_bytes: &[u8; 32],
) -> [u8; 32] {
    let event = deterministic_invite_privkey_event(*invite_event_id, *private_key_bytes);
    let blob =
        super::encode_event(&event).expect("deterministic invite_privkey encoding should succeed");
    crate::crypto::hash_event(&blob)
}

use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS invite_privkeys (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            invite_event_id TEXT NOT NULL,
            private_key BLOB NOT NULL,
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
        ParsedEvent::InvitePrivkey(v) => v,
        _ => return ProjectorResult::reject("not an invite_privkey event".to_string()),
    };

    ProjectorResult::valid(vec![WriteOp::InsertOrIgnore {
        table: "invite_privkeys",
        columns: vec![
            "recorded_by",
            "event_id",
            "invite_event_id",
            "private_key",
            "created_at",
        ],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(event_id_to_base64(&e.invite_event_id)),
            SqlVal::Blob(e.private_key_bytes.to_vec()),
            SqlVal::Int(e.created_at_ms as i64),
        ],
    }])
}

pub static INVITE_PRIVKEY_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_INVITE_PRIVKEY,
    type_name: "invite_privkey",
    projection_table: "invite_privkeys",
    share_scope: ShareScope::Local,
    dep_fields: &["invite_event_id"],
    dep_field_type_codes: &[&[10, 12]],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_invite_privkey,
    encode: encode_invite_privkey,
    projector: project_pure,
    context_loader: crate::event_modules::registry::load_empty_context,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::{encode_event, parse_event};

    #[test]
    fn test_roundtrip_invite_privkey() {
        let e = ParsedEvent::InvitePrivkey(InvitePrivkeyEvent {
            created_at_ms: 12345,
            invite_event_id: [9u8; 32],
            private_key_bytes: [7u8; 32],
        });
        let blob = encode_event(&e).unwrap();
        assert_eq!(blob.len(), INVITE_PRIVKEY_WIRE_SIZE);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, e);
    }

    #[test]
    fn test_deterministic_invite_privkey_event_id_stable() {
        let invite = [7u8; 32];
        let key = [11u8; 32];
        let a = deterministic_invite_privkey_event_id(&invite, &key);
        let b = deterministic_invite_privkey_event_id(&invite, &key);
        assert_eq!(a, b);
    }
}
