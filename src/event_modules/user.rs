use super::layout::common::{COMMON_HEADER_BYTES, SIGNATURE_TRAILER_BYTES, NAME_BYTES, read_text_slot, write_text_slot};
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_USER_BOOT, EVENT_TYPE_USER_ONGOING};

// ─── Layout (owned by this module) ───

/// User (types 14, 15): type(1) + created_at(8) + public_key(32) + username(64)
///                     + signed_by(32) + signer_type(1) + signature(64) = 202
pub const USER_WIRE_SIZE: usize = COMMON_HEADER_BYTES + 32 + NAME_BYTES + SIGNATURE_TRAILER_BYTES;

mod user_offsets {
    use super::super::layout::common::NAME_BYTES;
    pub const TYPE_CODE: usize = 0;
    pub const CREATED_AT: usize = 1;
    pub const PUBLIC_KEY: usize = 9;
    pub const USERNAME: usize = 41;
    pub const SIGNED_BY: usize = 41 + NAME_BYTES;           // 105
    pub const SIGNER_TYPE: usize = SIGNED_BY + 32;                  // 137
    pub const SIGNATURE: usize = SIGNER_TYPE + 1;                   // 138
}

use user_offsets as off;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserBootEvent {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],
    pub username: String,        // Display name (64-byte text slot)
    pub signed_by: [u8; 32],     // signer event_id (UserInviteBoot event)
    pub signer_type: u8,         // 2 = user_invite
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserOngoingEvent {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],
    pub username: String,        // Display name (64-byte text slot)
    pub signed_by: [u8; 32],     // signer event_id (UserInviteOngoing event)
    pub signer_type: u8,         // 2 = user_invite
    pub signature: [u8; 64],
}

/// Wire format (202 bytes fixed):
/// [0]          type_code = 14
/// [1..9]       created_at_ms (u64 LE)
/// [9..41]      public_key (32 bytes)
/// [41..105]    username (64 bytes, UTF-8 zero-padded)
/// [105..137]   signed_by (32 bytes)
/// [137]        signer_type (1 byte)
/// [138..202]   signature (64 bytes)
pub fn parse_user_boot(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < USER_WIRE_SIZE {
        return Err(EventError::TooShort { expected: USER_WIRE_SIZE, actual: blob.len() });
    }
    if blob.len() > USER_WIRE_SIZE {
        return Err(EventError::TrailingData { expected: USER_WIRE_SIZE, actual: blob.len() });
    }
    if blob[0] != EVENT_TYPE_USER_BOOT {
        return Err(EventError::WrongType { expected: EVENT_TYPE_USER_BOOT, actual: blob[0] });
    }

    let created_at_ms = u64::from_le_bytes(blob[off::CREATED_AT..off::PUBLIC_KEY].try_into().unwrap());
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&blob[off::PUBLIC_KEY..off::USERNAME]);

    let username = read_text_slot(&blob[off::USERNAME..off::USERNAME + NAME_BYTES])
        .map_err(EventError::TextSlot)?;

    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[off::SIGNED_BY..off::SIGNER_TYPE]);
    let signer_type = blob[off::SIGNER_TYPE];
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[off::SIGNATURE..off::SIGNATURE + 64]);

    Ok(ParsedEvent::UserBoot(UserBootEvent {
        created_at_ms,
        public_key,
        username,
        signed_by,
        signer_type,
        signature,
    }))
}

pub fn encode_user_boot(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::UserBoot(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    let mut buf = vec![0u8; USER_WIRE_SIZE];
    buf[off::TYPE_CODE] = EVENT_TYPE_USER_BOOT;
    buf[off::CREATED_AT..off::PUBLIC_KEY].copy_from_slice(&e.created_at_ms.to_le_bytes());
    buf[off::PUBLIC_KEY..off::USERNAME].copy_from_slice(&e.public_key);
    write_text_slot(&e.username, &mut buf[off::USERNAME..off::USERNAME + NAME_BYTES])
        .map_err(EventError::TextSlot)?;
    buf[off::SIGNED_BY..off::SIGNER_TYPE].copy_from_slice(&e.signed_by);
    buf[off::SIGNER_TYPE] = e.signer_type;
    buf[off::SIGNATURE..off::SIGNATURE + 64].copy_from_slice(&e.signature);
    Ok(buf)
}

/// Wire format (202 bytes fixed):
/// [0]          type_code = 15
/// [1..9]       created_at_ms (u64 LE)
/// [9..41]      public_key (32 bytes)
/// [41..105]    username (64 bytes, UTF-8 zero-padded)
/// [105..137]   signed_by (32 bytes)
/// [137]        signer_type (1 byte)
/// [138..202]   signature (64 bytes)
pub fn parse_user_ongoing(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < USER_WIRE_SIZE {
        return Err(EventError::TooShort { expected: USER_WIRE_SIZE, actual: blob.len() });
    }
    if blob.len() > USER_WIRE_SIZE {
        return Err(EventError::TrailingData { expected: USER_WIRE_SIZE, actual: blob.len() });
    }
    if blob[0] != EVENT_TYPE_USER_ONGOING {
        return Err(EventError::WrongType { expected: EVENT_TYPE_USER_ONGOING, actual: blob[0] });
    }

    let created_at_ms = u64::from_le_bytes(blob[off::CREATED_AT..off::PUBLIC_KEY].try_into().unwrap());
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&blob[off::PUBLIC_KEY..off::USERNAME]);

    let username = read_text_slot(&blob[off::USERNAME..off::USERNAME + NAME_BYTES])
        .map_err(EventError::TextSlot)?;

    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[off::SIGNED_BY..off::SIGNER_TYPE]);
    let signer_type = blob[off::SIGNER_TYPE];
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[off::SIGNATURE..off::SIGNATURE + 64]);

    Ok(ParsedEvent::UserOngoing(UserOngoingEvent {
        created_at_ms,
        public_key,
        username,
        signed_by,
        signer_type,
        signature,
    }))
}

pub fn encode_user_ongoing(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::UserOngoing(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    let mut buf = vec![0u8; USER_WIRE_SIZE];
    buf[off::TYPE_CODE] = EVENT_TYPE_USER_ONGOING;
    buf[off::CREATED_AT..off::PUBLIC_KEY].copy_from_slice(&e.created_at_ms.to_le_bytes());
    buf[off::PUBLIC_KEY..off::USERNAME].copy_from_slice(&e.public_key);
    write_text_slot(&e.username, &mut buf[off::USERNAME..off::USERNAME + NAME_BYTES])
        .map_err(EventError::TextSlot)?;
    buf[off::SIGNED_BY..off::SIGNER_TYPE].copy_from_slice(&e.signed_by);
    buf[off::SIGNER_TYPE] = e.signer_type;
    buf[off::SIGNATURE..off::SIGNATURE + 64].copy_from_slice(&e.signature);
    Ok(buf)
}

// === Projector (event-module locality) ===

use crate::projection::result::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

/// Pure projector: User (Boot or Ongoing) → users table.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let (public_key, username) = match parsed {
        ParsedEvent::UserBoot(u) => (&u.public_key, &u.username),
        ParsedEvent::UserOngoing(u) => (&u.public_key, &u.username),
        _ => return ProjectorResult::reject("not a user event".to_string()),
    };

    let ops = vec![WriteOp::InsertOrIgnore {
        table: "users",
        columns: vec!["recorded_by", "event_id", "public_key", "username"],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Blob(public_key.to_vec()),
            SqlVal::Text(username.to_string()),
        ],
    }];
    ProjectorResult::valid(ops)
}

pub static USER_BOOT_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_USER_BOOT,
    type_name: "user_boot",
    projection_table: "users",
    share_scope: ShareScope::Shared,
    dep_fields: &["signed_by"],
    dep_field_type_codes: &[&[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: false,
    parse: parse_user_boot,
    encode: encode_user_boot,
    projector: project_pure,
};

pub static USER_ONGOING_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_USER_ONGOING,
    type_name: "user_ongoing",
    projection_table: "users",
    share_scope: ShareScope::Shared,
    dep_fields: &["signed_by"],
    dep_field_type_codes: &[&[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: false,
    parse: parse_user_ongoing,
    encode: encode_user_ongoing,
    projector: project_pure,
};

// === Query APIs (event-module locality) ===

use rusqlite::Connection;

pub struct UserRow {
    pub event_id: String,
    pub username: String,
}

pub fn list(
    db: &Connection,
    recorded_by: &str,
) -> Result<Vec<UserRow>, rusqlite::Error> {
    let mut stmt = db.prepare(
        "SELECT event_id, COALESCE(username, '') FROM users WHERE recorded_by = ?1"
    )?;
    let rows = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            Ok(UserRow {
                event_id: row.get(0)?,
                username: row.get(1)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub fn count(
    db: &Connection,
    recorded_by: &str,
) -> Result<i64, rusqlite::Error> {
    db.query_row(
        "SELECT COUNT(*) FROM users WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
        |row| row.get(0),
    )
}
