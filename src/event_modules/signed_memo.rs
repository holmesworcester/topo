use super::layout::common::{COMMON_HEADER_BYTES, read_text_slot, write_text_slot};
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_SIGNED_MEMO};

// ─── Layout (owned by this module) ───

/// SignedMemo content: fixed UTF-8 slot (1024 bytes, zero-padded)
pub const SIGNED_MEMO_CONTENT_BYTES: usize = 1024;

/// SignedMemo (type 4): type(1) + created_at(8) + signed_by(32) + signer_type(1)
///                    + content(1024) + signature(64) = 1130
pub const SIGNED_MEMO_WIRE_SIZE: usize =
    COMMON_HEADER_BYTES + 32 + 1 + SIGNED_MEMO_CONTENT_BYTES + 64;

pub mod signed_memo_offsets {
    pub const TYPE_CODE: usize = 0;
    pub const CREATED_AT: usize = 1;
    pub const SIGNED_BY: usize = 9;
    pub const SIGNER_TYPE: usize = 41;
    pub const CONTENT: usize = 42;
    pub const SIGNATURE: usize = 42 + super::SIGNED_MEMO_CONTENT_BYTES; // 1066
}

use signed_memo_offsets as off;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedMemoEvent {
    pub created_at_ms: u64,
    pub signed_by: [u8; 32],
    pub signer_type: u8,
    pub content: String,
    pub signature: [u8; 64],
}

/// Wire format (1130 bytes fixed, signed):
/// [0]            type_code = 4
/// [1..9]         created_at_ms (u64 LE)
/// [9..41]        signed_by (32 bytes)
/// [41]           signer_type (1 byte)
/// [42..1066]     content (1024 bytes, UTF-8 zero-padded)
/// [1066..1130]   signature (64 bytes)
pub fn parse_signed_memo(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < SIGNED_MEMO_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: SIGNED_MEMO_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > SIGNED_MEMO_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: SIGNED_MEMO_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_SIGNED_MEMO {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_SIGNED_MEMO,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[off::CREATED_AT..off::SIGNED_BY].try_into().unwrap());

    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[off::SIGNED_BY..off::SIGNER_TYPE]);

    let signer_type = blob[off::SIGNER_TYPE];

    let content = read_text_slot(&blob[off::CONTENT..off::CONTENT + SIGNED_MEMO_CONTENT_BYTES])
        .map_err(EventError::TextSlot)?;

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[off::SIGNATURE..off::SIGNATURE + 64]);

    Ok(ParsedEvent::SignedMemo(SignedMemoEvent {
        created_at_ms,
        signed_by,
        signer_type,
        content,
        signature,
    }))
}

pub fn encode_signed_memo(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let memo = match event {
        ParsedEvent::SignedMemo(m) => m,
        _ => return Err(EventError::WrongVariant),
    };

    let content_bytes = memo.content.as_bytes();
    if content_bytes.len() > SIGNED_MEMO_CONTENT_BYTES {
        return Err(EventError::ContentTooLong(content_bytes.len()));
    }

    let mut buf = vec![0u8; SIGNED_MEMO_WIRE_SIZE];

    buf[off::TYPE_CODE] = EVENT_TYPE_SIGNED_MEMO;
    buf[off::CREATED_AT..off::SIGNED_BY].copy_from_slice(&memo.created_at_ms.to_le_bytes());
    buf[off::SIGNED_BY..off::SIGNER_TYPE].copy_from_slice(&memo.signed_by);
    buf[off::SIGNER_TYPE] = memo.signer_type;
    write_text_slot(&memo.content, &mut buf[off::CONTENT..off::CONTENT + SIGNED_MEMO_CONTENT_BYTES])
        .map_err(EventError::TextSlot)?;
    buf[off::SIGNATURE..off::SIGNATURE + 64].copy_from_slice(&memo.signature);

    Ok(buf)
}

// === Projector (event-module locality) ===

use crate::crypto::event_id_to_base64;
use crate::projection::result::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS signed_memos (
            event_id TEXT NOT NULL,
            signed_by TEXT NOT NULL,
            signer_type INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            recorded_by TEXT NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        ",
    )?;
    Ok(())
}

/// Pure projector: SignedMemo → signed_memos table insert.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let memo = match parsed {
        ParsedEvent::SignedMemo(m) => m,
        _ => return ProjectorResult::reject("not a signed_memo event".to_string()),
    };

    let signed_by_b64 = event_id_to_base64(&memo.signed_by);
    let ops = vec![
        WriteOp::InsertOrIgnore {
            table: "signed_memos",
            columns: vec!["event_id", "signed_by", "signer_type", "content", "created_at", "recorded_by"],
            values: vec![
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Text(signed_by_b64),
                SqlVal::Int(memo.signer_type as i64),
                SqlVal::Text(memo.content.clone()),
                SqlVal::Int(memo.created_at_ms as i64),
                SqlVal::Text(recorded_by.to_string()),
            ],
        },
    ];
    ProjectorResult::valid(ops)
}

pub static SIGNED_MEMO_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_SIGNED_MEMO,
    type_name: "signed_memo",
    projection_table: "signed_memos",
    share_scope: ShareScope::Shared,
    dep_fields: &["signed_by"],
    dep_field_type_codes: &[&[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: true,
    parse: parse_signed_memo,
    encode: encode_signed_memo,
    projector: project_pure,
};

#[cfg(test)]
mod layout_tests {
    use super::*;
    #[test]
    fn offsets_consistent() {
        assert_eq!(signed_memo_offsets::SIGNATURE + 64, SIGNED_MEMO_WIRE_SIZE);
    }
}
