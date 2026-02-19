use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_MESSAGE_DELETION};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageDeletionEvent {
    pub created_at_ms: u64,
    pub target_event_id: [u8; 32], // message being deleted
    pub author_id: [u8; 32],       // must match message author (enables cross-device deletion)
    pub signed_by: [u8; 32],
    pub signer_type: u8,
    pub signature: [u8; 64],
}

/// Wire format (170 bytes fixed, signed):
/// [0]      type_code = 7
/// [1..9]   created_at_ms (u64 LE)
/// [9..41]  target_event_id (32 bytes)
/// [41..73] author_id (32 bytes)
/// --- signature trailer (97 bytes) ---
/// [73..105] signed_by (32 bytes)
/// [105]     signer_type (1 byte)
/// [106..170] signature (64 bytes)
pub fn parse_message_deletion(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < 170 {
        return Err(EventError::TooShort {
            expected: 170,
            actual: blob.len(),
        });
    }
    if blob.len() > 170 {
        return Err(EventError::TrailingData {
            expected: 170,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_MESSAGE_DELETION {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_MESSAGE_DELETION,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());

    let mut target_event_id = [0u8; 32];
    target_event_id.copy_from_slice(&blob[9..41]);

    let mut author_id = [0u8; 32];
    author_id.copy_from_slice(&blob[41..73]);

    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[73..105]);

    let signer_type = blob[105];

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[106..170]);

    Ok(ParsedEvent::MessageDeletion(MessageDeletionEvent {
        created_at_ms,
        target_event_id,
        author_id,
        signed_by,
        signer_type,
        signature,
    }))
}

pub fn encode_message_deletion(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let del = match event {
        ParsedEvent::MessageDeletion(d) => d,
        _ => return Err(EventError::WrongVariant),
    };

    let mut buf = Vec::with_capacity(170);
    buf.push(EVENT_TYPE_MESSAGE_DELETION);
    buf.extend_from_slice(&del.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&del.target_event_id);
    buf.extend_from_slice(&del.author_id);
    buf.extend_from_slice(&del.signed_by);
    buf.push(del.signer_type);
    buf.extend_from_slice(&del.signature);
    Ok(buf)
}

pub static MESSAGE_DELETION_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_MESSAGE_DELETION,
    type_name: "message_deletion",
    projection_table: "deleted_messages",
    share_scope: ShareScope::Shared,
    dep_fields: &["target_event_id", "author_id", "signed_by"],
    dep_field_type_codes: &[&[1], &[14, 15], &[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: true,
    parse: parse_message_deletion,
    encode: encode_message_deletion,
};

// === Command/Query APIs (event-module locality) ===

use crate::crypto::EventId;
use crate::projection::create::create_signed_event_sync;
use ed25519_dalek::SigningKey;
use rusqlite::Connection;

pub struct CreateMessageDeletionCmd {
    pub target_event_id: [u8; 32],
    pub author_id: [u8; 32],
}

pub fn create(
    db: &Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
    created_at_ms: u64,
    cmd: CreateMessageDeletionCmd,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let del = ParsedEvent::MessageDeletion(MessageDeletionEvent {
        created_at_ms,
        target_event_id: cmd.target_event_id,
        author_id: cmd.author_id,
        signed_by: *signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let eid = create_signed_event_sync(db, recorded_by, &del, signing_key)?;
    Ok(eid)
}

pub fn query_deleted_ids(
    db: &Connection,
    recorded_by: &str,
) -> Result<Vec<String>, rusqlite::Error> {
    let mut stmt = db.prepare(
        "SELECT message_id FROM deleted_messages WHERE recorded_by = ?1",
    )?;
    let ids = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ids)
}
