use super::fixed_layout::{self, MESSAGE_WIRE_SIZE, MESSAGE_CONTENT_BYTES, message_offsets as off};
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_MESSAGE};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageEvent {
    pub created_at_ms: u64,
    pub workspace_id: [u8; 32],
    pub author_id: [u8; 32],
    pub content: String,
    pub signed_by: [u8; 32],
    pub signer_type: u8,
    pub signature: [u8; 64],
}

/// Wire format (1194 bytes fixed, signed):
/// [0]            type=1
/// [1..9]         created_at_ms (u64 LE)
/// [9..41]        workspace_id (32 bytes)
/// [41..73]       author_id (32 bytes)
/// [73..1097]     content (1024 bytes, UTF-8 zero-padded)
/// [1097..1129]   signed_by (32 bytes)
/// [1129]         signer_type (1 byte)
/// [1130..1194]   signature (64 bytes)
pub fn parse_message(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < MESSAGE_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: MESSAGE_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > MESSAGE_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: MESSAGE_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_MESSAGE {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_MESSAGE,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[off::CREATED_AT..off::WORKSPACE_ID].try_into().unwrap());

    let mut workspace_id = [0u8; 32];
    workspace_id.copy_from_slice(&blob[off::WORKSPACE_ID..off::AUTHOR_ID]);

    let mut author_id = [0u8; 32];
    author_id.copy_from_slice(&blob[off::AUTHOR_ID..off::CONTENT]);

    let content = fixed_layout::read_text_slot(&blob[off::CONTENT..off::CONTENT + MESSAGE_CONTENT_BYTES])
        .map_err(EventError::TextSlot)?;

    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[off::SIGNED_BY..off::SIGNER_TYPE]);

    let signer_type = blob[off::SIGNER_TYPE];

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[off::SIGNATURE..off::SIGNATURE + 64]);

    Ok(ParsedEvent::Message(MessageEvent {
        created_at_ms,
        workspace_id,
        author_id,
        content,
        signed_by,
        signer_type,
        signature,
    }))
}

pub fn encode_message(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let msg = match event {
        ParsedEvent::Message(m) => m,
        _ => return Err(EventError::WrongVariant),
    };

    let content_bytes = msg.content.as_bytes();
    if content_bytes.len() > MESSAGE_CONTENT_BYTES {
        return Err(EventError::ContentTooLong(content_bytes.len()));
    }

    let mut buf = vec![0u8; MESSAGE_WIRE_SIZE];

    buf[off::TYPE_CODE] = EVENT_TYPE_MESSAGE;
    buf[off::CREATED_AT..off::WORKSPACE_ID].copy_from_slice(&msg.created_at_ms.to_le_bytes());
    buf[off::WORKSPACE_ID..off::AUTHOR_ID].copy_from_slice(&msg.workspace_id);
    buf[off::AUTHOR_ID..off::CONTENT].copy_from_slice(&msg.author_id);
    fixed_layout::write_text_slot(&msg.content, &mut buf[off::CONTENT..off::CONTENT + MESSAGE_CONTENT_BYTES])
        .map_err(EventError::TextSlot)?;
    buf[off::SIGNED_BY..off::SIGNER_TYPE].copy_from_slice(&msg.signed_by);
    buf[off::SIGNER_TYPE] = msg.signer_type;
    buf[off::SIGNATURE..off::SIGNATURE + 64].copy_from_slice(&msg.signature);

    Ok(buf)
}

// === Projector (event-module locality) ===

use crate::crypto::event_id_to_base64;
use crate::projection::result::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

/// Pure projector: Message → messages table insert.
///
/// Also checks the context snapshot for a matching deletion_intent — if the
/// message target already has a deletion intent recorded, the message is
/// projected as tombstoned on first materialization (deletion-before-create
/// convergence).
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let msg = match parsed {
        ParsedEvent::Message(m) => m,
        _ => return ProjectorResult::reject("not a message event".to_string()),
    };

    if let Some(reason) = &ctx.signer_user_mismatch_reason {
        return ProjectorResult::reject(reason.clone());
    }

    let workspace_id_b64 = event_id_to_base64(&msg.workspace_id);
    let author_id_b64 = event_id_to_base64(&msg.author_id);

    // Check for pre-existing deletion intents (delete-before-create convergence).
    // Multiple intents may exist (different deletion events targeting this message).
    // Find the first one whose author matches the message author.
    if let Some(intent) = ctx.deletion_intents.iter().find(|i| i.author_id == author_id_b64) {
        // Message was already targeted for deletion before it arrived.
        // Record the tombstone immediately using the original deletion event ID
        // for replay invariance — the same tombstone row results regardless of
        // whether delete or create arrives first.
        let ops = vec![
            WriteOp::InsertOrIgnore {
                table: "deleted_messages",
                columns: vec!["recorded_by", "message_id", "deletion_event_id", "author_id", "deleted_at"],
                values: vec![
                    SqlVal::Text(recorded_by.to_string()),
                    SqlVal::Text(event_id_b64.to_string()),
                    SqlVal::Text(intent.deletion_event_id.clone()),
                    SqlVal::Text(intent.author_id.clone()),
                    SqlVal::Int(intent.created_at),
                ],
            },
        ];
        // Structurally valid (the event itself is fine), but tombstoned.
        return ProjectorResult::valid(ops);
    }
    // No matching-author intent found — materialize the message normally.
    // Any wrong-author intents are stale and ignored.

    let ops = vec![
        WriteOp::InsertOrIgnore {
            table: "messages",
            columns: vec!["message_id", "workspace_id", "author_id", "content", "created_at", "recorded_by"],
            values: vec![
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Text(workspace_id_b64),
                SqlVal::Text(author_id_b64),
                SqlVal::Text(msg.content.clone()),
                SqlVal::Int(msg.created_at_ms as i64),
                SqlVal::Text(recorded_by.to_string()),
            ],
        },
    ];
    ProjectorResult::valid(ops)
}

pub static MESSAGE_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_MESSAGE,
    type_name: "message",
    projection_table: "messages",
    share_scope: ShareScope::Shared,
    dep_fields: &["author_id", "signed_by"],
    dep_field_type_codes: &[&[14, 15], &[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: true,
    parse: parse_message,
    encode: encode_message,
    projector: project_pure,
};

// === Command/Query APIs (event-module locality) ===

use crate::crypto::{self, EventId, b64_to_hex, event_id_from_base64};
use crate::projection::create::create_signed_event_sync;
use ed25519_dalek::SigningKey;
use rusqlite::Connection;

pub struct CreateMessageCmd {
    pub workspace_id: [u8; 32],
    pub author_id: [u8; 32],
    pub content: String,
}

pub fn create(
    db: &Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
    created_at_ms: u64,
    cmd: CreateMessageCmd,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let msg = ParsedEvent::Message(MessageEvent {
        created_at_ms,
        workspace_id: cmd.workspace_id,
        author_id: cmd.author_id,
        content: cmd.content,
        signed_by: *signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let eid = create_signed_event_sync(db, recorded_by, &msg, signing_key)?;
    Ok(eid)
}

pub struct MessageRow {
    pub message_id_b64: String,
    pub message_id_hex: String,
    pub author_id: String,
    pub author_name: String,
    pub content: String,
    pub created_at: i64,
}

pub fn query_list(
    db: &Connection,
    recorded_by: &str,
    limit: usize,
) -> Result<Vec<MessageRow>, rusqlite::Error> {
    let limit_clause = if limit > 0 {
        format!("LIMIT {}", limit)
    } else {
        String::new()
    };

    let query = format!(
        "SELECT m.message_id, m.author_id, m.content, m.created_at,
                COALESCE(u.username, '') as author_name
         FROM messages m
         LEFT JOIN users u ON m.author_id = u.event_id AND m.recorded_by = u.recorded_by
         WHERE m.recorded_by = ?1
         ORDER BY m.created_at ASC, m.rowid ASC {}",
        limit_clause
    );

    let mut stmt = db.prepare(&query)?;
    let rows = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            let msg_id_b64: String = row.get(0)?;
            let msg_id_hex = b64_to_hex(&msg_id_b64);
            Ok(MessageRow {
                message_id_b64: msg_id_b64,
                message_id_hex: msg_id_hex,
                author_id: row.get(1)?,
                content: row.get(2)?,
                created_at: row.get(3)?,
                author_name: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub fn query_count(
    db: &Connection,
    recorded_by: &str,
) -> Result<i64, rusqlite::Error> {
    db.query_row(
        "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
        |row| row.get(0),
    )
}

pub fn resolve_by_number(
    db: &Connection,
    recorded_by: &str,
    num: usize,
) -> Result<EventId, String> {
    if num == 0 {
        return Err("message number must be >= 1".into());
    }
    let mut stmt = db.prepare(
        "SELECT message_id FROM messages WHERE recorded_by = ?1 ORDER BY created_at ASC, rowid ASC LIMIT 1 OFFSET ?2"
    ).map_err(|e| e.to_string())?;
    let msg_id_b64: Option<String> = stmt
        .query_row(rusqlite::params![recorded_by, num - 1], |row| row.get(0))
        .ok();
    match msg_id_b64 {
        Some(b64) => {
            event_id_from_base64(&b64)
                .ok_or_else(|| format!("invalid event ID for message {}", num))
        }
        None => {
            let total: i64 = db.query_row(
                "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
                rusqlite::params![recorded_by],
                |row| row.get(0),
            ).map_err(|e| e.to_string())?;
            Err(format!(
                "invalid message number {}; available: 1-{}",
                num, total
            ))
        }
    }
}

pub fn resolve_selector(
    db: &Connection,
    recorded_by: &str,
    selector: &str,
) -> Result<EventId, String> {
    let stripped = selector.strip_prefix('#').unwrap_or(selector);
    if let Ok(num) = stripped.parse::<usize>() {
        resolve_by_number(db, recorded_by, num)
    } else {
        crypto::event_id_from_hex(selector)
            .ok_or_else(|| format!("invalid hex event ID: {}", selector))
    }
}
