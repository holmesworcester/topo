use super::layout::common::{COMMON_HEADER_BYTES, SIGNATURE_TRAILER_BYTES};
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_MESSAGE_DELETION};

// ─── Layout (owned by this module) ───

/// MessageDeletion (type 7): type(1) + created_at(8) + target_event_id(32) + author_id(32)
///                          + signed_by(32) + signer_type(1) + signature(64) = 170
pub const MESSAGE_DELETION_WIRE_SIZE: usize = COMMON_HEADER_BYTES + 32 + 32 + SIGNATURE_TRAILER_BYTES;

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

// === Projector (event-module locality) ===

use crate::crypto::event_id_to_base64;
use crate::projection::decision::ProjectionDecision;
use crate::projection::result::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

/// Pure projector: MessageDeletion → two-stage deletion intent + tombstone model.
///
/// 1. Always emits an idempotent deletion_intent write keyed by (recorded_by, "message", target_id).
/// 2. If target exists in projected state (ctx.target_message_author is Some), verifies
///    author match and emits tombstone + cascade writes.
/// 3. If target doesn't exist yet (None), only records intent — the message projector
///    will tombstone on first materialization when it checks deletion_intents.
/// 4. If already tombstoned, verifies author and returns AlreadyProcessed.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let del = match parsed {
        ParsedEvent::MessageDeletion(d) => d,
        _ => return ProjectorResult::reject("not a message_deletion event".to_string()),
    };

    if let Some(reason) = &ctx.signer_user_mismatch_reason {
        return ProjectorResult::reject(reason.clone());
    }

    let target_b64 = event_id_to_base64(&del.target_event_id);
    let del_author_b64 = event_id_to_base64(&del.author_id);

    // Type validation: reject if target is a known non-message event.
    if ctx.target_is_non_message {
        return ProjectorResult::reject(
            "deletion target is a non-message event".to_string(),
        );
    }

    // Already tombstoned — verify author, return AlreadyProcessed
    if let Some(ref stored_author) = ctx.target_tombstone_author {
        if stored_author != &del_author_b64 {
            return ProjectorResult::reject(
                "deletion author does not match message author".to_string(),
            );
        }
        // Deletion intent should still be recorded for idempotence,
        // but it's a no-op if already exists.
        let ops = vec![
            WriteOp::InsertOrIgnore {
                table: "deletion_intents",
                columns: vec!["recorded_by", "target_kind", "target_id", "deletion_event_id", "author_id", "created_at"],
                values: vec![
                    SqlVal::Text(recorded_by.to_string()),
                    SqlVal::Text("message".to_string()),
                    SqlVal::Text(target_b64),
                    SqlVal::Text(event_id_b64.to_string()),
                    SqlVal::Text(del_author_b64),
                    SqlVal::Int(del.created_at_ms as i64),
                ],
            },
        ];
        return ProjectorResult {
            decision: ProjectionDecision::AlreadyProcessed,
            write_ops: ops,
            emit_commands: Vec::new(),
        };
    }

    // Always record deletion intent (idempotent via INSERT OR IGNORE)
    let mut ops = vec![
        WriteOp::InsertOrIgnore {
            table: "deletion_intents",
            columns: vec!["recorded_by", "target_kind", "target_id", "deletion_event_id", "author_id", "created_at"],
            values: vec![
                SqlVal::Text(recorded_by.to_string()),
                SqlVal::Text("message".to_string()),
                SqlVal::Text(target_b64.clone()),
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Text(del_author_b64.clone()),
                SqlVal::Int(del.created_at_ms as i64),
            ],
        },
    ];

    // Target exists — verify author, emit tombstone + cascade
    if let Some(ref msg_author) = ctx.target_message_author {
        if msg_author != &del_author_b64 {
            return ProjectorResult::reject(
                "deletion author does not match message author".to_string(),
            );
        }

        // Tombstone
        ops.push(WriteOp::InsertOrIgnore {
            table: "deleted_messages",
            columns: vec!["recorded_by", "message_id", "deletion_event_id", "author_id", "deleted_at"],
            values: vec![
                SqlVal::Text(recorded_by.to_string()),
                SqlVal::Text(target_b64.clone()),
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Text(del_author_b64),
                SqlVal::Int(del.created_at_ms as i64),
            ],
        });

        // Cascade: delete message and its reactions (explicit write ops, not hidden side effects)
        ops.push(WriteOp::Delete {
            table: "messages",
            where_clause: vec![
                ("recorded_by", SqlVal::Text(recorded_by.to_string())),
                ("message_id", SqlVal::Text(target_b64.clone())),
            ],
        });
        ops.push(WriteOp::Delete {
            table: "reactions",
            where_clause: vec![
                ("recorded_by", SqlVal::Text(recorded_by.to_string())),
                ("target_event_id", SqlVal::Text(target_b64)),
            ],
        });

        return ProjectorResult::valid(ops);
    }

    // Target doesn't exist yet — only record intent.
    // When the message arrives, message::project_pure will check deletion_intents
    // and tombstone immediately (delete-before-create convergence).
    ProjectorResult::valid(ops)
}

pub static MESSAGE_DELETION_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_MESSAGE_DELETION,
    type_name: "message_deletion",
    projection_table: "deleted_messages",
    share_scope: ShareScope::Shared,
    // Two-stage deletion intent model: do not dep-block on target or author.
    // The projector validates target/author from context and records intent first.
    dep_fields: &["signed_by"],
    dep_field_type_codes: &[&[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: true,
    parse: parse_message_deletion,
    encode: encode_message_deletion,
    projector: project_pure,
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

pub fn list_deleted_ids(
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

// --- Service-level command helper ---

/// High-level delete command: creates a message_deletion event and returns target hex.
pub fn delete_message(
    db: &Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
    created_at_ms: u64,
    author_id: [u8; 32],
    target_event_id: [u8; 32],
) -> Result<String, String> {
    create(
        db, recorded_by, signer_eid, signing_key, created_at_ms,
        CreateMessageDeletionCmd {
            target_event_id,
            author_id,
        },
    ).map_err(|e| format!("{}", e))?;

    Ok(hex::encode(target_event_id))
}
