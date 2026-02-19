use super::fixed_layout::{self, REACTION_WIRE_SIZE, REACTION_EMOJI_BYTES, reaction_offsets as off};
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_REACTION};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactionEvent {
    pub created_at_ms: u64,
    pub target_event_id: [u8; 32],
    pub author_id: [u8; 32],
    pub emoji: String,
    pub signed_by: [u8; 32],
    pub signer_type: u8,
    pub signature: [u8; 64],
}

/// Wire format (234 bytes fixed, signed):
/// [0]            type=2
/// [1..9]         created_at_ms (u64 LE)
/// [9..41]        target_event_id (32 bytes)
/// [41..73]       author_id (32 bytes)
/// [73..137]      emoji (64 bytes, UTF-8 zero-padded)
/// [137..169]     signed_by (32 bytes)
/// [169]          signer_type (1 byte)
/// [170..234]     signature (64 bytes)
pub fn parse_reaction(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < REACTION_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: REACTION_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > REACTION_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: REACTION_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_REACTION {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_REACTION,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[off::CREATED_AT..off::TARGET_EVENT_ID].try_into().unwrap());

    let mut target_event_id = [0u8; 32];
    target_event_id.copy_from_slice(&blob[off::TARGET_EVENT_ID..off::AUTHOR_ID]);

    let mut author_id = [0u8; 32];
    author_id.copy_from_slice(&blob[off::AUTHOR_ID..off::EMOJI]);

    let emoji = fixed_layout::read_text_slot(&blob[off::EMOJI..off::EMOJI + REACTION_EMOJI_BYTES])
        .map_err(EventError::TextSlot)?;

    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[off::SIGNED_BY..off::SIGNER_TYPE]);

    let signer_type = blob[off::SIGNER_TYPE];

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[off::SIGNATURE..off::SIGNATURE + 64]);

    Ok(ParsedEvent::Reaction(ReactionEvent {
        created_at_ms,
        target_event_id,
        author_id,
        emoji,
        signed_by,
        signer_type,
        signature,
    }))
}

pub fn encode_reaction(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let rxn = match event {
        ParsedEvent::Reaction(r) => r,
        _ => return Err(EventError::WrongVariant),
    };

    let emoji_bytes = rxn.emoji.as_bytes();
    if emoji_bytes.len() > REACTION_EMOJI_BYTES {
        return Err(EventError::ContentTooLong(emoji_bytes.len()));
    }

    let mut buf = vec![0u8; REACTION_WIRE_SIZE];

    buf[off::TYPE_CODE] = EVENT_TYPE_REACTION;
    buf[off::CREATED_AT..off::TARGET_EVENT_ID].copy_from_slice(&rxn.created_at_ms.to_le_bytes());
    buf[off::TARGET_EVENT_ID..off::AUTHOR_ID].copy_from_slice(&rxn.target_event_id);
    buf[off::AUTHOR_ID..off::EMOJI].copy_from_slice(&rxn.author_id);
    fixed_layout::write_text_slot(&rxn.emoji, &mut buf[off::EMOJI..off::EMOJI + REACTION_EMOJI_BYTES])
        .map_err(EventError::TextSlot)?;
    buf[off::SIGNED_BY..off::SIGNER_TYPE].copy_from_slice(&rxn.signed_by);
    buf[off::SIGNER_TYPE] = rxn.signer_type;
    buf[off::SIGNATURE..off::SIGNATURE + 64].copy_from_slice(&rxn.signature);

    Ok(buf)
}

// === Projector (event-module locality) ===

use crate::crypto::event_id_to_base64;
use crate::projection::result::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

/// Pure projector: Reaction → reactions table insert.
///
/// If the target message has been deleted, the
/// reaction is structurally valid but no row is written.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let rxn = match parsed {
        ParsedEvent::Reaction(r) => r,
        _ => return ProjectorResult::reject("not a reaction event".to_string()),
    };

    if let Some(reason) = &ctx.signer_user_mismatch_reason {
        return ProjectorResult::reject(reason.clone());
    }

    let target_id_b64 = event_id_to_base64(&rxn.target_event_id);

    // Check deletion state — skip if target is tombstoned or has deletion intent
    if ctx.target_message_deleted {
        return ProjectorResult::valid(vec![]); // valid event, no row written
    }

    let author_id_b64 = event_id_to_base64(&rxn.author_id);
    let ops = vec![
        WriteOp::InsertOrIgnore {
            table: "reactions",
            columns: vec!["event_id", "target_event_id", "author_id", "emoji", "created_at", "recorded_by"],
            values: vec![
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Text(target_id_b64),
                SqlVal::Text(author_id_b64),
                SqlVal::Text(rxn.emoji.clone()),
                SqlVal::Int(rxn.created_at_ms as i64),
                SqlVal::Text(recorded_by.to_string()),
            ],
        },
    ];
    ProjectorResult::valid(ops)
}

pub static REACTION_TYPE_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_REACTION,
    type_name: "reaction",
    projection_table: "reactions",
    share_scope: ShareScope::Shared,
    dep_fields: &["target_event_id", "author_id", "signed_by"],
    dep_field_type_codes: &[&[1], &[14, 15], &[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: true,
    parse: parse_reaction,
    encode: encode_reaction,
    projector: project_pure,
};

// === Command/Query APIs (event-module locality) ===

use crate::crypto::EventId;
use crate::projection::create::create_signed_event_sync;
use ed25519_dalek::SigningKey;
use rusqlite::Connection;

pub struct CreateReactionCmd {
    pub target_event_id: [u8; 32],
    pub author_id: [u8; 32],
    pub emoji: String,
}

pub fn create(
    db: &Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
    created_at_ms: u64,
    cmd: CreateReactionCmd,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let rxn = ParsedEvent::Reaction(ReactionEvent {
        created_at_ms,
        target_event_id: cmd.target_event_id,
        author_id: cmd.author_id,
        emoji: cmd.emoji,
        signed_by: *signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let eid = create_signed_event_sync(db, recorded_by, &rxn, signing_key)?;
    Ok(eid)
}

pub struct ReactionRow {
    pub event_id: String,
    pub target_event_id: String,
    pub emoji: String,
}

pub fn list_rows(
    db: &Connection,
    recorded_by: &str,
) -> Result<Vec<ReactionRow>, rusqlite::Error> {
    let mut stmt = db
        .prepare("SELECT event_id, target_event_id, emoji FROM reactions WHERE recorded_by = ?1")?;
    let rows = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            Ok(ReactionRow {
                event_id: row.get(0)?,
                target_event_id: row.get(1)?,
                emoji: row.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub fn list_for_message(
    db: &Connection,
    recorded_by: &str,
    target_event_id_b64: &str,
) -> Result<Vec<String>, rusqlite::Error> {
    let mut stmt = db.prepare(
        "SELECT emoji FROM reactions WHERE recorded_by = ?1 AND target_event_id = ?2",
    )?;
    let emojis = stmt
        .query_map(rusqlite::params![recorded_by, target_event_id_b64], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(emojis)
}

pub fn count(
    db: &Connection,
    recorded_by: &str,
) -> Result<i64, rusqlite::Error> {
    db.query_row(
        "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
        |row| row.get(0),
    )
}

// --- Response types and service-level query/command helpers ---

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ReactResponse {
    pub emoji: String,
    pub event_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReactionItem {
    pub event_id: String,
    pub target_event_id: String,
    pub emoji: String,
}

/// High-level react command: creates a reaction event and returns a ReactResponse.
pub fn react(
    db: &Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
    created_at_ms: u64,
    author_id: [u8; 32],
    target_event_id: [u8; 32],
    emoji: &str,
) -> Result<ReactResponse, String> {
    let eid = create(
        db, recorded_by, signer_eid, signing_key, created_at_ms,
        CreateReactionCmd {
            target_event_id,
            author_id,
            emoji: emoji.to_string(),
        },
    ).map_err(|e| format!("{}", e))?;

    Ok(ReactResponse {
        emoji: emoji.to_string(),
        event_id: hex::encode(eid),
    })
}

/// Assemble a list of ReactionItems from the database.
pub fn list(
    db: &Connection,
    recorded_by: &str,
) -> Result<Vec<ReactionItem>, rusqlite::Error> {
    let rows = list_rows(db, recorded_by)?;
    Ok(rows
        .into_iter()
        .map(|row| ReactionItem {
            event_id: row.event_id,
            target_event_id: row.target_event_id,
            emoji: row.emoji,
        })
        .collect())
}
