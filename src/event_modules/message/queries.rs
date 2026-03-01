use crate::crypto::{self, b64_to_hex, event_id_from_base64, event_id_to_base64, EventId};
use crate::event_modules::ParsedEvent;
use crate::projection::result::{ContextSnapshot, DeletionIntentInfo};
use rusqlite::Connection;

pub struct MessageRow {
    pub message_id_b64: String,
    pub message_id_hex: String,
    pub author_id: String,
    pub author_name: String,
    pub content: String,
    pub created_at: i64,
}

fn signer_user_mismatch_reason(
    conn: &Connection,
    recorded_by: &str,
    signed_by: &[u8; 32],
    author_id: &[u8; 32],
) -> Result<Option<String>, rusqlite::Error> {
    let signed_by_b64 = event_id_to_base64(signed_by);
    let author_id_b64 = event_id_to_base64(author_id);

    let peer_user_eid: String = match conn.query_row(
        "SELECT COALESCE(user_event_id, '') FROM peers_shared WHERE recorded_by = ?1 AND event_id = ?2",
        rusqlite::params![recorded_by, &signed_by_b64],
        |row| row.get::<_, String>(0),
    ) {
        Ok(v) => v,
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            return Ok(Some(format!(
                "no peers_shared entry for signer {}",
                signed_by_b64
            )));
        }
        Err(e) => return Err(e),
    };

    if peer_user_eid.is_empty() {
        return Ok(Some(format!(
            "peers_shared entry for signer {} has no user_event_id (legacy row)",
            signed_by_b64
        )));
    }

    if peer_user_eid != author_id_b64 {
        return Ok(Some(format!(
            "signer {} belongs to user {} but author_id claims {}",
            signed_by_b64, peer_user_eid, author_id_b64
        )));
    }

    Ok(None)
}

/// Build projector-local context for Message projection.
pub fn build_projector_context(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let msg = match parsed {
        ParsedEvent::Message(msg) => msg,
        _ => return Err("message context loader called for non-message event".into()),
    };

    let signer_user_mismatch_reason =
        signer_user_mismatch_reason(conn, recorded_by, &msg.signed_by, &msg.author_id)?;

    let mut stmt = conn.prepare_cached(
        "SELECT deletion_event_id, author_id, created_at
         FROM deletion_intents
         WHERE recorded_by = ?1
           AND target_kind = 'message'
           AND target_id = ?2
         ORDER BY deletion_event_id",
    )?;
    let deletion_intents = stmt
        .query_map(rusqlite::params![recorded_by, event_id_b64], |row| {
            Ok(DeletionIntentInfo {
                deletion_event_id: row.get(0)?,
                author_id: row.get(1)?,
                created_at: row.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ContextSnapshot {
        signer_user_mismatch_reason,
        deletion_intents,
        ..ContextSnapshot::default()
    })
}

pub fn list_rows(
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

pub fn count(db: &Connection, recorded_by: &str) -> Result<i64, rusqlite::Error> {
    db.query_row(
        "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
        |row| row.get(0),
    )
}

pub fn resolve_number(db: &Connection, recorded_by: &str, num: usize) -> Result<EventId, String> {
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
        Some(b64) => event_id_from_base64(&b64)
            .ok_or_else(|| format!("invalid event ID for message {}", num)),
        None => {
            let total: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
                    rusqlite::params![recorded_by],
                    |row| row.get(0),
                )
                .map_err(|e| e.to_string())?;
            Err(format!(
                "invalid message number {}; available: 1-{}",
                num, total
            ))
        }
    }
}

pub fn resolve(db: &Connection, recorded_by: &str, selector: &str) -> Result<EventId, String> {
    let stripped = selector.strip_prefix('#').unwrap_or(selector);
    if let Ok(num) = stripped.parse::<usize>() {
        resolve_number(db, recorded_by, num)
    } else {
        crypto::event_id_from_hex(selector)
            .ok_or_else(|| format!("invalid hex event ID: {}", selector))
    }
}

/// Assemble a MessagesResponse from the database.
pub fn list(
    db: &Connection,
    recorded_by: &str,
    limit: usize,
) -> Result<super::MessagesResponse, rusqlite::Error> {
    let rows = list_rows(db, recorded_by, limit)?;
    let total = count(db, recorded_by)?;

    let messages = rows
        .into_iter()
        .map(|row| super::MessageItem {
            id: row.message_id_hex,
            id_b64: row.message_id_b64,
            author_id: row.author_id,
            author_name: row.author_name,
            content: row.content,
            created_at: row.created_at,
        })
        .collect();

    Ok(super::MessagesResponse { messages, total })
}

// ---------------------------------------------------------------------------
// Message deletion queries (moved from message_deletion/queries.rs)
// ---------------------------------------------------------------------------

pub fn list_deleted_ids(
    db: &Connection,
    recorded_by: &str,
) -> Result<Vec<String>, rusqlite::Error> {
    let mut stmt = db.prepare("SELECT message_id FROM deleted_messages WHERE recorded_by = ?1")?;
    let ids = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ids)
}
