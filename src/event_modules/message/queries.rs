use crate::crypto::{self, EventId, b64_to_hex, event_id_from_base64};
use rusqlite::Connection;

pub struct MessageRow {
    pub message_id_b64: String,
    pub message_id_hex: String,
    pub author_id: String,
    pub author_name: String,
    pub content: String,
    pub created_at: i64,
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

pub fn count(
    db: &Connection,
    recorded_by: &str,
) -> Result<i64, rusqlite::Error> {
    db.query_row(
        "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
        |row| row.get(0),
    )
}

pub fn resolve_number(
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

pub fn resolve(
    db: &Connection,
    recorded_by: &str,
    selector: &str,
) -> Result<EventId, String> {
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
