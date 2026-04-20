use crate::crypto::{event_id_from_base64, event_id_from_hex, EventId};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct UserItem {
    pub event_id: String,
    pub username: String,
}

/// List user items (response type) from the database.
pub fn list_items(db: &Connection, recorded_by: &str) -> Result<Vec<UserItem>, rusqlite::Error> {
    let rows = list(db, recorded_by)?;
    Ok(rows
        .into_iter()
        .map(|row| UserItem {
            event_id: row.event_id,
            username: row.username,
        })
        .collect())
}

pub struct UserRow {
    pub event_id: String,
    pub username: String,
}

pub fn list(db: &Connection, recorded_by: &str) -> Result<Vec<UserRow>, rusqlite::Error> {
    let mut stmt = db.prepare(
        "SELECT event_id, COALESCE(username, '')
         FROM users
         WHERE recorded_by = ?1
         ORDER BY event_id ASC",
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

pub fn count(db: &Connection, recorded_by: &str) -> Result<i64, rusqlite::Error> {
    db.query_row(
        "SELECT COUNT(*) FROM users WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
        |row| row.get(0),
    )
}

/// Return the first user event_id, if any.
pub fn first_event_id(
    db: &Connection,
    recorded_by: &str,
) -> Result<Option<String>, rusqlite::Error> {
    use rusqlite::OptionalExtension;
    db.query_row(
        "SELECT event_id FROM users WHERE recorded_by = ?1 LIMIT 1",
        rusqlite::params![recorded_by],
        |row| crate::db::sql_types::get_text(row, 0),
    )
    .optional()
}

pub fn resolve_number(db: &Connection, recorded_by: &str, num: usize) -> Result<EventId, String> {
    if num == 0 {
        return Err("user number must be >= 1".into());
    }
    let rows = list(db, recorded_by).map_err(|e| e.to_string())?;
    let Some(row) = rows.get(num - 1) else {
        return Err(format!(
            "invalid user number {}; available: 1-{}",
            num,
            rows.len()
        ));
    };
    event_id_from_base64(&row.event_id)
        .ok_or_else(|| format!("invalid event ID for user {}", num))
}

pub fn resolve(db: &Connection, recorded_by: &str, selector: &str) -> Result<EventId, String> {
    let stripped = selector.strip_prefix('#').unwrap_or(selector);
    if let Ok(num) = stripped.parse::<usize>() {
        return resolve_number(db, recorded_by, num);
    }
    if let Some(event_id) = event_id_from_base64(selector) {
        return Ok(event_id);
    }
    event_id_from_hex(selector).ok_or_else(|| format!("invalid user selector: {}", selector))
}
