use rusqlite::Connection;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct UserItem {
    pub event_id: String,
    pub username: String,
}

/// List user items (response type) from the database.
pub fn list_items(
    db: &Connection,
    recorded_by: &str,
) -> Result<Vec<UserItem>, rusqlite::Error> {
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

/// Return the first user event_id, if any.
pub fn first_event_id(
    db: &Connection,
    recorded_by: &str,
) -> Result<Option<String>, rusqlite::Error> {
    use rusqlite::OptionalExtension;
    db.query_row(
        "SELECT event_id FROM users WHERE recorded_by = ?1 LIMIT 1",
        rusqlite::params![recorded_by],
        |row| row.get::<_, String>(0),
    )
    .optional()
}
