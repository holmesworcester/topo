use rusqlite::Connection;

use serde::{Deserialize, Serialize};

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

#[derive(Debug, Serialize, Deserialize)]
pub struct ReactionItem {
    pub event_id: String,
    pub target_event_id: String,
    pub emoji: String,
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
