use rusqlite::Connection;

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
