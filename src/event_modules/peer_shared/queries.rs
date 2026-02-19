use rusqlite::Connection;

pub fn count(
    db: &Connection,
    recorded_by: &str,
) -> Result<i64, rusqlite::Error> {
    db.query_row(
        "SELECT COUNT(*) FROM peers_shared WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
        |row| row.get(0),
    )
}

/// List event_ids for all peer_shared rows.
pub fn list_event_ids(
    db: &Connection,
    recorded_by: &str,
) -> Result<Vec<String>, rusqlite::Error> {
    let mut stmt = db.prepare("SELECT event_id FROM peers_shared WHERE recorded_by = ?1")?;
    let rows = stmt
        .query_map(rusqlite::params![recorded_by], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Return the first peer_shared event_id, if any.
pub fn first_event_id(
    db: &Connection,
    recorded_by: &str,
) -> Result<Option<String>, rusqlite::Error> {
    use rusqlite::OptionalExtension;
    db.query_row(
        "SELECT event_id FROM peers_shared WHERE recorded_by = ?1 LIMIT 1",
        rusqlite::params![recorded_by],
        |row| row.get::<_, String>(0),
    )
    .optional()
}

pub struct AccountRow {
    pub event_id: String,
    pub device_name: String,
    pub user_event_id: String,
    pub username: String,
}

/// List peer accounts with joined username from users table.
pub fn list_accounts(
    db: &Connection,
    recorded_by: &str,
) -> Result<Vec<AccountRow>, rusqlite::Error> {
    let mut stmt = db.prepare(
        "SELECT ps.event_id, COALESCE(ps.device_name, ''), COALESCE(ps.user_event_id, ''),
                COALESCE(u.username, '')
         FROM peers_shared ps
         LEFT JOIN users u ON ps.user_event_id = u.event_id AND ps.recorded_by = u.recorded_by
         WHERE ps.recorded_by = ?1",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            Ok(AccountRow {
                event_id: row.get(0)?,
                device_name: row.get(1)?,
                user_event_id: row.get(2)?,
                username: row.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}
