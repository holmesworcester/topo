use rusqlite::Connection;

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
