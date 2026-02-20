use rusqlite::Connection;

pub struct WorkspaceRow {
    pub event_id: String,
    pub workspace_id: String,
}

pub fn list(
    db: &Connection,
    recorded_by: &str,
) -> Result<Vec<WorkspaceRow>, rusqlite::Error> {
    let mut stmt =
        db.prepare("SELECT event_id, workspace_id FROM workspaces WHERE recorded_by = ?1")?;
    let rows = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            Ok(WorkspaceRow {
                event_id: row.get(0)?,
                workspace_id: row.get(1)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Return the workspace display name for the first workspace, or empty string.
pub fn name(
    db: &Connection,
    recorded_by: &str,
) -> Result<String, rusqlite::Error> {
    use rusqlite::OptionalExtension;
    Ok(db
        .query_row(
            "SELECT COALESCE(name, '') FROM workspaces WHERE recorded_by = ?1 LIMIT 1",
            rusqlite::params![recorded_by],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .unwrap_or_default())
}
