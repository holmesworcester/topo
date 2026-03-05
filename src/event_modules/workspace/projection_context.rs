use crate::event_modules::ParsedEvent;
use crate::projection::contract::ContextSnapshot;
use rusqlite::Connection;

/// Build projector-local context for Workspace projection.
pub fn build_projector_context(
    db: &Connection,
    recorded_by: &str,
    _event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    if !matches!(parsed, ParsedEvent::Workspace(_)) {
        return Err("workspace context loader called for non-workspace event".into());
    }

    let accepted_workspace_id = match db.query_row(
        "SELECT workspace_id
         FROM invites_accepted
         WHERE recorded_by = ?1
         ORDER BY created_at ASC, event_id ASC
         LIMIT 1",
        rusqlite::params![recorded_by],
        |row| row.get::<_, String>(0),
    ) {
        Ok(v) => Some(v),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(e) => return Err(e.into()),
    };

    Ok(ContextSnapshot {
        accepted_workspace_id,
        ..ContextSnapshot::default()
    })
}
