use super::super::ParsedEvent;
use crate::projection::contract::ContextSnapshot;
use rusqlite::Connection;

/// Build projector-local context for PeerShared projection.
pub fn build_projector_context(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let mut ctx = ContextSnapshot::default();
    if matches!(parsed, ParsedEvent::PeerShared(_)) {
        let has_local_signer: bool = conn.query_row(
            "SELECT EXISTS(
                 SELECT 1
                 FROM local_signer_material
                 WHERE recorded_by = ?1
                   AND signer_kind = 3
                   AND signer_event_id = ?2
                 LIMIT 1
             )",
            rusqlite::params![recorded_by, event_id_b64],
            |row| row.get(0),
        )?;
        ctx.peer_shared_has_local_signer_material = Some(has_local_signer);
    }
    Ok(ctx)
}
