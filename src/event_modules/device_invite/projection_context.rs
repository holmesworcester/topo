use super::super::ParsedEvent;
use crate::projection::contract::{BootstrapContextSnapshot, ContextSnapshot};
use rusqlite::Connection;

/// Build projector-local context for DeviceInvite projection.
pub fn build_projector_context(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let mut ctx = ContextSnapshot::default();

    if matches!(parsed, ParsedEvent::DeviceInviteFirst(_)) {
        ctx.is_local_create = match conn.query_row(
            "SELECT source FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, event_id_b64],
            |row| row.get::<_, String>(0),
        ) {
            Ok(source) => source == "local" || source == "local_create",
            Err(_) => false,
        };

        if let Some(bc) =
            crate::db::transport_trust::read_bootstrap_context(conn, recorded_by, event_id_b64)
                .map_err(|e| -> Box<dyn std::error::Error> { e })?
        {
            ctx.bootstrap_context = Some(BootstrapContextSnapshot {
                workspace_id: bc.workspace_id,
                bootstrap_addr: bc.bootstrap_addr,
                bootstrap_spki_fingerprint: bc.bootstrap_spki_fingerprint,
            });
        }
    }

    Ok(ctx)
}
