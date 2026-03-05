use super::super::ParsedEvent;
use crate::crypto::event_id_to_base64;
use crate::projection::contract::{BootstrapContextSnapshot, ContextSnapshot};
use rusqlite::Connection;

/// Build projector-local context for UserInvite projection.
pub fn build_projector_context(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let mut ctx = ContextSnapshot::default();

    if let ParsedEvent::UserInvite(ui) = parsed {
        ctx.is_local_create = match conn.query_row(
            "SELECT source FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, event_id_b64],
            |row| row.get::<_, String>(0),
        ) {
            Ok(source) => source == "local" || source == "local_create",
            Err(_) => false,
        };

        if ui.signer_type == 5 {
            let signer_b64 = event_id_to_base64(&ui.signed_by);
            let authority_b64 = event_id_to_base64(&ui.authority_event_id);
            let authority_matches_signer: bool = conn.query_row(
                "SELECT EXISTS(
                     SELECT 1
                     FROM peers_shared ps
                     JOIN users u
                       ON u.recorded_by = ps.recorded_by
                      AND u.event_id = ps.user_event_id
                     JOIN admins a
                       ON a.recorded_by = u.recorded_by
                      AND a.public_key = u.public_key
                     WHERE ps.recorded_by = ?1
                       AND ps.event_id = ?2
                       AND a.event_id = ?3
                 )",
                rusqlite::params![recorded_by, signer_b64, authority_b64],
                |row| row.get(0),
            )?;
            ctx.invite_authority_matches_signer = Some(authority_matches_signer);
        }

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
