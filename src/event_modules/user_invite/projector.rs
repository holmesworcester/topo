use super::super::ParsedEvent;
use crate::projection::result::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use rusqlite::Connection;

/// Build projector-local context for UserInvite projection.
pub fn build_projector_context(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let mut ctx = ContextSnapshot::default();

    if matches!(parsed, ParsedEvent::UserInviteBoot(_)) {
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
            ctx.bootstrap_context = Some(crate::projection::result::BootstrapContextSnapshot {
                workspace_id: bc.workspace_id,
                bootstrap_addr: bc.bootstrap_addr,
                bootstrap_spki_fingerprint: bc.bootstrap_spki_fingerprint,
            });
        }
    }

    Ok(ctx)
}

/// Pure projector: UserInvite (Boot or Ongoing) → user_invites table.
/// When bootstrap_context is available (locally-created invite), this is a
/// Boot variant, it also writes a pending_invite_bootstrap_trust row.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let (public_key, created_at_ms, is_boot) = match parsed {
        ParsedEvent::UserInviteBoot(ui) => (&ui.public_key, ui.created_at_ms as i64, true),
        ParsedEvent::UserInviteOngoing(ui) => (&ui.public_key, ui.created_at_ms as i64, false),
        _ => return ProjectorResult::reject("not a user_invite event".to_string()),
    };

    let mut ops = vec![WriteOp::InsertOrIgnore {
        table: "user_invites",
        columns: vec!["recorded_by", "event_id", "public_key"],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Blob(public_key.to_vec()),
        ],
    }];

    if is_boot && ctx.is_local_create {
        if let Some(ref bc) = ctx.bootstrap_context {
            let expected_spki =
                crate::transport::cert::spki_fingerprint_from_ed25519_pubkey(public_key);
            ops.push(WriteOp::InsertOrIgnore {
                table: "pending_invite_bootstrap_trust",
                columns: vec![
                    "recorded_by",
                    "invite_event_id",
                    "workspace_id",
                    "expected_bootstrap_spki_fingerprint",
                    "created_at",
                    "expires_at",
                ],
                values: vec![
                    SqlVal::Text(recorded_by.to_string()),
                    SqlVal::Text(event_id_b64.to_string()),
                    SqlVal::Text(bc.workspace_id.clone()),
                    SqlVal::Blob(expected_spki.to_vec()),
                    SqlVal::Int(created_at_ms),
                    SqlVal::Int(
                        created_at_ms + crate::db::transport_trust::PENDING_INVITE_BOOTSTRAP_TTL_MS,
                    ),
                ],
            });
        }
    }

    ProjectorResult::valid(ops)
}
