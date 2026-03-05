use super::super::ParsedEvent;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

/// Pure projector: UserInvite -> user_invites table.
/// When bootstrap_context is available and this event is locally created,
/// also write pending_invite_bootstrap_trust.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let (public_key, created_at_ms, signed_by, signer_type, workspace_id, authority_event_id) =
        match parsed {
            ParsedEvent::UserInvite(ui) => (
                &ui.public_key,
                ui.created_at_ms as i64,
                ui.signed_by,
                ui.signer_type,
                ui.workspace_id,
                ui.authority_event_id,
            ),
            _ => return ProjectorResult::reject("not a user_invite event".to_string()),
        };

    if signer_type == 1 {
        if signed_by != workspace_id || authority_event_id != workspace_id {
            return ProjectorResult::reject(
                "bootstrap user_invite must use workspace as signer and authority".to_string(),
            );
        }
    } else if signer_type == 5 {
        if ctx.invite_authority_matches_signer != Some(true) {
            return ProjectorResult::reject(
                "peer-signed user_invite authority does not match signer admin identity"
                    .to_string(),
            );
        }
    } else {
        return ProjectorResult::reject("unsupported user_invite signer_type".to_string());
    }

    let mut ops = vec![WriteOp::InsertOrIgnore {
        table: "user_invites",
        columns: vec!["recorded_by", "event_id", "public_key"],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Blob(public_key.to_vec()),
        ],
    }];

    if ctx.is_local_create {
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
