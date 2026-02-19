use super::super::ParsedEvent;
use crate::projection::result::{ContextSnapshot, EmitCommand, ProjectorResult, SqlVal, WriteOp};

/// Pure projector: DeviceInvite (First or Ongoing) → device_invites table.
/// When bootstrap_context is available (locally-created invite) and this is a
/// First variant, emits WritePendingBootstrapTrust for the device link invite.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let public_key = match parsed {
        ParsedEvent::DeviceInviteFirst(di) => &di.public_key,
        ParsedEvent::DeviceInviteOngoing(di) => &di.public_key,
        _ => return ProjectorResult::reject("not a device_invite event".to_string()),
    };

    let ops = vec![WriteOp::InsertOrIgnore {
        table: "device_invites",
        columns: vec!["recorded_by", "event_id", "public_key"],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Blob(public_key.to_vec()),
        ],
    }];

    let mut commands = Vec::new();
    if matches!(parsed, ParsedEvent::DeviceInviteFirst(_)) && ctx.is_local_create {
        if let Some(ref bc) = ctx.bootstrap_context {
            let expected_spki = crate::transport::cert::spki_fingerprint_from_ed25519_pubkey(public_key);
            commands.push(EmitCommand::WritePendingBootstrapTrust {
                invite_event_id: event_id_b64.to_string(),
                workspace_id: bc.workspace_id.clone(),
                expected_bootstrap_spki_fingerprint: expected_spki,
            });
        }
    }

    ProjectorResult::valid_with_commands(ops, commands)
}
