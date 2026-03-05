use super::super::ParsedEvent;
use crate::crypto::event_id_from_base64;
use crate::projection::contract::{ContextSnapshot, EmitCommand, ProjectorResult, SqlVal, WriteOp};

/// Pure projector: DeviceInvite -> device_invites table.
/// When bootstrap_context is available and this event is locally created,
/// also write pending_invite_bootstrap_trust.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let (public_key, created_at_ms) = match parsed {
        ParsedEvent::DeviceInvite(di) => (&di.public_key, di.created_at_ms as i64),
        _ => return ProjectorResult::reject("not a device_invite event".to_string()),
    };

    let mut ops = vec![WriteOp::InsertOrIgnore {
        table: "device_invites",
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

    if let Some(recipient_event_id) = event_id_from_base64(event_id_b64) {
        let unwrap_evt = crate::event_modules::unwrap_secret::deterministic_unwrap_secret_event(
            recipient_event_id,
        );
        let unwrap_blob = match crate::event_modules::encode_event(&unwrap_evt) {
            Ok(v) => v,
            Err(err) => {
                return ProjectorResult::reject(format!(
                    "failed to encode deterministic unwrap_secret event: {}",
                    err
                ));
            }
        };
        ProjectorResult::valid_with_commands(
            ops,
            vec![EmitCommand::EmitDeterministicBlob { blob: unwrap_blob }],
        )
    } else {
        ProjectorResult::valid(ops)
    }
}
