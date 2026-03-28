use super::super::{parse_event, ParsedEvent};
use crate::crypto::event_id_to_base64;
use crate::event_modules::endpoint_shared::load_endpoint_shared_by_event_id;
use crate::projection::contract::ContextSnapshot;
use rusqlite::{Connection, OptionalExtension};

fn load_valid_event_blob(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
) -> Result<Option<Vec<u8>>, rusqlite::Error> {
    conn.query_row(
        "SELECT e.blob
         FROM events e
         INNER JOIN valid_events v ON v.event_id = e.event_id
         WHERE v.peer_id = ?1 AND e.event_id = ?2",
        rusqlite::params![recorded_by, event_id_b64],
        |row| row.get(0),
    )
    .optional()
}

fn authorized_user_for_device_invite(
    conn: &Connection,
    recorded_by: &str,
    device_invite: &crate::event_modules::DeviceInviteEvent,
) -> Result<Option<String>, rusqlite::Error> {
    match device_invite.signer_type {
        4 => Ok(Some(event_id_to_base64(&device_invite.authority_event_id))),
        5 => {
            let signer_b64 = event_id_to_base64(&device_invite.signed_by);
            let signer_user_event_id: Option<String> = conn
                .query_row(
                    "SELECT COALESCE(user_event_id, '')
                     FROM peers_shared
                     WHERE recorded_by = ?1 AND event_id = ?2",
                    rusqlite::params![recorded_by, &signer_b64],
                    |row| row.get(0),
                )
                .optional()?;

            let Some(signer_user_event_id) = signer_user_event_id else {
                return Ok(Some(format!(
                    "__ERROR__:no peers_shared row for device_invite signer {}",
                    signer_b64
                )));
            };
            if signer_user_event_id.is_empty() {
                return Ok(Some(format!(
                    "__ERROR__:device_invite signer {} has empty peers_shared.user_event_id",
                    signer_b64
                )));
            }
            Ok(Some(signer_user_event_id))
        }
        other => Ok(Some(format!(
            "__ERROR__:unsupported device_invite signer_type {} for peer_shared authorization",
            other
        ))),
    }
}

fn peer_shared_user_mismatch_reason(
    conn: &Connection,
    recorded_by: &str,
    device_invite: &crate::event_modules::DeviceInviteEvent,
    user_event_id: &[u8; 32],
) -> Result<Option<String>, rusqlite::Error> {
    let claimed_user_b64 = event_id_to_base64(user_event_id);
    let expected_user = authorized_user_for_device_invite(conn, recorded_by, device_invite)?;

    let Some(expected_user) = expected_user else {
        return Ok(None);
    };

    if let Some(detail) = expected_user.strip_prefix("__ERROR__:") {
        return Ok(Some(detail.to_string()));
    }

    if expected_user != claimed_user_b64 {
        return Ok(Some(format!(
            "peer_shared signer authorizes user {} but event claims {}",
            expected_user, claimed_user_b64
        )));
    }

    Ok(None)
}

/// Build projector-local context for PeerShared projection.
pub fn build_projector_context(
    conn: &Connection,
    recorded_by: &str,
    _event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let peer_shared = match parsed {
        ParsedEvent::PeerShared(peer_shared) => peer_shared,
        _ => return Err("peer_shared context loader called for non-peer_shared event".into()),
    };

    let signed_by_b64 = event_id_to_base64(&peer_shared.signed_by);
    let blob = load_valid_event_blob(conn, recorded_by, &signed_by_b64)?;
    let Some(blob) = blob else {
        return Ok(ContextSnapshot {
            peer_shared_user_mismatch_reason: Some(format!(
                "no valid device_invite blob for signer {}",
                signed_by_b64
            )),
            ..ContextSnapshot::default()
        });
    };

    let device_invite = match parse_event(&blob) {
        Ok(ParsedEvent::DeviceInvite(device_invite)) => device_invite,
        Ok(other) => {
            return Ok(ContextSnapshot {
                peer_shared_user_mismatch_reason: Some(format!(
                    "peer_shared signer {} resolved to unexpected event type {}",
                    signed_by_b64,
                    other.event_type_code()
                )),
                ..ContextSnapshot::default()
            })
        }
        Err(err) => {
            return Ok(ContextSnapshot {
                peer_shared_user_mismatch_reason: Some(format!(
                    "failed to parse device_invite signer {}: {}",
                    signed_by_b64, err
                )),
                ..ContextSnapshot::default()
            })
        }
    };

    let endpoint_shared_event_id_b64 = event_id_to_base64(&peer_shared.endpoint_shared_event_id);
    let (peer_shared_endpoint_id, peer_shared_endpoint_binding_reason) =
        match load_endpoint_shared_by_event_id(conn, &endpoint_shared_event_id_b64)
            .map_err(|e| -> Box<dyn std::error::Error> { e })?
        {
            Some(row) => (Some(row.endpoint_id), None),
            None => (
                None,
                Some(format!(
                    "no projected endpoint_shared row for {}",
                    endpoint_shared_event_id_b64
                )),
            ),
        };

    Ok(ContextSnapshot {
        peer_shared_user_mismatch_reason: peer_shared_user_mismatch_reason(
            conn,
            recorded_by,
            &device_invite,
            &peer_shared.user_event_id,
        )?,
        peer_shared_endpoint_id,
        peer_shared_endpoint_binding_reason,
        ..ContextSnapshot::default()
    })
}
