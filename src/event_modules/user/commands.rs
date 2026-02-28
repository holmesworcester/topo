use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::EventId;
use crate::event_modules::user_removed::{UserRemovedEvent, CreateUserRemovedCmd};
use crate::projection::create::create_signed_event_synchronous;
use crate::service::open_db_for_peer;
use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use super::super::ParsedEvent;
use super::super::peer_shared;

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

pub fn create_user_removed(
    db: &Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
    created_at_ms: u64,
    cmd: CreateUserRemovedCmd,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let ur = ParsedEvent::UserRemoved(UserRemovedEvent {
        created_at_ms,
        target_event_id: cmd.target_event_id,
        signed_by: *signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let eid = create_signed_event_synchronous(db, recorded_by, &ur, signing_key)?;
    Ok(eid)
}

/// High-level remove-user command: creates a UserRemoved event and returns target hex.
pub fn remove_user(
    db: &Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
    created_at_ms: u64,
    target_event_id: EventId,
) -> Result<String, String> {
    create_user_removed(
        db, recorded_by, signer_eid, signing_key, created_at_ms,
        CreateUserRemovedCmd { target_event_id },
    ).map_err(|e| format!("{}", e))?;

    Ok(hex::encode(target_event_id))
}

// ---------------------------------------------------------------------------
// Peer-level command wrapper (moved from service.rs)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct BanResponse {
    pub target: String,
    pub banned: bool,
}

/// Ban (remove) a user for a specific peer.
/// Target selector: numeric (1-based user list index), #N, or hex event ID.
pub fn ban_for_peer(
    db_path: &str,
    peer_id: &str,
    target_selector: &str,
) -> Result<BanResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (_recorded_by, db) = open_db_for_peer(db_path, peer_id)?;
    let (signer_eid, signing_key) = peer_shared::load_local_peer_signer_required(&db, peer_id)?;

    // Resolve target: numeric → user list index, or hex event ID
    let target_event_id = if let Ok(num) = target_selector.parse::<usize>() {
        let users = super::list_items(&db, peer_id)?;
        if num == 0 || num > users.len() {
            return Err(format!(
                "Invalid user number {}. Available: 1-{}",
                num,
                users.len()
            )
            .into());
        }
        crate::crypto::event_id_from_base64(&users[num - 1].event_id)
            .ok_or_else(|| -> Box<dyn std::error::Error + Send + Sync> {
                "Invalid event ID for user".into()
            })?
    } else if target_selector.starts_with('#') {
        let num: usize = target_selector[1..]
            .parse()
            .map_err(|_| -> Box<dyn std::error::Error + Send + Sync> {
                format!("Invalid user ref: {}", target_selector).into()
            })?;
        let users = super::list_items(&db, peer_id)?;
        if num == 0 || num > users.len() {
            return Err(format!(
                "Invalid user number {}. Available: 1-{}",
                num,
                users.len()
            )
            .into());
        }
        crate::crypto::event_id_from_base64(&users[num - 1].event_id)
            .ok_or_else(|| -> Box<dyn std::error::Error + Send + Sync> {
                "Invalid event ID for user".into()
            })?
    } else {
        // Hex event ID
        let bytes = hex::decode(target_selector)?;
        if bytes.len() != 32 {
            return Err(format!("Event ID must be 32 bytes, got {}", bytes.len()).into());
        }
        let mut eid = [0u8; 32];
        eid.copy_from_slice(&bytes);
        eid
    };

    remove_user(
        &db,
        peer_id,
        &signer_eid,
        &signing_key,
        current_timestamp_ms(),
        target_event_id,
    )
    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;

    Ok(BanResponse {
        target: hex::encode(target_event_id),
        banned: true,
    })
}
