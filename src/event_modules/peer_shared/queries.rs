use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};

use crate::crypto::{event_id_from_base64, EventId};

// ---------------------------------------------------------------------------
// Identity helpers (moved from service.rs)
// ---------------------------------------------------------------------------

fn decode_signing_key(key_bytes: Vec<u8>) -> Result<SigningKey, String> {
    let key_arr: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "bad signing key length in local signer table".to_string())?;
    Ok(SigningKey::from_bytes(&key_arr))
}

/// Load the local peer signer (signer_kind=3) from local_signer_material,
/// joined with peers_shared to ensure the signer is projected.
pub fn load_local_peer_signer(
    db: &Connection,
    recorded_by: &str,
) -> Result<Option<(EventId, SigningKey)>, Box<dyn std::error::Error + Send + Sync>> {
    if let Some((eid_b64, key_bytes)) = db
        .query_row(
            "SELECT l.signer_event_id, l.private_key
             FROM local_signer_material l
             INNER JOIN peers_shared p
               ON p.recorded_by = l.recorded_by AND p.event_id = l.signer_event_id
             WHERE l.recorded_by = ?1 AND l.signer_kind = 3
             LIMIT 1",
            rusqlite::params![recorded_by],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?
    {
        let signing_key = decode_signing_key(key_bytes)?;
        let eid = event_id_from_base64(&eid_b64)
            .ok_or_else(|| "bad local peer signer event_id".to_string())?;
        return Ok(Some((eid, signing_key)));
    }
    Ok(None)
}

/// Like `load_local_peer_signer` but returns an error if no signer is found.
pub fn load_local_peer_signer_required(
    db: &Connection,
    recorded_by: &str,
) -> Result<(EventId, SigningKey), Box<dyn std::error::Error + Send + Sync>> {
    load_local_peer_signer(db, recorded_by)?
        .ok_or_else(|| "no identity — run `topo create-workspace` first".into())
}

/// Resolve the user_event_id for a specific signer from the peers_shared table.
pub fn resolve_user_event_id(
    db: &Connection,
    recorded_by: &str,
    signer_eid: &EventId,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let signer_b64 = crate::crypto::event_id_to_base64(signer_eid);
    let user_eid_b64: String = db
        .query_row(
            "SELECT COALESCE(user_event_id, '') FROM peers_shared WHERE recorded_by = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &signer_b64],
            |row| row.get(0),
        )
        .map_err(|_| -> Box<dyn std::error::Error + Send + Sync> {
            "no peer_shared entry found for signer — identity chain incomplete".into()
        })?;
    if user_eid_b64.is_empty() {
        return Err(
            "peer_shared entry has no user_event_id (legacy row) — recreate database".into(),
        );
    }
    event_id_from_base64(&user_eid_b64)
        .ok_or_else(|| "invalid user_event_id in peers_shared".into())
}

/// Load the local user key (signer_kind=2) from local_signer_material.
pub fn load_local_user_key(
    db: &Connection,
    recorded_by: &str,
) -> Result<Option<(EventId, SigningKey)>, Box<dyn std::error::Error + Send + Sync>> {
    if let Some((eid_b64, key_bytes)) = db
        .query_row(
            "SELECT signer_event_id, private_key FROM local_signer_material
             WHERE recorded_by = ?1 AND signer_kind = 2
             LIMIT 1",
            rusqlite::params![recorded_by],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?
    {
        let signing_key = decode_signing_key(key_bytes)?;
        let eid = event_id_from_base64(&eid_b64)
            .ok_or_else(|| "bad local user key event_id".to_string())?;
        return Ok(Some((eid, signing_key)));
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Projection queries
// ---------------------------------------------------------------------------

pub fn count(db: &Connection, recorded_by: &str) -> Result<i64, rusqlite::Error> {
    db.query_row(
        "SELECT COUNT(*) FROM peers_shared WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
        |row| row.get(0),
    )
}

/// List event_ids for all peer_shared rows.
pub fn list_event_ids(db: &Connection, recorded_by: &str) -> Result<Vec<String>, rusqlite::Error> {
    let mut stmt = db.prepare("SELECT event_id FROM peers_shared WHERE recorded_by = ?1")?;
    let rows = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Return the first peer_shared event_id, if any.
pub fn first_event_id(
    db: &Connection,
    recorded_by: &str,
) -> Result<Option<String>, rusqlite::Error> {
    use rusqlite::OptionalExtension;
    db.query_row(
        "SELECT event_id FROM peers_shared WHERE recorded_by = ?1 LIMIT 1",
        rusqlite::params![recorded_by],
        |row| row.get::<_, String>(0),
    )
    .optional()
}

/// Resolve a projected peer_shared event_id by transport fingerprint.
///
/// Uses `(recorded_by, transport_fingerprint)` lookup to map transport identity
/// back to canonical event-graph identity.
pub fn resolve_event_id_by_transport_fingerprint(
    db: &Connection,
    recorded_by: &str,
    transport_fingerprint: &[u8; 32],
) -> Result<Option<String>, rusqlite::Error> {
    db.query_row(
        "SELECT event_id
         FROM peers_shared
         WHERE recorded_by = ?1
           AND transport_fingerprint = ?2
         LIMIT 1",
        rusqlite::params![recorded_by, transport_fingerprint.as_slice()],
        |row| row.get::<_, String>(0),
    )
    .optional()
}

pub struct AccountRow {
    pub event_id: String,
    pub device_name: String,
    pub user_event_id: String,
    pub username: String,
}

/// List peer accounts with joined username from users table.
pub fn list_accounts(
    db: &Connection,
    recorded_by: &str,
) -> Result<Vec<AccountRow>, rusqlite::Error> {
    let mut stmt = db.prepare(
        "SELECT ps.event_id, COALESCE(ps.device_name, ''), COALESCE(ps.user_event_id, ''),
                COALESCE(u.username, '')
         FROM peers_shared ps
         LEFT JOIN users u ON ps.user_event_id = u.event_id AND ps.recorded_by = u.recorded_by
         WHERE ps.recorded_by = ?1",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            Ok(AccountRow {
                event_id: row.get(0)?,
                device_name: row.get(1)?,
                user_event_id: row.get(2)?,
                username: row.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

// ---------------------------------------------------------------------------
// Response types & high-level query functions
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountItem {
    pub event_id: String,
    pub device_name: String,
    pub user_event_id: String,
    pub username: String,
}

/// List account items (response type) from the database.
pub fn list_account_items(
    db: &Connection,
    recorded_by: &str,
) -> Result<Vec<AccountItem>, rusqlite::Error> {
    let rows = list_accounts(db, recorded_by)?;
    Ok(rows
        .into_iter()
        .map(|row| AccountItem {
            event_id: row.event_id,
            device_name: row.device_name,
            user_event_id: row.user_event_id,
            username: row.username,
        })
        .collect())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityResponse {
    pub transport_fingerprint: String,
    pub user_event_id: Option<String>,
    pub peer_shared_event_id: Option<String>,
}

/// Get combined identity info for a specific peer.
pub fn identity(db: &Connection, recorded_by: &str) -> Result<IdentityResponse, rusqlite::Error> {
    let user_event_id = super::super::user::first_event_id(db, recorded_by)?;
    let peer_shared_event_id = first_event_id(db, recorded_by)?;
    Ok(IdentityResponse {
        transport_fingerprint: recorded_by.to_string(),
        user_event_id,
        peer_shared_event_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::spki_fingerprint_from_ed25519_pubkey;
    use crate::db::{open_in_memory, schema::create_tables};

    #[test]
    fn resolve_event_id_by_transport_fingerprint_uses_projected_index() {
        let conn = open_in_memory().expect("open in-memory db");
        create_tables(&conn).expect("create tables");

        let recorded_by = "tenant-a";
        let event_id = "ps-event-1";
        let public_key: [u8; 32] = [0x11; 32];
        let transport_fingerprint = spki_fingerprint_from_ed25519_pubkey(&public_key);

        conn.execute(
            "INSERT INTO peers_shared
             (recorded_by, event_id, public_key, transport_fingerprint)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                recorded_by,
                event_id,
                public_key.as_slice(),
                transport_fingerprint.as_slice(),
            ],
        )
        .expect("insert peers_shared row");

        let resolved =
            resolve_event_id_by_transport_fingerprint(&conn, recorded_by, &transport_fingerprint)
                .expect("resolve event id");
        assert_eq!(resolved.as_deref(), Some(event_id));
    }
}
