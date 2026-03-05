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

// ---------------------------------------------------------------------------
// Peers listing (all known peers with endpoint + local status)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerItem {
    pub peer_id: String,
    pub device_name: String,
    pub username: String,
    pub user_event_id: String,
    /// True if this peer has local transport credentials (i.e. is a local tenant).
    pub local: bool,
    /// Most recently observed endpoint address, if any.
    pub endpoint: Option<String>,
}

/// List all known peers with local/remote status and last-observed endpoint.
///
/// Joins `peers_shared` → `users` for display names, checks
/// `local_transport_creds` for local flag, and picks the most recent
/// non-expired `peer_endpoint_observations` row for endpoint info.
pub fn list_peers(db: &Connection, recorded_by: &str) -> Result<Vec<PeerItem>, rusqlite::Error> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let mut stmt = db.prepare(
        "SELECT
            ps.event_id,
            COALESCE(ps.device_name, ''),
            COALESCE(u.username, ''),
            COALESCE(ps.user_event_id, ''),
            EXISTS(
                SELECT 1 FROM local_transport_creds c
                WHERE c.peer_id = lower(hex(ps.transport_fingerprint))
            ) AS is_local,
            (
                SELECT e.origin_ip || ':' || e.origin_port
                FROM peer_endpoint_observations e
                WHERE e.recorded_by = ps.recorded_by
                  AND e.via_peer_id = lower(hex(ps.transport_fingerprint))
                  AND e.expires_at > ?2
                ORDER BY e.observed_at DESC
                LIMIT 1
            ) AS endpoint
         FROM peers_shared ps
         LEFT JOIN users u
           ON ps.user_event_id = u.event_id
          AND ps.recorded_by = u.recorded_by
         WHERE ps.recorded_by = ?1
         ORDER BY is_local DESC, ps.event_id",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![recorded_by, now_ms], |row| {
            Ok(PeerItem {
                peer_id: row.get(0)?,
                device_name: row.get(1)?,
                username: row.get(2)?,
                user_event_id: row.get(3)?,
                local: row.get(4)?,
                endpoint: row.get(5)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
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

    #[test]
    fn list_peers_returns_local_and_remote() {
        let conn = open_in_memory().expect("open in-memory db");
        create_tables(&conn).expect("create tables");

        let recorded_by = "tenant-a";

        // Insert a local peer (has local_transport_creds matched via transport_fingerprint)
        let local_tf: [u8; 32] = [0x11; 32];
        let local_tf_hex = hex::encode(local_tf);
        conn.execute(
            "INSERT INTO peers_shared (recorded_by, event_id, public_key, transport_fingerprint, device_name, user_event_id)
             VALUES (?1, 'local-peer', X'1111111111111111111111111111111111111111111111111111111111111111', ?2, 'my-laptop', 'user-1')",
            rusqlite::params![recorded_by, local_tf.as_slice()],
        ).unwrap();
        conn.execute(
            "INSERT INTO local_transport_creds (peer_id, cert_der, key_der, created_at, source)
             VALUES (?1, X'AA', X'BB', 1000, 'random')",
            rusqlite::params![local_tf_hex],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO users (recorded_by, event_id, public_key, username)
             VALUES (?1, 'user-1', X'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'alice')",
            rusqlite::params![recorded_by],
        ).unwrap();

        // Insert a remote peer (no local creds)
        conn.execute(
            "INSERT INTO peers_shared (recorded_by, event_id, public_key, device_name, user_event_id)
             VALUES (?1, 'remote-peer', X'2222222222222222222222222222222222222222222222222222222222222222', 'bobs-phone', 'user-2')",
            rusqlite::params![recorded_by],
        ).unwrap();
        conn.execute(
            "INSERT INTO users (recorded_by, event_id, public_key, username)
             VALUES (?1, 'user-2', X'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB', 'bob')",
            rusqlite::params![recorded_by],
        ).unwrap();

        let peers = list_peers(&conn, recorded_by).unwrap();
        assert_eq!(peers.len(), 2);

        // Local peer should come first (ORDER BY is_local DESC)
        assert_eq!(peers[0].peer_id, "local-peer");
        assert!(peers[0].local);
        assert_eq!(peers[0].username, "alice");
        assert_eq!(peers[0].device_name, "my-laptop");
        assert!(peers[0].endpoint.is_none());

        assert_eq!(peers[1].peer_id, "remote-peer");
        assert!(!peers[1].local);
        assert_eq!(peers[1].username, "bob");
        assert_eq!(peers[1].device_name, "bobs-phone");
    }

    #[test]
    fn list_peers_includes_endpoint_observations() {
        let conn = open_in_memory().expect("open in-memory db");
        create_tables(&conn).expect("create tables");

        let recorded_by = "tenant-a";
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        // transport_fingerprint blob whose hex is used as via_peer_id
        let tf: [u8; 32] = [0x33; 32];
        let tf_hex = hex::encode(tf);

        conn.execute(
            "INSERT INTO peers_shared (recorded_by, event_id, public_key, transport_fingerprint, device_name)
             VALUES (?1, 'peer-x', X'3333333333333333333333333333333333333333333333333333333333333333', ?2, 'device-x')",
            rusqlite::params![recorded_by, tf.as_slice()],
        ).unwrap();

        // Endpoint observation uses hex(transport_fingerprint) as via_peer_id
        conn.execute(
            "INSERT INTO peer_endpoint_observations
             (recorded_by, via_peer_id, origin_ip, origin_port, observed_at, expires_at)
             VALUES (?1, ?2, '10.0.0.5', 4433, ?3, ?4)",
            rusqlite::params![recorded_by, tf_hex, now_ms - 1000, now_ms + 86400000],
        )
        .unwrap();

        let peers = list_peers(&conn, recorded_by).unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].endpoint.as_deref(), Some("10.0.0.5:4433"));
    }

    #[test]
    fn list_peers_excludes_expired_endpoints() {
        let conn = open_in_memory().expect("open in-memory db");
        create_tables(&conn).expect("create tables");

        let recorded_by = "tenant-a";
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let tf: [u8; 32] = [0x44; 32];
        let tf_hex = hex::encode(tf);

        conn.execute(
            "INSERT INTO peers_shared (recorded_by, event_id, public_key, transport_fingerprint, device_name)
             VALUES (?1, 'peer-y', X'4444444444444444444444444444444444444444444444444444444444444444', ?2, 'device-y')",
            rusqlite::params![recorded_by, tf.as_slice()],
        ).unwrap();

        // Add an expired endpoint observation
        conn.execute(
            "INSERT INTO peer_endpoint_observations
             (recorded_by, via_peer_id, origin_ip, origin_port, observed_at, expires_at)
             VALUES (?1, ?2, '10.0.0.6', 5555, ?3, ?4)",
            rusqlite::params![recorded_by, tf_hex, now_ms - 100000, now_ms - 1000],
        )
        .unwrap();

        let peers = list_peers(&conn, recorded_by).unwrap();
        assert_eq!(peers.len(), 1);
        assert!(
            peers[0].endpoint.is_none(),
            "expired endpoint should not appear"
        );
    }

    #[test]
    fn list_peers_empty_db() {
        let conn = open_in_memory().expect("open in-memory db");
        create_tables(&conn).expect("create tables");
        let peers = list_peers(&conn, "no-such-tenant").unwrap();
        assert!(peers.is_empty());
    }
}
