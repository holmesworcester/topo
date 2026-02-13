use rusqlite::Connection;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::transport::AllowedPeers;

/// Pending bootstrap trust from locally-created invites is temporary.
/// If a peer never joins, this entry should not authorize transport forever.
const PENDING_INVITE_BOOTSTRAP_TTL_MS: i64 = 24 * 60 * 60 * 1000;
/// Accepted bootstrap trust is also temporary until steady-state transport key
/// trust converges for that same SPKI.
const ACCEPTED_INVITE_BOOTSTRAP_TTL_MS: i64 = 24 * 60 * 60 * 1000;

fn now_ms_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn decode_32_byte_blob(blob: Vec<u8>) -> Option<[u8; 32]> {
    if blob.len() != 32 {
        return None;
    }
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&blob);
    Some(fp)
}

/// Record an observed transport binding (observation telemetry only).
/// peer_id (hex SPKI fingerprint) was seen on a TLS connection with this SPKI
/// fingerprint. Idempotent (INSERT OR IGNORE). NOT used for trust decisions —
/// allowed_peers_from_db queries only event-derived transport_keys.
pub fn record_transport_binding(
    conn: &Connection,
    recorded_by: &str,
    peer_id: &str,
    spki_fingerprint: &[u8; 32],
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT OR IGNORE INTO peer_transport_bindings (recorded_by, peer_id, spki_fingerprint, bound_at)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![recorded_by, peer_id, spki_fingerprint.as_slice(), now_ms_i64()],
    )?;
    Ok(())
}

/// Record invite-accepted bootstrap trust metadata.
/// This allows sync bootstrapping from accepted invite links before TransportKey
/// events have propagated.
pub fn record_invite_bootstrap_trust(
    conn: &Connection,
    recorded_by: &str,
    invite_accepted_event_id: &str,
    invite_event_id: &str,
    workspace_id: &str,
    bootstrap_addr: &str,
    bootstrap_spki_fingerprint: &[u8; 32],
) -> Result<(), rusqlite::Error> {
    let now = now_ms_i64();
    conn.execute(
        "INSERT INTO invite_bootstrap_trust (
             recorded_by,
             invite_accepted_event_id,
             invite_event_id,
             workspace_id,
             bootstrap_addr,
             bootstrap_spki_fingerprint,
             accepted_at,
             expires_at,
             superseded_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL)
         ON CONFLICT(recorded_by, invite_accepted_event_id) DO UPDATE SET
             invite_event_id = excluded.invite_event_id,
             workspace_id = excluded.workspace_id,
             bootstrap_addr = excluded.bootstrap_addr,
             bootstrap_spki_fingerprint = excluded.bootstrap_spki_fingerprint,
             accepted_at = excluded.accepted_at,
             expires_at = excluded.expires_at,
             superseded_at = NULL",
        rusqlite::params![
            recorded_by,
            invite_accepted_event_id,
            invite_event_id,
            workspace_id,
            bootstrap_addr,
            bootstrap_spki_fingerprint.as_slice(),
            now,
            now + ACCEPTED_INVITE_BOOTSTRAP_TTL_MS,
        ],
    )?;
    Ok(())
}

/// Record inviter-side pending bootstrap trust for an invite before the invitee
/// has connected. This lets incoming invitee TLS certs pass strict mTLS checks
/// without CLI pin flags.
pub fn record_pending_invite_bootstrap_trust(
    conn: &Connection,
    recorded_by: &str,
    invite_event_id: &str,
    workspace_id: &str,
    expected_bootstrap_spki_fingerprint: &[u8; 32],
) -> Result<(), rusqlite::Error> {
    let now = now_ms_i64();
    conn.execute(
        "INSERT INTO pending_invite_bootstrap_trust (
             recorded_by,
             invite_event_id,
             workspace_id,
             expected_bootstrap_spki_fingerprint,
             created_at,
             expires_at,
             superseded_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)
         ON CONFLICT(recorded_by, invite_event_id) DO UPDATE SET
             workspace_id = excluded.workspace_id,
             expected_bootstrap_spki_fingerprint = excluded.expected_bootstrap_spki_fingerprint,
             created_at = excluded.created_at,
             expires_at = excluded.expires_at,
             superseded_at = NULL",
        rusqlite::params![
            recorded_by,
            invite_event_id,
            workspace_id,
            expected_bootstrap_spki_fingerprint.as_slice(),
            now,
            now + PENDING_INVITE_BOOTSTRAP_TTL_MS,
        ],
    )?;
    Ok(())
}

/// When steady-state transport_keys are available for an SPKI, pending invite
/// bootstrap trust for that same SPKI is no longer authoritative.
fn supersede_pending_bootstrap_if_steady_trust_exists(
    conn: &Connection,
    recorded_by: &str,
) -> Result<(), rusqlite::Error> {
    let now = now_ms_i64();
    conn.execute(
        "UPDATE pending_invite_bootstrap_trust
            SET superseded_at = ?2
          WHERE recorded_by = ?1
            AND superseded_at IS NULL
            AND expected_bootstrap_spki_fingerprint IN (
                SELECT spki_fingerprint
                  FROM transport_keys
                 WHERE recorded_by = ?1
            )",
        rusqlite::params![recorded_by, now],
    )?;
    Ok(())
}

/// When steady-state transport_keys are available for an SPKI, accepted invite
/// bootstrap trust for that same SPKI is no longer authoritative.
fn supersede_accepted_bootstrap_if_steady_trust_exists(
    conn: &Connection,
    recorded_by: &str,
) -> Result<(), rusqlite::Error> {
    let now = now_ms_i64();
    conn.execute(
        "UPDATE invite_bootstrap_trust
            SET superseded_at = ?2
          WHERE recorded_by = ?1
            AND superseded_at IS NULL
            AND bootstrap_spki_fingerprint IN (
                SELECT spki_fingerprint
                  FROM transport_keys
                 WHERE recorded_by = ?1
            )",
        rusqlite::params![recorded_by, now],
    )?;
    Ok(())
}

/// Build AllowedPeers from SQL trust sources only.
/// Observation telemetry (peer_transport_bindings) is NOT consulted for trust.
pub fn allowed_peers_from_db(
    conn: &Connection,
    recorded_by: &str,
) -> Result<AllowedPeers, Box<dyn std::error::Error + Send + Sync>> {
    supersede_pending_bootstrap_if_steady_trust_exists(conn, recorded_by)?;
    supersede_accepted_bootstrap_if_steady_trust_exists(conn, recorded_by)?;
    let now = now_ms_i64();
    let mut stmt = conn.prepare(
        "SELECT DISTINCT spki_fingerprint FROM transport_keys WHERE recorded_by = ?1
         UNION
         SELECT DISTINCT bootstrap_spki_fingerprint AS spki_fingerprint
          FROM invite_bootstrap_trust
          WHERE recorded_by = ?1
            AND superseded_at IS NULL
            AND expires_at > ?2
         UNION
         SELECT DISTINCT expected_bootstrap_spki_fingerprint AS spki_fingerprint
          FROM pending_invite_bootstrap_trust
          WHERE recorded_by = ?1
            AND superseded_at IS NULL
            AND expires_at > ?2",
    )?;
    let fps: Vec<[u8; 32]> = stmt
        .query_map(rusqlite::params![recorded_by, now], |row| {
            let blob: Vec<u8> = row.get(0)?;
            Ok(decode_32_byte_blob(blob))
        })?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect();
    Ok(AllowedPeers::from_fingerprints(fps))
}

/// Check a single peer fingerprint against SQL trust sources plus optional
/// CLI fallback pins.
pub fn is_peer_allowed(
    conn: &Connection,
    recorded_by: &str,
    spki_fingerprint: &[u8; 32],
    cli_pins: &AllowedPeers,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    if cli_pins.contains(spki_fingerprint) {
        return Ok(true);
    }

    supersede_pending_bootstrap_if_steady_trust_exists(conn, recorded_by)?;
    supersede_accepted_bootstrap_if_steady_trust_exists(conn, recorded_by)?;
    let now = now_ms_i64();
    let allowed: i64 = conn.query_row(
        "SELECT
            EXISTS(
                SELECT 1
                  FROM transport_keys
                 WHERE recorded_by = ?1
                   AND spki_fingerprint = ?2
            )
            OR EXISTS(
                SELECT 1
                  FROM invite_bootstrap_trust
                 WHERE recorded_by = ?1
                   AND bootstrap_spki_fingerprint = ?2
                   AND superseded_at IS NULL
                   AND expires_at > ?3
            )
            OR EXISTS(
                SELECT 1
                  FROM pending_invite_bootstrap_trust
                 WHERE recorded_by = ?1
                   AND expected_bootstrap_spki_fingerprint = ?2
                   AND superseded_at IS NULL
                   AND expires_at > ?3
            )",
        rusqlite::params![recorded_by, spki_fingerprint.as_slice(), now],
        |row| row.get(0),
    )?;
    Ok(allowed != 0)
}

/// Build AllowedPeers from CLI pin-peer flags plus SQL trust rows
/// (projected transport_keys + accepted/pending invite bootstrap trust).
pub fn allowed_peers_combined(
    conn: &Connection,
    recorded_by: &str,
    cli_pins: &AllowedPeers,
) -> Result<AllowedPeers, Box<dyn std::error::Error + Send + Sync>> {
    let db_peers = allowed_peers_from_db(conn, recorded_by)?;
    Ok(cli_pins.union(&db_peers))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_in_memory, schema::create_tables};

    #[test]
    fn test_binding_alone_not_in_allowlist() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let peer_id = "bbbb";
        let spki: [u8; 32] = [42u8; 32];

        // Record a transport binding (observation telemetry)
        record_transport_binding(&conn, recorded_by, peer_id, &spki).unwrap();

        // Binding alone must NOT appear in allowed peers
        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(!allowed.contains(&spki));

        // Idempotent insert still works
        record_transport_binding(&conn, recorded_by, peer_id, &spki).unwrap();
    }

    #[test]
    fn test_transport_keys_in_allowlist() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let spki: [u8; 32] = [42u8; 32];

        // Insert directly into transport_keys (event-derived)
        conn.execute(
            "INSERT INTO transport_keys (recorded_by, event_id, spki_fingerprint) VALUES (?1, ?2, ?3)",
            rusqlite::params![recorded_by, "evt1", spki.as_slice()],
        ).unwrap();

        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(allowed.contains(&spki));
    }

    #[test]
    fn test_invite_bootstrap_trust_in_allowlist() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let spki: [u8; 32] = [11u8; 32];
        record_invite_bootstrap_trust(
            &conn,
            recorded_by,
            "ia1",
            "invite1",
            "workspace1",
            "127.0.0.1:4433",
            &spki,
        )
        .unwrap();

        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(allowed.contains(&spki));
    }

    #[test]
    fn test_invite_bootstrap_superseded_when_transport_key_exists() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let spki: [u8; 32] = [14u8; 32];
        record_invite_bootstrap_trust(
            &conn,
            recorded_by,
            "ia-supersede",
            "invite-supersede",
            "workspace-supersede",
            "127.0.0.1:4433",
            &spki,
        )
        .unwrap();
        conn.execute(
            "INSERT INTO transport_keys (recorded_by, event_id, spki_fingerprint) VALUES (?1, ?2, ?3)",
            rusqlite::params![recorded_by, "tk-supersede", spki.as_slice()],
        )
        .unwrap();

        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(allowed.contains(&spki));

        let superseded_at: Option<i64> = conn
            .query_row(
                "SELECT superseded_at FROM invite_bootstrap_trust
                  WHERE recorded_by = ?1 AND invite_accepted_event_id = ?2",
                rusqlite::params![recorded_by, "ia-supersede"],
                |row| row.get(0),
            )
            .unwrap();
        assert!(superseded_at.is_some());
    }

    #[test]
    fn test_expired_invite_bootstrap_not_in_allowlist() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let spki: [u8; 32] = [15u8; 32];
        let now = now_ms_i64();
        conn.execute(
            "INSERT INTO invite_bootstrap_trust
             (recorded_by, invite_accepted_event_id, invite_event_id, workspace_id, bootstrap_addr, bootstrap_spki_fingerprint, accepted_at, expires_at, superseded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL)",
            rusqlite::params![
                recorded_by,
                "ia-expired",
                "invite-expired",
                "workspace-expired",
                "127.0.0.1:4433",
                spki.as_slice(),
                now - 1000,
                now - 1,
            ],
        )
        .unwrap();

        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(!allowed.contains(&spki));
    }

    #[test]
    fn test_pending_invite_bootstrap_trust_in_allowlist() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let invite_eid = "invite-bootstrap";
        let workspace_id = "workspace-bootstrap";
        let spki: [u8; 32] = [55u8; 32];
        record_pending_invite_bootstrap_trust(&conn, recorded_by, invite_eid, workspace_id, &spki)
            .unwrap();

        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(allowed.contains(&spki));
    }

    #[test]
    fn test_pending_invite_bootstrap_superseded_when_transport_key_exists() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let spki: [u8; 32] = [12u8; 32];
        record_pending_invite_bootstrap_trust(&conn, recorded_by, "invite1", "workspace1", &spki)
            .unwrap();
        conn.execute(
            "INSERT INTO transport_keys (recorded_by, event_id, spki_fingerprint) VALUES (?1, ?2, ?3)",
            rusqlite::params![recorded_by, "tk1", spki.as_slice()],
        )
        .unwrap();

        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(allowed.contains(&spki));

        let superseded_at: Option<i64> = conn
            .query_row(
                "SELECT superseded_at FROM pending_invite_bootstrap_trust
                  WHERE recorded_by = ?1 AND invite_event_id = ?2",
                rusqlite::params![recorded_by, "invite1"],
                |row| row.get(0),
            )
            .unwrap();
        assert!(superseded_at.is_some());
    }

    #[test]
    fn test_expired_pending_invite_bootstrap_not_in_allowlist() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let spki: [u8; 32] = [13u8; 32];
        let now = now_ms_i64();
        conn.execute(
            "INSERT INTO pending_invite_bootstrap_trust
             (recorded_by, invite_event_id, workspace_id, expected_bootstrap_spki_fingerprint, created_at, expires_at, superseded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
            rusqlite::params![
                recorded_by,
                "invite-expired",
                "workspace-expired",
                spki.as_slice(),
                now - 1000,
                now - 1,
            ],
        )
        .unwrap();

        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(!allowed.contains(&spki));
    }

    #[test]
    fn test_allowed_peers_combined() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let spki_db: [u8; 32] = [42u8; 32];
        let spki_cli: [u8; 32] = [99u8; 32];
        let spki_bootstrap: [u8; 32] = [88u8; 32];
        let spki_pending: [u8; 32] = [66u8; 32];
        let spki_binding: [u8; 32] = [77u8; 32];

        // transport_keys row should appear
        conn.execute(
            "INSERT INTO transport_keys (recorded_by, event_id, spki_fingerprint) VALUES (?1, ?2, ?3)",
            rusqlite::params![recorded_by, "evt1", spki_db.as_slice()],
        ).unwrap();

        // binding-only row should NOT appear
        record_transport_binding(&conn, recorded_by, "remote", &spki_binding).unwrap();

        // accepted-invite bootstrap trust should appear
        record_invite_bootstrap_trust(
            &conn,
            recorded_by,
            "ia2",
            "invite2",
            "workspace2",
            "127.0.0.1:4434",
            &spki_bootstrap,
        )
        .unwrap();
        record_pending_invite_bootstrap_trust(
            &conn,
            recorded_by,
            "invite3",
            "workspace3",
            &spki_pending,
        )
        .unwrap();

        let cli_pins = AllowedPeers::from_fingerprints(vec![spki_cli]);
        let combined = allowed_peers_combined(&conn, recorded_by, &cli_pins).unwrap();

        assert!(combined.contains(&spki_db));
        assert!(combined.contains(&spki_bootstrap));
        assert!(combined.contains(&spki_pending));
        assert!(combined.contains(&spki_cli));
        assert!(!combined.contains(&spki_binding));
    }

    #[test]
    fn test_is_peer_allowed_checks_all_sources() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let cli_only: [u8; 32] = [1u8; 32];
        let db_only: [u8; 32] = [2u8; 32];
        let pending_only: [u8; 32] = [3u8; 32];
        let denied: [u8; 32] = [4u8; 32];

        conn.execute(
            "INSERT INTO transport_keys (recorded_by, event_id, spki_fingerprint) VALUES (?1, ?2, ?3)",
            rusqlite::params![recorded_by, "evt_db", db_only.as_slice()],
        )
        .unwrap();
        record_pending_invite_bootstrap_trust(
            &conn,
            recorded_by,
            "invite-pending",
            "workspace",
            &pending_only,
        )
        .unwrap();

        let cli = AllowedPeers::from_fingerprints(vec![cli_only]);
        assert!(is_peer_allowed(&conn, recorded_by, &cli_only, &cli).unwrap());
        assert!(is_peer_allowed(&conn, recorded_by, &db_only, &cli).unwrap());
        assert!(is_peer_allowed(&conn, recorded_by, &pending_only, &cli).unwrap());
        assert!(!is_peer_allowed(&conn, recorded_by, &denied, &cli).unwrap());
    }

    #[test]
    fn test_invite_bootstrap_trust_upsert_updates_in_place() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let spki: [u8; 32] = [20u8; 32];

        // First insert
        record_invite_bootstrap_trust(
            &conn, recorded_by, "ia1", "invite1", "workspace1", "127.0.0.1:4433", &spki,
        ).unwrap();

        // Second insert with same PK but different values
        let spki2: [u8; 32] = [21u8; 32];
        record_invite_bootstrap_trust(
            &conn, recorded_by, "ia1", "invite2", "workspace2", "10.0.0.1:4434", &spki2,
        ).unwrap();

        // Should be exactly 1 row (updated in place, not deleted+reinserted)
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM invite_bootstrap_trust
             WHERE recorded_by = ?1 AND invite_accepted_event_id = ?2",
            rusqlite::params![recorded_by, "ia1"],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 1, "upsert should update in place, not create duplicate");

        // Verify new values
        let (addr, ws): (String, String) = conn.query_row(
            "SELECT bootstrap_addr, workspace_id FROM invite_bootstrap_trust
             WHERE recorded_by = ?1 AND invite_accepted_event_id = ?2",
            rusqlite::params![recorded_by, "ia1"],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert_eq!(addr, "10.0.0.1:4434");
        assert_eq!(ws, "workspace2");
    }

    #[test]
    fn test_pending_invite_bootstrap_trust_upsert_updates_in_place() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let spki: [u8; 32] = [30u8; 32];

        // First insert
        record_pending_invite_bootstrap_trust(
            &conn, recorded_by, "invite1", "workspace1", &spki,
        ).unwrap();

        // Second insert with same PK but different values
        let spki2: [u8; 32] = [31u8; 32];
        record_pending_invite_bootstrap_trust(
            &conn, recorded_by, "invite1", "workspace2", &spki2,
        ).unwrap();

        // Should be exactly 1 row
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM pending_invite_bootstrap_trust
             WHERE recorded_by = ?1 AND invite_event_id = ?2",
            rusqlite::params![recorded_by, "invite1"],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 1, "upsert should update in place, not create duplicate");

        // Verify new values
        let ws: String = conn.query_row(
            "SELECT workspace_id FROM pending_invite_bootstrap_trust
             WHERE recorded_by = ?1 AND invite_event_id = ?2",
            rusqlite::params![recorded_by, "invite1"],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(ws, "workspace2");

        // Verify new SPKI
        let fp_blob: Vec<u8> = conn.query_row(
            "SELECT expected_bootstrap_spki_fingerprint FROM pending_invite_bootstrap_trust
             WHERE recorded_by = ?1 AND invite_event_id = ?2",
            rusqlite::params![recorded_by, "invite1"],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(fp_blob, spki2.to_vec());
    }

    #[test]
    fn test_different_recorded_by_isolation() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let spki: [u8; 32] = [42u8; 32];
        conn.execute(
            "INSERT INTO transport_keys (recorded_by, event_id, spki_fingerprint) VALUES (?1, ?2, ?3)",
            rusqlite::params!["peer_a", "evt1", spki.as_slice()],
        ).unwrap();

        let allowed_a = allowed_peers_from_db(&conn, "peer_a").unwrap();
        assert!(allowed_a.contains(&spki));

        let allowed_b = allowed_peers_from_db(&conn, "peer_b").unwrap();
        assert!(!allowed_b.contains(&spki));
    }

    #[test]
    fn test_malformed_spki_blob_skipped() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let good_spki: [u8; 32] = [42u8; 32];

        // Insert a valid row
        conn.execute(
            "INSERT INTO transport_keys (recorded_by, event_id, spki_fingerprint) VALUES (?1, ?2, ?3)",
            rusqlite::params![recorded_by, "evt1", good_spki.as_slice()],
        ).unwrap();

        // Insert a malformed row (wrong length blob)
        conn.execute(
            "INSERT INTO transport_keys (recorded_by, event_id, spki_fingerprint) VALUES (?1, ?2, ?3)",
            rusqlite::params![recorded_by, "evt2", &[0u8; 16][..]],
        ).unwrap();

        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(allowed.contains(&good_spki));
        // Should have exactly 1 entry (malformed skipped)
        let zero_fp: [u8; 32] = [0u8; 32];
        assert!(!allowed.contains(&zero_fp));
    }
}
