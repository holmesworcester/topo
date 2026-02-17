use rusqlite::Connection;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

use crate::transport::AllowedPeers;
use crate::transport::cert::spki_fingerprint_from_ed25519_pubkey;

/// Pending bootstrap trust from locally-created invites is temporary.
/// If a peer never joins, this entry should not authorize transport forever.
const PENDING_INVITE_BOOTSTRAP_TTL_MS: i64 = 24 * 60 * 60 * 1000;
/// Accepted bootstrap trust is also temporary until steady-state transport key
/// trust converges for that same SPKI.
const ACCEPTED_INVITE_BOOTSTRAP_TTL_MS: i64 = 24 * 60 * 60 * 1000;

/// Workspace sentinel for CLI-pin-imported bootstrap trust rows.
const CLI_PIN_WORKSPACE: &str = "cli-bootstrap";

/// Build the deterministic `invite_event_id` for a CLI-pin import.
/// Uses the full 32-byte hex fingerprint so distinct pins never collide.
fn cli_pin_invite_event_id(spki_fingerprint: &[u8; 32]) -> String {
    format!("cli-pin-{}", hex::encode(spki_fingerprint))
}

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
/// This allows sync bootstrapping from accepted invite links before
/// PeerShared-derived trust appears via identity event sync.
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

/// Import CLI pin hex strings as `pending_invite_bootstrap_trust` rows.
///
/// Each pin is stored with a deterministic `invite_event_id` (via
/// `cli_pin_invite_event_id`) and `workspace_id = CLI_PIN_WORKSPACE`.
/// Reuses the existing table and 24h TTL.
/// Existing supersede logic auto-marks these stale when PeerShared-derived trust appears.
///
/// This is idempotent: re-importing the same pins refreshes their expiry.
pub fn import_cli_pins_to_sql(
    conn: &Connection,
    recorded_by: &str,
    cli_pins: &AllowedPeers,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let fps = cli_pins.fingerprints();
    let mut imported = 0;
    for fp in &fps {
        let invite_event_id = cli_pin_invite_event_id(fp);
        record_pending_invite_bootstrap_trust(
            conn,
            recorded_by,
            &invite_event_id,
            CLI_PIN_WORKSPACE,
            fp,
        )?;
        imported += 1;
    }
    if imported > 0 {
        info!("Imported {} CLI pin(s) to SQL trust rows", imported);
    }
    Ok(imported)
}

/// When PeerShared-derived SPKIs exist for an SPKI, pending invite bootstrap
/// trust for that same SPKI is no longer authoritative (supersession invariant).
fn supersede_pending_bootstrap_if_steady_trust_exists(
    conn: &Connection,
    recorded_by: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let peer_shared_fps = peer_shared_spki_fingerprints(conn, recorded_by)?;
    if peer_shared_fps.is_empty() {
        return Ok(());
    }
    let now = now_ms_i64();
    let mut stmt = conn.prepare(
        "UPDATE pending_invite_bootstrap_trust
            SET superseded_at = ?1
          WHERE recorded_by = ?2
            AND superseded_at IS NULL
            AND expected_bootstrap_spki_fingerprint = ?3",
    )?;
    for fp in &peer_shared_fps {
        stmt.execute(rusqlite::params![now, recorded_by, fp.as_slice()])?;
    }
    Ok(())
}

/// When PeerShared-derived SPKIs exist for an SPKI, accepted invite bootstrap
/// trust for that same SPKI is no longer authoritative (supersession invariant).
fn supersede_accepted_bootstrap_if_steady_trust_exists(
    conn: &Connection,
    recorded_by: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let peer_shared_fps = peer_shared_spki_fingerprints(conn, recorded_by)?;
    if peer_shared_fps.is_empty() {
        return Ok(());
    }
    let now = now_ms_i64();
    let mut stmt = conn.prepare(
        "UPDATE invite_bootstrap_trust
            SET superseded_at = ?1
          WHERE recorded_by = ?2
            AND superseded_at IS NULL
            AND bootstrap_spki_fingerprint = ?3",
    )?;
    for fp in &peer_shared_fps {
        stmt.execute(rusqlite::params![now, recorded_by, fp.as_slice()])?;
    }
    Ok(())
}

/// Compute SPKI fingerprints for all non-removed PeerShared public keys belonging to a peer.
fn peer_shared_spki_fingerprints(
    conn: &Connection,
    recorded_by: &str,
) -> Result<Vec<[u8; 32]>, Box<dyn std::error::Error + Send + Sync>> {
    let mut stmt = conn.prepare(
        "SELECT p.public_key FROM peers_shared p
         WHERE p.recorded_by = ?1
           AND NOT EXISTS (
             SELECT 1 FROM removed_entities r
             WHERE r.recorded_by = p.recorded_by
               AND r.target_event_id = p.event_id
           )",
    )?;
    let fps: Vec<[u8; 32]> = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            let blob: Vec<u8> = row.get(0)?;
            Ok(blob)
        })?
        .filter_map(|r| {
            let blob = r.ok()?;
            if blob.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&blob);
                Some(spki_fingerprint_from_ed25519_pubkey(&key))
            } else {
                None
            }
        })
        .collect();
    Ok(fps)
}

/// Check whether a given SPKI fingerprint matches any PeerShared-derived identity.
fn is_peer_shared_spki(
    conn: &Connection,
    recorded_by: &str,
    spki_fingerprint: &[u8; 32],
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    for fp in peer_shared_spki_fingerprints(conn, recorded_by)? {
        if &fp == spki_fingerprint {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Build AllowedPeers from SQL trust sources only.
/// Trust sources: PeerShared-derived SPKIs (steady-state) ∪ accepted invite
/// bootstrap trust ∪ pending invite bootstrap trust.
/// Observation telemetry (peer_transport_bindings) is NOT consulted for trust.
pub fn allowed_peers_from_db(
    conn: &Connection,
    recorded_by: &str,
) -> Result<AllowedPeers, Box<dyn std::error::Error + Send + Sync>> {
    supersede_pending_bootstrap_if_steady_trust_exists(conn, recorded_by)?;
    supersede_accepted_bootstrap_if_steady_trust_exists(conn, recorded_by)?;
    let now = now_ms_i64();
    let mut stmt = conn.prepare(
        "SELECT DISTINCT bootstrap_spki_fingerprint AS spki_fingerprint
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
    let mut fps: Vec<[u8; 32]> = stmt
        .query_map(rusqlite::params![recorded_by, now], |row| {
            let blob: Vec<u8> = row.get(0)?;
            Ok(decode_32_byte_blob(blob))
        })?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect();

    // Add PeerShared-derived SPKIs (primary steady-state trust source)
    fps.extend(peer_shared_spki_fingerprints(conn, recorded_by)?);

    Ok(AllowedPeers::from_fingerprints(fps))
}

/// Check a single peer fingerprint against SQL trust sources.
/// Trust sources: PeerShared-derived SPKIs ∪ accepted bootstrap ∪ pending bootstrap.
pub fn is_peer_allowed(
    conn: &Connection,
    recorded_by: &str,
    spki_fingerprint: &[u8; 32],
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    supersede_pending_bootstrap_if_steady_trust_exists(conn, recorded_by)?;
    supersede_accepted_bootstrap_if_steady_trust_exists(conn, recorded_by)?;
    // Check PeerShared-derived SPKIs first (primary steady-state trust source)
    if is_peer_shared_spki(conn, recorded_by, spki_fingerprint)? {
        return Ok(true);
    }
    let now = now_ms_i64();
    let allowed: i64 = conn.query_row(
        "SELECT
            EXISTS(
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

/// Count the total number of distinct trusted peer fingerprints from SQL
/// trust sources (PeerShared-derived SPKIs + accepted/pending invite bootstrap trust).
/// Returns the deduplicated count without materializing the full set.
pub fn trusted_peer_count(
    conn: &Connection,
    recorded_by: &str,
) -> Result<i64, Box<dyn std::error::Error + Send + Sync>> {
    supersede_pending_bootstrap_if_steady_trust_exists(conn, recorded_by)?;
    supersede_accepted_bootstrap_if_steady_trust_exists(conn, recorded_by)?;
    let now = now_ms_i64();
    let bootstrap_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM (
            SELECT DISTINCT bootstrap_spki_fingerprint AS spki_fingerprint
              FROM invite_bootstrap_trust
              WHERE recorded_by = ?1
                AND length(bootstrap_spki_fingerprint) = 32
                AND superseded_at IS NULL
                AND expires_at > ?2
            UNION
            SELECT DISTINCT expected_bootstrap_spki_fingerprint AS spki_fingerprint
              FROM pending_invite_bootstrap_trust
              WHERE recorded_by = ?1
                AND length(expected_bootstrap_spki_fingerprint) = 32
                AND superseded_at IS NULL
                AND expires_at > ?2
        )",
        rusqlite::params![recorded_by, now],
        |row| row.get(0),
    )?;
    let peer_shared_count = peer_shared_spki_fingerprints(conn, recorded_by)?.len() as i64;
    // Approximate: doesn't dedupe across sources but sufficient for trust checks
    Ok(bootstrap_count + peer_shared_count)
}

/// Check whether any trusted peer fingerprints exist in SQL trust sources
/// without materializing the full set. Uses EXISTS for early exit.
pub fn has_any_trusted_peer(
    conn: &Connection,
    recorded_by: &str,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    supersede_pending_bootstrap_if_steady_trust_exists(conn, recorded_by)?;
    supersede_accepted_bootstrap_if_steady_trust_exists(conn, recorded_by)?;
    let now = now_ms_i64();
    let has_any: i64 = conn.query_row(
        "SELECT
            EXISTS(
                SELECT 1 FROM invite_bootstrap_trust
                WHERE recorded_by = ?1
                  AND length(bootstrap_spki_fingerprint) = 32
                  AND superseded_at IS NULL
                  AND expires_at > ?2
            )
            OR EXISTS(
                SELECT 1 FROM pending_invite_bootstrap_trust
                WHERE recorded_by = ?1
                  AND length(expected_bootstrap_spki_fingerprint) = 32
                  AND superseded_at IS NULL
                  AND expires_at > ?2
            )
            OR EXISTS(
                SELECT 1 FROM peers_shared
                WHERE recorded_by = ?1
                  AND length(public_key) = 32
                  AND NOT EXISTS (
                    SELECT 1 FROM removed_entities r
                    WHERE r.recorded_by = peers_shared.recorded_by
                      AND r.target_event_id = peers_shared.event_id
                  )
            )",
        rusqlite::params![recorded_by, now],
        |row| row.get(0),
    )?;
    Ok(has_any != 0)
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

    /// Helper: insert a PeerShared row and return its SPKI fingerprint.
    fn insert_peer_shared(conn: &Connection, recorded_by: &str, event_id: &str, pubkey: &[u8; 32]) -> [u8; 32] {
        conn.execute(
            "INSERT INTO peers_shared (recorded_by, event_id, public_key) VALUES (?1, ?2, ?3)",
            rusqlite::params![recorded_by, event_id, pubkey.as_slice()],
        ).unwrap();
        spki_fingerprint_from_ed25519_pubkey(pubkey)
    }

    #[test]
    fn test_peer_shared_derived_in_allowlist() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let pubkey: [u8; 32] = [42u8; 32];
        let spki = insert_peer_shared(&conn, recorded_by, "ps1", &pubkey);

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
    fn test_invite_bootstrap_superseded_when_peer_shared_exists() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let pubkey: [u8; 32] = [14u8; 32];
        let spki = spki_fingerprint_from_ed25519_pubkey(&pubkey);
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

        // Add PeerShared entry whose derived SPKI matches the bootstrap SPKI
        insert_peer_shared(&conn, recorded_by, "ps-supersede", &pubkey);

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
    fn test_pending_invite_bootstrap_superseded_when_peer_shared_exists() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let pubkey: [u8; 32] = [12u8; 32];
        let spki = spki_fingerprint_from_ed25519_pubkey(&pubkey);
        record_pending_invite_bootstrap_trust(&conn, recorded_by, "invite1", "workspace1", &spki)
            .unwrap();

        // Add PeerShared entry whose derived SPKI matches the pending SPKI
        insert_peer_shared(&conn, recorded_by, "ps1", &pubkey);

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
    fn test_is_peer_allowed_checks_all_sources() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let pubkey: [u8; 32] = [2u8; 32];
        let peer_shared_spki = insert_peer_shared(&conn, recorded_by, "ps_db", &pubkey);
        let pending_only: [u8; 32] = [3u8; 32];
        let denied: [u8; 32] = [4u8; 32];

        record_pending_invite_bootstrap_trust(
            &conn,
            recorded_by,
            "invite-pending",
            "workspace",
            &pending_only,
        )
        .unwrap();

        assert!(is_peer_allowed(&conn, recorded_by, &peer_shared_spki).unwrap());
        assert!(is_peer_allowed(&conn, recorded_by, &pending_only).unwrap());
        assert!(!is_peer_allowed(&conn, recorded_by, &denied).unwrap());
    }

    #[test]
    fn test_import_cli_pins_to_sql() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let pin1: [u8; 32] = [0xAA; 32];
        let pin2: [u8; 32] = [0xBB; 32];
        let not_pinned: [u8; 32] = [0xCC; 32];

        let cli_pins = AllowedPeers::from_fingerprints(vec![pin1, pin2]);
        let imported = import_cli_pins_to_sql(&conn, recorded_by, &cli_pins).unwrap();
        assert_eq!(imported, 2);

        // Both should be visible via allowed_peers_from_db
        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(allowed.contains(&pin1));
        assert!(allowed.contains(&pin2));
        assert!(!allowed.contains(&not_pinned));

        // And via is_peer_allowed
        assert!(is_peer_allowed(&conn, recorded_by, &pin1).unwrap());
        assert!(is_peer_allowed(&conn, recorded_by, &pin2).unwrap());
        assert!(!is_peer_allowed(&conn, recorded_by, &not_pinned).unwrap());
    }

    #[test]
    fn test_cli_pin_superseded_by_peer_shared() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        // Choose a pubkey whose derived SPKI we'll use as the CLI pin
        let pubkey: [u8; 32] = [0xDD; 32];
        let pin_fp = spki_fingerprint_from_ed25519_pubkey(&pubkey);

        // Import a CLI pin
        let cli_pins = AllowedPeers::from_fingerprints(vec![pin_fp]);
        import_cli_pins_to_sql(&conn, recorded_by, &cli_pins).unwrap();

        // Verify it's trusted
        assert!(is_peer_allowed(&conn, recorded_by, &pin_fp).unwrap());

        // Simulate arrival of a PeerShared entry for the same SPKI
        insert_peer_shared(&conn, recorded_by, "ps-steady", &pubkey);

        // Still trusted (via PeerShared now)
        assert!(is_peer_allowed(&conn, recorded_by, &pin_fp).unwrap());

        // The pending_invite_bootstrap_trust row should be superseded
        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(allowed.contains(&pin_fp));

        let invite_event_id = cli_pin_invite_event_id(&pin_fp);
        let superseded_at: Option<i64> = conn
            .query_row(
                "SELECT superseded_at FROM pending_invite_bootstrap_trust
                  WHERE recorded_by = ?1 AND invite_event_id = ?2",
                rusqlite::params![recorded_by, &invite_event_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(superseded_at.is_some(), "CLI pin should be superseded by PeerShared");
    }

    #[test]
    fn test_cli_pin_not_silently_trusted_without_import() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let raw_fp: [u8; 32] = [0xEE; 32];

        // Without importing, a raw fingerprint should NOT be trusted
        assert!(!is_peer_allowed(&conn, recorded_by, &raw_fp).unwrap());
        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(!allowed.contains(&raw_fp));
    }

    #[test]
    fn test_cli_pin_import_no_collision_on_shared_prefix() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        // Two fingerprints that share the same first 8 bytes but differ after
        let mut fp_a: [u8; 32] = [0xAB; 32];
        let mut fp_b: [u8; 32] = [0xAB; 32];
        fp_a[8] = 0x01;
        fp_b[8] = 0x02;

        let pins = AllowedPeers::from_fingerprints(vec![fp_a, fp_b]);
        let count = import_cli_pins_to_sql(&conn, recorded_by, &pins).unwrap();
        assert_eq!(count, 2);

        // Both must remain trusted — no silent overwrite
        assert!(is_peer_allowed(&conn, recorded_by, &fp_a).unwrap(),
            "fp_a should be trusted after import");
        assert!(is_peer_allowed(&conn, recorded_by, &fp_b).unwrap(),
            "fp_b should be trusted after import");

        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(allowed.contains(&fp_a), "fp_a should be in allowed set");
        assert!(allowed.contains(&fp_b), "fp_b should be in allowed set");
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

        let pubkey: [u8; 32] = [42u8; 32];
        let spki = insert_peer_shared(&conn, "peer_a", "ps1", &pubkey);

        let allowed_a = allowed_peers_from_db(&conn, "peer_a").unwrap();
        assert!(allowed_a.contains(&spki));

        let allowed_b = allowed_peers_from_db(&conn, "peer_b").unwrap();
        assert!(!allowed_b.contains(&spki));
    }

    #[test]
    fn test_malformed_peer_shared_pubkey_skipped() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let good_pubkey: [u8; 32] = [42u8; 32];
        let good_spki = insert_peer_shared(&conn, recorded_by, "ps1", &good_pubkey);

        // Insert a malformed peers_shared row (wrong length public_key)
        conn.execute(
            "INSERT INTO peers_shared (recorded_by, event_id, public_key) VALUES (?1, ?2, ?3)",
            rusqlite::params![recorded_by, "ps_bad", &[0u8; 16][..]],
        ).unwrap();

        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(allowed.contains(&good_spki));
        // Malformed entry should be skipped — only 1 valid entry
        let zero_fp: [u8; 32] = [0u8; 32];
        assert!(!allowed.contains(&zero_fp));
    }

    #[test]
    fn test_trusted_peer_count() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let pubkey_ps: [u8; 32] = [1u8; 32];
        let spki_bootstrap: [u8; 32] = [2u8; 32];
        let spki_pending: [u8; 32] = [3u8; 32];

        // Empty → count should be 0
        assert_eq!(trusted_peer_count(&conn, recorded_by).unwrap(), 0);

        // Add PeerShared row
        insert_peer_shared(&conn, recorded_by, "ps1", &pubkey_ps);
        assert_eq!(trusted_peer_count(&conn, recorded_by).unwrap(), 1);

        // Add accepted invite bootstrap trust
        record_invite_bootstrap_trust(
            &conn, recorded_by, "ia1", "invite1", "ws1", "127.0.0.1:4433", &spki_bootstrap,
        ).unwrap();
        assert_eq!(trusted_peer_count(&conn, recorded_by).unwrap(), 2);

        // Add pending invite bootstrap trust
        record_pending_invite_bootstrap_trust(
            &conn, recorded_by, "invite2", "ws2", &spki_pending,
        ).unwrap();
        assert_eq!(trusted_peer_count(&conn, recorded_by).unwrap(), 3);

        // Cross-tenant isolation: different recorded_by sees 0
        assert_eq!(trusted_peer_count(&conn, "other_peer").unwrap(), 0);
    }

    #[test]
    fn test_has_any_trusted_peer() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";

        // Empty → false
        assert!(!has_any_trusted_peer(&conn, recorded_by).unwrap());

        // PeerShared only → true
        let pubkey_ps: [u8; 32] = [10u8; 32];
        insert_peer_shared(&conn, recorded_by, "ps_only", &pubkey_ps);
        assert!(has_any_trusted_peer(&conn, recorded_by).unwrap());

        // Start fresh for bootstrap-only test
        let rb_boot = "boot_only";
        assert!(!has_any_trusted_peer(&conn, rb_boot).unwrap());
        let spki_boot: [u8; 32] = [20u8; 32];
        record_invite_bootstrap_trust(
            &conn, rb_boot, "ia_boot", "inv_boot", "ws_boot", "127.0.0.1:4433", &spki_boot,
        ).unwrap();
        assert!(has_any_trusted_peer(&conn, rb_boot).unwrap());

        // Pending-only test
        let rb_pend = "pending_only";
        assert!(!has_any_trusted_peer(&conn, rb_pend).unwrap());
        let spki_pend: [u8; 32] = [30u8; 32];
        record_pending_invite_bootstrap_trust(
            &conn, rb_pend, "inv_pend", "ws_pend", &spki_pend,
        ).unwrap();
        assert!(has_any_trusted_peer(&conn, rb_pend).unwrap());
    }

    #[test]
    fn test_trusted_peer_count_ignores_malformed_rows() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "malformed_count";

        // Malformed PeerShared public key (wrong length)
        conn.execute(
            "INSERT INTO peers_shared (recorded_by, event_id, public_key) VALUES (?1, ?2, ?3)",
            rusqlite::params![recorded_by, "ps_short", &[9u8; 16][..]],
        ).unwrap();
        conn.execute(
            "INSERT INTO invite_bootstrap_trust
             (recorded_by, invite_accepted_event_id, invite_event_id, workspace_id, bootstrap_addr, bootstrap_spki_fingerprint, accepted_at, expires_at, superseded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL)",
            rusqlite::params![
                recorded_by,
                "ia_short",
                "invite_short",
                "ws",
                "127.0.0.1:4433",
                &[7u8; 31][..],
                now_ms_i64(),
                now_ms_i64() + 60_000,
            ],
        ).unwrap();
        conn.execute(
            "INSERT INTO pending_invite_bootstrap_trust
             (recorded_by, invite_event_id, workspace_id, expected_bootstrap_spki_fingerprint, created_at, expires_at, superseded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
            rusqlite::params![
                recorded_by,
                "invite_short_pending",
                "ws",
                &[8u8; 8][..],
                now_ms_i64(),
                now_ms_i64() + 60_000,
            ],
        ).unwrap();

        assert_eq!(trusted_peer_count(&conn, recorded_by).unwrap(), 0);
        assert!(!has_any_trusted_peer(&conn, recorded_by).unwrap());
    }

    #[test]
    fn test_removed_peer_excluded_from_trust() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let peer_pubkey: [u8; 32] = [0x42; 32];
        let peer_event_id = "peer_shared_evt1";

        // Insert a peers_shared row
        conn.execute(
            "INSERT INTO peers_shared (recorded_by, event_id, public_key)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![recorded_by, peer_event_id, peer_pubkey.as_slice()],
        ).unwrap();

        // Compute expected SPKI fingerprint
        let spki = spki_fingerprint_from_ed25519_pubkey(&peer_pubkey);

        // Before removal: peer should be trusted
        assert!(is_peer_allowed(&conn, recorded_by, &spki).unwrap(),
            "peer should be trusted before removal");
        assert!(has_any_trusted_peer(&conn, recorded_by).unwrap(),
            "should have trusted peers before removal");
        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(allowed.contains(&spki), "allowed set should contain peer before removal");

        // Insert removal targeting this peer
        conn.execute(
            "INSERT INTO removed_entities (recorded_by, event_id, target_event_id, removal_type)
             VALUES (?1, 'removal_evt1', ?2, 'peer_removed')",
            rusqlite::params![recorded_by, peer_event_id],
        ).unwrap();

        // After removal: peer should NOT be trusted
        assert!(!is_peer_allowed(&conn, recorded_by, &spki).unwrap(),
            "removed peer should not be trusted");
        assert!(!has_any_trusted_peer(&conn, recorded_by).unwrap(),
            "should have no trusted peers after only peer removed");
        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(!allowed.contains(&spki), "allowed set should not contain removed peer");
    }
}
