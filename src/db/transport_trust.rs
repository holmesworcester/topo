use rusqlite::Connection;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::transport::AllowedPeers;

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
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    conn.execute(
        "INSERT OR IGNORE INTO peer_transport_bindings (recorded_by, peer_id, spki_fingerprint, bound_at)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![recorded_by, peer_id, spki_fingerprint.as_slice(), now_ms],
    )?;
    Ok(())
}

/// Build AllowedPeers from event-derived transport keys only.
/// peer_transport_bindings is observation telemetry and NOT consulted for trust.
pub fn allowed_peers_from_db(
    conn: &Connection,
    recorded_by: &str,
) -> Result<AllowedPeers, Box<dyn std::error::Error + Send + Sync>> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT spki_fingerprint FROM transport_keys WHERE recorded_by = ?1"
    )?;
    let fps: Vec<[u8; 32]> = stmt.query_map(
        rusqlite::params![recorded_by],
        |row| {
            let blob: Vec<u8> = row.get(0)?;
            if blob.len() == 32 {
                let mut fp = [0u8; 32];
                fp.copy_from_slice(&blob);
                Ok(Some(fp))
            } else {
                Ok(None)
            }
        },
    )?.collect::<Result<Vec<_>, _>>()?
     .into_iter()
     .flatten()
     .collect();
    Ok(AllowedPeers::from_fingerprints(fps))
}

/// Build AllowedPeers from the union of CLI pin-peer flags and projected transport bindings.
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
    fn test_allowed_peers_combined() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let spki_db: [u8; 32] = [42u8; 32];
        let spki_cli: [u8; 32] = [99u8; 32];
        let spki_binding: [u8; 32] = [77u8; 32];

        // transport_keys row should appear
        conn.execute(
            "INSERT INTO transport_keys (recorded_by, event_id, spki_fingerprint) VALUES (?1, ?2, ?3)",
            rusqlite::params![recorded_by, "evt1", spki_db.as_slice()],
        ).unwrap();

        // binding-only row should NOT appear
        record_transport_binding(&conn, recorded_by, "remote", &spki_binding).unwrap();

        let cli_pins = AllowedPeers::from_fingerprints(vec![spki_cli]);
        let combined = allowed_peers_combined(&conn, recorded_by, &cli_pins).unwrap();

        assert!(combined.contains(&spki_db));
        assert!(combined.contains(&spki_cli));
        assert!(!combined.contains(&spki_binding));
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
