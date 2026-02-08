use rusqlite::Connection;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::transport::AllowedPeers;

/// Record an observed transport binding: peer_id (hex SPKI fingerprint) was seen
/// on a TLS connection with this SPKI fingerprint. Idempotent (INSERT OR IGNORE).
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

/// Build AllowedPeers from projected transport bindings in the database.
/// Includes both event-derived bindings (transport_keys) and connection-observation
/// bindings (peer_transport_bindings).
pub fn allowed_peers_from_db(
    conn: &Connection,
    recorded_by: &str,
) -> Result<AllowedPeers, Box<dyn std::error::Error + Send + Sync>> {
    // Union of transport_keys (event-derived) and peer_transport_bindings (connection-observed)
    let mut stmt = conn.prepare(
        "SELECT DISTINCT spki_fingerprint FROM transport_keys WHERE recorded_by = ?1
         UNION
         SELECT DISTINCT spki_fingerprint FROM peer_transport_bindings WHERE recorded_by = ?1"
    )?;
    let fps: Vec<[u8; 32]> = stmt.query_map(
        rusqlite::params![recorded_by],
        |row| {
            let blob: Vec<u8> = row.get(0)?;
            let mut fp = [0u8; 32];
            if blob.len() == 32 {
                fp.copy_from_slice(&blob);
            }
            Ok(fp)
        },
    )?.collect::<Result<Vec<_>, _>>()?;
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
    fn test_record_and_query_transport_binding() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let peer_id = "bbbb";
        let spki: [u8; 32] = [42u8; 32];

        record_transport_binding(&conn, recorded_by, peer_id, &spki).unwrap();

        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(allowed.contains(&spki));

        // Idempotent
        record_transport_binding(&conn, recorded_by, peer_id, &spki).unwrap();
        let allowed2 = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(allowed2.contains(&spki));
    }

    #[test]
    fn test_allowed_peers_combined() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let peer_id = "bbbb";
        let spki_db: [u8; 32] = [42u8; 32];
        let spki_cli: [u8; 32] = [99u8; 32];

        record_transport_binding(&conn, recorded_by, peer_id, &spki_db).unwrap();

        let cli_pins = AllowedPeers::from_fingerprints(vec![spki_cli]);
        let combined = allowed_peers_combined(&conn, recorded_by, &cli_pins).unwrap();

        assert!(combined.contains(&spki_db));
        assert!(combined.contains(&spki_cli));
    }

    #[test]
    fn test_different_recorded_by_isolation() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let spki: [u8; 32] = [42u8; 32];
        record_transport_binding(&conn, "peer_a", "remote", &spki).unwrap();

        let allowed_a = allowed_peers_from_db(&conn, "peer_a").unwrap();
        assert!(allowed_a.contains(&spki));

        let allowed_b = allowed_peers_from_db(&conn, "peer_b").unwrap();
        assert!(!allowed_b.contains(&spki));
    }
}
