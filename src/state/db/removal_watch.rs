//! Removal watch: detect when peers are removed and signal active sessions.
//!
//! When a `PeerRemoved` event is projected, the removed peer's SPKI fingerprint
//! should be denied for new TLS handshakes (already handled by `is_peer_allowed`
//! excluding removed peers) AND active transport sessions should be torn down.
//!
//! This module provides `check_removed_peers` which queries `removed_entities`
//! to determine if a given SPKI fingerprint corresponds to a removed peer.
//! The sync engine calls this periodically to close sessions for removed peers.

use rusqlite::Connection;

use crate::transport::cert::spki_fingerprint_from_ed25519_pubkey;

/// Check whether a peer identified by hex SPKI fingerprint has been removed.
///
/// Returns `true` if the peer's PeerShared event exists AND has a corresponding
/// `removed_entities` row. This is the inverse of the trust check — a peer that
/// was once trusted but has since been removed.
pub fn is_peer_removed(
    conn: &Connection,
    recorded_by: &str,
    spki_fingerprint: &[u8; 32],
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    // Find PeerShared events whose derived SPKI matches the given fingerprint
    let mut stmt = conn.prepare(
        "SELECT p.event_id, p.public_key FROM peers_shared p
         WHERE p.recorded_by = ?1",
    )?;
    let rows: Vec<(String, Vec<u8>)> = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?
        .filter_map(|r| r.ok())
        .collect();

    for (event_id, pubkey_blob) in rows {
        if pubkey_blob.len() != 32 {
            continue;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&pubkey_blob);
        let derived_spki = spki_fingerprint_from_ed25519_pubkey(&key);
        if &derived_spki == spki_fingerprint {
            // Found the PeerShared event for this SPKI. Check if it's been directly removed.
            let removed: bool = conn.query_row(
                "SELECT COUNT(*) > 0 FROM removed_entities
                 WHERE recorded_by = ?1 AND target_event_id = ?2",
                rusqlite::params![recorded_by, &event_id],
                |row| row.get(0),
            )?;
            if removed {
                return Ok(true);
            }
            // Check if the peer's user has been removed (transitive user_removed denial).
            let user_removed: bool = conn.query_row(
                "SELECT COUNT(*) > 0 FROM removed_entities r
                 WHERE r.recorded_by = ?1
                   AND r.removal_type = 'user'
                   AND r.target_event_id = (
                     SELECT p.user_event_id FROM peers_shared p
                     WHERE p.recorded_by = ?1 AND p.event_id = ?2 AND p.user_event_id IS NOT NULL
                   )",
                rusqlite::params![recorded_by, &event_id],
                |row| row.get(0),
            )?;
            if user_removed {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Return a list of hex-encoded SPKI fingerprints for all removed peers.
///
/// Used by the sync engine to check active connections against the removal set.
pub fn removed_peer_spki_fingerprints(
    conn: &Connection,
    recorded_by: &str,
) -> Result<Vec<[u8; 32]>, Box<dyn std::error::Error + Send + Sync>> {
    let mut stmt = conn.prepare(
        "SELECT p.public_key FROM peers_shared p
         WHERE p.recorded_by = ?1
           AND (
             EXISTS (
               SELECT 1 FROM removed_entities r
               WHERE r.recorded_by = p.recorded_by
                 AND r.target_event_id = p.event_id
             )
             OR EXISTS (
               SELECT 1 FROM removed_entities r
               WHERE r.recorded_by = p.recorded_by
                 AND p.user_event_id IS NOT NULL
                 AND r.target_event_id = p.user_event_id
                 AND r.removal_type = 'user'
             )
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_in_memory, schema::create_tables};
    use crate::transport::cert::spki_fingerprint_from_ed25519_pubkey;

    #[test]
    fn test_is_peer_removed_false_when_no_removal() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let pubkey: [u8; 32] = [0x42; 32];
        let spki = spki_fingerprint_from_ed25519_pubkey(&pubkey);

        conn.execute(
            "INSERT INTO peers_shared (recorded_by, event_id, public_key) VALUES (?1, ?2, ?3)",
            rusqlite::params![recorded_by, "ps_evt1", pubkey.as_slice()],
        )
        .unwrap();

        assert!(!is_peer_removed(&conn, recorded_by, &spki).unwrap());
    }

    #[test]
    fn test_is_peer_removed_true_after_removal() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let pubkey: [u8; 32] = [0x42; 32];
        let spki = spki_fingerprint_from_ed25519_pubkey(&pubkey);

        conn.execute(
            "INSERT INTO peers_shared (recorded_by, event_id, public_key) VALUES (?1, ?2, ?3)",
            rusqlite::params![recorded_by, "ps_evt1", pubkey.as_slice()],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO removed_entities (recorded_by, event_id, target_event_id, removal_type) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![recorded_by, "removal_evt1", "ps_evt1", "peer"],
        )
        .unwrap();

        assert!(is_peer_removed(&conn, recorded_by, &spki).unwrap());
    }

    #[test]
    fn test_removed_peer_spki_fingerprints() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let pubkey_a: [u8; 32] = [0x01; 32];
        let pubkey_b: [u8; 32] = [0x02; 32];
        let spki_a = spki_fingerprint_from_ed25519_pubkey(&pubkey_a);

        conn.execute(
            "INSERT INTO peers_shared (recorded_by, event_id, public_key) VALUES (?1, ?2, ?3)",
            rusqlite::params![recorded_by, "ps_a", pubkey_a.as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO peers_shared (recorded_by, event_id, public_key) VALUES (?1, ?2, ?3)",
            rusqlite::params![recorded_by, "ps_b", pubkey_b.as_slice()],
        )
        .unwrap();

        // Remove only peer A
        conn.execute(
            "INSERT INTO removed_entities (recorded_by, event_id, target_event_id, removal_type) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![recorded_by, "removal_a", "ps_a", "peer"],
        )
        .unwrap();

        let removed = removed_peer_spki_fingerprints(&conn, recorded_by).unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0], spki_a);
    }

    #[test]
    fn test_cross_tenant_isolation() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let pubkey: [u8; 32] = [0x42; 32];
        let spki = spki_fingerprint_from_ed25519_pubkey(&pubkey);

        // Tenant A has the peer, removes it
        conn.execute(
            "INSERT INTO peers_shared (recorded_by, event_id, public_key) VALUES (?1, ?2, ?3)",
            rusqlite::params!["tenant_a", "ps_evt1", pubkey.as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO removed_entities (recorded_by, event_id, target_event_id, removal_type) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params!["tenant_a", "removal_evt1", "ps_evt1", "peer"],
        )
        .unwrap();

        // Tenant A sees the removal
        assert!(is_peer_removed(&conn, "tenant_a", &spki).unwrap());
        // Tenant B does NOT see the removal
        assert!(!is_peer_removed(&conn, "tenant_b", &spki).unwrap());
    }

    #[test]
    fn test_user_removed_peer_appears_in_removed_spki() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let pubkey_a: [u8; 32] = [0x10; 32];
        let pubkey_b: [u8; 32] = [0x20; 32];
        let spki_a = spki_fingerprint_from_ed25519_pubkey(&pubkey_a);
        let spki_b = spki_fingerprint_from_ed25519_pubkey(&pubkey_b);
        let user_event_id = "user_evt1";

        // Both peers linked to same user
        conn.execute(
            "INSERT INTO peers_shared (recorded_by, event_id, public_key, user_event_id) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![recorded_by, "ps_a", pubkey_a.as_slice(), user_event_id],
        ).unwrap();
        conn.execute(
            "INSERT INTO peers_shared (recorded_by, event_id, public_key, user_event_id) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![recorded_by, "ps_b", pubkey_b.as_slice(), user_event_id],
        ).unwrap();

        // Before removal: neither peer is removed
        assert!(!is_peer_removed(&conn, recorded_by, &spki_a).unwrap());
        assert!(!is_peer_removed(&conn, recorded_by, &spki_b).unwrap());
        assert!(removed_peer_spki_fingerprints(&conn, recorded_by).unwrap().is_empty());

        // Remove the user (transitive removal of both peers)
        conn.execute(
            "INSERT INTO removed_entities (recorded_by, event_id, target_event_id, removal_type) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![recorded_by, "removal_user", user_event_id, "user"],
        ).unwrap();

        // Both peers should now be detected as removed
        assert!(is_peer_removed(&conn, recorded_by, &spki_a).unwrap());
        assert!(is_peer_removed(&conn, recorded_by, &spki_b).unwrap());

        let removed = removed_peer_spki_fingerprints(&conn, recorded_by).unwrap();
        assert_eq!(removed.len(), 2);
        assert!(removed.contains(&spki_a));
        assert!(removed.contains(&spki_b));
    }
}
