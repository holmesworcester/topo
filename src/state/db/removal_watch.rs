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
use std::collections::HashSet;

use crate::event_modules::peer_shared::resolve_event_id_by_transport_fingerprint;

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
    let Some(event_id) =
        resolve_event_id_by_transport_fingerprint(conn, recorded_by, spki_fingerprint)?
    else {
        return Ok(false);
    };

    let removed: bool = conn.query_row(
        "SELECT EXISTS (
            SELECT 1 FROM removed_entities
            WHERE recorded_by = ?1 AND target_event_id = ?2
        ) OR EXISTS (
            SELECT 1 FROM removed_entities r
            WHERE r.recorded_by = ?1
              AND r.removal_type = 'user'
              AND r.target_event_id = (
                SELECT p.user_event_id FROM peers_shared p
                WHERE p.recorded_by = ?1 AND p.event_id = ?2 AND p.user_event_id IS NOT NULL
              )
        )",
        rusqlite::params![recorded_by, &event_id],
        |row| row.get(0),
    )?;
    Ok(removed)
}

/// Return a list of hex-encoded SPKI fingerprints for all removed peers.
///
/// Used by the sync engine to check active connections against the removal set.
pub fn removed_peer_spki_fingerprints(
    conn: &Connection,
    recorded_by: &str,
) -> Result<Vec<[u8; 32]>, Box<dyn std::error::Error + Send + Sync>> {
    let mut out = HashSet::new();

    // Transport removal watch is projection-backed only.
    let mut stmt = conn.prepare(
        "SELECT p.transport_fingerprint FROM peers_shared p
         WHERE p.recorded_by = ?1
           AND length(p.transport_fingerprint) = 32
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
    let direct_fps: Vec<[u8; 32]> = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            Ok(row.get::<_, Vec<u8>>(0)?)
        })?
        .filter_map(|r| {
            let blob = r.ok()?;
            if blob.len() != 32 {
                return None;
            }
            let mut fp = [0u8; 32];
            fp.copy_from_slice(&blob);
            Some(fp)
        })
        .collect();
    out.extend(direct_fps);

    Ok(out.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::spki_fingerprint_from_ed25519_pubkey;
    use crate::db::{open_in_memory, schema::create_tables};

    #[test]
    fn test_is_peer_removed_false_when_no_removal() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let pubkey: [u8; 32] = [0x42; 32];
        let spki = spki_fingerprint_from_ed25519_pubkey(&pubkey);

        conn.execute(
            "INSERT INTO peers_shared (recorded_by, event_id, public_key, transport_fingerprint)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![recorded_by, "ps_evt1", pubkey.as_slice(), spki.as_slice()],
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
            "INSERT INTO peers_shared (recorded_by, event_id, public_key, transport_fingerprint)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![recorded_by, "ps_evt1", pubkey.as_slice(), spki.as_slice()],
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
        let spki_b = spki_fingerprint_from_ed25519_pubkey(&pubkey_b);

        conn.execute(
            "INSERT INTO peers_shared (recorded_by, event_id, public_key, transport_fingerprint)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![recorded_by, "ps_a", pubkey_a.as_slice(), spki_a.as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO peers_shared (recorded_by, event_id, public_key, transport_fingerprint)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![recorded_by, "ps_b", pubkey_b.as_slice(), spki_b.as_slice()],
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
            "INSERT INTO peers_shared (recorded_by, event_id, public_key, transport_fingerprint)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params!["tenant_a", "ps_evt1", pubkey.as_slice(), spki.as_slice()],
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
            "INSERT INTO peers_shared (recorded_by, event_id, public_key, transport_fingerprint, user_event_id)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                recorded_by,
                "ps_a",
                pubkey_a.as_slice(),
                spki_a.as_slice(),
                user_event_id
            ],
        ).unwrap();
        conn.execute(
            "INSERT INTO peers_shared (recorded_by, event_id, public_key, transport_fingerprint, user_event_id)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                recorded_by,
                "ps_b",
                pubkey_b.as_slice(),
                spki_b.as_slice(),
                user_event_id
            ],
        ).unwrap();

        // Before removal: neither peer is removed
        assert!(!is_peer_removed(&conn, recorded_by, &spki_a).unwrap());
        assert!(!is_peer_removed(&conn, recorded_by, &spki_b).unwrap());
        assert!(removed_peer_spki_fingerprints(&conn, recorded_by)
            .unwrap()
            .is_empty());

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
