use rusqlite::Connection;

use crate::events::{ParsedEvent, TransportKeyEvent};
use crate::projection::create::create_event_sync;
use crate::transport::{
    extract_spki_fingerprint, generate_self_signed_cert_from_signing_key,
    load_cert_from_db, load_or_generate_cert_db, store_cert_in_db,
};

/// Load local transport peer identity from existing credentials in SQLite.
/// Fails if no credential exists. Use this for read/query commands that should
/// not silently generate a new identity.
pub fn load_transport_peer_id(
    conn: &Connection,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    match load_cert_from_db(conn)? {
        Some((cert_der, _)) => {
            let fp = extract_spki_fingerprint(cert_der.as_ref())?;
            Ok(hex::encode(fp))
        }
        None => Err("Transport identity not found in database. \
            Run 'transport-identity' or 'send' first to generate."
            .into()),
    }
}

/// Compute the local transport peer identity (hex SPKI fingerprint),
/// generating cert if needed. Use this for bootstrap commands
/// (transport-identity, send, generate, sync).
pub fn ensure_transport_peer_id(
    conn: &Connection,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let (cert_der, _) = load_or_generate_cert_db(conn)?;
    let fp = extract_spki_fingerprint(cert_der.as_ref())?;
    Ok(hex::encode(fp))
}

/// Derive the expected bootstrap transport SPKI fingerprint for an invitee from
/// the invite signing key material.
pub fn expected_invite_bootstrap_spki_from_invite_key(
    invite_key: &ed25519_dalek::SigningKey,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let (cert_der, _) = generate_self_signed_cert_from_signing_key(invite_key)?;
    extract_spki_fingerprint(cert_der.as_ref())
}

/// Install a deterministic transport cert/key derived from the invite signing
/// key into the SQLite credential store. This makes invitee transport identity
/// predictable from invite material so inviter-side bootstrap trust can be
/// precomputed without CLI pinning.
pub fn install_invite_bootstrap_transport_identity(
    conn: &Connection,
    invite_key: &ed25519_dalek::SigningKey,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let (cert_der, key_der) = generate_self_signed_cert_from_signing_key(invite_key)?;
    let fp = store_cert_in_db(conn, &cert_der, &key_der)?;
    Ok(hex::encode(fp))
}

/// Ensure a TransportKey event exists for the local TLS cert's SPKI fingerprint.
/// Returns Ok(None) if no cert exists, no PeerShared event exists, or the binding already exists.
/// Returns Ok(Some(event_id)) if a new TransportKey event was created.
///
/// TransportKey is an unsigned deterministic emitted event. Its bytes are fully
/// determined by (peer_shared_event_id, spki_fingerprint, peer_shared.created_at_ms).
pub fn ensure_transport_key_event(
    conn: &Connection,
    recorded_by: &str,
) -> Result<Option<[u8; 32]>, Box<dyn std::error::Error + Send + Sync>> {
    // Load local transport credential from SQLite
    let (cert_der, _) = match load_cert_from_db(conn)? {
        Some(pair) => pair,
        None => return Ok(None),
    };

    let spki_fp = extract_spki_fingerprint(cert_der.as_ref())?;

    // Check if a TransportKey event already exists with this SPKI
    let already_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM transport_keys WHERE recorded_by = ?1 AND spki_fingerprint = ?2",
            rusqlite::params![recorded_by, spki_fp.as_slice()],
            |row| row.get(0),
        )
        .unwrap_or(false);

    if already_exists {
        return Ok(None);
    }

    // Find the PeerShared event for the local identity.
    // We need the event_id and created_at_ms for deterministic emission.
    let peer_shared: Option<([u8; 32], u64)> = match conn.query_row(
        "SELECT e.event_id, e.blob FROM events e
         INNER JOIN peers_shared ps ON ps.event_id = e.event_id AND ps.recorded_by = ?1
         INNER JOIN valid_events ve ON ve.event_id = e.event_id AND ve.peer_id = ?1
         LIMIT 1",
        rusqlite::params![recorded_by],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
    ) {
        Ok((eid_b64, blob)) => {
            if let Some(eid) = crate::crypto::event_id_from_base64(&eid_b64) {
                // Extract created_at_ms from blob bytes [1..9]
                let ts = if blob.len() >= 9 {
                    u64::from_le_bytes(blob[1..9].try_into().unwrap_or([0u8; 8]))
                } else {
                    0
                };
                Some((eid, ts))
            } else {
                None
            }
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(e) => return Err(e.into()),
    };

    let (peer_shared_event_id, peer_shared_created_at_ms) = match peer_shared {
        Some(ps) => ps,
        None => return Ok(None),
    };

    // Build deterministic unsigned TransportKey event
    let evt = ParsedEvent::TransportKey(TransportKeyEvent {
        created_at_ms: peer_shared_created_at_ms,
        spki_fingerprint: spki_fp,
        peer_shared_event_id,
    });

    let event_id = create_event_sync(conn, recorded_by, &evt)?;

    Ok(Some(event_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn test_expected_invite_bootstrap_spki_is_deterministic() {
        let invite_key = SigningKey::from_bytes(&[9u8; 32]);
        let fp1 = expected_invite_bootstrap_spki_from_invite_key(&invite_key).unwrap();
        let fp2 = expected_invite_bootstrap_spki_from_invite_key(&invite_key).unwrap();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_install_invite_bootstrap_transport_identity_roundtrip() {
        let tmpdir = tempfile::tempdir().unwrap();
        let db_path = tmpdir.path().join("peer.db").to_str().unwrap().to_string();
        let conn = crate::db::open_connection(&db_path).unwrap();
        crate::db::schema::create_tables(&conn).unwrap();

        let invite_key = SigningKey::from_bytes(&[7u8; 32]);

        let installed = install_invite_bootstrap_transport_identity(&conn, &invite_key).unwrap();
        let loaded = load_transport_peer_id(&conn).unwrap();
        assert_eq!(installed, loaded);

        let expected =
            hex::encode(expected_invite_bootstrap_spki_from_invite_key(&invite_key).unwrap());
        assert_eq!(loaded, expected);
    }
}
