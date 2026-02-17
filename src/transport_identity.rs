use rusqlite::Connection;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use crate::db::transport_creds::{load_sole_local_creds, load_local_creds, store_local_creds};
use crate::events::{ParsedEvent, TransportKeyEvent};
use crate::projection::create::create_signed_event_sync;
use crate::transport::{
    extract_spki_fingerprint, generate_self_signed_cert,
    generate_self_signed_cert_from_signing_key,
};

// ---------------------------------------------------------------------------
// Core functions (take &Connection)
// ---------------------------------------------------------------------------

/// Load local transport peer identity from DB. Fails if no credentials stored.
/// Use this for read/query commands that should not silently generate a new identity.
pub fn load_transport_peer_id(
    conn: &Connection,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    match load_sole_local_creds(conn)? {
        Some((peer_id, _, _)) => Ok(peer_id),
        None => Err(
            "Transport identity not found in database. Run 'transport-identity' or 'send' first to generate."
                .into(),
        ),
    }
}

/// Compute the local transport peer identity (hex SPKI fingerprint), generating cert if needed.
/// Use this for bootstrap commands (transport-identity, send, generate, sync).
pub fn ensure_transport_peer_id(
    conn: &Connection,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    if let Some((peer_id, _, _)) = load_sole_local_creds(conn)? {
        return Ok(peer_id);
    }
    let (cert_der, key_der) = generate_self_signed_cert()?;
    let fp = extract_spki_fingerprint(cert_der.as_ref())?;
    let peer_id = hex::encode(fp);
    store_local_creds(conn, &peer_id, cert_der.as_ref(), key_der.secret_pkcs8_der())?;
    Ok(peer_id)
}

/// Ensure transport credentials exist and return (peer_id, cert, key).
/// Generates a new identity if none exists.
pub fn ensure_transport_cert(
    conn: &Connection,
) -> Result<
    (String, CertificateDer<'static>, PrivatePkcs8KeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    if let Some((peer_id, cert_bytes, key_bytes)) = load_sole_local_creds(conn)? {
        let cert_der = CertificateDer::from(cert_bytes);
        let key_der = PrivatePkcs8KeyDer::from(key_bytes);
        return Ok((peer_id, cert_der, key_der));
    }
    let (cert_der, key_der) = generate_self_signed_cert()?;
    let fp = extract_spki_fingerprint(cert_der.as_ref())?;
    let peer_id = hex::encode(fp);
    store_local_creds(conn, &peer_id, cert_der.as_ref(), key_der.secret_pkcs8_der())?;
    Ok((peer_id, cert_der, key_der))
}

/// Load transport credentials for a specific peer_id. Returns (cert, key) or error.
pub fn load_transport_cert(
    conn: &Connection,
    peer_id: &str,
) -> Result<
    (CertificateDer<'static>, PrivatePkcs8KeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    match load_local_creds(conn, peer_id)? {
        Some((cert_bytes, key_bytes)) => {
            let cert_der = CertificateDer::from(cert_bytes);
            let key_der = PrivatePkcs8KeyDer::from(key_bytes);
            Ok((cert_der, key_der))
        }
        None => Err(format!("No transport credentials found for peer_id {}", peer_id).into()),
    }
}

// ---------------------------------------------------------------------------
// Convenience wrappers (take db_path, open their own connection)
// ---------------------------------------------------------------------------

/// Load local transport peer identity from DB. Fails if no credentials stored.
/// Convenience wrapper that opens its own connection.
pub fn load_transport_peer_id_from_db(
    db_path: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let conn = crate::db::open_connection(db_path)?;
    crate::db::schema::create_tables(&conn)?;
    load_transport_peer_id(&conn)
}

/// Compute the local transport peer identity, generating cert if needed.
/// Convenience wrapper that opens its own connection.
pub fn ensure_transport_peer_id_from_db(
    db_path: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let conn = crate::db::open_connection(db_path)?;
    crate::db::schema::create_tables(&conn)?;
    ensure_transport_peer_id(&conn)
}

/// Ensure transport credentials exist and return (peer_id, cert, key).
/// Convenience wrapper that opens its own connection.
pub fn ensure_transport_cert_from_db(
    db_path: &str,
) -> Result<
    (String, CertificateDer<'static>, PrivatePkcs8KeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let conn = crate::db::open_connection(db_path)?;
    crate::db::schema::create_tables(&conn)?;
    ensure_transport_cert(&conn)
}

// ---------------------------------------------------------------------------
// Peer-key-derived transport identity (for all roles)
// ---------------------------------------------------------------------------

/// Install a deterministic transport cert/key derived from a PeerShared signing
/// key. This replaces any prior transport identity (random or invite-derived)
/// so that `recorded_by` (SPKI fingerprint) matches the event-layer peer identity.
pub fn install_peer_key_transport_identity(
    conn: &Connection,
    peer_signing_key: &ed25519_dalek::SigningKey,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    // Delete any pre-existing creds
    conn.execute("DELETE FROM local_transport_creds", [])?;

    let (cert_der, key_der) = generate_self_signed_cert_from_signing_key(peer_signing_key)?;
    let fp = extract_spki_fingerprint(cert_der.as_ref())?;
    let peer_id = hex::encode(fp);
    store_local_creds(conn, &peer_id, cert_der.as_ref(), key_der.secret_pkcs8_der())?;
    Ok(peer_id)
}

// ---------------------------------------------------------------------------
// Invite bootstrap identity
// ---------------------------------------------------------------------------

/// Derive the expected bootstrap transport SPKI fingerprint for an invitee from
/// the invite signing key material.
pub fn expected_invite_bootstrap_spki_from_invite_key(
    invite_key: &ed25519_dalek::SigningKey,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let (cert_der, _) = generate_self_signed_cert_from_signing_key(invite_key)?;
    extract_spki_fingerprint(cert_der.as_ref())
}

/// Install a deterministic transport cert/key derived from the invite signing
/// key into the database. This makes invitee transport identity predictable
/// from invite material so inviter-side bootstrap trust can be precomputed.
pub fn install_invite_bootstrap_transport_identity(
    db_path: &str,
    invite_key: &ed25519_dalek::SigningKey,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let conn = crate::db::open_connection(db_path)?;
    crate::db::schema::create_tables(&conn)?;
    install_invite_bootstrap_transport_identity_conn(&conn, invite_key)
}

/// Install a deterministic transport cert/key derived from the invite signing
/// key into the database. Connection-based variant.
pub fn install_invite_bootstrap_transport_identity_conn(
    conn: &Connection,
    invite_key: &ed25519_dalek::SigningKey,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    // Delete any pre-existing random cert — at invite acceptance time the
    // random identity generated by ensure_transport_peer_id is unused and
    // must be replaced by the deterministic one derived from the invite key.
    conn.execute("DELETE FROM local_transport_creds", [])?;

    let (cert_der, key_der) = generate_self_signed_cert_from_signing_key(invite_key)?;
    let fp = extract_spki_fingerprint(cert_der.as_ref())?;
    let peer_id = hex::encode(fp);
    store_local_creds(conn, &peer_id, cert_der.as_ref(), key_der.secret_pkcs8_der())?;
    Ok(peer_id)
}

// ---------------------------------------------------------------------------
// TransportKey event creation
// ---------------------------------------------------------------------------

/// Ensure a TransportKey event exists for the local TLS cert's SPKI fingerprint.
/// Returns Ok(None) if no cert exists, no PeerShared event exists, or the binding already exists.
/// Returns Ok(Some(event_id)) if a new TransportKey event was created.
///
/// Requires the PeerShared signing key to sign the TransportKey event.
pub fn ensure_transport_key_event(
    conn: &Connection,
    recorded_by: &str,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<Option<[u8; 32]>, Box<dyn std::error::Error + Send + Sync>> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let cert_bytes = match load_local_creds(conn, recorded_by)? {
        Some((cert, _)) => cert,
        None => return Ok(None),
    };

    let spki_fp = extract_spki_fingerprint(&cert_bytes)?;

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

    // Find the PeerShared event whose public key matches the provided signing key.
    let local_pubkey = signing_key.verifying_key().to_bytes();
    let peer_shared_eid: Option<[u8; 32]> = match conn.query_row(
        "SELECT event_id FROM peers_shared WHERE recorded_by = ?1 AND public_key = ?2 LIMIT 1",
        rusqlite::params![recorded_by, local_pubkey.as_slice()],
        |row| row.get::<_, String>(0),
    ) {
        Ok(eid_b64) => crate::crypto::event_id_from_base64(&eid_b64),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(e) => return Err(e.into()),
    };

    let peer_shared_eid = match peer_shared_eid {
        Some(eid) => eid,
        None => return Ok(None),
    };

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let evt = ParsedEvent::TransportKey(TransportKeyEvent {
        created_at_ms: now_ms,
        spki_fingerprint: spki_fp,
        signed_by: peer_shared_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });

    let event_id = create_signed_event_sync(conn, recorded_by, &evt, signing_key)
        .map_err(|e| format!("failed to create transport key event: {:?}", e))?;

    Ok(Some(event_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;
    use ed25519_dalek::SigningKey;

    #[test]
    fn test_expected_invite_bootstrap_spki_is_deterministic() {
        let invite_key = SigningKey::from_bytes(&[9u8; 32]);
        let fp1 = expected_invite_bootstrap_spki_from_invite_key(&invite_key).unwrap();
        let fp2 = expected_invite_bootstrap_spki_from_invite_key(&invite_key).unwrap();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_ensure_transport_peer_id_generates_and_persists() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let id1 = ensure_transport_peer_id(&conn).unwrap();
        let id2 = ensure_transport_peer_id(&conn).unwrap();
        assert_eq!(id1, id2, "should return same identity on second call");
        assert_eq!(id1.len(), 64, "should be 32-byte hex");
    }

    #[test]
    fn test_load_transport_peer_id_fails_when_empty() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        assert!(load_transport_peer_id(&conn).is_err());
    }

    #[test]
    fn test_load_transport_peer_id_succeeds_after_ensure() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let ensured = ensure_transport_peer_id(&conn).unwrap();
        let loaded = load_transport_peer_id(&conn).unwrap();
        assert_eq!(ensured, loaded);
    }

    #[test]
    fn test_ensure_transport_cert_returns_valid_cert() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let (peer_id, cert, key) = ensure_transport_cert(&conn).unwrap();
        assert!(!cert.as_ref().is_empty());
        assert!(!key.secret_pkcs8_der().is_empty());

        // Verify fingerprint matches peer_id
        let fp = extract_spki_fingerprint(cert.as_ref()).unwrap();
        assert_eq!(hex::encode(fp), peer_id);
    }

    #[test]
    fn test_install_invite_bootstrap_transport_identity_roundtrip() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let invite_key = SigningKey::from_bytes(&[7u8; 32]);

        let installed =
            install_invite_bootstrap_transport_identity_conn(&conn, &invite_key).unwrap();
        let loaded = load_transport_peer_id(&conn).unwrap();
        assert_eq!(installed, loaded);

        let expected =
            hex::encode(expected_invite_bootstrap_spki_from_invite_key(&invite_key).unwrap());
        assert_eq!(loaded, expected);
    }

    /// Regression: random cert → deterministic install must not leave two rows.
    /// Previously `load_sole_local_creds()` would error with "Multiple local identities".
    #[test]
    fn test_install_after_random_cert_replaces_not_duplicates() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        // Step 1: generate a random transport identity (as Account::new does)
        let random_id = ensure_transport_peer_id(&conn).unwrap();
        assert_eq!(random_id.len(), 64);

        // Step 2: install deterministic identity from invite key
        let invite_key = SigningKey::from_bytes(&[42u8; 32]);
        let deterministic_id =
            install_invite_bootstrap_transport_identity_conn(&conn, &invite_key).unwrap();

        // The two identities should differ
        assert_ne!(random_id, deterministic_id);

        // load_sole_local_creds must succeed (exactly 1 row)
        let (loaded_id, _, _) = crate::db::transport_creds::load_sole_local_creds(&conn)
            .expect("load_sole_local_creds should not error")
            .expect("should have exactly one row");
        assert_eq!(loaded_id, deterministic_id);

        // Verify there's only 1 row
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM local_transport_creds", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1, "should have exactly 1 row, not {}", count);
    }
}
