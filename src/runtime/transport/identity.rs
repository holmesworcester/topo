use rusqlite::Connection;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use crate::db::transport_creds::{load_sole_local_creds, load_local_creds, store_local_creds};
use super::{
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

/// Compute the local transport peer identity (hex SPKI fingerprint), generating a
/// **random** cert if none exists.
///
/// **Bootstrap-only**: this path generates a throwaway random identity that will be
/// replaced by a deterministic event-derived identity (via the transport identity adapter)
/// during workspace bootstrap or invite
/// acceptance. Production code that expects a stable identity should use
/// `load_transport_peer_id` instead, which fails if no credentials exist rather than
/// silently generating new ones.
///
/// Acceptable callers: `Peer::new()` in test harness, initial CLI `transport-identity`
/// command before any workspace exists. All other paths must go through the event-derived
/// identity flow (bootstrap_workspace → install_peer_key_transport_identity).
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
///
/// **Bootstrap-only**: generates a random identity if none exists. See
/// `ensure_transport_peer_id` docs for authority semantics. Production sync/connect
/// code should use `load_transport_cert_required` which fails rather than silently
/// generating a new identity.
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

/// Load existing transport credentials. Returns error if none exist.
///
/// This is the **production** path for loading transport identity. Unlike
/// `ensure_transport_cert`, it never silently generates a new random identity.
/// The caller must have already established identity through the event-derived
/// flow (bootstrap_workspace, accept_invite, or install_peer_key_transport_identity).
pub fn load_transport_cert_required(
    conn: &Connection,
) -> Result<
    (String, CertificateDer<'static>, PrivatePkcs8KeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    match load_sole_local_creds(conn)? {
        Some((peer_id, cert_bytes, key_bytes)) => {
            let cert_der = CertificateDer::from(cert_bytes);
            let key_der = PrivatePkcs8KeyDer::from(key_bytes);
            Ok((peer_id, cert_der, key_der))
        }
        None => Err(
            "Transport identity not found. Identity must be established through workspace \
             bootstrap or invite acceptance before transport operations. \
             No silent regeneration — event-derived identity is the sole authority."
                .into(),
        ),
    }
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
/// Bootstrap-only convenience wrapper that opens its own connection.
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

/// Load existing transport credentials from DB. Fails if none exist.
/// Production convenience wrapper — never silently generates new identity.
pub fn load_transport_cert_required_from_db(
    db_path: &str,
) -> Result<
    (String, CertificateDer<'static>, PrivatePkcs8KeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let conn = crate::db::open_connection(db_path)?;
    crate::db::schema::create_tables(&conn)?;
    load_transport_cert_required(&conn)
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
// Invite bootstrap identity materialization
// ---------------------------------------------------------------------------

/// Install a deterministic transport cert/key derived from the invite signing
/// key into the database. This makes invitee transport identity predictable
/// from invite material so inviter-side bootstrap trust can be precomputed.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;
    use ed25519_dalek::SigningKey;

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

        let expected = {
            let (cert_der, _) = generate_self_signed_cert_from_signing_key(&invite_key).unwrap();
            hex::encode(extract_spki_fingerprint(cert_der.as_ref()).unwrap())
        };
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

    #[test]
    fn test_load_transport_cert_required_fails_when_empty() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let err = load_transport_cert_required(&conn).unwrap_err();
        assert!(
            err.to_string().contains("Transport identity not found"),
            "should fail with clear message, got: {}",
            err
        );
    }

    #[test]
    fn test_load_transport_cert_required_succeeds_after_install() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        // Install deterministic identity
        let key = SigningKey::from_bytes(&[99u8; 32]);
        let installed = install_peer_key_transport_identity(&conn, &key).unwrap();

        // load_transport_cert_required should succeed
        let (peer_id, cert, _key) = load_transport_cert_required(&conn).unwrap();
        assert_eq!(peer_id, installed);
        assert!(!cert.as_ref().is_empty());
    }

    #[test]
    fn test_load_transport_cert_required_never_generates() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        // Calling load_transport_cert_required on empty DB must fail, not generate
        assert!(load_transport_cert_required(&conn).is_err());

        // Verify no row was created
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM local_transport_creds", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "load_transport_cert_required must never generate creds");
    }
}
