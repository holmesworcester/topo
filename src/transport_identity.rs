use rusqlite::Connection;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::events::{LocalTlsCredentialEvent, ParsedEvent, TransportKeyEvent};
use crate::projection::create::create_event_sync;
use crate::transport::{
    extract_spki_fingerprint, generate_self_signed_cert, generate_self_signed_cert_from_signing_key,
    load_cert_from_db, load_or_generate_cert_db, store_cert_in_db,
};

// ---------------------------------------------------------------------------
// Event-backed credential helpers
// ---------------------------------------------------------------------------

/// Load the active TLS credential from the event-backed `local_tls_credentials` table.
/// Returns `(cert_der, key_der, spki_fingerprint_hex)` or `None` if no credential exists.
pub fn load_active_tls_credential(
    conn: &Connection,
) -> Result<Option<(Vec<u8>, Vec<u8>, String)>, Box<dyn std::error::Error + Send + Sync>> {
    let result: Result<(Vec<u8>, Vec<u8>, String), _> = conn.query_row(
        "SELECT cert_der, key_der, spki_fingerprint
         FROM local_tls_credentials
         WHERE is_active = 1
         ORDER BY created_at DESC
         LIMIT 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    );
    match result {
        Ok(triple) => Ok(Some(triple)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Create a `LocalTlsCredentialEvent` and project it into the database.
/// Returns the hex-encoded SPKI fingerprint.
pub fn store_tls_credential_event(
    conn: &Connection,
    recorded_by: &str,
    cert_der: &[u8],
    key_der: &[u8],
    created_at_ms: u64,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let fp = extract_spki_fingerprint(cert_der)?;
    let evt = ParsedEvent::LocalTlsCredential(LocalTlsCredentialEvent {
        created_at_ms,
        cert_der: cert_der.to_vec(),
        key_der: key_der.to_vec(),
    });
    create_event_sync(conn, recorded_by, &evt)?;
    Ok(hex::encode(fp))
}

/// Ensure event-backed transport identity exists in SQLite.
///
/// 1. If SQLite `local_tls_credentials` has an active credential → return its SPKI hex.
/// 2. If no event-backed credential but `local_transport_credentials` has one → migrate it
///    into the event store.
/// 3. If neither exists → generate a fresh cert, store as event, also write to legacy table.
///
/// Returns the hex SPKI fingerprint.
pub fn ensure_transport_identity_from_db(
    conn: &Connection,
    recorded_by: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    // Step 1: Check event-backed table
    if let Some((_cert, _key, spki_hex)) = load_active_tls_credential(conn)? {
        return Ok(spki_hex);
    }

    // Step 2: Check legacy local_transport_credentials for migration
    if let Some((cert_der, key_der)) = load_cert_from_db(conn)? {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let spki_hex = store_tls_credential_event(
            conn,
            recorded_by,
            cert_der.as_ref(),
            key_der.secret_pkcs8_der(),
            now_ms,
        )?;
        return Ok(spki_hex);
    }

    // Step 3: Fresh install — generate new cert
    let (cert_der, key_der) = generate_self_signed_cert()?;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    // Store in event log
    let spki_hex = store_tls_credential_event(
        conn,
        recorded_by,
        cert_der.as_ref(),
        key_der.secret_pkcs8_der(),
        now_ms,
    )?;
    // Also store in legacy table for backward compatibility
    store_cert_in_db(conn, &cert_der, &key_der)?;
    Ok(spki_hex)
}

// ---------------------------------------------------------------------------
// Public API (existing functions preserved/updated)
// ---------------------------------------------------------------------------

/// Load local transport peer identity from existing credentials in SQLite.
/// Fails if no credential exists. Use this for read/query commands that should
/// not silently generate a new identity.
///
/// Tries event-backed table first, then falls back to legacy table.
pub fn load_transport_peer_id(
    conn: &Connection,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    // Try event-backed table first
    if let Some((_cert, _key, spki_hex)) = load_active_tls_credential(conn)? {
        return Ok(spki_hex);
    }
    // Fall back to legacy table
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
///
/// Also stores a `LocalTlsCredentialEvent` so the credential is event-backed.
pub fn install_invite_bootstrap_transport_identity(
    conn: &Connection,
    invite_key: &ed25519_dalek::SigningKey,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let (cert_der, key_der) = generate_self_signed_cert_from_signing_key(invite_key)?;
    // Store in legacy table
    let fp = store_cert_in_db(conn, &cert_der, &key_der)?;
    let spki_hex = hex::encode(fp);

    // Also store as event — use spki_hex as recorded_by (the peer's own identity)
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let _ = store_tls_credential_event(
        conn,
        &spki_hex,
        cert_der.as_ref(),
        key_der.secret_pkcs8_der(),
        now_ms,
    );

    Ok(spki_hex)
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
    // Try event-backed credential first, then fall back to legacy
    let spki_fp = if let Some((_cert, _key, spki_hex)) = load_active_tls_credential(conn)? {
        let mut fp = [0u8; 32];
        let bytes = hex::decode(&spki_hex)
            .map_err(|e| format!("invalid spki hex: {}", e))?;
        if bytes.len() != 32 {
            return Err("invalid spki fingerprint length".into());
        }
        fp.copy_from_slice(&bytes);
        fp
    } else {
        // Fall back to legacy table
        let (cert_der, _) = match load_cert_from_db(conn)? {
            Some(pair) => pair,
            None => return Ok(None),
        };
        extract_spki_fingerprint(cert_der.as_ref())?
    };

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

    #[test]
    fn test_load_active_tls_credential_empty() {
        let tmpdir = tempfile::tempdir().unwrap();
        let db_path = tmpdir.path().join("peer.db").to_str().unwrap().to_string();
        let conn = crate::db::open_connection(&db_path).unwrap();
        crate::db::schema::create_tables(&conn).unwrap();

        assert!(load_active_tls_credential(&conn).unwrap().is_none());
    }

    #[test]
    fn test_store_and_load_tls_credential_event() {
        let tmpdir = tempfile::tempdir().unwrap();
        let db_path = tmpdir.path().join("peer.db").to_str().unwrap().to_string();
        let conn = crate::db::open_connection(&db_path).unwrap();
        crate::db::schema::create_tables(&conn).unwrap();

        // Generate a cert so we have valid DER blobs
        let (cert_der, key_der) = generate_self_signed_cert().unwrap();
        let expected_fp = hex::encode(extract_spki_fingerprint(cert_der.as_ref()).unwrap());

        let recorded_by = "test_peer_id";
        let spki_hex = store_tls_credential_event(
            &conn,
            recorded_by,
            cert_der.as_ref(),
            key_der.secret_pkcs8_der(),
            1700000000000,
        )
        .unwrap();
        assert_eq!(spki_hex, expected_fp);

        // Verify it's now active
        let active = load_active_tls_credential(&conn).unwrap();
        assert!(active.is_some());
        let (loaded_cert, loaded_key, loaded_fp) = active.unwrap();
        assert_eq!(loaded_cert, cert_der.as_ref());
        assert_eq!(loaded_key, key_der.secret_pkcs8_der());
        assert_eq!(loaded_fp, expected_fp);
    }

    #[test]
    fn test_credential_rotation_latest_wins() {
        let tmpdir = tempfile::tempdir().unwrap();
        let db_path = tmpdir.path().join("peer.db").to_str().unwrap().to_string();
        let conn = crate::db::open_connection(&db_path).unwrap();
        crate::db::schema::create_tables(&conn).unwrap();

        let recorded_by = "test_peer_id";

        // Store first cert at t=1000
        let (cert1, key1) = generate_self_signed_cert().unwrap();
        let fp1 = store_tls_credential_event(
            &conn,
            recorded_by,
            cert1.as_ref(),
            key1.secret_pkcs8_der(),
            1000,
        )
        .unwrap();

        // Store second cert at t=2000
        let (cert2, key2) = generate_self_signed_cert().unwrap();
        let fp2 = store_tls_credential_event(
            &conn,
            recorded_by,
            cert2.as_ref(),
            key2.secret_pkcs8_der(),
            2000,
        )
        .unwrap();

        assert_ne!(fp1, fp2);

        // Active credential should be the second one (latest-wins)
        let active = load_active_tls_credential(&conn).unwrap().unwrap();
        assert_eq!(active.2, fp2);

        // First credential should be inactive
        let first_active: bool = conn
            .query_row(
                "SELECT is_active FROM local_tls_credentials WHERE recorded_by = ?1 AND spki_fingerprint = ?2",
                rusqlite::params![recorded_by, &fp1],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!first_active);
    }

    #[test]
    fn test_ensure_transport_identity_from_db_fresh_install() {
        let tmpdir = tempfile::tempdir().unwrap();
        let db_path = tmpdir.path().join("peer.db").to_str().unwrap().to_string();
        let conn = crate::db::open_connection(&db_path).unwrap();
        crate::db::schema::create_tables(&conn).unwrap();

        let recorded_by = "fresh_peer_id";
        let spki_hex = ensure_transport_identity_from_db(&conn, recorded_by).unwrap();

        // Should be a valid hex string of 64 chars (32 bytes)
        assert_eq!(spki_hex.len(), 64);

        // Should now be loadable from event-backed table
        let active = load_active_tls_credential(&conn).unwrap();
        assert!(active.is_some());
        assert_eq!(active.unwrap().2, spki_hex);

        // Calling again should return same fingerprint (idempotent)
        let spki_hex2 = ensure_transport_identity_from_db(&conn, recorded_by).unwrap();
        assert_eq!(spki_hex, spki_hex2);
    }

    #[test]
    fn test_ensure_transport_identity_migrates_legacy() {
        let tmpdir = tempfile::tempdir().unwrap();
        let db_path = tmpdir.path().join("peer.db").to_str().unwrap().to_string();
        let conn = crate::db::open_connection(&db_path).unwrap();
        crate::db::schema::create_tables(&conn).unwrap();

        // Store a cert in legacy table only
        let (cert_der, key_der) = generate_self_signed_cert().unwrap();
        let legacy_fp = hex::encode(store_cert_in_db(&conn, &cert_der, &key_der).unwrap());

        // No event-backed credential yet
        assert!(load_active_tls_credential(&conn).unwrap().is_none());

        let recorded_by = "migrating_peer";
        let spki_hex = ensure_transport_identity_from_db(&conn, recorded_by).unwrap();

        // Should match the legacy fingerprint
        assert_eq!(spki_hex, legacy_fp);

        // Should now be in the event-backed table
        let active = load_active_tls_credential(&conn).unwrap();
        assert!(active.is_some());
        assert_eq!(active.unwrap().2, legacy_fp);
    }
}
