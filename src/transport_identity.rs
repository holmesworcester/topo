use std::path::{Path, PathBuf};

use rusqlite::Connection;

use crate::events::{ParsedEvent, TransportKeyEvent};
use crate::projection::create::create_signed_event_sync;
use crate::transport::{
    extract_spki_fingerprint, generate_self_signed_cert_from_signing_key, load_or_generate_cert,
    write_cert_and_key,
};

/// Derive cert/key file paths from a DB path (e.g. "alice.db" -> "alice.cert.der", "alice.key.der")
pub fn transport_cert_paths_from_db(db_path: &str) -> (PathBuf, PathBuf) {
    let base = Path::new(db_path);
    let stem = base
        .file_stem()
        .unwrap_or_default()
        .to_str()
        .unwrap_or("peer");
    let dir = base.parent().unwrap_or_else(|| Path::new("."));
    let cert_path = dir.join(format!("{}.cert.der", stem));
    let key_path = dir.join(format!("{}.key.der", stem));
    (cert_path, key_path)
}

/// Load local transport peer identity from existing cert files. Fails if cert is missing.
/// Use this for read/query commands that should not silently generate a new identity.
pub fn load_transport_peer_id_from_db(
    db_path: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = transport_cert_paths_from_db(db_path);
    if !cert_path.exists() || !key_path.exists() {
        return Err(format!(
            "Transport identity not found: cert or key missing at {} / {}. Run 'transport-identity' or 'send' first to generate.",
            cert_path.display(),
            key_path.display(),
        ).into());
    }
    let cert_bytes = std::fs::read(&cert_path)?;
    let fp = extract_spki_fingerprint(&cert_bytes)?;
    Ok(hex::encode(fp))
}

/// Compute the local transport peer identity (hex SPKI fingerprint), generating cert if needed.
/// Use this for bootstrap commands (transport-identity, send, generate, sync).
pub fn ensure_transport_peer_id_from_db(
    db_path: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = transport_cert_paths_from_db(db_path);
    let (cert_der, _) = load_or_generate_cert(&cert_path, &key_path)?;
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
/// key. This makes invitee transport identity predictable from invite material
/// so inviter-side bootstrap trust can be precomputed without CLI pinning.
pub fn install_invite_bootstrap_transport_identity(
    db_path: &str,
    invite_key: &ed25519_dalek::SigningKey,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = transport_cert_paths_from_db(db_path);
    let (cert_der, key_der) = generate_self_signed_cert_from_signing_key(invite_key)?;
    write_cert_and_key(&cert_path, &key_path, &cert_der, &key_der)?;
    let fp = extract_spki_fingerprint(cert_der.as_ref())?;
    Ok(hex::encode(fp))
}

/// Ensure a TransportKey event exists for the local TLS cert's SPKI fingerprint.
/// Returns Ok(None) if no cert exists, no PeerShared event exists, or the binding already exists.
/// Returns Ok(Some(event_id)) if a new TransportKey event was created.
///
/// Requires the PeerShared signing key to sign the TransportKey event.
pub fn ensure_transport_key_event(
    conn: &Connection,
    recorded_by: &str,
    db_path: &str,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<Option<[u8; 32]>, Box<dyn std::error::Error + Send + Sync>> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let (cert_path, key_path) = transport_cert_paths_from_db(db_path);
    if !cert_path.exists() || !key_path.exists() {
        return Ok(None);
    }

    let cert_bytes = std::fs::read(&cert_path)?;
    let spki_fp = extract_spki_fingerprint(&cert_bytes)?;

    // Check if a TransportKey event already exists with this SPKI
    let already_exists: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM transport_keys WHERE recorded_by = ?1 AND spki_fingerprint = ?2",
        rusqlite::params![recorded_by, spki_fp.as_slice()],
        |row| row.get(0),
    ).unwrap_or(false);

    if already_exists {
        return Ok(None);
    }

    // Find the PeerShared event whose public key matches the provided signing key.
    // This ensures the selected signed_by event corresponds to the local identity,
    // not an arbitrary peer in the workspace.
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
        let db_path = tmpdir.path().join("peer.db");
        let db_path = db_path.to_str().unwrap();
        let invite_key = SigningKey::from_bytes(&[7u8; 32]);

        let installed = install_invite_bootstrap_transport_identity(db_path, &invite_key).unwrap();
        let loaded = load_transport_peer_id_from_db(db_path).unwrap();
        assert_eq!(installed, loaded);

        let expected =
            hex::encode(expected_invite_bootstrap_spki_from_invite_key(&invite_key).unwrap());
        assert_eq!(loaded, expected);
    }
}
