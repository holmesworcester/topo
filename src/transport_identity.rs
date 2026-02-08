use std::path::{Path, PathBuf};

use rusqlite::Connection;

use crate::events::{ParsedEvent, TransportKeyEvent};
use crate::projection::create::create_signed_event_sync;
use crate::transport::{extract_spki_fingerprint, load_or_generate_cert};

/// Derive cert/key file paths from a DB path (e.g. "alice.db" -> "alice.cert.der", "alice.key.der")
pub fn transport_cert_paths_from_db(db_path: &str) -> (PathBuf, PathBuf) {
    let base = Path::new(db_path);
    let stem = base.file_stem().unwrap_or_default().to_str().unwrap_or("peer");
    let dir = base.parent().unwrap_or_else(|| Path::new("."));
    let cert_path = dir.join(format!("{}.cert.der", stem));
    let key_path = dir.join(format!("{}.key.der", stem));
    (cert_path, key_path)
}

/// Load local transport peer identity from existing cert files. Fails if cert is missing.
/// Use this for read/query commands that should not silently generate a new identity.
pub fn load_transport_peer_id_from_db(db_path: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
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
pub fn ensure_transport_peer_id_from_db(db_path: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = transport_cert_paths_from_db(db_path);
    let (cert_der, _) = load_or_generate_cert(&cert_path, &key_path)?;
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

    // Find a PeerShared event for this peer — needed as signer
    let peer_shared_eid: Option<[u8; 32]> = match conn.query_row(
        "SELECT event_id FROM peers_shared WHERE recorded_by = ?1 LIMIT 1",
        rusqlite::params![recorded_by],
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
