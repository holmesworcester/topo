use std::path::{Path, PathBuf};

use crate::transport::{extract_spki_fingerprint, load_or_generate_cert};

/// Derive cert/key file paths from a DB path (e.g. "alice.db" -> "alice.cert.der", "alice.key.der")
pub fn cert_paths_from_db(db_path: &str) -> (PathBuf, PathBuf) {
    let base = Path::new(db_path);
    let stem = base.file_stem().unwrap_or_default().to_str().unwrap_or("peer");
    let dir = base.parent().unwrap_or_else(|| Path::new("."));
    let cert_path = dir.join(format!("{}.cert.der", stem));
    let key_path = dir.join(format!("{}.key.der", stem));
    (cert_path, key_path)
}

/// Compute the local peer identity (hex SPKI fingerprint) from the DB-derived cert path.
pub fn local_identity_from_db(db_path: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = cert_paths_from_db(db_path);
    let (cert_der, _) = load_or_generate_cert(&cert_path, &key_path)?;
    let fp = extract_spki_fingerprint(cert_der.as_ref())?;
    Ok(hex::encode(fp))
}
