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

/// Load local peer identity from existing cert files. Fails if cert is missing.
/// Use this for read/query commands that should not silently generate a new identity.
pub fn load_identity_from_db(db_path: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = cert_paths_from_db(db_path);
    if !cert_path.exists() || !key_path.exists() {
        return Err(format!(
            "Identity not found: cert or key missing at {} / {}. Run 'identity' or 'send' first to generate.",
            cert_path.display(),
            key_path.display(),
        ).into());
    }
    let cert_bytes = std::fs::read(&cert_path)?;
    let fp = extract_spki_fingerprint(&cert_bytes)?;
    Ok(hex::encode(fp))
}

/// Compute the local peer identity (hex SPKI fingerprint), generating cert if needed.
/// Use this for bootstrap commands (identity, send, generate, sync).
pub fn local_identity_from_db(db_path: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = cert_paths_from_db(db_path);
    let (cert_der, _) = load_or_generate_cert(&cert_path, &key_path)?;
    let fp = extract_spki_fingerprint(cert_der.as_ref())?;
    Ok(hex::encode(fp))
}
