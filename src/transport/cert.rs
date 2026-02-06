use blake2::{Blake2b, Digest};
use blake2::digest::consts::U32;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::io::Write;
use std::path::Path;
use x509_parser::prelude::*;

/// Generate a new Ed25519 keypair (for future event signing, not TLS)
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Generate a self-signed certificate with a new keypair.
/// Returns the certificate and private key in PKCS#8 format.
pub fn generate_self_signed_cert() -> Result<
    (CertificateDer<'static>, PrivatePkcs8KeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let subject_alt_names = vec!["localhost".to_string()];
    let cert = generate_simple_self_signed(subject_alt_names)?;

    let cert_der = CertificateDer::from(cert.serialize_der()?);
    let key_der = PrivatePkcs8KeyDer::from(cert.serialize_private_key_der());

    Ok((cert_der, key_der))
}

/// Load a cert/key from disk, or generate and save new ones.
///
/// Persistence hardening:
/// - Writes via temp file + fsync + rename (atomic replacement, crash-safe).
/// - Sets private key file to mode 0600 on Unix.
/// - Validates that the loaded cert's public key matches the private key.
pub fn load_or_generate_cert(
    cert_path: &Path,
    key_path: &Path,
) -> Result<
    (CertificateDer<'static>, PrivatePkcs8KeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    if cert_path.exists() && key_path.exists() {
        let cert_bytes = std::fs::read(cert_path)?;
        let key_bytes = std::fs::read(key_path)?;
        let cert_der = CertificateDer::from(cert_bytes);
        let key_der = PrivatePkcs8KeyDer::from(key_bytes);
        validate_cert_key_match(&cert_der, &key_der)?;
        #[cfg(unix)]
        if let Err(e) = set_owner_only_permissions(key_path) {
            eprintln!("warning: could not normalize key permissions on {}: {}", key_path.display(), e);
        }
        Ok((cert_der, key_der))
    } else {
        let (cert_der, key_der) = generate_self_signed_cert()?;
        atomic_write(cert_path, cert_der.as_ref())?;
        atomic_write(key_path, key_der.secret_pkcs8_der())?;
        #[cfg(unix)]
        set_owner_only_permissions(key_path)?;
        Ok((cert_der, key_der))
    }
}

/// Write data atomically: write to a temporary sibling file, fsync, then rename.
fn atomic_write(path: &Path, data: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let parent = path.parent().unwrap_or(Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(data)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path)?;
    Ok(())
}

/// Set file permissions to owner-only (0600) on Unix.
#[cfg(unix)]
fn set_owner_only_permissions(path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

/// Validate that the certificate's public key matches the private key.
///
/// Derives the public key from the private key via rcgen and compares the
/// raw SPKI bytes against those in the certificate. This catches mismatched
/// cert/key files and file corruption.
fn validate_cert_key_match(
    cert_der: &CertificateDer<'_>,
    key_der: &PrivatePkcs8KeyDer<'_>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Extract SPKI from certificate
    let (_, cert) = X509Certificate::from_der(cert_der.as_ref())
        .map_err(|e| format!("failed to parse certificate: {}", e))?;
    let cert_spki = cert.public_key().raw;

    // Derive public key from private key via rcgen
    let key_pair = rcgen::KeyPair::from_der(key_der.secret_pkcs8_der())
        .map_err(|e| format!("failed to parse private key: {}", e))?;
    let key_spki = key_pair.public_key_der();

    if cert_spki != key_spki.as_slice() {
        return Err(format!(
            "cert/key mismatch: certificate SPKI ({} bytes) does not match \
             private key's public component ({} bytes)",
            cert_spki.len(),
            key_spki.len(),
        ).into());
    }

    Ok(())
}

/// Extract SPKI from a DER-encoded certificate and hash it with BLAKE2b-256.
pub fn extract_spki_fingerprint(cert_der: &[u8]) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| format!("failed to parse X.509 certificate: {}", e))?;
    let spki_bytes = cert.public_key().raw;
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(spki_bytes);
    let result = hasher.finalize();
    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(&result);
    Ok(fingerprint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let (signing, verifying) = generate_keypair();
        assert_eq!(signing.verifying_key(), verifying);
    }

    #[test]
    fn test_generate_cert() {
        let result = generate_self_signed_cert();
        assert!(result.is_ok(), "Failed to generate cert: {:?}", result.err());

        let (cert_der, key_der) = result.unwrap();
        assert!(!cert_der.is_empty());
        assert!(!key_der.secret_pkcs8_der().is_empty());
    }

    #[test]
    fn test_spki_fingerprint_deterministic() {
        let (cert_der, _) = generate_self_signed_cert().unwrap();
        let fp1 = extract_spki_fingerprint(cert_der.as_ref()).unwrap();
        let fp2 = extract_spki_fingerprint(cert_der.as_ref()).unwrap();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_spki_fingerprint_different_certs() {
        let (cert1, _) = generate_self_signed_cert().unwrap();
        let (cert2, _) = generate_self_signed_cert().unwrap();
        let fp1 = extract_spki_fingerprint(cert1.as_ref()).unwrap();
        let fp2 = extract_spki_fingerprint(cert2.as_ref()).unwrap();
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_cert_persistence_roundtrip() {
        let tmpdir = tempfile::tempdir().unwrap();
        let cert_path = tmpdir.path().join("test.cert.der");
        let key_path = tmpdir.path().join("test.key.der");

        let (cert1, key1) = load_or_generate_cert(&cert_path, &key_path).unwrap();
        let fp1 = extract_spki_fingerprint(cert1.as_ref()).unwrap();

        // Load again — should get same cert
        let (cert2, key2) = load_or_generate_cert(&cert_path, &key_path).unwrap();
        let fp2 = extract_spki_fingerprint(cert2.as_ref()).unwrap();

        assert_eq!(fp1, fp2);
        assert_eq!(cert1.as_ref(), cert2.as_ref());
        assert_eq!(key1.secret_pkcs8_der(), key2.secret_pkcs8_der());
    }

    #[test]
    fn test_cert_persistence_identical_fingerprint_after_reload() {
        let tmpdir = tempfile::tempdir().unwrap();
        let cert_path = tmpdir.path().join("reload.cert.der");
        let key_path = tmpdir.path().join("reload.key.der");

        let (cert1, _) = load_or_generate_cert(&cert_path, &key_path).unwrap();
        let fp1 = extract_spki_fingerprint(cert1.as_ref()).unwrap();

        // Simulate process restart — reload from persisted files
        let (cert2, _) = load_or_generate_cert(&cert_path, &key_path).unwrap();
        let fp2 = extract_spki_fingerprint(cert2.as_ref()).unwrap();

        assert_eq!(fp1, fp2, "fingerprint must be identical after reload");
    }

    #[test]
    fn test_mismatched_cert_key_detected() {
        let tmpdir = tempfile::tempdir().unwrap();
        let cert_path = tmpdir.path().join("mismatch.cert.der");
        let key_path = tmpdir.path().join("mismatch.key.der");

        // Generate and save first keypair
        let (_cert1, _key1) = load_or_generate_cert(&cert_path, &key_path).unwrap();

        // Overwrite key file with a different key
        let (_cert2, key2) = generate_self_signed_cert().unwrap();
        std::fs::write(&key_path, key2.secret_pkcs8_der()).unwrap();

        // Loading must detect the mismatch: cert SPKI != private key's public SPKI
        let result = load_or_generate_cert(&cert_path, &key_path);
        assert!(result.is_err(), "expected error for mismatched cert/key pair");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("cert/key mismatch"), "error should mention mismatch: {}", err);
    }

    #[cfg(unix)]
    #[test]
    fn test_private_key_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmpdir = tempfile::tempdir().unwrap();
        let cert_path = tmpdir.path().join("perms.cert.der");
        let key_path = tmpdir.path().join("perms.key.der");

        let _ = load_or_generate_cert(&cert_path, &key_path).unwrap();

        let metadata = std::fs::metadata(&key_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "private key should be owner-only (0600), got {:o}", mode);
    }
}
