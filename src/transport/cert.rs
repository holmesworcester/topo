use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rcgen::{generate_simple_self_signed, Certificate, CertificateParams, KeyPair, PKCS_ED25519};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
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

/// Generate a deterministic self-signed Ed25519 certificate from an existing
/// signing key. This is used for invite bootstrap identities so both inviter
/// and invitee can derive the same expected transport SPKI fingerprint.
pub fn generate_self_signed_cert_from_signing_key(
    signing_key: &SigningKey,
) -> Result<
    (CertificateDer<'static>, PrivatePkcs8KeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let pkcs8 = signing_key.to_pkcs8_der()?;
    let key_bytes = pkcs8.as_bytes().to_vec();

    let key_pair = KeyPair::from_der(&key_bytes)
        .map_err(|e| format!("failed to parse invite signing key as PKCS#8: {}", e))?;

    let mut params = CertificateParams::new(vec!["localhost".to_string()]);
    params.alg = &PKCS_ED25519;
    params.key_pair = Some(key_pair);

    let cert = Certificate::from_params(params)
        .map_err(|e| format!("failed to build deterministic certificate params: {}", e))?;
    let cert_der = CertificateDer::from(cert.serialize_der()?);
    let key_der = PrivatePkcs8KeyDer::from(key_bytes);

    validate_cert_key_match(&cert_der, &key_der)?;
    Ok((cert_der, key_der))
}

/// Validate that the certificate's public key matches the private key.
///
/// Derives the public key from the private key via rcgen and compares the
/// raw SPKI bytes against those in the certificate. This catches mismatched
/// cert/key pairs and data corruption.
pub fn validate_cert_key_match(
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
        )
        .into());
    }

    Ok(())
}

/// Compute the SPKI fingerprint (BLAKE2b-256) from raw Ed25519 public key bytes.
///
/// Constructs the DER-encoded SubjectPublicKeyInfo for Ed25519 and hashes it.
/// This gives the same result as `extract_spki_fingerprint` on a cert generated
/// from the corresponding signing key via `generate_self_signed_cert_from_signing_key`.
pub fn spki_fingerprint_from_ed25519_pubkey(pubkey: &[u8; 32]) -> [u8; 32] {
    // Ed25519 SubjectPublicKeyInfo DER encoding:
    //   SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING { 0x00, <32 key bytes> } }
    let mut spki = Vec::with_capacity(44);
    spki.extend_from_slice(&[
        0x30, 0x2a, // SEQUENCE (42 bytes)
        0x30, 0x05, // SEQUENCE (5 bytes) - AlgorithmIdentifier
        0x06, 0x03, // OID (3 bytes)
        0x2b, 0x65, 0x70, // 1.3.101.112 = Ed25519
        0x03, 0x21, // BIT STRING (33 bytes)
        0x00, // unused bits = 0
    ]);
    spki.extend_from_slice(pubkey);

    let mut hasher = Blake2b::<U32>::new();
    hasher.update(&spki);
    let result = hasher.finalize();
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&result);
    fp
}

/// Extract SPKI from a DER-encoded certificate and hash it with BLAKE2b-256.
pub fn extract_spki_fingerprint(
    cert_der: &[u8],
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
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
        assert!(
            result.is_ok(),
            "Failed to generate cert: {:?}",
            result.err()
        );

        let (cert_der, key_der) = result.unwrap();
        assert!(!cert_der.is_empty());
        assert!(!key_der.secret_pkcs8_der().is_empty());
    }

    #[test]
    fn test_deterministic_cert_from_signing_key() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let (cert1, key1) = generate_self_signed_cert_from_signing_key(&key).unwrap();
        let (cert2, key2) = generate_self_signed_cert_from_signing_key(&key).unwrap();

        let fp1 = extract_spki_fingerprint(cert1.as_ref()).unwrap();
        let fp2 = extract_spki_fingerprint(cert2.as_ref()).unwrap();
        assert_eq!(fp1, fp2);
        assert_eq!(cert1.as_ref(), cert2.as_ref());
        assert_eq!(key1.secret_pkcs8_der(), key2.secret_pkcs8_der());
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
    fn test_spki_fingerprint_from_pubkey_matches_cert() {
        let key = SigningKey::from_bytes(&[42u8; 32]);
        let pubkey = key.verifying_key().to_bytes();
        let fp_direct = spki_fingerprint_from_ed25519_pubkey(&pubkey);
        let (cert, _) = generate_self_signed_cert_from_signing_key(&key).unwrap();
        let fp_cert = extract_spki_fingerprint(cert.as_ref()).unwrap();
        assert_eq!(fp_direct, fp_cert,
            "direct pubkey SPKI fingerprint must match cert-derived fingerprint");
    }

    #[test]
    fn test_validate_cert_key_match_detects_mismatch() {
        let (cert1, _) = generate_self_signed_cert().unwrap();
        let (_, key2) = generate_self_signed_cert().unwrap();
        let result = validate_cert_key_match(&cert1, &key2);
        assert!(result.is_err(), "expected error for mismatched cert/key pair");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("cert/key mismatch"), "error should mention mismatch: {}", err);
    }
}
