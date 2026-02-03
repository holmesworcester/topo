use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

/// Generate a new Ed25519 keypair
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Generate a self-signed certificate with a new keypair
/// Returns the certificate and private key in PKCS#8 format
pub fn generate_self_signed_cert(
    _signing_key: &SigningKey,
) -> Result<
    (CertificateDer<'static>, PrivatePkcs8KeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    // Use rcgen's simple self-signed generator
    let subject_alt_names = vec!["localhost".to_string()];
    let cert = generate_simple_self_signed(subject_alt_names)?;

    let cert_der = CertificateDer::from(cert.serialize_der()?);
    let key_der = PrivatePkcs8KeyDer::from(cert.serialize_private_key_der());

    Ok((cert_der, key_der))
}

/// Extract the public key bytes from the signing key
pub fn pubkey_bytes(signing_key: &SigningKey) -> [u8; 32] {
    signing_key.verifying_key().to_bytes()
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
        let (signing_key, _) = generate_keypair();
        let result = generate_self_signed_cert(&signing_key);
        if let Err(ref e) = result {
            eprintln!("Error: {:?}", e);
        }
        assert!(result.is_ok(), "Failed to generate cert: {:?}", result.err());

        let (cert_der, key_der) = result.unwrap();
        assert!(!cert_der.is_empty());
        assert!(!key_der.secret_pkcs8_der().is_empty());
    }

    #[test]
    fn test_pubkey_bytes() {
        let (signing_key, verifying_key) = generate_keypair();
        let bytes = pubkey_bytes(&signing_key);
        assert_eq!(bytes, verifying_key.to_bytes());
    }
}
