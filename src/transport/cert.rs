use base64::Engine;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls_webpki::EndEntityCert;

pub struct SelfSignedCert {
    pub cert_der: CertificateDer<'static>,
    pub key_der: PrivatePkcs8KeyDer<'static>,
    pub spki_der: Vec<u8>,
}

/// Generate a self-signed certificate with a new keypair
/// Returns the certificate and private key in PKCS#8 format
pub fn generate_self_signed_cert(
)-> Result<SelfSignedCert, Box<dyn std::error::Error + Send + Sync>> {
    // Use rcgen's simple self-signed generator
    let subject_alt_names = vec!["localhost".to_string()];
    let cert = generate_simple_self_signed(subject_alt_names)?;

    let cert_der = CertificateDer::from(cert.serialize_der()?);
    let key_der = PrivatePkcs8KeyDer::from(cert.serialize_private_key_der());
    let spki_der = EndEntityCert::try_from(&cert_der)?
        .subject_public_key_info()
        .as_ref()
        .to_vec();

    Ok(SelfSignedCert {
        cert_der,
        key_der,
        spki_der,
    })
}

pub fn spki_to_base64(spki_der: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(spki_der)
}

pub fn spki_from_base64(
    spki_b64: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    Ok(base64::engine::general_purpose::STANDARD.decode(spki_b64)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_cert() {
        let result = generate_self_signed_cert();
        if let Err(ref e) = result {
            eprintln!("Error: {:?}", e);
        }
        assert!(result.is_ok(), "Failed to generate cert: {:?}", result.err());

        let cert = result.unwrap();
        assert!(!cert.cert_der.is_empty());
        assert!(!cert.key_der.secret_pkcs8_der().is_empty());
        assert!(!cert.spki_der.is_empty());
    }

}
