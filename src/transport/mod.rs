pub mod cert;
pub mod connection;
pub mod sim;
pub mod sync_conn;

pub use cert::{generate_self_signed_cert, spki_from_base64, spki_to_base64, SelfSignedCert};
pub use connection::Connection;
pub use sim::{create_sim_pair, SimConfig, SimConnection};
pub use sync_conn::SyncConnection;

use quinn::{ClientConfig, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::{CertificateError, DistinguishedName};
use rustls_webpki::EndEntityCert;
use std::net::SocketAddr;
use std::sync::Arc;

pub trait PeerKeyStore: Send + Sync {
    fn is_allowed(&self, spki_der: &[u8]) -> bool;
}

#[derive(Debug)]
pub struct StaticPeerKeyStore {
    allowed_spki: Vec<Vec<u8>>,
}

impl StaticPeerKeyStore {
    pub fn new(allowed_spki: Vec<Vec<u8>>) -> Self {
        Self { allowed_spki }
    }
}

impl PeerKeyStore for StaticPeerKeyStore {
    fn is_allowed(&self, spki_der: &[u8]) -> bool {
        self.allowed_spki
            .iter()
            .any(|allowed| allowed.as_slice() == spki_der)
    }
}

/// Create a QUIC server endpoint
pub fn create_server_endpoint(
    bind_addr: SocketAddr,
    cert_der: CertificateDer<'static>,
    key_der: PrivatePkcs8KeyDer<'static>,
    peer_store: Option<Arc<dyn PeerKeyStore>>,
) -> Result<Endpoint, Box<dyn std::error::Error + Send + Sync>> {
    let server_crypto = if let Some(store) = peer_store {
        rustls::ServerConfig::builder()
            .with_client_cert_verifier(Arc::new(PinnedCertVerifier::new(store)))
            .with_single_cert(vec![cert_der], key_der.into())?
    } else {
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der.into())?
    };

    let server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    ));

    let endpoint = Endpoint::server(server_config, bind_addr)?;
    Ok(endpoint)
}

/// Create a QUIC client endpoint
pub fn create_client_endpoint(
    bind_addr: SocketAddr,
    cert_der: CertificateDer<'static>,
    key_der: PrivatePkcs8KeyDer<'static>,
    peer_store: Option<Arc<dyn PeerKeyStore>>,
) -> Result<Endpoint, Box<dyn std::error::Error + Send + Sync>> {
    let crypto = if let Some(store) = peer_store {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedCertVerifier::new(store)))
            .with_client_auth_cert(vec![cert_der], key_der.into())?
    } else {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth()
    };

    let client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));

    let mut endpoint = Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

#[derive(Debug)]
struct PinnedCertVerifier {
    peer_store: Arc<dyn PeerKeyStore>,
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
    root_hints: Vec<DistinguishedName>,
}

impl PinnedCertVerifier {
    fn new(peer_store: Arc<dyn PeerKeyStore>) -> Self {
        Self {
            peer_store,
            supported: rustls::crypto::ring::default_provider().signature_verification_algorithms,
            root_hints: Vec::new(),
        }
    }

    fn verify_spki(&self, end_entity: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        let cert = EndEntityCert::try_from(end_entity)
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        let spki = cert.subject_public_key_info();
        if self.peer_store.is_allowed(spki.as_ref()) {
            Ok(())
        } else {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.verify_spki(end_entity)?;
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported.supported_schemes()
    }
}

impl rustls::verify::ClientCertVerifier for PinnedCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.root_hints
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::verify::ClientCertVerified, rustls::Error> {
        self.verify_spki(end_entity)?;
        Ok(rustls::verify::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::verify::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::verify::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported.supported_schemes()
    }
}

/// Skip server certificate verification (for self-signed certs in testing)
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mtls_allows_only_pinned_peer() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let server_id = generate_self_signed_cert()?;
        let client_id = generate_self_signed_cert()?;

        let server_store = Arc::new(StaticPeerKeyStore::new(vec![client_id.spki_der.clone()]));
        let client_store = Arc::new(StaticPeerKeyStore::new(vec![server_id.spki_der.clone()]));

        let server_endpoint = create_server_endpoint(
            "127.0.0.1:0".parse()?,
            server_id.cert_der,
            server_id.key_der,
            Some(server_store),
        )?;
        let server_addr = server_endpoint.local_addr()?;

        let server_task = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.ok_or("no incoming connection")?;
            let connection = incoming.await?;
            connection.close(0u32.into(), b"done");
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });

        let client_endpoint = create_client_endpoint(
            "0.0.0.0:0".parse()?,
            client_id.cert_der,
            client_id.key_der,
            Some(client_store),
        )?;
        let connection = client_endpoint.connect(server_addr, "localhost")?.await?;
        connection.close(0u32.into(), b"done");

        server_task.await??;
        Ok(())
    }
}
