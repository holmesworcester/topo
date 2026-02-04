pub mod cert;
pub mod connection;

pub use cert::{generate_keypair, generate_self_signed_cert};
pub use connection::{Connection, DualConnection, SplitDualConnection, SendHalf, RecvHalf};

use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Create transport config with appropriate timeouts for large syncs
fn create_transport_config() -> TransportConfig {
    let mut config = TransportConfig::default();
    // 5 minute idle timeout for large transfers
    config.max_idle_timeout(Some(Duration::from_secs(300).try_into().unwrap()));
    // Keep-alive to prevent idle timeout during slow transfers
    config.keep_alive_interval(Some(Duration::from_secs(10)));
    config
}

/// Create a QUIC server endpoint
pub fn create_server_endpoint(
    bind_addr: SocketAddr,
    cert_der: CertificateDer<'static>,
    key_der: PrivatePkcs8KeyDer<'static>,
) -> Result<Endpoint, Box<dyn std::error::Error + Send + Sync>> {
    let server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der.into())?;

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    ));
    server_config.transport_config(Arc::new(create_transport_config()));

    let endpoint = Endpoint::server(server_config, bind_addr)?;
    Ok(endpoint)
}

/// Create a QUIC client endpoint
pub fn create_client_endpoint(
    bind_addr: SocketAddr,
) -> Result<Endpoint, Box<dyn std::error::Error + Send + Sync>> {
    // Client config that skips certificate verification (for self-signed certs)
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));
    client_config.transport_config(Arc::new(create_transport_config()));

    let mut endpoint = Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
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
