pub mod cert;
pub mod connection;

pub use cert::{
    extract_spki_fingerprint, generate_keypair, generate_self_signed_cert,
    generate_self_signed_cert_from_signing_key, load_or_generate_cert, write_cert_and_key,
};
pub use connection::{DualConnection, StreamConn, StreamRecv, StreamSend};

use quinn::{ClientConfig, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::warn;

/// Set of allowed peer fingerprints (BLAKE2b-256 of SPKI).
#[derive(Debug, Clone)]
pub struct AllowedPeers {
    fingerprints: HashSet<[u8; 32]>,
}

impl AllowedPeers {
    /// Build from a list of hex-encoded fingerprints.
    pub fn from_hex_strings(
        hexes: &[String],
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut fingerprints = HashSet::new();
        for h in hexes {
            let bytes = hex::decode(h)?;
            if bytes.len() != 32 {
                return Err(format!("fingerprint must be 32 bytes, got {}", bytes.len()).into());
            }
            let mut fp = [0u8; 32];
            fp.copy_from_slice(&bytes);
            fingerprints.insert(fp);
        }
        Ok(Self { fingerprints })
    }

    /// Build from raw fingerprints.
    pub fn from_fingerprints(fps: Vec<[u8; 32]>) -> Self {
        Self {
            fingerprints: fps.into_iter().collect(),
        }
    }

    pub fn contains(&self, fp: &[u8; 32]) -> bool {
        self.fingerprints.contains(fp)
    }

    /// Return a new AllowedPeers that is the union of self and other.
    pub fn union(&self, other: &AllowedPeers) -> AllowedPeers {
        let mut combined = self.fingerprints.clone();
        for fp in &other.fingerprints {
            combined.insert(*fp);
        }
        AllowedPeers {
            fingerprints: combined,
        }
    }

    pub fn len(&self) -> usize {
        self.fingerprints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fingerprints.is_empty()
    }

    /// Return a copy of all fingerprints as a Vec.
    pub fn fingerprints(&self) -> Vec<[u8; 32]> {
        self.fingerprints.iter().copied().collect()
    }
}

pub type DynamicAllowFn =
    dyn Fn(&[u8; 32]) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> + Send + Sync;

#[derive(Clone)]
enum AllowPolicy {
    Static(Arc<AllowedPeers>),
    Dynamic(Arc<DynamicAllowFn>),
}

impl std::fmt::Debug for AllowPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AllowPolicy::Static(_) => f.write_str("AllowPolicy::Static"),
            AllowPolicy::Dynamic(_) => f.write_str("AllowPolicy::Dynamic"),
        }
    }
}

/// Verifies peer certificates by checking SPKI fingerprint against an allowed set.
/// Implements both ServerCertVerifier (client verifies server) and
/// ClientCertVerifier (server verifies client).
/// Tracks rejection counts for observability.
#[derive(Debug)]
pub struct PinnedCertVerifier {
    policy: AllowPolicy,
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
    rejections: AtomicU64,
}

impl PinnedCertVerifier {
    pub fn new(allowed: Arc<AllowedPeers>) -> Self {
        Self::new_with_policy(AllowPolicy::Static(allowed))
    }

    pub fn new_dynamic(allow_fn: Arc<DynamicAllowFn>) -> Self {
        Self::new_with_policy(AllowPolicy::Dynamic(allow_fn))
    }

    fn new_with_policy(policy: AllowPolicy) -> Self {
        Self {
            policy,
            crypto_provider: Arc::new(rustls::crypto::ring::default_provider()),
            rejections: AtomicU64::new(0),
        }
    }

    /// Number of certificate rejections since creation.
    pub fn rejection_count(&self) -> u64 {
        self.rejections.load(Ordering::Relaxed)
    }

    fn check_fingerprint(&self, cert_der: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        let fp = extract_spki_fingerprint(cert_der.as_ref())
            .map_err(|e| rustls::Error::General(format!("SPKI extraction failed: {}", e)))?;
        let allowed = match &self.policy {
            AllowPolicy::Static(peers) => peers.contains(&fp),
            AllowPolicy::Dynamic(check_fn) => check_fn(&fp).map_err(|e| {
                rustls::Error::General(format!("dynamic trust check failed: {}", e))
            })?,
        };
        if allowed {
            Ok(())
        } else {
            let count = self.rejections.fetch_add(1, Ordering::Relaxed) + 1;
            warn!(
                fingerprint = %hex::encode(fp),
                total_rejections = count,
                "rejected peer certificate: fingerprint not in allowed set"
            );
            Err(rustls::Error::General(format!(
                "peer fingerprint {} not in allowed set",
                hex::encode(fp)
            )))
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
        self.check_fingerprint(end_entity)?;
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.crypto_provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl rustls::server::danger::ClientCertVerifier for PinnedCertVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        self.check_fingerprint(end_entity)?;
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.crypto_provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Create a QUIC server endpoint with mTLS (requires client cert, verifies against allowed peers).
pub fn create_server_endpoint(
    bind_addr: SocketAddr,
    cert_der: CertificateDer<'static>,
    key_der: PrivatePkcs8KeyDer<'static>,
    allowed_peers: Arc<AllowedPeers>,
) -> Result<Endpoint, Box<dyn std::error::Error + Send + Sync>> {
    let verifier = Arc::new(PinnedCertVerifier::new(allowed_peers));

    let server_crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![cert_der], key_der.into())?;

    let server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    ));

    let endpoint = Endpoint::server(server_config, bind_addr)?;
    Ok(endpoint)
}

/// Create a QUIC client endpoint with mTLS (presents client cert, verifies server against allowed peers).
pub fn create_client_endpoint(
    bind_addr: SocketAddr,
    cert_der: CertificateDer<'static>,
    key_der: PrivatePkcs8KeyDer<'static>,
    allowed_peers: Arc<AllowedPeers>,
) -> Result<Endpoint, Box<dyn std::error::Error + Send + Sync>> {
    let verifier = Arc::new(PinnedCertVerifier::new(allowed_peers));

    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![cert_der], key_der.into())?;

    let client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));

    let mut endpoint = Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// Create a dual-role QUIC endpoint that can both accept and connect.
/// Both roles use mTLS with the same identity and trust set.
/// This is required for hole punching: the same UDP socket must be used
/// for outbound connect() and inbound accept() so NAT mappings align.
pub fn create_dual_endpoint(
    bind_addr: SocketAddr,
    cert_der: CertificateDer<'static>,
    key_der: PrivatePkcs8KeyDer<'static>,
    allowed_peers: Arc<AllowedPeers>,
) -> Result<Endpoint, Box<dyn std::error::Error + Send + Sync>> {
    // Server-side config (for accepting incoming connections)
    let server_verifier = Arc::new(PinnedCertVerifier::new(allowed_peers.clone()));
    let server_crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(server_verifier)
        .with_single_cert(vec![cert_der.clone()], key_der.clone_key().into())?;
    let server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    ));

    // Client-side config (for outbound connections)
    let client_verifier = Arc::new(PinnedCertVerifier::new(allowed_peers));
    let client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(client_verifier)
        .with_client_auth_cert(vec![cert_der], key_der.into())?;
    let client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
    ));

    // Create server endpoint (binds the socket), then add client config
    let mut endpoint = Endpoint::server(server_config, bind_addr)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// Create a dual-role QUIC endpoint that validates peers by consulting a
/// dynamic trust source on each handshake.
pub fn create_dual_endpoint_dynamic(
    bind_addr: SocketAddr,
    cert_der: CertificateDer<'static>,
    key_der: PrivatePkcs8KeyDer<'static>,
    allow_fn: Arc<DynamicAllowFn>,
) -> Result<Endpoint, Box<dyn std::error::Error + Send + Sync>> {
    // Server-side config (for accepting incoming connections)
    let server_verifier = Arc::new(PinnedCertVerifier::new_dynamic(allow_fn.clone()));
    let server_crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(server_verifier)
        .with_single_cert(vec![cert_der.clone()], key_der.clone_key().into())?;
    let server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    ));

    // Client-side config (for outbound connections)
    let client_verifier = Arc::new(PinnedCertVerifier::new_dynamic(allow_fn));
    let client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(client_verifier)
        .with_client_auth_cert(vec![cert_der], key_der.into())?;
    let client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
    ));

    // Create server endpoint (binds the socket), then add client config
    let mut endpoint = Endpoint::server(server_config, bind_addr)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// Extract peer identity from a QUIC connection's TLS session.
/// Returns the hex-encoded SPKI fingerprint of the peer's certificate.
pub fn peer_identity_from_connection(conn: &quinn::Connection) -> Option<String> {
    let certs = conn.peer_identity()?;
    let certs = certs.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    let first = certs.first()?;
    let fp = extract_spki_fingerprint(first.as_ref()).ok()?;
    Some(hex::encode(fp))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pinned_verifier_accepts_allowed_cert() {
        let (cert, _) = generate_self_signed_cert().unwrap();
        let fp = extract_spki_fingerprint(cert.as_ref()).unwrap();
        let allowed = Arc::new(AllowedPeers::from_fingerprints(vec![fp]));
        let verifier = PinnedCertVerifier::new(allowed);
        assert!(verifier.check_fingerprint(&cert).is_ok());
    }

    #[test]
    fn test_pinned_verifier_rejects_unknown_cert() {
        let (cert, _) = generate_self_signed_cert().unwrap();
        let (other_cert, _) = generate_self_signed_cert().unwrap();
        let fp = extract_spki_fingerprint(other_cert.as_ref()).unwrap();
        let allowed = Arc::new(AllowedPeers::from_fingerprints(vec![fp]));
        let verifier = PinnedCertVerifier::new(allowed);
        assert!(verifier.check_fingerprint(&cert).is_err());
    }

    #[test]
    fn test_allowed_peers_from_hex() {
        let (cert, _) = generate_self_signed_cert().unwrap();
        let fp = extract_spki_fingerprint(cert.as_ref()).unwrap();
        let hex_str = hex::encode(fp);
        let allowed = AllowedPeers::from_hex_strings(&[hex_str]).unwrap();
        assert!(allowed.contains(&fp));
    }

    #[test]
    fn test_dynamic_verifier_checks_callback() {
        let (cert, _) = generate_self_signed_cert().unwrap();
        let fp = extract_spki_fingerprint(cert.as_ref()).unwrap();
        let verifier =
            PinnedCertVerifier::new_dynamic(Arc::new(move |candidate| Ok(candidate == &fp)));
        assert!(verifier.check_fingerprint(&cert).is_ok());
    }
}
