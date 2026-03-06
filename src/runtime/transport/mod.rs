pub mod bootstrap_dial_context;
pub mod cert;
pub mod connection;
pub mod connection_lifecycle;
pub mod identity;
pub mod identity_adapter;
pub mod intro_io;
pub mod multi_workspace;
pub mod peering_boundary;
pub mod session_factory;
pub mod transport_session_io;

pub use crate::crypto::AllowedPeers;
pub use bootstrap_dial_context::{
    derive_bootstrap_dial_context, BootstrapDialContext, BootstrapDialMode,
};
pub use cert::{
    extract_spki_fingerprint, generate_keypair, generate_self_signed_cert,
    generate_self_signed_cert_from_signing_key, validate_cert_key_match,
};
pub use connection::{DualConnection, StreamConn, StreamRecv, StreamSend};
pub use connection_lifecycle::{accept_peer, dial_peer, ConnectedPeer, ConnectionLifecycleError};
pub use peering_boundary::{
    accept_session_peer, accept_session_provider,
    build_tenant_bootstrap_fallback_client_config_for_invite_from_db,
    build_tenant_bootstrap_fallback_client_config_from_db, build_tenant_client_config_from_creds,
    build_tenant_client_config_from_db, create_runtime_endpoint_for_tenants, dial_session_peer,
    dial_session_provider, open_inbound_session, open_outbound_session,
    outbound_session_provider_for_connection, read_intro_offer_frame, resolve_trusting_tenant,
    send_intro_offer_frame, tenant_trusts_peer, SessionEnvelope, SessionProvider,
    TenantClientConfigs, TransportClientConfig, TransportConnection, TransportEndpoint,
};
pub use transport_session_io::{QuicTransportSessionIo, DEFAULT_SYNC_FRAME_MAX_BYTES};

use quinn::{ClientConfig, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use tracing::warn;

pub type DynamicAllowFn =
    dyn Fn(&[u8; 32]) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> + Send + Sync;

pub(crate) const TRUST_REJECTION_MARKER: &str = "trust_rejected";

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
/// Tracks rejection counts per fingerprint for log suppression.
pub struct PinnedCertVerifier {
    policy: AllowPolicy,
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
    rejections: Mutex<HashMap<[u8; 32], u64>>,
}

impl std::fmt::Debug for PinnedCertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinnedCertVerifier")
            .field("policy", &self.policy)
            .finish()
    }
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
            rejections: Mutex::new(HashMap::new()),
        }
    }

    /// Total number of certificate rejections since creation.
    pub fn rejection_count(&self) -> u64 {
        self.rejections
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .sum()
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
            let fp_hex = hex::encode(fp);
            let count = {
                let mut map = self.rejections.lock().unwrap_or_else(|p| p.into_inner());
                // Cap tracked fingerprints to prevent unbounded memory growth
                // from unauthenticated traffic presenting novel certs.
                if map.len() >= 1024 && !map.contains_key(&fp) {
                    // At capacity — suppress logging for untracked fingerprints.
                    u64::MAX
                } else {
                    let entry = map.entry(fp).or_insert(0);
                    *entry += 1;
                    *entry
                }
            };
            if count <= 3 {
                warn!(
                    fingerprint = %fp_hex,
                    rejections_for_fingerprint = count,
                    "Rejected peer certificate: TLS fingerprint {} is not trusted by any \
                     local workspace. If this peer just accepted an invite, its transport \
                     identity may still be bootstrapping.",
                    &fp_hex[..16.min(fp_hex.len())]
                );
            } else if count == 4 {
                warn!(
                    fingerprint = %fp_hex,
                    rejections_for_fingerprint = count,
                    "Rejected peer certificate (suppressing further logs for \
                     fingerprint {})",
                    &fp_hex[..16.min(fp_hex.len())]
                );
            }
            // count > 4: suppress repeated logs for this specific fingerprint
            Err(rustls::Error::General(format!(
                "{}: peer fingerprint {} not in allowed set",
                TRUST_REJECTION_MARKER, fp_hex
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

/// Create a single-port dual-role QUIC endpoint that serves multiple workspaces.
///
/// Server side: uses `WorkspaceCertResolver` to select the correct cert based
/// on the client's SNI. Client side: uses a default client config with the
/// first workspace's cert (outbound connections use `connect_with()` for
/// per-workspace config).
///
/// Trust verification is via a dynamic allow function that checks across
/// all workspaces.
pub fn create_single_port_endpoint(
    bind_addr: SocketAddr,
    cert_resolver: Arc<multi_workspace::WorkspaceCertResolver>,
    allow_fn: Arc<DynamicAllowFn>,
    default_client_cert: CertificateDer<'static>,
    default_client_key: PrivatePkcs8KeyDer<'static>,
) -> Result<Endpoint, Box<dyn std::error::Error + Send + Sync>> {
    // Server config: multi-workspace cert resolver + dynamic trust
    let server_verifier = Arc::new(PinnedCertVerifier::new_dynamic(allow_fn.clone()));
    let server_crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(server_verifier)
        .with_cert_resolver(cert_resolver);
    let server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    ));

    // Default client config (for outbound connections that don't use connect_with)
    let client_verifier = Arc::new(PinnedCertVerifier::new_dynamic(allow_fn));
    let client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(client_verifier)
        .with_client_auth_cert(vec![default_client_cert], default_client_key.into())?;
    let client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
    ));

    let mut endpoint = Endpoint::server(server_config, bind_addr)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// Build a per-workspace `ClientConfig` for outbound connections.
///
/// Used with `endpoint.connect_with(config, addr, sni)` to present the
/// correct workspace cert and verify the remote server's workspace cert.
pub fn workspace_client_config(
    cert_der: CertificateDer<'static>,
    key_der: PrivatePkcs8KeyDer<'static>,
    allow_fn: Arc<DynamicAllowFn>,
) -> Result<ClientConfig, Box<dyn std::error::Error + Send + Sync>> {
    let verifier = Arc::new(PinnedCertVerifier::new_dynamic(allow_fn));
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![cert_der], key_der.into())?;
    Ok(ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    )))
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
