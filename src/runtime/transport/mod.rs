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
    dial_session_provider, node_trusts_peer, open_inbound_session, open_outbound_session,
    outbound_session_provider_for_connection, read_intro_offer_frame,
    resolve_authorizing_tenant_from_db, resolve_trusting_tenant, send_intro_offer_frame,
    tenant_trusts_peer, SessionEnvelope, SessionProvider, TenantClientConfigs,
    TransportClientConfig, TransportConnection, TransportEndpoint,
};
pub use transport_session_io::{QuicTransportSessionIo, DEFAULT_SYNC_FRAME_MAX_BYTES};

use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig, VarInt};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use tracing::warn;

use crate::runtime::repeated_warning::should_emit_globally;
use crate::tuning::{low_mem_mode, max_recv_buffer};

pub type DynamicAllowFn =
    dyn Fn(&[u8; 32]) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> + Send + Sync;

pub(crate) const TRUST_REJECTION_MARKER: &str = "trust_rejected";

fn low_mem_transport_config() -> Option<Arc<TransportConfig>> {
    if !low_mem_mode() {
        return None;
    }

    // Keep transport-level buffering aligned with the lowmem app-level queue
    // caps so Quinn cannot hide large amounts of in-flight data underneath the
    // DB-backed receiver.
    let base_window = max_recv_buffer().max(256 * 1024);
    let stream_window = base_window.saturating_mul(2).min(u32::MAX as usize) as u32;
    let receive_window = stream_window.saturating_mul(2);

    let mut transport = TransportConfig::default();
    transport.stream_receive_window(VarInt::from_u32(stream_window));
    transport.receive_window(VarInt::from_u32(receive_window));
    transport.send_window(u64::from(receive_window));
    Some(Arc::new(transport))
}

/// Verifies peer certificates by checking SPKI fingerprint against an allowed set.
/// Implements both ServerCertVerifier (client verifies server) and
/// ClientCertVerifier (server verifies client).
/// Tracks rejection counts per fingerprint for log suppression.
pub struct PinnedCertVerifier {
    allow_fn: Arc<DynamicAllowFn>,
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
    rejections: Mutex<HashMap<[u8; 32], u64>>,
}

impl std::fmt::Debug for PinnedCertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinnedCertVerifier")
            .field("allow_fn", &"DynamicAllowFn")
            .finish()
    }
}

impl PinnedCertVerifier {
    pub fn new_dynamic(allow_fn: Arc<DynamicAllowFn>) -> Self {
        Self {
            allow_fn,
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

    fn verify_authorized_fingerprint(&self, fp: [u8; 32]) -> Result<(), rustls::Error> {
        let allowed = (self.allow_fn)(&fp)
            .map_err(|e| rustls::Error::General(format!("dynamic trust check failed: {}", e)))?;
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
            let should_warn =
                count != u64::MAX && should_emit_globally(format!("transport-reject:{fp_hex}"));
            if should_warn {
                warn!(
                    fingerprint = %fp_hex,
                    rejections_for_fingerprint = count,
                    "Rejected peer certificate: TLS fingerprint {} is not trusted by any \
                     local workspace. If this peer just accepted an invite, its transport \
                     identity may still be bootstrapping. Further identical certificate \
                     rejections are suppressed while this condition persists.",
                    &fp_hex[..16.min(fp_hex.len())]
                );
            }
            Err(rustls::Error::General(format!(
                "{}: peer fingerprint {} not in allowed set",
                TRUST_REJECTION_MARKER, fp_hex
            )))
        }
    }

    fn verified_fingerprint(
        &self,
        cert_der: &CertificateDer<'_>,
    ) -> Result<[u8; 32], rustls::Error> {
        let fp = extract_spki_fingerprint(cert_der.as_ref())
            .map_err(|e| rustls::Error::General(format!("SPKI extraction failed: {}", e)))?;
        self.verify_authorized_fingerprint(fp)?;
        Ok(fp)
    }

    fn verify_expected_server_identity(
        &self,
        server_name: &rustls::pki_types::ServerName<'_>,
        presented_fp: &[u8; 32],
    ) -> Result<(), rustls::Error> {
        let requested_sni = match server_name {
            rustls::pki_types::ServerName::DnsName(dns_name) => dns_name.as_ref(),
            other => {
                return Err(rustls::Error::General(format!(
                    "missing exact transport-target SNI: unsupported server name {other:?}"
                )));
            }
        };
        let expected = multi_workspace::parse_transport_sni(requested_sni).ok_or_else(|| {
            rustls::Error::General(format!(
                "missing exact transport-target SNI: requested server name '{requested_sni}' is not a transport target"
            ))
        })?;
        let presented = hex::encode(presented_fp);
        if presented == expected.transport_peer_id {
            Ok(())
        } else {
            Err(rustls::Error::General(format!(
                "{}: expected remote transport fingerprint {} but peer presented {}",
                TRUST_REJECTION_MARKER, expected.transport_peer_id, presented
            )))
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let fp = self.verified_fingerprint(end_entity)?;
        self.verify_expected_server_identity(server_name, &fp)?;
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
        self.verified_fingerprint(end_entity)?;
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

/// Create a QUIC server endpoint with mTLS and dynamic projected-state trust.
pub fn create_server_endpoint(
    bind_addr: SocketAddr,
    cert_der: CertificateDer<'static>,
    key_der: PrivatePkcs8KeyDer<'static>,
    allow_fn: Arc<DynamicAllowFn>,
) -> Result<Endpoint, Box<dyn std::error::Error + Send + Sync>> {
    let verifier = Arc::new(PinnedCertVerifier::new_dynamic(allow_fn));

    let server_crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![cert_der], key_der.into())?;

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    ));
    if let Some(transport) = low_mem_transport_config() {
        server_config.transport_config(transport);
    }

    let endpoint = Endpoint::server(server_config, bind_addr)?;
    Ok(endpoint)
}

/// Create a QUIC client endpoint with mTLS and dynamic projected-state trust.
pub fn create_client_endpoint(
    bind_addr: SocketAddr,
    cert_der: CertificateDer<'static>,
    key_der: PrivatePkcs8KeyDer<'static>,
    allow_fn: Arc<DynamicAllowFn>,
) -> Result<Endpoint, Box<dyn std::error::Error + Send + Sync>> {
    let verifier = Arc::new(PinnedCertVerifier::new_dynamic(allow_fn));

    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![cert_der], key_der.into())?;

    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));
    if let Some(transport) = low_mem_transport_config() {
        client_config.transport_config(transport);
    }

    let mut endpoint = Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// Create a dual-role QUIC endpoint that can both accept and connect.
/// Both roles use mTLS with the same identity and dynamic trust policy.
/// This is required for hole punching: the same UDP socket must be used
/// for outbound connect() and inbound accept() so NAT mappings align.
pub fn create_dual_endpoint(
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
    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    ));
    if let Some(transport) = low_mem_transport_config() {
        server_config.transport_config(transport.clone());
    }

    // Client-side config (for outbound connections)
    let client_verifier = Arc::new(PinnedCertVerifier::new_dynamic(allow_fn));
    let client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(client_verifier)
        .with_client_auth_cert(vec![cert_der], key_der.into())?;
    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
    ));
    if let Some(transport) = low_mem_transport_config() {
        client_config.transport_config(transport);
    }

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
    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    ));
    if let Some(transport) = low_mem_transport_config() {
        server_config.transport_config(transport.clone());
    }

    // Client-side config (for outbound connections)
    let client_verifier = Arc::new(PinnedCertVerifier::new_dynamic(allow_fn));
    let client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(client_verifier)
        .with_client_auth_cert(vec![cert_der], key_der.into())?;
    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
    ));
    if let Some(transport) = low_mem_transport_config() {
        client_config.transport_config(transport);
    }

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

/// Extract the client-requested server name (SNI) from a QUIC connection.
///
/// On accepted server-side connections Quinn exposes rustls handshake data with
/// the requested `server_name`. Outbound connections always return `None`.
pub fn requested_server_name_from_connection(conn: &quinn::Connection) -> Option<String> {
    let handshake = conn.handshake_data()?;
    let handshake = handshake
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .ok()?;
    handshake.server_name.clone()
}

/// Create a single-port dual-role QUIC endpoint that serves multiple workspaces.
///
/// Server side: uses `TransportTargetCertResolver` to select the correct cert based
/// on the client's SNI. Client side: uses a default client config with the
/// first local transport cert (outbound connections use `connect_with()` for
/// per-tenant config).
///
/// Trust verification is via a dynamic allow function that checks across
/// all local tenants.
pub fn create_single_port_endpoint(
    bind_addr: SocketAddr,
    cert_resolver: Arc<multi_workspace::TransportTargetCertResolver>,
    allow_fn: Arc<DynamicAllowFn>,
    default_client_cert: CertificateDer<'static>,
    default_client_key: PrivatePkcs8KeyDer<'static>,
) -> Result<Endpoint, Box<dyn std::error::Error + Send + Sync>> {
    // Server config: exact transport-target cert resolver + dynamic trust
    let server_verifier = Arc::new(PinnedCertVerifier::new_dynamic(allow_fn.clone()));
    let server_crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(server_verifier)
        .with_cert_resolver(cert_resolver);
    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    ));
    if let Some(transport) = low_mem_transport_config() {
        server_config.transport_config(transport.clone());
    }

    // Default client config (for outbound connections that don't use connect_with)
    let client_verifier = Arc::new(PinnedCertVerifier::new_dynamic(allow_fn));
    let client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(client_verifier)
        .with_client_auth_cert(vec![default_client_cert], default_client_key.into())?;
    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
    ));
    if let Some(transport) = low_mem_transport_config() {
        client_config.transport_config(transport);
    }

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
    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));
    if let Some(transport) = low_mem_transport_config() {
        client_config.transport_config(transport);
    }
    Ok(client_config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::ServerCertVerifier;

    #[test]
    fn test_dynamic_verifier_accepts_allowed_cert() {
        let (cert, _) = generate_self_signed_cert().unwrap();
        let fp = extract_spki_fingerprint(cert.as_ref()).unwrap();
        let verifier =
            PinnedCertVerifier::new_dynamic(Arc::new(move |candidate| Ok(candidate == &fp)));
        assert!(verifier.verified_fingerprint(&cert).is_ok());
    }

    #[test]
    fn test_dynamic_verifier_rejects_unknown_cert() {
        let (cert, _) = generate_self_signed_cert().unwrap();
        let (other_cert, _) = generate_self_signed_cert().unwrap();
        let fp = extract_spki_fingerprint(other_cert.as_ref()).unwrap();
        let verifier =
            PinnedCertVerifier::new_dynamic(Arc::new(move |candidate| Ok(candidate == &fp)));
        assert!(verifier.verified_fingerprint(&cert).is_err());
    }

    #[test]
    fn test_dynamic_verifier_checks_callback() {
        let (cert, _) = generate_self_signed_cert().unwrap();
        let fp = extract_spki_fingerprint(cert.as_ref()).unwrap();
        let verifier =
            PinnedCertVerifier::new_dynamic(Arc::new(move |candidate| Ok(candidate == &fp)));
        assert!(verifier.verified_fingerprint(&cert).is_ok());
    }

    #[test]
    fn test_server_verifier_requires_exact_transport_target_sni() {
        let (cert, _) = generate_self_signed_cert().unwrap();
        let fp = extract_spki_fingerprint(cert.as_ref()).unwrap();
        let expected = multi_workspace::transport_sni(&hex::encode(fp));
        let verifier =
            PinnedCertVerifier::new_dynamic(Arc::new(move |candidate| Ok(candidate == &fp)));
        let server_name = rustls::pki_types::ServerName::try_from(expected).unwrap();
        assert!(verifier
            .verify_server_cert(
                &cert,
                &[],
                &server_name,
                &[],
                rustls::pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(1)),
            )
            .is_ok());
    }
}
