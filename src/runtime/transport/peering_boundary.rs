//! Transport-owned boundary for peering/runtime orchestration.
//!
//! Peering code should use these helpers/types rather than importing QUIC
//! concrete types or transport trust internals directly.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rusqlite::OptionalExtension;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use crate::contracts::peering_contract::TransportSessionIo;
use crate::db::open_connection;
use crate::db::transport_creds::discover_local_tenants;
use crate::db::transport_trust::is_peer_allowed;
use crate::protocol::{encode_frame, Frame};

use super::connection_lifecycle::{
    accept_peer, dial_peer, ConnectedPeer, ConnectionLifecycleError,
};
use super::multi_workspace::WorkspaceCertResolver;
use super::session_factory::{accept_session_io, open_session_io, SessionOpenError};
use super::{create_single_port_endpoint, workspace_client_config, DynamicAllowFn};

pub type TransportEndpoint = quinn::Endpoint;
pub type TransportConnection = quinn::Connection;
pub type TransportClientConfig = quinn::ClientConfig;
pub type TenantClientConfigs = HashMap<String, TransportClientConfig>;

#[derive(Clone, Copy)]
enum SessionOpenMode {
    Outbound,
    Inbound,
}

/// Transport-owned provider for repeated sync sessions over one QUIC connection.
///
/// Peering orchestration uses this to avoid touching stream-open details.
#[derive(Clone)]
pub struct SessionProvider {
    connection: TransportConnection,
    /// Hex-encoded peer certificate SPKI fingerprint.
    peer_id: String,
    mode: SessionOpenMode,
}

/// One ready-to-run sync session from a [`SessionProvider`].
pub struct SessionEnvelope {
    /// Hex-encoded peer certificate SPKI fingerprint.
    pub peer_id: String,
    pub remote_addr: SocketAddr,
    pub session_id: u64,
    pub io: Box<dyn TransportSessionIo>,
}

impl SessionProvider {
    fn from_connected(connected: ConnectedPeer, mode: SessionOpenMode) -> Self {
        Self {
            connection: connected.connection,
            peer_id: connected.peer_id,
            mode,
        }
    }

    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    pub fn transport_fingerprint(&self) -> &str {
        &self.peer_id
    }

    pub fn remote_addr(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    pub fn connection(&self) -> TransportConnection {
        self.connection.clone()
    }

    pub async fn next_session(&self) -> Result<SessionEnvelope, SessionOpenError> {
        let (session_id, io) = match self.mode {
            SessionOpenMode::Outbound => open_session_io(&self.connection).await?,
            SessionOpenMode::Inbound => accept_session_io(&self.connection).await?,
        };
        Ok(SessionEnvelope {
            peer_id: self.peer_id.clone(),
            remote_addr: self.connection.remote_address(),
            session_id,
            io,
        })
    }
}

pub fn create_runtime_endpoint_for_tenants(
    bind_addr: SocketAddr,
    cert_resolver: Arc<WorkspaceCertResolver>,
    db_path: &str,
    tenant_peer_ids: Vec<String>,
    default_client_cert: CertificateDer<'static>,
    default_client_key: PrivatePkcs8KeyDer<'static>,
) -> Result<TransportEndpoint, Box<dyn std::error::Error + Send + Sync>> {
    let db_path = db_path.to_string();
    let dynamic_allow: Arc<DynamicAllowFn> = Arc::new(move |peer_fp: &[u8; 32]| {
        for tenant_id in &tenant_peer_ids {
            if tenant_trusts_peer(&db_path, tenant_id, *peer_fp)? {
                return Ok(true);
            }
        }
        Ok(false)
    });

    create_single_port_endpoint(
        bind_addr,
        cert_resolver,
        dynamic_allow,
        default_client_cert,
        default_client_key,
    )
}

pub fn build_tenant_client_config_from_creds(
    db_path: &str,
    tenant_id: &str,
    cert_der: CertificateDer<'static>,
    key_der: PrivatePkcs8KeyDer<'static>,
) -> Result<TransportClientConfig, Box<dyn std::error::Error + Send + Sync>> {
    let db_path = db_path.to_string();
    let tenant_id = tenant_id.to_string();
    let tenant_allow: Arc<DynamicAllowFn> =
        Arc::new(move |peer_fp: &[u8; 32]| tenant_trusts_peer(&db_path, &tenant_id, *peer_fp));
    workspace_client_config(cert_der, key_der, tenant_allow)
}

pub fn build_tenant_client_config_from_db(
    db_path: &str,
    tenant_id: &str,
) -> Result<TransportClientConfig, Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    let tenants = discover_local_tenants(&db)?;
    let tenant = tenants
        .into_iter()
        .find(|t| t.peer_id == tenant_id)
        .ok_or_else(|| format!("local creds missing for tenant {}", tenant_id))?;
    let cert_der = tenant.cert_der;
    let key_der = tenant.key_der;
    drop(db);

    let cert_der = CertificateDer::from(cert_der);
    let key_der = PrivatePkcs8KeyDer::from(key_der);
    build_tenant_client_config_from_creds(db_path, tenant_id, cert_der, key_der)
}

/// Build an optional bootstrap-fallback client config for a tenant.
///
/// Fallback identity is derived from the latest pending invite unwrap key
/// (`local_signer_material.signer_kind = 4`) for this tenant. This enables
/// retrying outbound bootstrap dials when permanent transport identity is
/// rejected by a peer that has not yet converged peer_shared trust.
pub fn build_tenant_bootstrap_fallback_client_config_from_db(
    db_path: &str,
    tenant_id: &str,
) -> Result<Option<TransportClientConfig>, Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    let key_bytes: Option<Vec<u8>> = db
        .query_row(
            "SELECT private_key
             FROM local_signer_material
             WHERE recorded_by = ?1
               AND signer_kind = 4
               AND length(private_key) = 32
             ORDER BY created_at DESC, rowid DESC
             LIMIT 1",
            rusqlite::params![tenant_id],
            |row| row.get(0),
        )
        .optional()?;
    let Some(key_bytes) = key_bytes else {
        return Ok(None);
    };
    if key_bytes.len() != 32 {
        return Ok(None);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    let signing_key = SigningKey::from_bytes(&key);
    let (cert_der, key_der) =
        crate::transport::generate_self_signed_cert_from_signing_key(&signing_key)?;
    let cfg = build_tenant_client_config_from_creds(db_path, tenant_id, cert_der, key_der)?;
    Ok(Some(cfg))
}

pub fn tenant_trusts_peer(
    db_path: &str,
    tenant_id: &str,
    peer_fp: [u8; 32],
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    is_peer_allowed(&db, tenant_id, &peer_fp)
}

pub fn resolve_trusting_tenant(
    db_path: &str,
    tenant_ids: &[String],
    peer_fp: [u8; 32],
) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
    for tenant_id in tenant_ids {
        if tenant_trusts_peer(db_path, tenant_id, peer_fp)? {
            return Ok(Some(tenant_id.clone()));
        }
    }
    Ok(None)
}

pub async fn dial_session_peer(
    endpoint: &TransportEndpoint,
    remote: SocketAddr,
    sni: &str,
    client_config: Option<&TransportClientConfig>,
) -> Result<ConnectedPeer, ConnectionLifecycleError> {
    dial_peer(endpoint, remote, sni, client_config).await
}

pub async fn dial_session_provider(
    endpoint: &TransportEndpoint,
    remote: SocketAddr,
    sni: &str,
    client_config: Option<&TransportClientConfig>,
) -> Result<SessionProvider, ConnectionLifecycleError> {
    let connected = dial_session_peer(endpoint, remote, sni, client_config).await?;
    Ok(SessionProvider::from_connected(
        connected,
        SessionOpenMode::Outbound,
    ))
}

pub async fn accept_session_peer(
    endpoint: &TransportEndpoint,
) -> Result<Option<ConnectedPeer>, ConnectionLifecycleError> {
    accept_peer(endpoint).await
}

pub async fn accept_session_provider(
    endpoint: &TransportEndpoint,
) -> Result<Option<SessionProvider>, ConnectionLifecycleError> {
    let connected = match accept_session_peer(endpoint).await? {
        Some(c) => c,
        None => return Ok(None),
    };
    Ok(Some(SessionProvider::from_connected(
        connected,
        SessionOpenMode::Inbound,
    )))
}

pub fn outbound_session_provider_for_connection(
    connection: TransportConnection,
    peer_id: String,
) -> SessionProvider {
    SessionProvider {
        connection,
        peer_id,
        mode: SessionOpenMode::Outbound,
    }
}

pub async fn open_outbound_session(
    conn: &TransportConnection,
) -> Result<(u64, Box<dyn TransportSessionIo>), SessionOpenError> {
    open_session_io(conn).await
}

pub async fn open_inbound_session(
    conn: &TransportConnection,
) -> Result<(u64, Box<dyn TransportSessionIo>), SessionOpenError> {
    accept_session_io(conn).await
}

pub async fn read_intro_offer_frame(
    conn: &TransportConnection,
) -> Result<Option<Frame>, Box<dyn std::error::Error + Send + Sync>> {
    super::intro_io::accept_and_read_intro(conn).await
}

pub async fn send_intro_offer_frame(
    conn: &TransportConnection,
    msg: &Frame,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let encoded = encode_frame(msg);
    let mut send_stream = conn.open_uni().await?;
    send_stream.write_all(&encoded).await?;
    send_stream.finish()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use crate::db::open_connection;
    use crate::db::schema::create_tables;
    use crate::db::transport_creds::store_local_creds;
    use crate::db::transport_trust::record_pending_invite_bootstrap_trust;
    use crate::transport::{
        create_dual_endpoint, extract_spki_fingerprint, generate_self_signed_cert, AllowedPeers,
    };

    use super::*;

    async fn endpoint_pair() -> Result<
        (
            TransportEndpoint,
            TransportEndpoint,
            SocketAddr,
            String,
            String,
        ),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let (server_cert, server_key) = generate_self_signed_cert()?;
        let (client_cert, client_key) = generate_self_signed_cert()?;

        let server_fp = extract_spki_fingerprint(server_cert.as_ref())?;
        let client_fp = extract_spki_fingerprint(client_cert.as_ref())?;

        let server_ep = create_dual_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            server_cert,
            server_key,
            Arc::new(AllowedPeers::from_fingerprints(vec![client_fp])),
        )?;
        let client_ep = create_dual_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            client_cert,
            client_key,
            Arc::new(AllowedPeers::from_fingerprints(vec![server_fp])),
        )?;
        let server_addr = server_ep.local_addr()?;
        Ok((
            server_ep,
            client_ep,
            server_addr,
            hex::encode(server_fp),
            hex::encode(client_fp),
        ))
    }

    #[test]
    fn trust_resolution_uses_sql_state() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("trust.sqlite3");
        let db = open_connection(&db_path).unwrap();
        create_tables(&db).unwrap();

        let allowed = [0xAB; 32];
        record_pending_invite_bootstrap_trust(&db, "tenant-a", "invite-1", "ws-1", &allowed)
            .unwrap();
        drop(db);

        assert!(
            tenant_trusts_peer(db_path.to_str().unwrap(), "tenant-a", allowed).unwrap(),
            "tenant-a should trust pending bootstrap spki"
        );
        assert!(
            !tenant_trusts_peer(db_path.to_str().unwrap(), "tenant-a", [0xCD; 32]).unwrap(),
            "unlisted peer must be denied"
        );

        let tenants = vec!["tenant-x".to_string(), "tenant-a".to_string()];
        let resolved =
            resolve_trusting_tenant(db_path.to_str().unwrap(), &tenants, allowed).unwrap();
        assert_eq!(resolved, Some("tenant-a".to_string()));
    }

    #[test]
    fn tenant_client_config_from_db_requires_local_creds() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("client_config.sqlite3");
        let db = open_connection(&db_path).unwrap();
        create_tables(&db).unwrap();
        drop(db);

        let err = build_tenant_client_config_from_db(db_path.to_str().unwrap(), "missing-tenant")
            .unwrap_err();
        assert!(
            err.to_string().contains("local creds missing"),
            "unexpected error: {}",
            err
        );

        let db = open_connection(&db_path).unwrap();
        let (cert, key) = generate_self_signed_cert().unwrap();
        store_local_creds(
            &db,
            "tenant-a",
            cert.as_ref(),
            key.secret_pkcs8_der().as_ref(),
        )
        .unwrap();
        db.execute(
            "INSERT INTO invites_accepted
             (recorded_by, event_id, tenant_event_id, invite_event_id, workspace_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params!["tenant-a", "ia-a", "tenant-a-eid", "invite-a", "ws-1", 1_i64],
        )
        .unwrap();
        drop(db);

        build_tenant_client_config_from_db(db_path.to_str().unwrap(), "tenant-a")
            .expect("tenant config should build from stored creds");
    }

    #[test]
    fn bootstrap_fallback_client_config_present_when_pending_invite_key_exists() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("fallback_cfg.sqlite3");
        let db = open_connection(&db_path).unwrap();
        create_tables(&db).unwrap();

        db.execute(
            "INSERT INTO local_signer_material
             (recorded_by, signer_event_id, signer_kind, private_key, created_at)
             VALUES (?1, ?2, 4, ?3, ?4)",
            rusqlite::params!["tenant-a", "invite-eid", vec![7u8; 32], 12345_i64,],
        )
        .unwrap();
        drop(db);

        let cfg = build_tenant_bootstrap_fallback_client_config_from_db(
            db_path.to_str().unwrap(),
            "tenant-a",
        )
        .expect("fallback config query should succeed");
        assert!(
            cfg.is_some(),
            "pending invite key should yield fallback config"
        );
    }

    #[test]
    fn bootstrap_fallback_client_config_absent_without_pending_invite_key() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("fallback_cfg_empty.sqlite3");
        let db = open_connection(&db_path).unwrap();
        create_tables(&db).unwrap();
        drop(db);

        let cfg = build_tenant_bootstrap_fallback_client_config_from_db(
            db_path.to_str().unwrap(),
            "tenant-a",
        )
        .expect("fallback config query should succeed");
        assert!(
            cfg.is_none(),
            "no pending invite key means no fallback config"
        );
    }

    #[tokio::test]
    async fn boundary_wrappers_cover_dial_accept_and_intro_roundtrip() {
        let (server_ep, client_ep, server_addr, server_peer_id, client_peer_id) =
            endpoint_pair().await.expect("endpoint pair");

        let (accepted_res, dialed_res) = tokio::join!(
            accept_session_peer(&server_ep),
            dial_session_peer(&client_ep, server_addr, "localhost", None)
        );
        let accepted = accepted_res.expect("accept").expect("accepted");
        let dialed = dialed_res.expect("dial");
        assert_eq!(accepted.peer_id, client_peer_id);
        assert_eq!(dialed.peer_id, server_peer_id);

        let intro = Frame::IntroOffer {
            intro_id: [0x11; 16],
            other_peer_id: [0x22; 32],
            origin_family: 4,
            origin_ip: [0; 16],
            origin_port: 4433,
            observed_at_ms: 10,
            expires_at_ms: 100,
            attempt_window_ms: 50,
        };
        send_intro_offer_frame(&dialed.connection, &intro)
            .await
            .expect("send intro");
        let read = read_intro_offer_frame(&accepted.connection)
            .await
            .expect("read intro result")
            .expect("intro frame");
        assert_eq!(read, intro);
    }
}
