//! Transport-owned boundary for peering/runtime orchestration.
//!
//! Peering code should use these helpers/types rather than importing QUIC
//! concrete types or transport trust internals directly.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use crate::contracts::peering_contract::{
    PeerFingerprint, TenantId, TransportSessionIo, TrustDecision,
};
use crate::db::open_connection;
use crate::db::transport_creds::load_local_creds;
use crate::protocol::{encode_frame, Frame};

use super::connection_lifecycle::{
    accept_peer, dial_peer, ConnectedPeer, ConnectionLifecycleError,
};
use super::multi_workspace::WorkspaceCertResolver;
use super::session_factory::{accept_session_io, open_session_io, SessionOpenError};
use super::{
    create_single_port_endpoint, workspace_client_config, DynamicAllowFn, SqliteTrustOracle,
};

pub type TransportEndpoint = quinn::Endpoint;
pub type TransportConnection = quinn::Connection;
pub type TransportClientConfig = quinn::ClientConfig;
pub type TenantClientConfigs = HashMap<String, TransportClientConfig>;

pub fn create_runtime_endpoint_for_tenants(
    bind_addr: SocketAddr,
    cert_resolver: Arc<WorkspaceCertResolver>,
    db_path: &str,
    tenant_peer_ids: Vec<String>,
    default_client_cert: CertificateDer<'static>,
    default_client_key: PrivatePkcs8KeyDer<'static>,
) -> Result<TransportEndpoint, Box<dyn std::error::Error + Send + Sync>> {
    let trust_oracle = SqliteTrustOracle::new(db_path);
    let dynamic_allow: Arc<DynamicAllowFn> = Arc::new(move |peer_fp: &[u8; 32]| {
        for tenant_id in &tenant_peer_ids {
            match trust_oracle.check_sync(&TenantId(tenant_id.clone()), &PeerFingerprint(*peer_fp))
            {
                Ok(TrustDecision::Allow) => return Ok(true),
                Ok(TrustDecision::Deny) => {}
                Err(e) => return Err(e.to_string().into()),
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
    let oracle = SqliteTrustOracle::new(db_path);
    let tid = TenantId(tenant_id.to_string());
    let tenant_allow: Arc<DynamicAllowFn> = Arc::new(move |peer_fp: &[u8; 32]| {
        match oracle.check_sync(&tid, &PeerFingerprint(*peer_fp)) {
            Ok(TrustDecision::Allow) => Ok(true),
            Ok(TrustDecision::Deny) => Ok(false),
            Err(e) => Err(e.to_string().into()),
        }
    });
    workspace_client_config(cert_der, key_der, tenant_allow)
}

pub fn build_tenant_client_config_from_db(
    db_path: &str,
    tenant_id: &str,
) -> Result<TransportClientConfig, Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    let (cert_der, key_der) = load_local_creds(&db, tenant_id)?
        .ok_or_else(|| format!("local creds missing for tenant {}", tenant_id))?;
    drop(db);

    let cert_der = CertificateDer::from(cert_der);
    let key_der = PrivatePkcs8KeyDer::from(key_der);
    build_tenant_client_config_from_creds(db_path, tenant_id, cert_der, key_der)
}

pub fn tenant_trusts_peer(
    db_path: &str,
    tenant_id: &str,
    peer_fp: [u8; 32],
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let oracle = SqliteTrustOracle::new(db_path);
    let decision = oracle.check_sync(&TenantId(tenant_id.to_string()), &PeerFingerprint(peer_fp));
    match decision {
        Ok(TrustDecision::Allow) => Ok(true),
        Ok(TrustDecision::Deny) => Ok(false),
        Err(e) => Err(e.to_string().into()),
    }
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

pub async fn accept_session_peer(
    endpoint: &TransportEndpoint,
) -> Result<Option<ConnectedPeer>, ConnectionLifecycleError> {
    accept_peer(endpoint).await
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
