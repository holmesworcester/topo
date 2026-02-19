//! Endpoint creation, tenant discovery, and cert resolver setup.
//!
//! Extracts the startup phase of `run_node`: discovers local tenants, verifies
//! SPKI fingerprints, builds the multi-workspace cert resolver, per-tenant
//! client configs, and creates the single QUIC endpoint.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use tracing::{error, info, warn};

use crate::contracts::network_contract::{PeerFingerprint, TenantId, TrustDecision};
use crate::db::transport_creds::discover_local_tenants;
use crate::db::{open_connection, schema::create_tables};
use crate::transport::{
    create_single_port_endpoint, extract_spki_fingerprint,
    multi_workspace::{workspace_sni, WorkspaceCertResolver},
    workspace_client_config, DynamicAllowFn, SqliteTrustOracle,
};
use rustls::sign::CertifiedKey;

use super::NodeRuntimeNetInfo;

/// Result of the startup phase: everything needed to run accept/connect loops.
pub(crate) struct StartupResult {
    pub(crate) endpoint: quinn::Endpoint,
    pub(crate) local_addr: SocketAddr,
    pub(crate) tenants: Vec<crate::db::transport_creds::TenantInfo>,
    pub(crate) tenant_client_configs: HashMap<String, quinn::ClientConfig>,
    /// Peer IDs of all local tenants (for mDNS self-filtering).
    pub(crate) local_peer_ids: HashSet<String>,
}

/// Discover local tenants, build certs, create the QUIC endpoint, and
/// optionally send `NodeRuntimeNetInfo` back to the caller.
pub(crate) fn setup_endpoint_and_tenants(
    db_path: &str,
    bind: SocketAddr,
    net_info_tx: Option<tokio::sync::oneshot::Sender<NodeRuntimeNetInfo>>,
) -> Result<StartupResult, Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    let tenants = discover_local_tenants(&db)?;
    drop(db);

    if tenants.is_empty() {
        return Err(
            "No local identities found. Bootstrap a workspace or accept an invite first.".into(),
        );
    }

    info!("Discovered {} local tenant(s)", tenants.len());

    // Collect all local peer_ids for mDNS self-filtering
    let local_peer_ids: HashSet<String> = tenants.iter().map(|t| t.peer_id.clone()).collect();

    // Build multi-workspace cert resolver + tenant metadata
    let provider = rustls::crypto::ring::default_provider();
    let mut cert_resolver = WorkspaceCertResolver::new();
    let mut peer_to_workspace: HashMap<String, String> = HashMap::new();
    let mut default_cert: Option<(
        rustls::pki_types::CertificateDer<'static>,
        rustls::pki_types::PrivatePkcs8KeyDer<'static>,
    )> = None;

    for tenant in &tenants {
        // Verify SPKI fingerprint matches peer_id
        let fp = match extract_spki_fingerprint(&tenant.cert_der) {
            Ok(fp) => fp,
            Err(e) => {
                error!(
                    "Failed to extract SPKI fingerprint for tenant {}: {}",
                    tenant.peer_id, e
                );
                continue;
            }
        };
        let expected_peer_id = hex::encode(fp);
        if expected_peer_id != tenant.peer_id {
            error!(
                "SPKI mismatch for tenant {}: cert yields {}",
                tenant.peer_id, expected_peer_id
            );
            continue;
        }

        let cert_der = rustls::pki_types::CertificateDer::from(tenant.cert_der.clone());
        let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(tenant.key_der.clone());

        // Build CertifiedKey for the resolver
        let ck = match CertifiedKey::from_der(
            vec![cert_der.clone()],
            key_der.clone_key().into(),
            &provider,
        ) {
            Ok(ck) => Arc::new(ck),
            Err(e) => {
                error!(
                    "Failed to create CertifiedKey for tenant {}: {}",
                    tenant.peer_id, e
                );
                continue;
            }
        };

        let sni = workspace_sni(&tenant.workspace_id);
        cert_resolver.add(sni.clone(), ck);
        peer_to_workspace.insert(tenant.peer_id.clone(), tenant.workspace_id.clone());

        if default_cert.is_none() {
            default_cert = Some((cert_der, key_der));
        }

        info!(
            "Registered tenant {} (workspace {}, sni={})",
            &tenant.peer_id[..16],
            &tenant.workspace_id[..16.min(tenant.workspace_id.len())],
            sni
        );
    }

    let (default_cert_der, default_key_der) = default_cert.ok_or("No valid tenant certs found")?;

    // Union trust closure for inbound (server) connections: accept if ANY tenant trusts
    // the remote. Per-tenant outbound trust is handled by tenant_client_configs below.
    let trust_oracle = SqliteTrustOracle::new(db_path);
    let tenant_peer_ids: Vec<String> = tenants.iter().map(|t| t.peer_id.clone()).collect();
    let dynamic_allow: Arc<
        dyn Fn(&[u8; 32]) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> + Send + Sync,
    > = Arc::new(move |peer_fp: &[u8; 32]| {
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

    // Create single QUIC endpoint
    let endpoint = create_single_port_endpoint(
        bind,
        Arc::new(cert_resolver),
        dynamic_allow,
        default_cert_der,
        default_key_der,
    )?;

    let local_addr = endpoint.local_addr().unwrap_or(bind);
    info!(
        "Node listening on {} ({} workspace(s))",
        local_addr,
        tenants.len()
    );

    // Send runtime networking info back to caller (e.g. DaemonState in main.rs).
    if let Some(tx) = net_info_tx {
        let info = NodeRuntimeNetInfo {
            listen_addr: local_addr.to_string(),
            upnp: None,
        };
        let _ = tx.send(info);
    }

    // Per-tenant outbound client configs
    let mut tenant_client_configs: HashMap<String, quinn::ClientConfig> = HashMap::new();
    for tenant in &tenants {
        let cert_der = rustls::pki_types::CertificateDer::from(tenant.cert_der.clone());
        let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(tenant.key_der.clone());
        let oracle = SqliteTrustOracle::new(db_path);
        let tid = TenantId(tenant.peer_id.clone());
        let tenant_allow: Arc<DynamicAllowFn> = Arc::new(move |peer_fp: &[u8; 32]| {
            match oracle.check_sync(&tid, &PeerFingerprint(*peer_fp)) {
                Ok(TrustDecision::Allow) => Ok(true),
                Ok(TrustDecision::Deny) => Ok(false),
                Err(e) => Err(e.to_string().into()),
            }
        });
        match workspace_client_config(cert_der, key_der, tenant_allow) {
            Ok(cfg) => {
                tenant_client_configs.insert(tenant.peer_id.clone(), cfg);
            }
            Err(e) => warn!(
                "Failed to build client config for {}: {}",
                &tenant.peer_id[..16],
                e
            ),
        }
    }

    // Suppress unused-variable warning: peer_to_workspace is built for future use
    let _ = peer_to_workspace;

    Ok(StartupResult {
        endpoint,
        local_addr,
        tenants,
        tenant_client_configs,
        local_peer_ids,
    })
}
