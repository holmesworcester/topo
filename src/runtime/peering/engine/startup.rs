//! Endpoint creation, tenant discovery, and daemon transport setup.
//!
//! Extracts the startup phase of `run_node`: discovers local tenants, verifies
//! local/runtime tenant state, loads the singleton daemon transport identity,
//! builds per-tenant client configs, and creates the single QUIC endpoint.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

use tracing::{error, info, warn};

use crate::db::transport_creds::discover_local_tenants;
use crate::db::{open_connection, schema::create_tables};
use crate::transport::{
    build_tenant_client_config_from_db, create_runtime_endpoint_for_tenants,
    ensure_daemon_identity, extract_spki_fingerprint, TenantClientConfigs, TransportEndpoint,
};

use super::NodeRuntimeNetInfo;

/// Result of the startup phase: everything needed to run accept/connect loops.
pub(crate) struct StartupResult {
    pub(crate) endpoint: TransportEndpoint,
    pub(crate) local_addr: SocketAddr,
    pub(crate) tenants: Vec<crate::db::transport_creds::TenantInfo>,
    pub(crate) tenant_client_configs: TenantClientConfigs,
    /// Transport fingerprints of all local tenants (for mDNS self-filtering).
    pub(crate) local_transport_peer_ids: HashSet<String>,
}

/// Discover local tenants, build certs, create the QUIC endpoint, and
/// optionally send `NodeRuntimeNetInfo` back to the caller.
pub(crate) fn setup_endpoint_and_tenants(
    db_path: &str,
    bind: SocketAddr,
    net_info_tx: tokio::sync::oneshot::Sender<NodeRuntimeNetInfo>,
) -> Result<StartupResult, Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    create_tables(&db)?;
    let (daemon_peer_id, _daemon_cert, _daemon_key) = ensure_daemon_identity(&db)?;

    let tenants = discover_local_tenants(&db)?;
    drop(db);

    if tenants.is_empty() {
        return Err("local tenant set is empty".into());
    }

    info!("Discovered {} local tenant(s)", tenants.len());

    // Collect all local transport fingerprints for mDNS self-filtering.
    let local_transport_peer_ids: HashSet<String> = tenants
        .iter()
        .map(|t| t.transport_peer_id.clone())
        .collect();

    let mut peer_to_workspace: HashMap<String, String> = HashMap::new();

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
        if expected_peer_id != tenant.transport_peer_id {
            error!(
                "SPKI mismatch for tenant {} transport identity {}: cert yields {}",
                tenant.peer_id, tenant.transport_peer_id, expected_peer_id
            );
            continue;
        }
        if tenant.transport_peer_id != tenant.peer_id {
            warn!(
                "Tenant {} using transitional transport identity {} — peer signer has \
                 not been derived yet. Connections will fail TLS trust checks until \
                 bootstrap sync completes and the permanent identity is materialized. \
                 The inviting peer's daemon must be running for this to succeed.",
                &tenant.peer_id[..16.min(tenant.peer_id.len())],
                &tenant.transport_peer_id[..16.min(tenant.transport_peer_id.len())]
            );
        }

        peer_to_workspace.insert(tenant.peer_id.clone(), tenant.workspace_id.clone());

        info!(
            "Registered tenant {} (workspace {}, daemon_peer_id={})",
            &tenant.peer_id[..16],
            &tenant.workspace_id[..16.min(tenant.workspace_id.len())],
            &daemon_peer_id[..16.min(daemon_peer_id.len())]
        );
    }

    let endpoint = create_runtime_endpoint_for_tenants(bind, db_path)?;

    let local_addr = endpoint.local_addr().unwrap_or(bind);
    info!(
        "Node listening on {} ({} workspace(s))",
        local_addr,
        tenants.len()
    );

    // Send runtime networking info back to caller (e.g. DaemonState in main.rs).
    let info = NodeRuntimeNetInfo {
        listen_addr: local_addr.to_string(),
        upnp: None,
    };
    let _ = net_info_tx.send(info);

    // Per-tenant outbound client configs
    let mut tenant_client_configs: TenantClientConfigs = HashMap::new();
    for tenant in &tenants {
        match build_tenant_client_config_from_db(db_path, &tenant.peer_id) {
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
        local_transport_peer_ids,
    })
}
