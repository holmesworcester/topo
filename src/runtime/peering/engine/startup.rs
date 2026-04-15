//! Endpoint creation and tenant discovery.
//!
//! Extracts the startup phase of `run_node`: discovers local tenants, verifies
//! local/runtime tenant state, loads the singleton daemon transport identity,
//! and creates the single QUIC endpoint.

use std::collections::HashMap;
use std::net::SocketAddr;

use tracing::{error, info, warn};

use crate::db::transport_creds::discover_local_tenants;
use crate::db::{open_connection, schema::create_tables};
use crate::transport::{
    create_runtime_endpoint_for_tenants, ensure_daemon_identity, extract_spki_fingerprint,
    TransportEndpoint,
};

use super::NodeRuntimeNetInfo;

/// Result of the startup phase: everything needed to run accept/connect loops.
pub(crate) struct StartupResult {
    pub(crate) endpoint: TransportEndpoint,
    pub(crate) tenants: Vec<crate::db::transport_creds::TenantInfo>,
}

/// Discover local tenants, build certs, create the QUIC endpoint, and
/// optionally send `NodeRuntimeNetInfo` back to the caller.
pub(crate) async fn setup_endpoint_and_tenants(
    db_path: &str,
    bind: SocketAddr,
    net_info_tx: tokio::sync::oneshot::Sender<NodeRuntimeNetInfo>,
) -> Result<StartupResult, Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    create_tables(&db)?;
    let (daemon_peer_id, _daemon_cert, _daemon_key) = ensure_daemon_identity(&db)?;

    let tenants = discover_local_tenants(&db)?;
    drop(db);

    info!("Discovered {} local tenant(s)", tenants.len());

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

    let endpoint = create_runtime_endpoint_for_tenants(bind, db_path).await?;

    let local_addr = endpoint.local_addr().unwrap_or(bind);
    info!(
        "Node listening on {} ({} workspace(s))",
        local_addr,
        tenants.len()
    );

    // Send runtime networking info back to caller (e.g. DaemonState in main.rs).
    let info = NodeRuntimeNetInfo {
        listen_addr: local_addr.to_string(),
        daemon_peer_id: endpoint.daemon_peer_id(),
        published_addrs: endpoint.published_addrs(),
        mdns_enabled: endpoint.discovery_enabled(),
        endpoint: Some(endpoint.clone()),
    };
    let _ = net_info_tx.send(info);

    // Suppress unused-variable warning: peer_to_workspace is built for future use
    let _ = peer_to_workspace;

    Ok(StartupResult { endpoint, tenants })
}
