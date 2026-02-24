//! Peering runtime: daemon lifecycle, discovery, and peer dispatch.
//!
//! Extracted from node.rs (Phase 4 of Option B refactor).
//! Discovers local tenant identities, creates a single QUIC endpoint with a
//! multi-workspace cert resolver, and routes all incoming events through a
//! single shared batch_writer.

mod discovery;
mod startup;
pub(crate) mod target_planner;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::peering::nat::upnp::UpnpMappingReport;

use crate::contracts::event_pipeline_contract::{IngestFns, IngestItem};
use crate::peering::loops::{accept_loop_with_ingest, IntroSpawnerFn};
use crate::sync::CoordinationManager;

use startup::setup_endpoint_and_tenants;
use target_planner::{
    build_tenant_client_config, collect_all_bootstrap_targets, dispatch_bootstrap_target,
    spawn_bootstrap_refresher, spawn_connect_loop_thread, PeerDispatcher,
};

/// Runtime networking information collected during node startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRuntimeNetInfo {
    /// Actual bound listen address (after OS port assignment).
    pub listen_addr: String,
    /// UPnP port mapping attempt result (None until `topo upnp` is run).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upnp: Option<UpnpMappingReport>,
}

/// Run the sync node.
///
/// Discovers all local identities from the DB, verifies their SPKI fingerprints,
/// builds a single QUIC endpoint with multi-workspace cert resolver, and runs
/// a single accept loop sharing a batch_writer thread. With `discovery` feature,
/// also advertises via mDNS and auto-connects to discovered peers.
///
/// Runtime networking info (listen addr + UPnP result) is sent as soon as the
/// endpoint is bound and UPnP is attempted.
pub async fn run_node(
    db_path: &str,
    bind: SocketAddr,
    net_info_tx: tokio::sync::oneshot::Sender<NodeRuntimeNetInfo>,
    shutdown_notify: Arc<tokio::sync::Notify>,
    intro_spawner: IntroSpawnerFn,
    ingest: IngestFns,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let startup::StartupResult {
        endpoint,
        local_addr: _local_addr,
        tenants,
        tenant_client_configs,
        local_peer_ids: _local_peer_ids,
    } = setup_endpoint_and_tenants(db_path, bind, net_info_tx)?;

    // Shared batch_writer: single writer thread for all tenants.
    let ingest_cap = if tenants.len() > 1 { 10000 } else { 5000 };
    let (shared_tx, shared_rx) = mpsc::channel::<IngestItem>(ingest_cap);
    let events_received = Arc::new(AtomicU64::new(0));
    let writer_events = events_received.clone();
    let writer_db = db_path.to_string();
    let bw = ingest.batch_writer;
    let _writer_handle = std::thread::spawn(move || {
        bw(writer_db, shared_rx, writer_events);
    });

    // Per-tenant coordination managers: all outbound initiator sessions for a
    // tenant share the same coordinator so download work is distributed across
    // concurrently connected peers.
    let coord_managers: HashMap<String, Arc<CoordinationManager>> = tenants
        .iter()
        .map(|t| (t.peer_id.clone(), Arc::new(CoordinationManager::new())))
        .collect();

    // Keep discovery handles alive so mDNS services stay registered
    #[cfg(feature = "discovery")]
    let _discovery_handles = {
        let disable_discovery = std::env::var("P7_DISABLE_DISCOVERY")
            .ok()
            .map(|v| {
                let lowered = v.to_ascii_lowercase();
                lowered == "1" || lowered == "true" || lowered == "yes"
            })
            .unwrap_or(false);
        if disable_discovery {
            warn!("mDNS discovery disabled by P7_DISABLE_DISCOVERY");
            Vec::new()
        } else {
            discovery::launch_mdns_discovery(
                &tenants,
                _local_addr,
                &_local_peer_ids,
                &endpoint,
                &tenant_client_configs,
                intro_spawner,
                ingest,
                db_path,
                &coord_managers,
            )
        }
    };

    // Clone endpoint before moving into accept thread (needed for connect_loop).
    let connect_endpoint = endpoint.clone();

    // Single accept loop for all workspaces.
    let all_tenant_ids: Vec<String> = tenants.iter().map(|t| t.peer_id.clone()).collect();
    let db_path_owned = db_path.to_string();
    let ingest_tx = shared_tx.clone();
    let accept_configs = tenant_client_configs.clone();
    let accept_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            if let Err(e) = accept_loop_with_ingest(
                &db_path_owned,
                &all_tenant_ids,
                endpoint,
                None,
                ingest_tx,
                accept_configs,
                intro_spawner,
                ingest,
            )
            .await
            {
                warn!("accept_loop exited: {}", e);
            }
        });
    });

    // Bootstrap invite-based autodial: polls SQL trust state for bootstrap
    // addresses and dials them. This is the primary bootstrap sync mechanism.
    let disable_placeholder_autodial = std::env::var("P7_DISABLE_PLACEHOLDER_AUTODIAL")
        .ok()
        .map(|v| {
            let lowered = v.to_ascii_lowercase();
            lowered == "1" || lowered == "true" || lowered == "yes"
        })
        .unwrap_or(false);
    if disable_placeholder_autodial {
        warn!("BOOTSTRAP AUTODIAL DISABLED by P7_DISABLE_PLACEHOLDER_AUTODIAL");
    } else {
        let autodial_targets = collect_all_bootstrap_targets(db_path)?;
        let mut dispatcher = PeerDispatcher::new();
        if !autodial_targets.is_empty() {
            warn!(
                "BOOTSTRAP AUTODIAL: launching {} invite-seeded outbound dial(s)",
                autodial_targets.len()
            );
        }
        for (tenant_id, remote) in autodial_targets {
            if !dispatch_bootstrap_target(&mut dispatcher, &tenant_id, remote) {
                continue;
            }
            let cfg = match build_tenant_client_config(db_path, &tenant_id) {
                Ok(c) => c,
                Err(e) => {
                    warn!(
                        "Skipping bootstrap autodial for {}: {}",
                        &tenant_id[..16.min(tenant_id.len())],
                        e
                    );
                    continue;
                }
            };
            info!(
                "BOOTSTRAP AUTODIAL: tenant {} dialing invite bootstrap {}",
                &tenant_id[..16.min(tenant_id.len())],
                remote
            );
            let coordination_manager = coord_managers[&tenant_id].clone();
            spawn_connect_loop_thread(
                db_path.to_string(),
                tenant_id,
                connect_endpoint.clone(),
                remote,
                cfg,
                "bootstrap-autodial",
                intro_spawner,
                ingest,
                coordination_manager,
            );
        }
        // Keep polling for runtime invite acceptance (shares PeerDispatcher dedup state)
        spawn_bootstrap_refresher(
            db_path.to_string(),
            connect_endpoint.clone(),
            dispatcher,
            intro_spawner,
            ingest,
            coord_managers.clone(),
        );
    }

    // Drop our copy so writer exits when all accept loops drop theirs
    drop(shared_tx);

    // Wait for daemon shutdown signal (RPC Shutdown or foreground Ctrl-C).
    shutdown_notify.notified().await;
    info!(
        "Shutting down ({} events received)",
        events_received.load(Ordering::Relaxed)
    );

    drop(accept_handle);
    Ok(())
}
