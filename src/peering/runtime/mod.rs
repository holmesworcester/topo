//! Network runtime: daemon lifecycle, discovery, and peer dispatch.
//!
//! Extracted from node.rs (Phase 4 of Option B refactor).
//! Discovers local tenant identities, creates a single QUIC endpoint with a
//! multi-workspace cert resolver, and routes all incoming events through a
//! single shared batch_writer.

mod autodial;
mod discovery;
mod peer_dispatch;
mod startup;

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::peering::nat::upnp::UpnpMappingReport;

use crate::contracts::event_pipeline_contract::{IngestFns, IngestItem};
use crate::peering::loops::{accept_loop_with_ingest, IntroSpawnerFn};

use autodial::{
    build_tenant_client_config, collect_placeholder_invite_autodial_targets,
    spawn_placeholder_autodial_refresher,
};
use peer_dispatch::spawn_connect_loop_thread;
use startup::setup_endpoint_and_tenants;

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
/// If `net_info_tx` is provided, runtime networking info (listen addr + UPnP
/// result) is sent as soon as the endpoint is bound and UPnP is attempted.
pub async fn run_node(
    db_path: &str,
    bind: SocketAddr,
    net_info_tx: Option<tokio::sync::oneshot::Sender<NodeRuntimeNetInfo>>,
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

    // Keep discovery handles alive so mDNS services stay registered
    #[cfg(feature = "discovery")]
    let _discovery_handles = discovery::launch_mdns_discovery(
        &tenants,
        _local_addr,
        &_local_peer_ids,
        &endpoint,
        &tenant_client_configs,
        intro_spawner,
        ingest,
        db_path,
    );

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

    // Placeholder invite-based autodial source for realism tests.
    let disable_placeholder_autodial = std::env::var("P7_DISABLE_PLACEHOLDER_AUTODIAL")
        .ok()
        .map(|v| {
            let lowered = v.to_ascii_lowercase();
            lowered == "1" || lowered == "true" || lowered == "yes"
        })
        .unwrap_or(false);
    if disable_placeholder_autodial {
        warn!("PLACEHOLDER AUTODIAL DISABLED by P7_DISABLE_PLACEHOLDER_AUTODIAL");
    } else {
        let autodial_targets = collect_placeholder_invite_autodial_targets(db_path)?;
        let mut launched_autodial: HashSet<(String, SocketAddr)> = HashSet::new();
        if !autodial_targets.is_empty() {
            warn!(
                "PLACEHOLDER AUTODIAL ENABLED: launching {} invite-seeded outbound dial(s)",
                autodial_targets.len()
            );
        }
        for (tenant_id, remote) in autodial_targets {
            launched_autodial.insert((tenant_id.clone(), remote));
            let cfg = match build_tenant_client_config(db_path, &tenant_id) {
                Ok(c) => c,
                Err(e) => {
                    warn!(
                        "Skipping placeholder autodial for {}: {}",
                        &tenant_id[..16.min(tenant_id.len())],
                        e
                    );
                    continue;
                }
            };
            info!(
                "PLACEHOLDER AUTODIAL: tenant {} dialing invite bootstrap {}",
                &tenant_id[..16.min(tenant_id.len())],
                remote
            );
            spawn_connect_loop_thread(
                db_path.to_string(),
                tenant_id,
                connect_endpoint.clone(),
                remote,
                cfg,
                "placeholder-autodial",
                intro_spawner,
                ingest,
            );
        }
        // Keep polling for runtime invite acceptance
        spawn_placeholder_autodial_refresher(
            db_path.to_string(),
            connect_endpoint.clone(),
            launched_autodial,
            intro_spawner,
            ingest,
        );
    }

    // Drop our copy so writer exits when all accept loops drop theirs
    drop(shared_tx);

    // Wait for Ctrl-C
    tokio::signal::ctrl_c().await?;
    info!(
        "Shutting down ({} events received)",
        events_received.load(Ordering::Relaxed)
    );

    drop(accept_handle);
    Ok(())
}
