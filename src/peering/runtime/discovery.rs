//! mDNS discovery and browsing for local tenants.
//!
//! Advertises each tenant via mDNS and spawns per-tenant browse threads
//! that auto-connect to discovered remote peers using `PeerDispatcher`.

#[cfg(feature = "discovery")]
use std::collections::HashMap;
#[cfg(feature = "discovery")]
use std::net::SocketAddr;

#[cfg(feature = "discovery")]
use tracing::{info, warn};

#[cfg(feature = "discovery")]
use crate::contracts::event_runtime_contract::IngestFns;
#[cfg(feature = "discovery")]
use crate::peering::loops::{connect_loop, IntroSpawnerFn};

#[cfg(feature = "discovery")]
use super::peer_dispatch::{normalize_discovered_addr_for_local_bind, DiscoveryAction, PeerDispatcher};

/// Launch mDNS advertisement and browse threads for all tenants.
///
/// Returns a `Vec<TenantDiscovery>` that must be kept alive to maintain
/// mDNS service registration.
#[cfg(feature = "discovery")]
pub(crate) fn launch_mdns_discovery(
    tenants: &[crate::db::transport_creds::TenantInfo],
    local_addr: SocketAddr,
    local_peer_ids: &std::collections::HashSet<String>,
    endpoint: &quinn::Endpoint,
    tenant_client_configs: &HashMap<String, quinn::ClientConfig>,
    intro_spawner: IntroSpawnerFn,
    ingest: IngestFns,
    db_path: &str,
) -> Vec<crate::peering::discovery::TenantDiscovery> {
    let mut discovery_handles: Vec<crate::peering::discovery::TenantDiscovery> = Vec::new();

    let actual_port = local_addr.port();
    let advertise_ip = if local_addr.ip().is_unspecified() || local_addr.ip().is_loopback() {
        crate::peering::discovery::local_non_loopback_ipv4().unwrap_or_else(|| "0.0.0.0".to_string())
    } else {
        local_addr.ip().to_string()
    };
    let local_listen_ip = local_addr.ip();

    for tenant in tenants {
        match crate::peering::discovery::TenantDiscovery::new(
            &tenant.peer_id,
            actual_port,
            local_peer_ids.clone(),
            &advertise_ip,
        ) {
            Ok(disc) => {
                match disc.browse() {
                    Ok(rx) => {
                        let ep_clone = endpoint.clone();
                        let db_path_disc = db_path.to_string();
                        let tenant_id = tenant.peer_id.clone();
                        let local_listen_ip_for_thread = local_listen_ip;
                        let disc_client_cfg =
                            match tenant_client_configs.get(&tenant.peer_id).cloned() {
                                Some(c) => c,
                                None => {
                                    warn!(
                                        "Skipping mDNS browse for {}: no client config",
                                        &tenant.peer_id[..16]
                                    );
                                    discovery_handles.push(disc);
                                    continue;
                                }
                            };
                        std::thread::spawn(move || {
                            let mut dispatcher = PeerDispatcher::new();
                            while let Ok(peer) = rx.recv() {
                                let dial_addr = normalize_discovered_addr_for_local_bind(
                                    local_listen_ip_for_thread,
                                    peer.addr,
                                );
                                let (action, cancel_rx) =
                                    dispatcher.dispatch(&peer.peer_id, dial_addr);
                                match action {
                                    DiscoveryAction::Skip => continue,
                                    DiscoveryAction::Reconnect => {
                                        info!(
                                            "mDNS: tenant {} peer {} addr changed, reconnecting at {}",
                                            &tenant_id[..16],
                                            &peer.peer_id[..16.min(peer.peer_id.len())],
                                            dial_addr
                                        );
                                    }
                                    DiscoveryAction::Connect => {
                                        info!(
                                            "mDNS: tenant {} connecting to discovered peer {} at {}",
                                            &tenant_id[..16],
                                            &peer.peer_id[..16.min(peer.peer_id.len())],
                                            dial_addr
                                        );
                                    }
                                }
                                let mut cancel = cancel_rx.unwrap();
                                let ep = ep_clone.clone();
                                let db = db_path_disc.clone();
                                let tid = tenant_id.clone();
                                let cfg = Some(disc_client_cfg.clone());
                                std::thread::spawn(move || {
                                    let rt = tokio::runtime::Builder::new_current_thread()
                                        .enable_all()
                                        .build()
                                        .unwrap();
                                    rt.block_on(async move {
                                        tokio::select! {
                                            _ = connect_loop(
                                                &db, &tid, ep, dial_addr, cfg, intro_spawner, ingest,
                                            ) => {}
                                            _ = cancel.changed() => {}
                                        }
                                    });
                                });
                            }
                        });
                    }
                    Err(e) => warn!("mDNS browse failed for {}: {}", &tenant.peer_id[..16], e),
                }
                discovery_handles.push(disc);
            }
            Err(e) => warn!(
                "mDNS registration failed for {}: {}",
                &tenant.peer_id[..16],
                e
            ),
        }
    }

    discovery_handles
}
