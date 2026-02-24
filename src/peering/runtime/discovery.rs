//! mDNS discovery setup for runtime supervision.
//!
//! This module only prepares discovery sources (advertisement handles + browse
//! receivers). Runtime worker ownership and spawning live in `supervisor.rs`.

#[cfg(feature = "discovery")]
use std::collections::HashSet;
#[cfg(feature = "discovery")]
use std::net::{IpAddr, SocketAddr};

#[cfg(feature = "discovery")]
use tracing::warn;

#[cfg(feature = "discovery")]
use crate::transport::TenantClientConfigs;

/// One tenant-scoped discovery receiver that the runtime supervisor ingests.
#[cfg(feature = "discovery")]
pub(crate) struct DiscoveryIngressSource {
    pub(crate) tenant_id: String,
    pub(crate) local_listen_ip: IpAddr,
    pub(crate) rx: std::sync::mpsc::Receiver<crate::peering::discovery::DiscoveredPeer>,
}

/// Prepared discovery runtime resources.
#[cfg(feature = "discovery")]
pub(crate) struct DiscoveryRuntimeSetup {
    /// Must be kept alive so mDNS service registrations remain active.
    pub(crate) handles: Vec<crate::peering::discovery::TenantDiscovery>,
    /// Per-tenant browse receivers consumed by supervisor-owned workers.
    pub(crate) ingress_sources: Vec<DiscoveryIngressSource>,
}

/// Prepare mDNS advertisement + browse receivers for all eligible tenants.
///
/// No workers are spawned here; caller owns runtime worker lifecycle.
#[cfg(feature = "discovery")]
pub(crate) fn prepare_mdns_discovery(
    tenants: &[crate::db::transport_creds::TenantInfo],
    local_addr: SocketAddr,
    local_peer_ids: &HashSet<String>,
    tenant_client_configs: &TenantClientConfigs,
) -> DiscoveryRuntimeSetup {
    let mut handles: Vec<crate::peering::discovery::TenantDiscovery> = Vec::new();
    let mut ingress_sources: Vec<DiscoveryIngressSource> = Vec::new();

    let actual_port = local_addr.port();
    let advertise_ip = if local_addr.ip().is_unspecified() || local_addr.ip().is_loopback() {
        crate::peering::discovery::local_non_loopback_ipv4().unwrap_or_else(|| "0.0.0.0".into())
    } else {
        local_addr.ip().to_string()
    };
    let local_listen_ip = local_addr.ip();

    for tenant in tenants {
        match crate::peering::discovery::TenantDiscovery::new_with_workspace(
            &tenant.peer_id,
            actual_port,
            local_peer_ids.clone(),
            &advertise_ip,
            Some(&tenant.workspace_id),
        ) {
            Ok(disc) => {
                if !tenant_client_configs.contains_key(&tenant.peer_id) {
                    warn!(
                        "Skipping mDNS browse for {}: no client config",
                        &tenant.peer_id[..16]
                    );
                    handles.push(disc);
                    continue;
                }

                match disc.browse() {
                    Ok(rx) => {
                        ingress_sources.push(DiscoveryIngressSource {
                            tenant_id: tenant.peer_id.clone(),
                            local_listen_ip,
                            rx,
                        });
                    }
                    Err(e) => {
                        warn!("mDNS browse failed for {}: {}", &tenant.peer_id[..16], e);
                    }
                }

                handles.push(disc);
            }
            Err(e) => warn!(
                "mDNS registration failed for {}: {}",
                &tenant.peer_id[..16],
                e
            ),
        }
    }

    DiscoveryRuntimeSetup {
        handles,
        ingress_sources,
    }
}
