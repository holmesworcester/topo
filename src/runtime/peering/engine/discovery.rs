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
pub(crate) fn resolve_mdns_advertise_ip(
    local_addr: SocketAddr,
    allow_autodetect: bool,
) -> Option<String> {
    if !local_addr.ip().is_unspecified() && !local_addr.ip().is_loopback() {
        return Some(local_addr.ip().to_string());
    }
    if allow_autodetect {
        return crate::peering::discovery::local_non_loopback_ipv4();
    }
    None
}

#[cfg(not(feature = "discovery"))]
pub(crate) fn resolve_mdns_advertise_ip(
    _local_addr: SocketAddr,
    _allow_autodetect: bool,
) -> Option<String> {
    None
}

/// Prepare mDNS advertisement + browse receivers for all eligible tenants.
///
/// No workers are spawned here; caller owns runtime worker lifecycle.
#[cfg(feature = "discovery")]
pub(crate) fn prepare_mdns_discovery(
    tenants: &[crate::db::transport_creds::TenantInfo],
    local_addr: SocketAddr,
    advertise_ip: Option<String>,
    local_peer_ids: &HashSet<String>,
    tenant_client_configs: &TenantClientConfigs,
) -> DiscoveryRuntimeSetup {
    let mut handles: Vec<crate::peering::discovery::TenantDiscovery> = Vec::new();
    let mut ingress_sources: Vec<DiscoveryIngressSource> = Vec::new();

    let actual_port = local_addr.port();
    let Some(advertise_ip) = advertise_ip else {
        warn!(
            "mDNS discovery disabled: no explicit advertise address and autodetection is disabled"
        );
        return DiscoveryRuntimeSetup {
            handles,
            ingress_sources,
        };
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

#[cfg(all(test, feature = "discovery"))]
mod tests {
    use super::resolve_mdns_advertise_ip;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn explicit_bind_without_autodetect_suppresses_loopback_discovery() {
        let advertise_ip = resolve_mdns_advertise_ip(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433),
            false,
        );
        assert_eq!(advertise_ip, None);
    }

    #[test]
    fn explicit_non_loopback_bind_stays_discoverable_without_autodetect() {
        let advertise_ip = resolve_mdns_advertise_ip(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 44)), 4433),
            false,
        );
        assert_eq!(advertise_ip.as_deref(), Some("192.168.1.44"));
    }
}
