//! LAN peer discovery via mDNS/DNS-SD.
//!
//! Each tenant advertises its QUIC endpoint under `_quiet-p7._udp.local.`
//! with the peer_id encoded in the service instance name. Browsing discovers
//! remote tenants, self-filtering local identities.

#[cfg(feature = "discovery")]
mod inner {
    use std::collections::HashSet;
    use std::net::{IpAddr, SocketAddr};

    use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
    use tracing::{info, debug};

    const SERVICE_TYPE: &str = "_quiet-p7._udp.local.";

    /// A discovered peer on the LAN.
    #[derive(Debug, Clone)]
    pub struct DiscoveredPeer {
        pub peer_id: String,
        pub addr: SocketAddr,
    }

    /// Per-tenant mDNS advertiser + browser.
    pub struct TenantDiscovery {
        peer_id: String,
        daemon: ServiceDaemon,
        local_peer_ids: HashSet<String>,
    }

    impl TenantDiscovery {
        /// Register this tenant's endpoint on mDNS and prepare to browse.
        ///
        /// `local_peer_ids` is the full set of peer IDs on this node,
        /// used to self-filter discoveries.
        pub fn new(
            peer_id: &str,
            port: u16,
            local_peer_ids: HashSet<String>,
        ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
            let daemon = ServiceDaemon::new()?;

            // Instance name: first 16 hex chars of peer_id for readability
            let label = &peer_id[..16.min(peer_id.len())];
            let instance = format!("p7-{}", label);

            let host = format!("{}.local.", hostname());
            let properties = [("peer_id", peer_id)];
            let service = ServiceInfo::new(
                SERVICE_TYPE,
                &instance,
                &host,
                "",  // empty IP = auto-detect
                port,
                &properties[..],
            )?;

            daemon.register(service)?;
            info!(
                "mDNS: advertising tenant {} on port {}",
                &peer_id[..16.min(peer_id.len())],
                port
            );

            Ok(Self {
                peer_id: peer_id.to_string(),
                daemon,
                local_peer_ids,
            })
        }

        /// Browse for peers, returning a receiver of discovered (non-local) peers.
        pub fn browse(
            &self,
        ) -> Result<
            std::sync::mpsc::Receiver<DiscoveredPeer>,
            Box<dyn std::error::Error + Send + Sync>,
        > {
            let browser = self.daemon.browse(SERVICE_TYPE)?;
            let (tx, rx) = std::sync::mpsc::channel();
            let local_ids = self.local_peer_ids.clone();
            let my_peer_id = self.peer_id.clone();

            std::thread::spawn(move || {
                while let Ok(event) = browser.recv() {
                    match event {
                        ServiceEvent::ServiceResolved(info) => {
                            let remote_peer_id = info
                                .get_property_val_str("peer_id")
                                .unwrap_or_default()
                                .to_string();

                            // Skip our own and other local tenants
                            if local_ids.contains(&remote_peer_id) {
                                debug!(
                                    "mDNS: skipping local peer {}",
                                    &remote_peer_id[..16.min(remote_peer_id.len())]
                                );
                                continue;
                            }

                            // Extract address
                            let addrs: Vec<&IpAddr> = info.get_addresses().iter().collect();
                            if let Some(ip) = addrs.first() {
                                let addr = SocketAddr::new(**ip, info.get_port());
                                info!(
                                    "mDNS: tenant {} discovered peer {} at {}",
                                    &my_peer_id[..16.min(my_peer_id.len())],
                                    &remote_peer_id[..16.min(remote_peer_id.len())],
                                    addr
                                );
                                let _ = tx.send(DiscoveredPeer {
                                    peer_id: remote_peer_id,
                                    addr,
                                });
                            }
                        }
                        ServiceEvent::SearchStarted(_) => {
                            debug!("mDNS: browse started");
                        }
                        _ => {}
                    }
                }
            });

            Ok(rx)
        }
    }

    impl Drop for TenantDiscovery {
        fn drop(&mut self) {
            let _ = self.daemon.shutdown();
        }
    }

    fn hostname() -> String {
        std::fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "localhost".to_string())
    }
}

#[cfg(feature = "discovery")]
pub use inner::*;
