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
        /// `advertise_ip` is the routable IP to advertise in the mDNS A record.
        /// The caller must provide a non-loopback IP — mDNS multicast does not
        /// discover services advertised on 127.0.0.1. Use
        /// [`local_non_loopback_ipv4`] to obtain a suitable address when the
        /// daemon is bound to loopback or a wildcard address.
        pub fn new(
            peer_id: &str,
            port: u16,
            local_peer_ids: HashSet<String>,
            advertise_ip: &str,
        ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
            let daemon = ServiceDaemon::new()?;

            // Instance name: truncated peer_id (DNS labels max 63 bytes).
            // Full peer_id is 64 hex chars; "p7-" prefix + 59 chars = 62.
            // The full peer_id is in the TXT "peer_id" property for exact matching.
            let id_truncated = &peer_id[..59.min(peer_id.len())];
            let instance = format!("p7-{}", id_truncated);

            // Do not use the machine hostname here. In segmented test harnesses
            // (and some container setups), many peers can share /etc/hostname,
            // which causes mDNS host-record collisions and wrong peer->addr
            // resolution. A per-tenant host label keeps records disjoint.
            let host_label = format!("p7h-{}", id_truncated);
            let host = format!("{}.local.", host_label);
            let properties = [("peer_id", peer_id)];
            let service = ServiceInfo::new(
                SERVICE_TYPE,
                &instance,
                &host,
                advertise_ip,
                port,
                &properties[..],
            )?;

            daemon.register(service)?;
            info!(
                "mDNS: advertising tenant {} on {}:{}",
                &peer_id[..16.min(peer_id.len())],
                advertise_ip,
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

                            // Extract address: prefer non-loopback, non-link-local
                            let addrs: Vec<&IpAddr> = info.get_addresses().iter().collect();
                            let best_ip = addrs.iter()
                                .find(|ip| !ip.is_loopback() && !is_link_local(ip))
                                .or_else(|| addrs.iter().find(|ip| !ip.is_loopback()))
                                .or(addrs.first());
                            if let Some(ip) = best_ip {
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

    fn is_link_local(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                octets[0] == 169 && octets[1] == 254 // 169.254.0.0/16
            }
            IpAddr::V6(v6) => {
                let segments = v6.segments();
                segments[0] & 0xffc0 == 0xfe80 // fe80::/10
            }
        }
    }

    /// Find a non-loopback IPv4 address suitable for mDNS advertisement.
    ///
    /// Uses the OS routing table to determine which local IP would be used
    /// to reach the internet. Returns `None` if no routable address is found.
    pub fn local_non_loopback_ipv4() -> Option<String> {
        use std::net::UdpSocket;
        // Connect a UDP socket to a public address to discover the local IP
        // the OS would route through. No data is actually sent.
        let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
        socket.connect("8.8.8.8:80").ok()?;
        let addr = socket.local_addr().ok()?;
        Some(addr.ip().to_string())
    }

}

#[cfg(feature = "discovery")]
pub use inner::*;
