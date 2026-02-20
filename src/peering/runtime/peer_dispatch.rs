//! Peer dispatch logic: deduplication and reconnect management for discovered peers.
//!
//! Also includes `normalize_discovered_addr_for_local_bind` and
//! `spawn_connect_loop_thread` helpers used across the runtime sub-modules.

use std::collections::HashMap;
use std::net::SocketAddr;

use tracing::warn;

use crate::contracts::event_pipeline_contract::IngestFns;
use crate::peering::loops::{connect_loop, IntroSpawnerFn};

/// Dispatch decision for a discovered peer.
#[derive(Debug, PartialEq)]
pub(crate) enum DiscoveryAction {
    /// Same peer at same address -- skip (dedupe).
    Skip,
    /// New peer -- spawn connect_loop.
    Connect,
    /// Known peer at new address -- cancel old loop, spawn new one.
    Reconnect,
}

/// Tracks discovered peers and manages cancellation of stale connect_loops.
/// Extracted for testability.
pub(crate) struct PeerDispatcher {
    pub(crate) known: HashMap<String, (SocketAddr, tokio::sync::watch::Sender<()>)>,
}

impl PeerDispatcher {
    pub(crate) fn new() -> Self {
        Self {
            known: HashMap::new(),
        }
    }

    /// Evaluate a discovery event. Returns the action to take and (for Connect/Reconnect)
    /// a watch::Receiver that will be signalled when this entry is superseded.
    pub(crate) fn dispatch(
        &mut self,
        peer_id: &str,
        addr: SocketAddr,
    ) -> (DiscoveryAction, Option<tokio::sync::watch::Receiver<()>>) {
        if let Some((prev_addr, _)) = self.known.get(peer_id) {
            if *prev_addr == addr {
                return (DiscoveryAction::Skip, None);
            }
        }
        let action = if self.known.contains_key(peer_id) {
            DiscoveryAction::Reconnect
        } else {
            DiscoveryAction::Connect
        };
        // Drop old sender (if any) to cancel the old connect_loop
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(());
        self.known.insert(peer_id.to_string(), (addr, cancel_tx));
        (action, Some(cancel_rx))
    }
}

pub(crate) fn normalize_discovered_addr_for_local_bind(
    local_listen_ip: std::net::IpAddr,
    discovered: SocketAddr,
) -> SocketAddr {
    if local_listen_ip.is_loopback() && !discovered.ip().is_loopback() {
        // Keep the exact loopback family we are actually bound on.
        // If we're bound to 127.0.0.1 and mDNS returns an IPv6 remote,
        // dialing ::1 would fail because the server is v4-only.
        SocketAddr::new(local_listen_ip, discovered.port())
    } else {
        discovered
    }
}

pub(crate) fn spawn_connect_loop_thread(
    db_path: String,
    tenant_id: String,
    endpoint: quinn::Endpoint,
    remote: SocketAddr,
    cfg: quinn::ClientConfig,
    source: &'static str,
    intro_spawner: IntroSpawnerFn,
    ingest: IngestFns,
) {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            if let Err(e) = connect_loop(
                &db_path,
                &tenant_id,
                endpoint,
                remote,
                Some(cfg),
                intro_spawner,
                ingest,
            )
            .await
            {
                warn!(
                    "{} connect_loop for {} to {} exited: {}",
                    source,
                    &tenant_id[..16.min(tenant_id.len())],
                    remote,
                    e
                );
            }
        });
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new("127.0.0.1".parse().unwrap(), port)
    }

    #[test]
    fn test_dispatch_new_peer_returns_connect() {
        let mut d = PeerDispatcher::new();
        let (action, rx) = d.dispatch("peer-a", addr(1000));
        assert_eq!(action, DiscoveryAction::Connect);
        assert!(rx.is_some(), "should return cancel receiver");
    }

    #[test]
    fn test_dispatch_same_addr_returns_skip() {
        let mut d = PeerDispatcher::new();
        d.dispatch("peer-a", addr(1000));

        let (action, rx) = d.dispatch("peer-a", addr(1000));
        assert_eq!(action, DiscoveryAction::Skip);
        assert!(rx.is_none());
    }

    #[test]
    fn test_dispatch_different_addr_returns_reconnect() {
        let mut d = PeerDispatcher::new();
        d.dispatch("peer-a", addr(1000));

        let (action, rx) = d.dispatch("peer-a", addr(2000));
        assert_eq!(action, DiscoveryAction::Reconnect);
        assert!(rx.is_some());
    }

    #[test]
    fn test_dispatch_addr_change_cancels_old_receiver() {
        let mut d = PeerDispatcher::new();
        let (_, old_rx) = d.dispatch("peer-a", addr(1000));
        let mut old_rx = old_rx.unwrap();

        // Address changes -- old sender should be dropped
        let (action, _new_rx) = d.dispatch("peer-a", addr(2000));
        assert_eq!(action, DiscoveryAction::Reconnect);

        // Old receiver should detect sender was dropped (changed returns Err)
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let result = old_rx.changed().await;
            assert!(result.is_err(), "old receiver should see sender dropped");
        });
    }

    #[test]
    fn test_dispatch_repeated_churn_only_one_active() {
        let mut d = PeerDispatcher::new();
        let mut receivers = Vec::new();

        // Simulate 10 address changes for the same peer
        for port in 1000..1010 {
            let (action, rx) = d.dispatch("peer-a", addr(port));
            assert_ne!(action, DiscoveryAction::Skip);
            if let Some(rx) = rx {
                receivers.push(rx);
            }
        }

        // Only the last receiver should be live (sender not dropped)
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // All but the last should be cancelled
            for mut rx in receivers.drain(..receivers.len() - 1) {
                let result = rx.changed().await;
                assert!(result.is_err(), "old receiver should be cancelled");
            }
        });

        // Exactly one entry in the map
        assert_eq!(d.known.len(), 1);
        assert_eq!(d.known.get("peer-a").unwrap().0, addr(1009));
    }

    #[test]
    fn test_dispatch_multiple_peers_independent() {
        let mut d = PeerDispatcher::new();

        let (a1, _) = d.dispatch("peer-a", addr(1000));
        let (b1, _) = d.dispatch("peer-b", addr(2000));
        assert_eq!(a1, DiscoveryAction::Connect);
        assert_eq!(b1, DiscoveryAction::Connect);

        // Changing peer-a doesn't affect peer-b
        let (a2, _) = d.dispatch("peer-a", addr(1001));
        let (b2, _) = d.dispatch("peer-b", addr(2000));
        assert_eq!(a2, DiscoveryAction::Reconnect);
        assert_eq!(b2, DiscoveryAction::Skip);
    }

    #[test]
    fn test_normalize_discovered_addr_for_loopback_bind_rewrites_ipv4() {
        let local_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let discovered: SocketAddr = "192.168.10.42:4455".parse().unwrap();
        let out = normalize_discovered_addr_for_local_bind(local_ip, discovered);
        assert_eq!(out, "127.0.0.1:4455".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn test_normalize_discovered_addr_for_non_loopback_bind_keeps_addr() {
        let local_ip: std::net::IpAddr = "192.168.10.10".parse().unwrap();
        let discovered: SocketAddr = "192.168.10.42:4455".parse().unwrap();
        let out = normalize_discovered_addr_for_local_bind(local_ip, discovered);
        assert_eq!(out, discovered);
    }

    #[test]
    fn test_normalize_discovered_ipv6_for_ipv4_loopback_bind_uses_ipv4_loopback() {
        let local_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let discovered: SocketAddr = "[2001:db8::42]:4455".parse().unwrap();
        let out = normalize_discovered_addr_for_local_bind(local_ip, discovered);
        assert_eq!(out, "127.0.0.1:4455".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn test_normalize_discovered_ipv4_for_ipv6_loopback_bind_uses_ipv6_loopback() {
        let local_ip: std::net::IpAddr = "::1".parse().unwrap();
        let discovered: SocketAddr = "192.168.10.42:4455".parse().unwrap();
        let out = normalize_discovered_addr_for_local_bind(local_ip, discovered);
        assert_eq!(out, "[::1]:4455".parse::<SocketAddr>().unwrap());
    }
}
