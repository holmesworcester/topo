//! Unified dial-target planning: the single owner of "what should we connect to."
//!
//! Both bootstrap trust autodial and mDNS discovery route their targets through
//! this module. It owns:
//!
//! - **Bootstrap target collection**: polls SQL invite_bootstrap_trust rows
//!   (materialized by InviteAccepted projection) and yields dial targets.
//! - **Discovery dispatch**: deduplicates mDNS-discovered peers and computes
//!   connect/reconnect/skip actions (`PeerDispatcher`).
//! - **Dispatch-key helpers**: deterministic keying for bootstrap + discovery
//!   target streams so one runtime dispatcher can own lifecycle decisions.
//!
//! This consolidation satisfies R3/SC3 of the peering readability plan:
//! one module is the source of truth for dial target planning.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

use tracing::warn;

use crate::db::open_connection;
use crate::db::transport_creds::list_local_peers;
use crate::db::transport_trust::list_active_invite_bootstrap_addrs;
use crate::event_modules::workspace::invite_link::parse_bootstrap_address;

// ---------------------------------------------------------------------------
// Discovery dispatch (PeerDispatcher)
// ---------------------------------------------------------------------------

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

    pub(crate) fn forget(&mut self, peer_id: &str) {
        self.known.remove(peer_id);
    }
}

pub(crate) fn normalize_discovered_addr_for_local_bind(
    local_listen_ip: std::net::IpAddr,
    discovered: SocketAddr,
) -> SocketAddr {
    if local_listen_ip.is_loopback() && !discovered.ip().is_loopback() {
        SocketAddr::new(local_listen_ip, discovered.port())
    } else {
        discovered
    }
}

// ---------------------------------------------------------------------------
// Unified dispatch-keying for bootstrap + discovery ingestion
// ---------------------------------------------------------------------------

pub(crate) fn bootstrap_dispatch_key(tenant_id: &str) -> String {
    format!("{}@bootstrap", tenant_id)
}

pub(crate) fn discovery_dispatch_key(tenant_id: &str, peer_id: &str) -> String {
    format!("{}@mdns:{}", tenant_id, peer_id)
}

// ---------------------------------------------------------------------------
// Bootstrap trust target collection
// ---------------------------------------------------------------------------

/// Load invite-seeded autodial targets for a set of known tenant IDs.
pub(crate) fn load_bootstrap_targets(
    db_path: &str,
    tenant_ids: &[String],
) -> Result<Vec<(String, SocketAddr)>, Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    let mut seen: HashSet<(String, SocketAddr)> = HashSet::new();
    let mut out = Vec::new();
    for tenant_id in tenant_ids {
        for addr_text in list_active_invite_bootstrap_addrs(&db, tenant_id)? {
            match parse_bootstrap_address(&addr_text).and_then(|addr| addr.to_socket_addr()) {
                Ok(addr) => {
                    let key = (tenant_id.clone(), addr);
                    if seen.insert(key.clone()) {
                        out.push(key);
                    }
                }
                Err(e) => {
                    warn!(
                        "Skipping invalid/unresolvable invite bootstrap_addr '{}' for tenant {}: {}",
                        addr_text,
                        &tenant_id[..16.min(tenant_id.len())],
                        e
                    );
                }
            }
        }
    }
    Ok(out)
}

/// Collect all bootstrap autodial targets across all local tenants.
pub(crate) fn collect_all_bootstrap_targets(
    db_path: &str,
) -> Result<Vec<(String, SocketAddr)>, Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    let tenant_ids = list_local_peers(&db)?;
    drop(db);
    load_bootstrap_targets(db_path, &tenant_ids)
}

// ---------------------------------------------------------------------------
// Bootstrap autodial refresher
// ---------------------------------------------------------------------------

/// Dispatch a bootstrap dial target through `PeerDispatcher`.
///
/// Uses `"{tenant_id}@bootstrap"` as the dispatch key so bootstrap targets
/// share the same dedup/reconnect mechanism as mDNS discovery targets.
/// Returns `true` if a new connect loop should be spawned.
pub(crate) fn dispatch_bootstrap_target(
    dispatcher: &mut PeerDispatcher,
    tenant_id: &str,
    remote: SocketAddr,
) -> bool {
    let key = bootstrap_dispatch_key(tenant_id);
    let (action, _cancel_rx) = dispatcher.dispatch(&key, remote);
    matches!(
        action,
        DiscoveryAction::Connect | DiscoveryAction::Reconnect
    )
}

/// Dispatch a discovery dial target through `PeerDispatcher`.
///
/// Discovery keys are tenant-scoped (`{tenant}@mdns:{peer}`) so one runtime
/// dispatcher can safely handle multi-tenant streams without cross-tenant
/// collisions.
pub(crate) fn dispatch_discovery_target(
    dispatcher: &mut PeerDispatcher,
    tenant_id: &str,
    peer_id: &str,
    remote: SocketAddr,
) -> bool {
    let key = discovery_dispatch_key(tenant_id, peer_id);
    let (action, _cancel_rx) = dispatcher.dispatch(&key, remote);
    matches!(
        action,
        DiscoveryAction::Connect | DiscoveryAction::Reconnect
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_connection;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;
    use crate::db::transport_trust;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new("127.0.0.1".parse().unwrap(), port)
    }

    // -- PeerDispatcher tests --

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

        let (action, _new_rx) = d.dispatch("peer-a", addr(2000));
        assert_eq!(action, DiscoveryAction::Reconnect);

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

        for port in 1000..1010 {
            let (action, rx) = d.dispatch("peer-a", addr(port));
            assert_ne!(action, DiscoveryAction::Skip);
            if let Some(rx) = rx {
                receivers.push(rx);
            }
        }

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            for mut rx in receivers.drain(..receivers.len() - 1) {
                let result = rx.changed().await;
                assert!(result.is_err(), "old receiver should be cancelled");
            }
        });

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

        let (a2, _) = d.dispatch("peer-a", addr(1001));
        let (b2, _) = d.dispatch("peer-b", addr(2000));
        assert_eq!(a2, DiscoveryAction::Reconnect);
        assert_eq!(b2, DiscoveryAction::Skip);
    }

    #[test]
    fn test_forget_clears_dispatch_slot() {
        let mut d = PeerDispatcher::new();
        d.dispatch("peer-a", addr(1000));
        d.forget("peer-a");

        let (action, rx) = d.dispatch("peer-a", addr(1000));
        assert_eq!(action, DiscoveryAction::Connect);
        assert!(rx.is_some(), "forgotten peer should be connectable again");
    }

    // -- Address normalization tests --

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

    // -- Bootstrap target collection tests --

    #[test]
    fn test_bootstrap_targets_from_trust_rows() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let recorded_by = "test-peer-1";

        let bootstrap_spki: [u8; 32] = [0xCC; 32];
        let bootstrap_addr = "192.168.1.100:4433";

        transport_trust::record_invite_bootstrap_trust(
            &conn,
            recorded_by,
            "ia-eid-1",
            "invite-eid-1",
            "ws-1",
            bootstrap_addr,
            &bootstrap_spki,
        )
        .unwrap();

        let addrs =
            transport_trust::list_active_invite_bootstrap_addrs(&conn, recorded_by).unwrap();
        assert_eq!(addrs.len(), 1, "must find one bootstrap addr");
        assert_eq!(addrs[0], bootstrap_addr);

        assert!(
            transport_trust::is_peer_allowed(&conn, recorded_by, &bootstrap_spki).unwrap(),
            "bootstrap SPKI must be allowed for TLS handshake"
        );
    }

    #[test]
    fn test_bootstrap_targets_cleared_after_supersession() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let recorded_by = "test-peer-2";

        let peer_pub: [u8; 32] = [0xDD; 32];
        let bootstrap_spki =
            crate::transport::cert::spki_fingerprint_from_ed25519_pubkey(&peer_pub);
        let bootstrap_addr = "10.0.0.1:5555";

        transport_trust::record_invite_bootstrap_trust(
            &conn,
            recorded_by,
            "ia-2",
            "inv-2",
            "ws-2",
            bootstrap_addr,
            &bootstrap_spki,
        )
        .unwrap();

        assert_eq!(
            transport_trust::list_active_invite_bootstrap_addrs(&conn, recorded_by)
                .unwrap()
                .len(),
            1
        );

        transport_trust::consume_bootstrap_for_peer_shared(&conn, recorded_by, &peer_pub)
            .unwrap();

        assert_eq!(
            transport_trust::list_active_invite_bootstrap_addrs(&conn, recorded_by)
                .unwrap()
                .len(),
            0,
            "superseded bootstrap trust must not appear in autodial"
        );
    }

    #[test]
    fn test_bootstrap_targets_resolve_hostname() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("autodial-hostname.db");
        let conn = open_connection(&db_path).unwrap();
        create_tables(&conn).unwrap();
        let recorded_by = "test-peer-hostname";

        let bootstrap_spki: [u8; 32] = [0xAB; 32];
        transport_trust::record_invite_bootstrap_trust(
            &conn,
            recorded_by,
            "ia-host",
            "inv-host",
            "ws-host",
            "localhost:4433",
            &bootstrap_spki,
        )
        .unwrap();
        drop(conn);

        let targets =
            load_bootstrap_targets(db_path.to_str().unwrap(), &[recorded_by.to_string()]).unwrap();

        assert_eq!(targets.len(), 1, "hostname bootstrap should resolve");
        assert_eq!(targets[0].0, recorded_by);
        assert_eq!(targets[0].1.port(), 4433);
    }

    // -- Multi-tenant target deduplication tests --

    #[test]
    fn test_bootstrap_targets_dedup_across_tenants() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("dedup.db");
        let conn = open_connection(&db_path).unwrap();
        create_tables(&conn).unwrap();

        let bootstrap_spki: [u8; 32] = [0xAA; 32];
        let bootstrap_addr = "10.0.0.1:4433";

        // Same bootstrap addr for two different tenants → should yield 2 targets
        // (dedup is per (tenant, addr), not per addr alone)
        transport_trust::record_invite_bootstrap_trust(
            &conn,
            "tenant-a",
            "ia-a",
            "inv-a",
            "ws-a",
            bootstrap_addr,
            &bootstrap_spki,
        )
        .unwrap();
        transport_trust::record_invite_bootstrap_trust(
            &conn,
            "tenant-b",
            "ia-b",
            "inv-b",
            "ws-b",
            bootstrap_addr,
            &bootstrap_spki,
        )
        .unwrap();
        drop(conn);

        let targets = load_bootstrap_targets(
            db_path.to_str().unwrap(),
            &["tenant-a".to_string(), "tenant-b".to_string()],
        )
        .unwrap();

        assert_eq!(
            targets.len(),
            2,
            "same addr for different tenants = 2 targets"
        );
        assert_ne!(
            targets[0].0, targets[1].0,
            "each target has different tenant"
        );
    }

    #[test]
    fn test_bootstrap_targets_dedup_same_tenant_same_addr() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("dedup2.db");
        let conn = open_connection(&db_path).unwrap();
        create_tables(&conn).unwrap();

        let bootstrap_addr = "10.0.0.1:4433";

        // Two bootstrap trust rows for same tenant + same addr → only 1 target
        transport_trust::record_invite_bootstrap_trust(
            &conn,
            "tenant-a",
            "ia-1",
            "inv-1",
            "ws-1",
            bootstrap_addr,
            &[0xAA; 32],
        )
        .unwrap();
        transport_trust::record_invite_bootstrap_trust(
            &conn,
            "tenant-a",
            "ia-2",
            "inv-2",
            "ws-2",
            bootstrap_addr,
            &[0xBB; 32],
        )
        .unwrap();
        drop(conn);

        let targets =
            load_bootstrap_targets(db_path.to_str().unwrap(), &["tenant-a".to_string()]).unwrap();

        assert_eq!(targets.len(), 1, "same tenant + same addr = 1 target");
    }

    // -- Bootstrap progression (new targets appearing after projection) --

    #[test]
    fn test_bootstrap_progression_new_targets_after_projection() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("progression.db");
        let conn = open_connection(&db_path).unwrap();
        create_tables(&conn).unwrap();
        let tenant = "tenant-progression";

        // Initially no targets
        let targets =
            load_bootstrap_targets(db_path.to_str().unwrap(), &[tenant.to_string()]).unwrap();
        assert!(targets.is_empty(), "no targets before any trust rows");

        // Simulate InviteAccepted projection writing bootstrap trust
        transport_trust::record_invite_bootstrap_trust(
            &conn,
            tenant,
            "ia-1",
            "inv-1",
            "ws-1",
            "10.0.0.1:4433",
            &[0xCC; 32],
        )
        .unwrap();

        // Target appears
        drop(conn);
        let targets =
            load_bootstrap_targets(db_path.to_str().unwrap(), &[tenant.to_string()]).unwrap();
        assert_eq!(targets.len(), 1, "target appears after trust row");

        // Simulate second invite acceptance → new bootstrap addr
        let conn = open_connection(&db_path).unwrap();
        transport_trust::record_invite_bootstrap_trust(
            &conn,
            tenant,
            "ia-2",
            "inv-2",
            "ws-2",
            "10.0.0.2:4433",
            &[0xDD; 32],
        )
        .unwrap();
        drop(conn);

        let targets =
            load_bootstrap_targets(db_path.to_str().unwrap(), &[tenant.to_string()]).unwrap();
        assert_eq!(
            targets.len(),
            2,
            "second target appears after second trust row"
        );
    }

    // -- Combined dispatch: bootstrap + discovery through same planner --

    #[test]
    fn test_dispatcher_handles_both_bootstrap_and_discovery_targets() {
        let mut d = PeerDispatcher::new();

        // Bootstrap target (remote peer_id not known yet, use bootstrap addr as key)
        let (action, _) = d.dispatch("bootstrap-peer-1", addr(4433));
        assert_eq!(
            action,
            DiscoveryAction::Connect,
            "bootstrap target dispatches as Connect"
        );

        // mDNS discovery target for a different peer
        let (action, _) = d.dispatch("mdns-peer-2", addr(5000));
        assert_eq!(
            action,
            DiscoveryAction::Connect,
            "discovery target dispatches as Connect"
        );

        // Same bootstrap target again → skip
        let (action, _) = d.dispatch("bootstrap-peer-1", addr(4433));
        assert_eq!(
            action,
            DiscoveryAction::Skip,
            "duplicate bootstrap target skipped"
        );

        // mDNS peer moves address → reconnect
        let (action, _) = d.dispatch("mdns-peer-2", addr(5001));
        assert_eq!(
            action,
            DiscoveryAction::Reconnect,
            "discovery peer addr change reconnects"
        );
    }
}
