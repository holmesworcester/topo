//! Unified dial-target planning: the single owner of "what should we connect to."
//!
//! Both bootstrap trust autodial and known-peer reconnect routes through
//! this module. It owns:
//!
//! - **Bootstrap target collection**: polls SQL invite_bootstrap_trust rows
//!   (materialized by InviteAccepted projection) and yields dial targets.
//! - **Observed endpoint collection**: polls projected peers + fresh endpoint
//!   observations so known peers remain dialable after bootstrap supersession.
//! - **Discovery dispatch**: deduplicates mDNS-discovered peers and computes
//!   connect/reconnect/skip actions (`PeerDispatcher`).
//! - **Dispatch-key helpers**: deterministic transport-target keying for bootstrap +
//!   discovery target streams so one runtime dispatcher can own lifecycle
//!   decisions once the authenticated transport fingerprint is known.
//!
//! This consolidation satisfies R3/SC3 of the peering readability plan:
//! one module is the source of truth for dial target planning.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::warn;

use crate::db::open_connection;
use crate::db::transport_creds::discover_local_tenants;
use crate::db::transport_trust::list_active_invite_bootstrap_targets;
use crate::event_modules::operational::connection_planned::{
    bootstrap_connection_id, known_peer_connection_id,
};
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

fn normalize_discovered_addr_for_local_bind_with_options(
    local_listen_ip: std::net::IpAddr,
    discovered: SocketAddr,
    force_loopback: bool,
) -> SocketAddr {
    if force_loopback && (local_listen_ip.is_unspecified() || local_listen_ip.is_loopback()) {
        let loopback_ip = match local_listen_ip {
            std::net::IpAddr::V6(_) => std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            _ => std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        };
        return SocketAddr::new(loopback_ip, discovered.port());
    }

    if local_listen_ip.is_loopback() && !discovered.ip().is_loopback() {
        SocketAddr::new(local_listen_ip, discovered.port())
    } else {
        discovered
    }
}

pub(crate) fn normalize_discovered_addr_for_local_bind(
    local_listen_ip: std::net::IpAddr,
    discovered: SocketAddr,
) -> SocketAddr {
    let force_loopback = std::env::var("TOPO_TEST_DISCOVERY_LOOPBACK")
        .map(|v| v != "0" && v.to_lowercase() != "false")
        .unwrap_or(false);
    normalize_discovered_addr_for_local_bind_with_options(
        local_listen_ip,
        discovered,
        force_loopback,
    )
}

// ---------------------------------------------------------------------------
// Bootstrap trust target collection
// ---------------------------------------------------------------------------

/// Load invite-seeded autodial targets for a set of known tenant IDs.
pub(crate) fn load_bootstrap_targets(
    db_path: &str,
    tenant_ids: &[String],
) -> Result<Vec<(String, String, String, SocketAddr)>, Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    let mut seen: HashSet<(String, String, SocketAddr)> = HashSet::new();
    let mut out = Vec::new();
    for tenant_id in tenant_ids {
        for target in list_active_invite_bootstrap_targets(&db, tenant_id)? {
            let addr_text = target.bootstrap_addr;
            match parse_bootstrap_address(&addr_text).and_then(|addr| addr.to_socket_addr()) {
                Ok(addr) => {
                    let key = (tenant_id.clone(), target.transport_peer_id.clone(), addr);
                    if seen.insert(key.clone()) {
                        out.push((
                            tenant_id.clone(),
                            target.transport_peer_id,
                            target.invite_event_id,
                            addr,
                        ));
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
) -> Result<Vec<(String, String, String, SocketAddr)>, Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    let mut tenant_ids: Vec<String> = discover_local_tenants(&db)?
        .into_iter()
        .map(|tenant| tenant.peer_id)
        .collect();
    tenant_ids.sort();
    tenant_ids.dedup();
    drop(db);
    load_bootstrap_targets(db_path, &tenant_ids)
}

/// Load steady-state reconnect targets from projected peers with fresh endpoint
/// observations.
pub(crate) fn load_observed_endpoint_targets(
    db_path: &str,
    tenant_ids: &[String],
) -> Result<Vec<(String, String, SocketAddr)>, Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;
    let mut seen: HashSet<(String, String, SocketAddr)> = HashSet::new();
    let mut out = Vec::new();

    let mut stmt = db.prepare(
        "SELECT
             lower(hex(ps.transport_fingerprint)) AS peer_id,
             (
                 SELECT e.origin_ip
                 FROM peer_endpoint_observations e
                 WHERE e.recorded_by = ps.recorded_by
                   AND e.via_peer_id = lower(hex(ps.transport_fingerprint))
                   AND e.expires_at > ?2
                 ORDER BY e.observed_at DESC, e.rowid DESC
                 LIMIT 1
             ) AS origin_ip,
             (
                 SELECT e.origin_port
                 FROM peer_endpoint_observations e
                 WHERE e.recorded_by = ps.recorded_by
                   AND e.via_peer_id = lower(hex(ps.transport_fingerprint))
                   AND e.expires_at > ?2
                 ORDER BY e.observed_at DESC, e.rowid DESC
                 LIMIT 1
             ) AS origin_port
         FROM peers_shared ps
         WHERE ps.recorded_by = ?1
           AND length(ps.transport_fingerprint) = 32
           AND NOT EXISTS(
               SELECT 1
               FROM local_transport_creds c
               WHERE c.peer_id = lower(hex(ps.transport_fingerprint))
           )
           AND NOT EXISTS(
               SELECT 1
               FROM pending_invite_bootstrap_trust p
               WHERE p.recorded_by = ps.recorded_by
                 AND p.expected_bootstrap_spki_fingerprint = ps.transport_fingerprint
                 AND p.expires_at > ?2
           )
           AND EXISTS(
               SELECT 1
               FROM peer_endpoint_observations e
               WHERE e.recorded_by = ps.recorded_by
                 AND e.via_peer_id = lower(hex(ps.transport_fingerprint))
                 AND e.expires_at > ?2
           )
         ORDER BY peer_id",
    )?;

    for tenant_id in tenant_ids {
        let rows = stmt.query_map(rusqlite::params![tenant_id, now_ms], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? as u16,
            ))
        })?;

        for row in rows {
            let (peer_id, origin_ip, origin_port) = row?;
            let ip: std::net::IpAddr = origin_ip.parse()?;
            let remote = SocketAddr::new(ip, origin_port);
            let key = (tenant_id.clone(), peer_id, remote);
            if seen.insert(key.clone()) {
                out.push(key);
            }
        }
    }

    Ok(out)
}

/// Collect all observed-endpoint reconnect targets across all local tenants.
pub(crate) fn collect_all_observed_endpoint_targets(
    db_path: &str,
) -> Result<Vec<(String, String, SocketAddr)>, Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    let mut tenant_ids: Vec<String> = discover_local_tenants(&db)?
        .into_iter()
        .map(|tenant| tenant.peer_id)
        .collect();
    tenant_ids.sort();
    tenant_ids.dedup();
    drop(db);
    load_observed_endpoint_targets(db_path, &tenant_ids)
}

// ---------------------------------------------------------------------------
// Bootstrap autodial refresher
// ---------------------------------------------------------------------------

/// Dispatch a bootstrap dial target through `PeerDispatcher`.
///
/// Bootstrap targets are keyed by authenticated transport fingerprint, not
/// invite event id, so invite bootstrap, observed endpoints, and discovery all
/// converge on one exact-target connect worker once the remote fingerprint is
/// known. Returns `true` if a new connect loop should be spawned.
pub(crate) fn dispatch_bootstrap_target(
    dispatcher: &mut PeerDispatcher,
    tenant_id: &str,
    transport_peer_id: &str,
    remote: SocketAddr,
) -> bool {
    let key = bootstrap_connection_id(tenant_id, transport_peer_id, remote);
    let (action, _cancel_rx) = dispatcher.dispatch(&key, remote);
    matches!(
        action,
        DiscoveryAction::Connect | DiscoveryAction::Reconnect
    )
}

/// Dispatch a known-peer dial target through `PeerDispatcher`.
///
/// Known peers share one tenant-scoped dispatch key regardless of whether the
/// target came from discovery or a persisted endpoint observation.
pub(crate) fn dispatch_known_peer_target(
    dispatcher: &mut PeerDispatcher,
    tenant_id: &str,
    transport_peer_id: &str,
    remote: SocketAddr,
) -> bool {
    let key = known_peer_connection_id(tenant_id, transport_peer_id);
    let (action, _cancel_rx) = dispatcher.dispatch(&key, remote);
    matches!(
        action,
        DiscoveryAction::Connect | DiscoveryAction::Reconnect
    )
}

/// Dispatch a discovery dial target through `PeerDispatcher`.
///
/// Discovery keys are tenant-scoped and peer-stable so one runtime dispatcher
/// can safely handle multi-tenant streams without duplicate workers for the
/// same remote peer.
pub(crate) fn dispatch_discovery_target(
    dispatcher: &mut PeerDispatcher,
    tenant_id: &str,
    peer_id: &str,
    remote: SocketAddr,
) -> bool {
    dispatch_known_peer_target(dispatcher, tenant_id, peer_id, remote)
}

/// Dispatch a persisted-observation dial target through `PeerDispatcher`.
pub(crate) fn dispatch_observed_endpoint_target(
    dispatcher: &mut PeerDispatcher,
    tenant_id: &str,
    peer_id: &str,
    remote: SocketAddr,
) -> bool {
    dispatch_known_peer_target(dispatcher, tenant_id, peer_id, remote)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::spki_fingerprint_from_ed25519_pubkey;
    use crate::db::open_connection;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;
    use crate::db::{transport_creds, transport_trust};

    fn seed_direct_bootstrap_tenant(
        conn: &rusqlite::Connection,
        tenant_id: &str,
        invite_event_id: &str,
        bootstrap_addr: &str,
    ) {
        conn.execute(
            "INSERT INTO invites_accepted
             (recorded_by, event_id, tenant_event_id, invite_event_id, workspace_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                tenant_id,
                format!("ia-{tenant_id}"),
                format!("tenant-event-{tenant_id}"),
                invite_event_id,
                format!("ws-{tenant_id}"),
                1i64
            ],
        )
        .unwrap();
        transport_creds::store_local_creds_with_source(
            conn,
            tenant_id,
            b"cert",
            b"key",
            transport_creds::CRED_SOURCE_PEER_SHARED,
        )
        .unwrap();
        transport_creds::set_local_transport_target(
            conn,
            tenant_id,
            tenant_id,
            transport_creds::CRED_SOURCE_PEER_SHARED,
        )
        .unwrap();
        transport_trust::record_invite_bootstrap_trust(
            conn,
            tenant_id,
            &format!("ia-{tenant_id}"),
            invite_event_id,
            &format!("ws-{tenant_id}"),
            bootstrap_addr,
            &[0xAA; 32],
        )
        .unwrap();
    }

    fn seed_transitional_bootstrap_tenant(
        conn: &rusqlite::Connection,
        tenant_id: &str,
        invite_event_id: &str,
        bootstrap_addr: &str,
    ) -> String {
        let invite_sk = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let bootstrap_peer_id = hex::encode(crate::crypto::spki_fingerprint_from_ed25519_pubkey(
            &invite_sk.verifying_key().to_bytes(),
        ));

        conn.execute(
            "INSERT INTO invites_accepted
             (recorded_by, event_id, tenant_event_id, invite_event_id, workspace_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                tenant_id,
                format!("ia-{tenant_id}"),
                format!("tenant-event-{tenant_id}"),
                invite_event_id,
                format!("ws-{tenant_id}"),
                1i64
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO invite_secrets
             (recorded_by, event_id, invite_event_id, private_key, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                tenant_id,
                format!("is-{tenant_id}"),
                invite_event_id,
                invite_sk.to_bytes().to_vec(),
                1i64
            ],
        )
        .unwrap();
        transport_creds::store_local_creds_with_source(
            conn,
            &bootstrap_peer_id,
            b"cert",
            b"key",
            transport_creds::CRED_SOURCE_BOOTSTRAP,
        )
        .unwrap();
        transport_creds::set_local_transport_target(
            conn,
            tenant_id,
            &bootstrap_peer_id,
            transport_creds::CRED_SOURCE_BOOTSTRAP,
        )
        .unwrap();
        transport_trust::record_invite_bootstrap_trust(
            conn,
            tenant_id,
            &format!("ia-{tenant_id}"),
            invite_event_id,
            &format!("ws-{tenant_id}"),
            bootstrap_addr,
            &[0xCC; 32],
        )
        .unwrap();

        bootstrap_peer_id
    }

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

    #[test]
    fn test_normalize_discovered_addr_for_unspecified_bind_can_force_loopback() {
        let local_ip: std::net::IpAddr = "0.0.0.0".parse().unwrap();
        let discovered: SocketAddr = "192.168.10.42:4455".parse().unwrap();
        let out = normalize_discovered_addr_for_local_bind_with_options(local_ip, discovered, true);
        assert_eq!(out, "127.0.0.1:4455".parse::<SocketAddr>().unwrap());
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
            transport_trust::is_authorized_for_tenant(&conn, recorded_by, &bootstrap_spki).unwrap(),
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

        transport_trust::consume_bootstrap_for_peer_shared(&conn, recorded_by, &peer_pub).unwrap();

        assert_eq!(
            transport_trust::list_active_invite_bootstrap_addrs(&conn, recorded_by)
                .unwrap()
                .len(),
            0,
            "superseded bootstrap trust must not appear in autodial"
        );
    }

    #[test]
    fn test_observed_endpoint_targets_survive_bootstrap_supersession() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("observed-endpoints.db");
        let conn = open_connection(&db_path).unwrap();
        create_tables(&conn).unwrap();
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let tenant_id = "tenant-observed";
        let invite_event_id = "inv-observed";
        conn.execute(
            "INSERT INTO invites_accepted
             (recorded_by, event_id, tenant_event_id, invite_event_id, workspace_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                tenant_id,
                format!("ia-{tenant_id}"),
                format!("tenant-event-{tenant_id}"),
                invite_event_id,
                format!("ws-{tenant_id}"),
                1i64
            ],
        )
        .unwrap();
        transport_creds::store_local_creds_with_source(
            &conn,
            tenant_id,
            b"cert",
            b"key",
            transport_creds::CRED_SOURCE_PEER_SHARED,
        )
        .unwrap();
        transport_creds::set_local_transport_target(
            &conn,
            tenant_id,
            tenant_id,
            transport_creds::CRED_SOURCE_PEER_SHARED,
        )
        .unwrap();

        let remote_pubkey = [0x44; 32];
        let remote_transport_fingerprint = spki_fingerprint_from_ed25519_pubkey(&remote_pubkey);
        let remote_peer_id = hex::encode(remote_transport_fingerprint);
        transport_trust::record_invite_bootstrap_trust(
            &conn,
            tenant_id,
            &format!("ia-{tenant_id}"),
            invite_event_id,
            &format!("ws-{tenant_id}"),
            "10.0.0.1:4433",
            &remote_transport_fingerprint,
        )
        .unwrap();

        conn.execute(
            "INSERT INTO peers_shared
             (recorded_by, event_id, public_key, transport_fingerprint, device_name)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                tenant_id,
                "ps-remote-observed",
                remote_pubkey.as_slice(),
                remote_transport_fingerprint.as_slice(),
                "remote-device",
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO peer_endpoint_observations
             (recorded_by, via_peer_id, origin_ip, origin_port, observed_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                tenant_id,
                remote_peer_id,
                "127.0.0.1",
                4455i64,
                now_ms,
                now_ms + 60_000i64
            ],
        )
        .unwrap();

        transport_trust::consume_bootstrap_for_transport_fingerprint(
            &conn,
            tenant_id,
            &remote_transport_fingerprint,
        )
        .unwrap();
        drop(conn);

        let bootstrap_targets =
            load_bootstrap_targets(db_path.to_str().unwrap(), &[tenant_id.to_string()]).unwrap();
        assert!(
            bootstrap_targets.is_empty(),
            "bootstrap targets should be cleared after peer_shared supersession"
        );

        let observed_targets =
            collect_all_observed_endpoint_targets(db_path.to_str().unwrap()).unwrap();
        assert_eq!(
            observed_targets.len(),
            1,
            "known peer should remain dialable"
        );
        assert_eq!(observed_targets[0].0, tenant_id);
        assert_eq!(observed_targets[0].1, remote_peer_id);
        assert_eq!(
            observed_targets[0].2,
            "127.0.0.1:4455".parse::<SocketAddr>().unwrap()
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
        assert_eq!(targets[0].1, hex::encode(bootstrap_spki));
        assert_eq!(targets[0].2, "inv-host");
        assert_eq!(targets[0].3.port(), 4433);
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
        // (dedup is per (tenant, peer_id, addr), not per addr alone)
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
    fn test_bootstrap_targets_collapse_distinct_invites_for_same_peer_same_addr() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("dedup2.db");
        let conn = open_connection(&db_path).unwrap();
        create_tables(&conn).unwrap();

        let bootstrap_addr = "10.0.0.1:4433";
        let bootstrap_spki = [0xAA; 32];

        // Two bootstrap trust rows for the same tenant + peer + addr but
        // different invite_event_id collapse to one peer-scoped target.
        transport_trust::record_invite_bootstrap_trust(
            &conn,
            "tenant-a",
            "ia-1",
            "inv-1",
            "ws-1",
            bootstrap_addr,
            &bootstrap_spki,
        )
        .unwrap();
        transport_trust::record_invite_bootstrap_trust(
            &conn,
            "tenant-a",
            "ia-2",
            "inv-2",
            "ws-2",
            bootstrap_addr,
            &bootstrap_spki,
        )
        .unwrap();
        drop(conn);

        let targets =
            load_bootstrap_targets(db_path.to_str().unwrap(), &["tenant-a".to_string()]).unwrap();

        assert_eq!(
            targets.len(),
            1,
            "same tenant + same peer + same addr collapses to one target"
        );
        assert_eq!(targets[0].1, hex::encode(bootstrap_spki));
    }

    #[test]
    fn test_collect_all_bootstrap_targets_uses_tenant_ids_for_transitional_bootstrap() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("transitional-bootstrap.db");
        let conn = open_connection(&db_path).unwrap();
        create_tables(&conn).unwrap();

        let tenant_id = "tenant-transitional";
        let invite_event_id = "inv-transitional";
        let bootstrap_peer_id =
            seed_transitional_bootstrap_tenant(&conn, tenant_id, invite_event_id, "10.0.0.1:4433");
        drop(conn);

        let wrong_namespace_targets = load_bootstrap_targets(
            db_path.to_str().unwrap(),
            std::slice::from_ref(&bootstrap_peer_id),
        )
        .unwrap();
        assert!(
            wrong_namespace_targets.is_empty(),
            "transport peer ids must not be used as bootstrap trust scope"
        );

        let targets = collect_all_bootstrap_targets(db_path.to_str().unwrap()).unwrap();
        assert_eq!(targets.len(), 1, "transitional tenant must still autodial");
        assert_eq!(targets[0].0, tenant_id);
        assert_eq!(targets[0].1, hex::encode([0xCC; 32]));
        assert_eq!(targets[0].2, invite_event_id);
        assert_eq!(targets[0].3, "10.0.0.1:4433".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn test_collect_all_bootstrap_targets_handles_mixed_direct_and_transitional_tenants() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("mixed-bootstrap.db");
        let conn = open_connection(&db_path).unwrap();
        create_tables(&conn).unwrap();

        seed_direct_bootstrap_tenant(&conn, "tenant-direct", "inv-direct", "10.0.0.10:4433");
        seed_transitional_bootstrap_tenant(
            &conn,
            "tenant-transitional",
            "inv-transitional",
            "10.0.0.20:4433",
        );
        drop(conn);

        let targets = collect_all_bootstrap_targets(db_path.to_str().unwrap()).unwrap();
        assert_eq!(
            targets.len(),
            2,
            "direct and transitional tenants must both autodial"
        );

        let by_tenant: std::collections::HashMap<String, SocketAddr> = targets
            .into_iter()
            .map(|(tenant_id, _peer_id, _invite_event_id, remote)| (tenant_id, remote))
            .collect();
        assert_eq!(
            by_tenant.get("tenant-direct"),
            Some(&"10.0.0.10:4433".parse::<SocketAddr>().unwrap())
        );
        assert_eq!(
            by_tenant.get("tenant-transitional"),
            Some(&"10.0.0.20:4433".parse::<SocketAddr>().unwrap())
        );
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

        // Bootstrap target for a known authenticated peer
        let (action, _) = d.dispatch("tenant-a@mdns:peer-1", addr(4433));
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

        // Same peer again via another source → skip
        let (action, _) = d.dispatch("tenant-a@mdns:peer-1", addr(4433));
        assert_eq!(
            action,
            DiscoveryAction::Skip,
            "duplicate peer target skipped"
        );

        // mDNS peer moves address → reconnect
        let (action, _) = d.dispatch("mdns-peer-2", addr(5001));
        assert_eq!(
            action,
            DiscoveryAction::Reconnect,
            "discovery peer addr change reconnects"
        );
    }

    #[test]
    fn test_bootstrap_dispatch_allows_multiple_addrs_for_same_peer() {
        let mut dispatcher = PeerDispatcher::new();
        let peer_id = format!("{:064x}", 9);

        assert!(dispatch_bootstrap_target(
            &mut dispatcher,
            "tenant-a",
            &peer_id,
            addr(4433)
        ));
        assert!(
            dispatch_bootstrap_target(&mut dispatcher, "tenant-a", &peer_id, addr(4434)),
            "a second bootstrap address for the same peer should get its own connect attempt"
        );
    }
}
