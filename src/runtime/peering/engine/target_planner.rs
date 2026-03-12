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
//! - **Dispatch-key helpers**: deterministic keying for bootstrap + discovery
//!   target streams so one runtime dispatcher can own lifecycle decisions.
//!
//! This consolidation satisfies R3/SC3 of the peering readability plan:
//! one module is the source of truth for dial target planning.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tracing::warn;

use crate::db::open_connection;
use crate::db::transport_creds::discover_local_tenants;
use crate::db::transport_trust::list_active_invite_bootstrap_targets;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DialTargetSource {
    Bootstrap,
    ObservedEndpoint,
    Discovery,
}

impl DialTargetSource {
    fn priority(self) -> u8 {
        match self {
            Self::Bootstrap => 0,
            Self::ObservedEndpoint => 1,
            Self::Discovery => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DialTarget {
    addr: SocketAddr,
    source: DialTargetSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SuppressedDialTarget {
    target: DialTarget,
    until: Instant,
}

/// Tracks discovered peers and manages cancellation of stale connect_loops.
pub(crate) struct PeerDispatcher {
    known: HashMap<String, (DialTarget, tokio::sync::watch::Sender<()>)>,
    suppressed: HashMap<String, Vec<SuppressedDialTarget>>,
}

impl PeerDispatcher {
    pub(crate) fn new() -> Self {
        Self {
            known: HashMap::new(),
            suppressed: HashMap::new(),
        }
    }

    /// Evaluate a discovery event. Returns the action to take and (for Connect/Reconnect)
    /// a watch::Receiver that will be signalled when this entry is superseded.
    pub(crate) fn dispatch(
        &mut self,
        peer_id: &str,
        addr: SocketAddr,
        source: DialTargetSource,
    ) -> (DiscoveryAction, Option<tokio::sync::watch::Receiver<()>>) {
        self.dispatch_at(peer_id, addr, source, Instant::now())
    }

    fn dispatch_at(
        &mut self,
        peer_id: &str,
        addr: SocketAddr,
        source: DialTargetSource,
        now: Instant,
    ) -> (DiscoveryAction, Option<tokio::sync::watch::Receiver<()>>) {
        self.prune_expired_suppressions(now);
        if self.is_suppressed_at(peer_id, addr, source, now) {
            return (DiscoveryAction::Skip, None);
        }
        if let Some((current, _)) = self.known.get_mut(peer_id) {
            if current.addr == addr {
                if source.priority() > current.source.priority() {
                    current.source = source;
                }
                return (DiscoveryAction::Skip, None);
            }
            if source.priority() < current.source.priority() {
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
        self.known.insert(
            peer_id.to_string(),
            (DialTarget { addr, source }, cancel_tx),
        );
        (action, Some(cancel_rx))
    }

    pub(crate) fn forget(&mut self, peer_id: &str) {
        self.known.remove(peer_id);
    }

    pub(crate) fn suppress_for(
        &mut self,
        peer_id: &str,
        addr: SocketAddr,
        source: DialTargetSource,
        duration: Duration,
    ) {
        self.prune_expired_suppressions(Instant::now());
        if duration.is_zero() {
            return;
        }
        let entries = self.suppressed.entry(peer_id.to_string()).or_default();
        entries.retain(|entry| !(entry.target.addr == addr && entry.target.source == source));
        entries.push(SuppressedDialTarget {
            target: DialTarget { addr, source },
            until: Instant::now() + duration,
        });
    }

    fn is_suppressed_at(
        &self,
        peer_id: &str,
        addr: SocketAddr,
        source: DialTargetSource,
        now: Instant,
    ) -> bool {
        self.suppressed
            .get(peer_id)
            .map(|entries| {
                entries.iter().any(|entry| {
                    entry.until > now && entry.target.addr == addr && entry.target.source == source
                })
            })
            .unwrap_or(false)
    }

    fn prune_expired_suppressions(&mut self, now: Instant) {
        self.suppressed.retain(|_, entries| {
            entries.retain(|entry| entry.until > now);
            !entries.is_empty()
        });
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

pub(crate) fn bootstrap_dispatch_key(
    tenant_id: &str,
    invite_event_id: &str,
    remote: SocketAddr,
) -> String {
    format!("{}@bootstrap:{}@{}", tenant_id, invite_event_id, remote)
}

pub(crate) fn known_peer_dispatch_key(tenant_id: &str, peer_id: &str) -> String {
    format!("{}@peer:{}", tenant_id, peer_id)
}

pub(crate) fn discovery_dispatch_key(tenant_id: &str, peer_id: &str) -> String {
    known_peer_dispatch_key(tenant_id, peer_id)
}

// ---------------------------------------------------------------------------
// Bootstrap trust target collection
// ---------------------------------------------------------------------------

/// Load invite-seeded autodial targets for a set of known tenant IDs.
pub(crate) fn load_bootstrap_targets(
    db_path: &str,
    tenant_ids: &[String],
) -> Result<Vec<(String, String, SocketAddr)>, Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    let mut seen: HashSet<(String, String, SocketAddr)> = HashSet::new();
    let mut out = Vec::new();
    for tenant_id in tenant_ids {
        for target in list_active_invite_bootstrap_targets(&db, tenant_id)? {
            let addr_text = target.bootstrap_addr;
            match parse_bootstrap_address(&addr_text).and_then(|addr| addr.to_socket_addr()) {
                Ok(addr) => {
                    let key = (tenant_id.clone(), target.invite_event_id, addr);
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
) -> Result<Vec<(String, String, SocketAddr)>, Box<dyn std::error::Error + Send + Sync>> {
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
/// Uses `"{tenant_id}@bootstrap"` as the dispatch key so bootstrap targets
/// share the same dedup/reconnect mechanism as mDNS discovery targets.
/// Returns `true` if a new connect loop should be spawned.
pub(crate) fn dispatch_bootstrap_target(
    dispatcher: &mut PeerDispatcher,
    tenant_id: &str,
    invite_event_id: &str,
    remote: SocketAddr,
) -> bool {
    let key = bootstrap_dispatch_key(tenant_id, invite_event_id, remote);
    let (action, _cancel_rx) = dispatcher.dispatch(&key, remote, DialTargetSource::Bootstrap);
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
    peer_id: &str,
    remote: SocketAddr,
    source: DialTargetSource,
) -> bool {
    let key = known_peer_dispatch_key(tenant_id, peer_id);
    let (action, _cancel_rx) = dispatcher.dispatch(&key, remote, source);
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
    dispatch_known_peer_target(
        dispatcher,
        tenant_id,
        peer_id,
        remote,
        DialTargetSource::Discovery,
    )
}

/// Dispatch a persisted-observation dial target through `PeerDispatcher`.
pub(crate) fn dispatch_observed_endpoint_target(
    dispatcher: &mut PeerDispatcher,
    tenant_id: &str,
    peer_id: &str,
    remote: SocketAddr,
) -> bool {
    dispatch_known_peer_target(
        dispatcher,
        tenant_id,
        peer_id,
        remote,
        DialTargetSource::ObservedEndpoint,
    )
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
        let (action, rx) = d.dispatch("peer-a", addr(1000), DialTargetSource::Discovery);
        assert_eq!(action, DiscoveryAction::Connect);
        assert!(rx.is_some(), "should return cancel receiver");
    }

    #[test]
    fn test_dispatch_same_addr_returns_skip() {
        let mut d = PeerDispatcher::new();
        d.dispatch("peer-a", addr(1000), DialTargetSource::Discovery);

        let (action, rx) = d.dispatch("peer-a", addr(1000), DialTargetSource::Discovery);
        assert_eq!(action, DiscoveryAction::Skip);
        assert!(rx.is_none());
    }

    #[test]
    fn test_dispatch_different_addr_returns_reconnect() {
        let mut d = PeerDispatcher::new();
        d.dispatch("peer-a", addr(1000), DialTargetSource::Discovery);

        let (action, rx) = d.dispatch("peer-a", addr(2000), DialTargetSource::Discovery);
        assert_eq!(action, DiscoveryAction::Reconnect);
        assert!(rx.is_some());
    }

    #[test]
    fn test_dispatch_addr_change_cancels_old_receiver() {
        let mut d = PeerDispatcher::new();
        let (_, old_rx) = d.dispatch("peer-a", addr(1000), DialTargetSource::Discovery);
        let mut old_rx = old_rx.unwrap();

        let (action, _new_rx) = d.dispatch("peer-a", addr(2000), DialTargetSource::Discovery);
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
            let (action, rx) = d.dispatch("peer-a", addr(port), DialTargetSource::Discovery);
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
        assert_eq!(d.known.get("peer-a").unwrap().0.addr, addr(1009));
    }

    #[test]
    fn test_dispatch_multiple_peers_independent() {
        let mut d = PeerDispatcher::new();

        let (a1, _) = d.dispatch("peer-a", addr(1000), DialTargetSource::Discovery);
        let (b1, _) = d.dispatch("peer-b", addr(2000), DialTargetSource::Discovery);
        assert_eq!(a1, DiscoveryAction::Connect);
        assert_eq!(b1, DiscoveryAction::Connect);

        let (a2, _) = d.dispatch("peer-a", addr(1001), DialTargetSource::Discovery);
        let (b2, _) = d.dispatch("peer-b", addr(2000), DialTargetSource::Discovery);
        assert_eq!(a2, DiscoveryAction::Reconnect);
        assert_eq!(b2, DiscoveryAction::Skip);
    }

    #[test]
    fn test_forget_clears_dispatch_slot() {
        let mut d = PeerDispatcher::new();
        d.dispatch("peer-a", addr(1000), DialTargetSource::Discovery);
        d.forget("peer-a");

        let (action, rx) = d.dispatch("peer-a", addr(1000), DialTargetSource::Discovery);
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
        assert_eq!(targets[0].1, "inv-host");
        assert_eq!(targets[0].2.port(), 4433);
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
        // (dedup is per (tenant, invite_event_id, addr), not per addr alone)
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
    fn test_bootstrap_targets_keep_distinct_invites_same_tenant_same_addr() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("dedup2.db");
        let conn = open_connection(&db_path).unwrap();
        create_tables(&conn).unwrap();

        let bootstrap_addr = "10.0.0.1:4433";

        // Two bootstrap trust rows for same tenant + same addr but different
        // invite_event_id should produce two targets (invite-specific fallback).
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

        assert_eq!(
            targets.len(),
            2,
            "same tenant + same addr + two invites = 2 targets"
        );
        let invite_ids: std::collections::HashSet<String> = targets
            .iter()
            .map(|(_, invite_id, _)| invite_id.clone())
            .collect();
        assert!(invite_ids.contains("inv-1"));
        assert!(invite_ids.contains("inv-2"));
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
        assert_eq!(targets[0].1, invite_event_id);
        assert_eq!(targets[0].2, "10.0.0.1:4433".parse::<SocketAddr>().unwrap());
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
            .map(|(tenant_id, _invite_event_id, remote)| (tenant_id, remote))
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

    #[test]
    fn test_bootstrap_dispatch_key_includes_invite_event_id_and_address() {
        let a = bootstrap_dispatch_key("tenant-a", "invite-1", addr(4433));
        let b = bootstrap_dispatch_key("tenant-a", "invite-2", addr(4433));
        let c = bootstrap_dispatch_key("tenant-a", "invite-1", addr(5544));
        assert_ne!(
            a, b,
            "different invites must produce distinct dispatch keys"
        );
        assert_ne!(
            a, c,
            "different bootstrap addresses for the same invite must not share a dispatch slot"
        );
    }

    #[test]
    fn test_dispatch_bootstrap_target_keeps_independent_slots_per_address() {
        let mut d = PeerDispatcher::new();

        assert!(dispatch_bootstrap_target(
            &mut d,
            "tenant-a",
            "invite-1",
            addr(4433)
        ));
        assert!(dispatch_bootstrap_target(
            &mut d,
            "tenant-a",
            "invite-1",
            addr(5544)
        ));
        assert!(
            !dispatch_bootstrap_target(&mut d, "tenant-a", "invite-1", addr(4433)),
            "same invite/address pair should still dedupe"
        );
        assert_eq!(
            d.known.len(),
            2,
            "dead-first/live-second bootstrap addresses must not cancel each other"
        );
    }

    // -- Combined dispatch: bootstrap + discovery through same planner --

    #[test]
    fn test_dispatcher_handles_both_bootstrap_and_discovery_targets() {
        let mut d = PeerDispatcher::new();

        // Bootstrap target (remote peer_id not known yet, use bootstrap addr as key)
        let (action, _) = d.dispatch("bootstrap-peer-1", addr(4433), DialTargetSource::Bootstrap);
        assert_eq!(
            action,
            DiscoveryAction::Connect,
            "bootstrap target dispatches as Connect"
        );

        // mDNS discovery target for a different peer
        let (action, _) = d.dispatch("mdns-peer-2", addr(5000), DialTargetSource::Discovery);
        assert_eq!(
            action,
            DiscoveryAction::Connect,
            "discovery target dispatches as Connect"
        );

        // Same bootstrap target again → skip
        let (action, _) = d.dispatch("bootstrap-peer-1", addr(4433), DialTargetSource::Bootstrap);
        assert_eq!(
            action,
            DiscoveryAction::Skip,
            "duplicate bootstrap target skipped"
        );

        // mDNS peer moves address → reconnect
        let (action, _) = d.dispatch("mdns-peer-2", addr(5001), DialTargetSource::Discovery);
        assert_eq!(
            action,
            DiscoveryAction::Reconnect,
            "discovery peer addr change reconnects"
        );
    }

    #[test]
    fn test_discovery_target_outranks_observed_target_for_same_peer() {
        let mut d = PeerDispatcher::new();

        let (action, _) = d.dispatch("peer-1", addr(4433), DialTargetSource::ObservedEndpoint);
        assert_eq!(action, DiscoveryAction::Connect);

        let (action, _) = d.dispatch("peer-1", addr(5000), DialTargetSource::Discovery);
        assert_eq!(action, DiscoveryAction::Reconnect);

        let (action, _) = d.dispatch("peer-1", addr(6000), DialTargetSource::ObservedEndpoint);
        assert_eq!(
            action,
            DiscoveryAction::Skip,
            "lower-priority observed endpoint must not displace discovery"
        );
    }

    #[test]
    fn test_same_addr_discovery_upgrades_priority_without_reconnect() {
        let mut d = PeerDispatcher::new();

        let (action, _) = d.dispatch("peer-1", addr(4433), DialTargetSource::ObservedEndpoint);
        assert_eq!(action, DiscoveryAction::Connect);

        let (action, _) = d.dispatch("peer-1", addr(4433), DialTargetSource::Discovery);
        assert_eq!(
            action,
            DiscoveryAction::Skip,
            "same-address discovery should upgrade priority without restarting the worker"
        );

        let (action, _) = d.dispatch("peer-1", addr(5000), DialTargetSource::ObservedEndpoint);
        assert_eq!(
            action,
            DiscoveryAction::Skip,
            "upgraded discovery priority must continue to shield against observed fallbacks"
        );
    }

    #[test]
    fn test_suppressed_discovery_target_allows_observed_fallback() {
        let now = Instant::now();
        let mut d = PeerDispatcher::new();

        let (action, _) = d.dispatch_at("peer-1", addr(4433), DialTargetSource::Discovery, now);
        assert_eq!(action, DiscoveryAction::Connect);
        d.forget("peer-1");
        d.suppress_for(
            "peer-1",
            addr(4433),
            DialTargetSource::Discovery,
            Duration::from_secs(5),
        );

        let (action, _) = d.dispatch_at(
            "peer-1",
            addr(4433),
            DialTargetSource::Discovery,
            now + Duration::from_secs(1),
        );
        assert_eq!(
            action,
            DiscoveryAction::Skip,
            "suppressed discovery target should not immediately redial"
        );

        let (action, _) = d.dispatch_at(
            "peer-1",
            addr(5544),
            DialTargetSource::ObservedEndpoint,
            now + Duration::from_secs(1),
        );
        assert_eq!(
            action,
            DiscoveryAction::Connect,
            "observed endpoint should be able to take over during discovery suppression"
        );
    }

    #[test]
    fn test_suppressed_target_expires() {
        let now = Instant::now();
        let mut d = PeerDispatcher::new();

        d.suppress_for(
            "peer-1",
            addr(4433),
            DialTargetSource::Discovery,
            Duration::from_secs(1),
        );

        let (action, _) = d.dispatch_at(
            "peer-1",
            addr(4433),
            DialTargetSource::Discovery,
            now + Duration::from_secs(2),
        );
        assert_eq!(
            action,
            DiscoveryAction::Connect,
            "suppression should expire and allow rediscovery"
        );
    }
}
