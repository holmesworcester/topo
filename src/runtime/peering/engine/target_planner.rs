//! Unified dial-target planning: the single owner of "what should we connect to."
//!
//! With daemon-scoped `iroh` transport, the runtime only needs two outbound
//! target classes:
//! - invite bootstrap daemons
//! - known peers, optionally with a projected observed endpoint
//!
//! When a known peer has no projected address, the connect worker dials the
//! remote daemon id directly and lets `iroh` resolve it via configured address
//! lookup services such as mDNS.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::{debug, warn};

use super::bootstrap_auth::should_initiate_connect_for_source_with_db;
use super::target_dispatch::{TargetIngressEvent, TargetIngressSource};
use crate::db::open_connection;
use crate::db::transport_creds::{discover_local_tenants, resolve_tenant_transport_target};
use crate::db::transport_trust::list_active_invite_bootstrap_targets;
use crate::event_modules::workspace::invite_link::parse_bootstrap_address;
use crate::runtime::repeated_warning::should_emit_globally;
use crate::shared::hash_graph::{connected_hash_graph_neighbors, DEFAULT_HASH_GRAPH_DEGREE};
use crate::transport::resolve_bootstrap_inviter_peer_id;

/// Dispatch decision for an outbound target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DispatchAction {
    Skip,
    Connect,
    Reconnect,
}

pub(crate) use topo_verus_proofs::runtime::peering::engine::bootstrap_dialer::{
    decide_bootstrap_dial_plan, normalize_bootstrap_dial_decision_context,
    BootstrapDialDecisionContext, BootstrapDialPlan, BootstrapDialRawRows,
};

/// Tracks outbound targets and manages cancellation of stale connect loops.
pub(crate) struct PeerDispatcher {
    pub(crate) known: HashMap<
        String,
        (
            Option<SocketAddr>,
            Option<String>,
            tokio::sync::watch::Sender<()>,
        ),
    >,
}

impl PeerDispatcher {
    pub(crate) fn new() -> Self {
        Self {
            known: HashMap::new(),
        }
    }

    pub(crate) fn dispatch(
        &mut self,
        key: &str,
        addr: Option<SocketAddr>,
        relay_url: Option<&str>,
    ) -> (DispatchAction, Option<tokio::sync::watch::Receiver<()>>) {
        let action = self.peek_action(key, addr, relay_url);
        if matches!(action, DispatchAction::Skip) {
            return (DispatchAction::Skip, None);
        }
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(());
        self.known.insert(
            key.to_string(),
            (addr, relay_url.map(str::to_string), cancel_tx),
        );
        (action, Some(cancel_rx))
    }

    pub(crate) fn peek_action(
        &self,
        key: &str,
        addr: Option<SocketAddr>,
        relay_url: Option<&str>,
    ) -> DispatchAction {
        if let Some((prev_addr, prev_relay_url, _)) = self.known.get(key) {
            if *prev_addr == addr && prev_relay_url.as_deref() == relay_url {
                return DispatchAction::Skip;
            }
            return DispatchAction::Reconnect;
        }

        DispatchAction::Connect
    }

    pub(crate) fn forget(&mut self, key: &str) {
        self.known.remove(key);
    }
}

pub(crate) fn bootstrap_dispatch_key(
    tenant_id: &str,
    transport_peer_id: &str,
    remote: Option<SocketAddr>,
    relay_url: Option<&str>,
) -> String {
    match remote {
        Some(remote) => format!("{tenant_id}@bootstrap:{transport_peer_id}@{remote}"),
        None => match relay_url {
            Some(relay_url) => {
                format!("{tenant_id}@bootstrap:{transport_peer_id}@relay:{relay_url}")
            }
            None => format!("{tenant_id}@bootstrap:{transport_peer_id}@lookup"),
        },
    }
}

pub(crate) fn bootstrap_dispatch_key_prefix(tenant_id: &str, transport_peer_id: &str) -> String {
    format!("{tenant_id}@bootstrap:{transport_peer_id}@")
}

pub(crate) fn known_peer_dispatch_key(tenant_id: &str, transport_peer_id: &str) -> String {
    format!("{tenant_id}@peer:{transport_peer_id}")
}

fn short_value(value: &str) -> &str {
    &value[..16.min(value.len())]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TargetPlannerOptions {
    pub(crate) include_bootstrap_targets: bool,
    pub(crate) allow_lookup_known_peers: bool,
    pub(crate) known_peer_target_degree: usize,
}

impl Default for TargetPlannerOptions {
    fn default() -> Self {
        Self {
            include_bootstrap_targets: true,
            allow_lookup_known_peers: true,
            known_peer_target_degree: DEFAULT_HASH_GRAPH_DEGREE,
        }
    }
}

fn discovered_local_tenant_ids(
    db_path: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    let mut tenant_ids: Vec<String> = discover_local_tenants(&db)?
        .into_iter()
        .map(|tenant| tenant.peer_id)
        .collect();
    tenant_ids.sort();
    tenant_ids.dedup();
    Ok(tenant_ids)
}

fn desired_target_sort_key(
    event: &TargetIngressEvent,
) -> (String, u8, String, String, Option<String>, Option<String>) {
    let (source_rank, peer_id, invite_event_id) = match &event.source {
        TargetIngressSource::Bootstrap {
            daemon_peer_id,
            invite_event_id,
        } => (0, daemon_peer_id.clone(), Some(invite_event_id.clone())),
        TargetIngressSource::KnownPeer { peer_id } => (1, peer_id.clone(), None),
    };
    (
        event.tenant_id.clone(),
        source_rank,
        peer_id,
        event
            .remote
            .map(|remote| remote.to_string())
            .unwrap_or_else(|| "lookup".to_string()),
        event.relay_url.clone(),
        invite_event_id,
    )
}

fn decode_hash_graph_key(value: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(value).ok()?;
    let array: [u8; 32] = bytes.try_into().ok()?;
    Some(array)
}

fn select_known_peer_mesh_targets(
    conn: &rusqlite::Connection,
    tenant_id: &str,
    candidates: Vec<(String, Option<SocketAddr>)>,
    degree: usize,
) -> Vec<(String, Option<SocketAddr>)> {
    if candidates.len() <= degree.max(1) {
        return candidates;
    }

    let Some(local_transport_peer_id) = resolve_tenant_transport_target(conn, tenant_id)
        .ok()
        .flatten()
        .map(|target| target.transport_peer_id)
    else {
        return candidates;
    };

    let mut keys = Vec::with_capacity(candidates.len() + 1);
    let Some(local_key) = decode_hash_graph_key(&local_transport_peer_id) else {
        return candidates;
    };
    keys.push(local_key);
    for (peer_id, _) in &candidates {
        let Some(peer_key) = decode_hash_graph_key(peer_id) else {
            return candidates;
        };
        keys.push(peer_key);
    }

    let neighbors = connected_hash_graph_neighbors(&keys, degree.max(1));
    let selected = neighbors[0]
        .iter()
        .copied()
        .filter_map(|neighbor_idx| neighbor_idx.checked_sub(1))
        .collect::<HashSet<_>>();

    candidates
        .into_iter()
        .enumerate()
        .filter_map(|(idx, candidate)| selected.contains(&idx).then_some(candidate))
        .collect()
}

pub(crate) fn load_desired_outbound_targets(
    db_path: &str,
    tenant_ids: &[String],
    options: &TargetPlannerOptions,
) -> Result<Vec<TargetIngressEvent>, Box<dyn std::error::Error + Send + Sync>> {
    let mut out = Vec::new();
    let db = open_connection(db_path)?;

    if options.include_bootstrap_targets {
        for (tenant_id, daemon_peer_id, invite_event_id, remote, relay_url) in
            load_bootstrap_targets(db_path, tenant_ids)?
        {
            let event = TargetIngressEvent {
                tenant_id,
                remote,
                relay_url,
                source: TargetIngressSource::Bootstrap {
                    daemon_peer_id,
                    invite_event_id,
                },
            };
            if should_initiate_connect_for_source_with_db(db_path, &event.tenant_id, &event.source)
            {
                out.push(event);
            }
        }
    }

    for tenant_id in tenant_ids {
        let mut candidates = load_known_peer_targets(db_path, std::slice::from_ref(tenant_id))?
            .into_iter()
            .filter_map(|(_, peer_id, remote)| {
                if remote.is_none() && !options.allow_lookup_known_peers {
                    return None;
                }
                Some((peer_id, remote))
            })
            .collect::<Vec<_>>();
        candidates = select_known_peer_mesh_targets(
            &db,
            tenant_id,
            candidates,
            options.known_peer_target_degree,
        );
        for (peer_id, remote) in candidates {
            let event = TargetIngressEvent {
                tenant_id: tenant_id.clone(),
                remote,
                relay_url: None,
                source: TargetIngressSource::KnownPeer { peer_id },
            };
            if should_initiate_connect_for_source_with_db(db_path, &event.tenant_id, &event.source)
            {
                out.push(event);
            }
        }
    }

    out.sort_by_key(desired_target_sort_key);
    Ok(out)
}

pub(crate) fn collect_desired_outbound_targets(
    db_path: &str,
    options: &TargetPlannerOptions,
) -> Result<Vec<TargetIngressEvent>, Box<dyn std::error::Error + Send + Sync>> {
    let tenant_ids = discovered_local_tenant_ids(db_path)?;
    load_desired_outbound_targets(db_path, &tenant_ids, options)
}

pub(crate) fn load_bootstrap_targets(
    db_path: &str,
    tenant_ids: &[String],
) -> Result<
    Vec<(String, String, String, Option<SocketAddr>, Option<String>)>,
    Box<dyn std::error::Error + Send + Sync>,
> {
    let db = open_connection(db_path)?;
    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;
    let mut seen: HashSet<(String, String, Option<SocketAddr>, Option<String>)> = HashSet::new();
    let mut out = Vec::new();

    for tenant_id in tenant_ids {
        for target in list_active_invite_bootstrap_targets(&db, tenant_id)? {
            let decision_context =
                normalize_bootstrap_dial_decision_context(BootstrapDialRawRows {
                    workspace_already_local_elsewhere: target.workspace_already_local_elsewhere,
                });
            if matches!(
                decide_bootstrap_dial_plan(&decision_context),
                BootstrapDialPlan::IgnoreAlreadyLocalWorkspace
            ) {
                continue;
            }
            if bootstrap_target_superseded_by_observed_endpoint(
                &db,
                tenant_id,
                &target.invite_event_id,
                now_ms,
            )? {
                let key = format!(
                    "bootstrap-target-superseded:{}:{}:{}",
                    tenant_id, target.transport_peer_id, target.invite_event_id
                );
                if should_emit_globally(key) {
                    debug!(
                        "Skipping bootstrap target tenant={} daemon={} invite={} because a live observed endpoint for the inviter is already present",
                        short_value(tenant_id),
                        short_value(&target.transport_peer_id),
                        short_value(&target.invite_event_id)
                    );
                }
                continue;
            }

            let (remote, relay_url) = if target.bootstrap_addr.trim().is_empty() {
                (None, None)
            } else if target.bootstrap_addr.starts_with("https://")
                || target.bootstrap_addr.starts_with("http://")
            {
                #[cfg(feature = "iroh-transport")]
                {
                    match target.bootstrap_addr.parse::<iroh::RelayUrl>() {
                        Ok(_) => (None, Some(target.bootstrap_addr.clone())),
                        Err(e) => {
                            warn!(
                                "Skipping invalid invite bootstrap relay_url '{}' for tenant {}: {}",
                                target.bootstrap_addr,
                                &tenant_id[..16.min(tenant_id.len())],
                                e
                            );
                            continue;
                        }
                    }
                }
                #[cfg(feature = "tor-transport")]
                {
                    debug!(
                        "Ignoring invite relay bootstrap_url '{}' for tenant {} under Tor transport",
                        target.bootstrap_addr,
                        short_value(tenant_id)
                    );
                    (None, None)
                }
            } else {
                #[cfg(feature = "iroh-transport")]
                {
                    match parse_bootstrap_address(&target.bootstrap_addr)
                        .and_then(|addr| addr.to_socket_addr())
                    {
                        Ok(addr) => (Some(addr), None),
                        Err(e) => {
                            warn!(
                                "Skipping invalid/unresolvable invite bootstrap_addr '{}' for tenant {}: {}",
                                target.bootstrap_addr,
                                &tenant_id[..16.min(tenant_id.len())],
                                e
                            );
                            continue;
                        }
                    }
                }
                #[cfg(feature = "tor-transport")]
                {
                    match parse_bootstrap_address(&target.bootstrap_addr) {
                        Ok(_) => (None, None),
                        Err(e) => {
                            warn!(
                                "Skipping invalid invite bootstrap_addr '{}' for tenant {} under Tor transport: {}",
                                target.bootstrap_addr,
                                &tenant_id[..16.min(tenant_id.len())],
                                e
                            );
                            continue;
                        }
                    }
                }
            };

            let key = (
                tenant_id.clone(),
                target.transport_peer_id.clone(),
                remote,
                relay_url.clone(),
            );
            if seen.insert(key.clone()) {
                out.push((
                    tenant_id.clone(),
                    target.transport_peer_id,
                    target.invite_event_id,
                    key.2,
                    key.3,
                ));
            }
        }
    }

    Ok(out)
}

pub(crate) fn load_observed_endpoint_targets(
    db_path: &str,
    tenant_ids: &[String],
) -> Result<Vec<(String, String, SocketAddr)>, Box<dyn std::error::Error + Send + Sync>> {
    Ok(load_known_peer_targets(db_path, tenant_ids)?
        .into_iter()
        .filter_map(|(tenant_id, transport_peer_id, remote)| {
            remote.map(|remote| (tenant_id, transport_peer_id, remote))
        })
        .collect())
}

pub(crate) fn load_known_peer_targets(
    db_path: &str,
    tenant_ids: &[String],
) -> Result<Vec<(String, String, Option<SocketAddr>)>, Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;
    let mut seen: HashSet<(String, String)> = HashSet::new();
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
         ORDER BY peer_id",
    )?;

    for tenant_id in tenant_ids {
        let rows = stmt.query_map(rusqlite::params![tenant_id, now_ms], |row| {
            Ok((
                crate::db::sql_types::get_text(row, 0)?,
                crate::db::sql_types::get_opt_text(row, 1)?,
                row.get::<_, Option<i64>>(2)?,
            ))
        })?;

        for row in rows {
            let (peer_id, origin_ip, origin_port) = row?;
            if !seen.insert((tenant_id.clone(), peer_id.clone())) {
                continue;
            }
            let remote = match (origin_ip, origin_port) {
                (Some(origin_ip), Some(origin_port)) => {
                    let ip: std::net::IpAddr = origin_ip.parse()?;
                    Some(SocketAddr::new(ip, origin_port as u16))
                }
                _ => None,
            };
            out.push((tenant_id.clone(), peer_id, remote));
        }
    }

    Ok(out)
}

fn bootstrap_target_superseded_by_observed_endpoint(
    conn: &rusqlite::Connection,
    tenant_id: &str,
    invite_event_id: &str,
    now_ms: i64,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let Some(peer_id) = resolve_bootstrap_inviter_peer_id(conn, tenant_id, invite_event_id)? else {
        return Ok(false);
    };
    let has_live_observation: bool = conn.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM peer_endpoint_observations
             WHERE recorded_by = ?1
               AND via_peer_id = ?2
               AND expires_at > ?3
         )",
        rusqlite::params![tenant_id, peer_id, now_ms],
        |row| row.get(0),
    )?;
    Ok(has_live_observation)
}

pub(crate) fn dispatch_bootstrap_target(
    dispatcher: &mut PeerDispatcher,
    tenant_id: &str,
    transport_peer_id: &str,
    remote: Option<SocketAddr>,
    relay_url: Option<&str>,
) -> bool {
    let key = bootstrap_dispatch_key(tenant_id, transport_peer_id, remote, relay_url);
    let (action, _cancel_rx) = dispatcher.dispatch(&key, remote, relay_url);
    matches!(action, DispatchAction::Connect | DispatchAction::Reconnect)
}

pub(crate) fn bootstrap_dispatch_action(
    dispatcher: &PeerDispatcher,
    tenant_id: &str,
    transport_peer_id: &str,
    remote: Option<SocketAddr>,
    relay_url: Option<&str>,
) -> DispatchAction {
    let key = bootstrap_dispatch_key(tenant_id, transport_peer_id, remote, relay_url);
    dispatcher.peek_action(&key, remote, relay_url)
}

pub(crate) fn dispatch_known_peer_target(
    dispatcher: &mut PeerDispatcher,
    tenant_id: &str,
    transport_peer_id: &str,
    remote: Option<SocketAddr>,
) -> bool {
    let key = known_peer_dispatch_key(tenant_id, transport_peer_id);
    let (action, _cancel_rx) = dispatcher.dispatch(&key, remote, None);
    matches!(action, DispatchAction::Connect | DispatchAction::Reconnect)
}

pub(crate) fn known_peer_dispatch_action(
    dispatcher: &PeerDispatcher,
    tenant_id: &str,
    transport_peer_id: &str,
    remote: Option<SocketAddr>,
) -> DispatchAction {
    let key = known_peer_dispatch_key(tenant_id, transport_peer_id);
    dispatcher.peek_action(&key, remote, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::transport_creds::{set_local_transport_target, CRED_SOURCE_PEER_SHARED};
    use crate::db::transport_trust::record_invite_bootstrap_trust;
    use crate::db::{open_connection, schema::create_tables};
    use rusqlite::params;

    #[test]
    fn dispatcher_reconnects_when_target_address_changes() {
        let mut dispatcher = PeerDispatcher::new();
        let key = "tenant@peer:abc";
        let addr_a: SocketAddr = "127.0.0.1:1111".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:2222".parse().unwrap();

        assert_eq!(
            dispatcher.dispatch(key, Some(addr_a), None).0,
            DispatchAction::Connect
        );
        assert_eq!(
            dispatcher.dispatch(key, Some(addr_a), None).0,
            DispatchAction::Skip
        );
        assert_eq!(
            dispatcher.dispatch(key, Some(addr_b), None).0,
            DispatchAction::Reconnect
        );
    }

    #[test]
    fn bootstrap_lookup_key_is_stable_without_address() {
        let key = bootstrap_dispatch_key("tenant", "peer", None, None);
        assert_eq!(key, "tenant@bootstrap:peer@lookup");
    }

    #[test]
    fn bootstrap_dial_plan_ignores_already_local_workspace_regardless_of_endpoint() {
        let direct = normalize_bootstrap_dial_decision_context(BootstrapDialRawRows {
            workspace_already_local_elsewhere: true,
        });
        let relay = normalize_bootstrap_dial_decision_context(BootstrapDialRawRows {
            workspace_already_local_elsewhere: true,
        });

        assert_eq!(
            decide_bootstrap_dial_plan(&direct),
            BootstrapDialPlan::IgnoreAlreadyLocalWorkspace
        );
        assert_eq!(
            decide_bootstrap_dial_plan(&direct),
            decide_bootstrap_dial_plan(&relay),
            "already-local workspaces must ignore attacker-controlled bootstrap endpoints"
        );
    }

    #[test]
    fn load_bootstrap_targets_skips_already_local_workspace() {
        let tmpdir = tempfile::tempdir().unwrap();
        let db_path = tmpdir.path().join("already-local-bootstrap.db");
        let conn = open_connection(db_path.to_str().unwrap()).unwrap();
        create_tables(&conn).unwrap();

        record_invite_bootstrap_trust(
            &conn,
            "tenant-a",
            "accepted-a",
            "invite-a",
            "workspace-shared",
            "127.0.0.1:17777",
            &[0xAB; 32],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO invites_accepted
                 (recorded_by, event_id, tenant_event_id, invite_event_id, workspace_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                "tenant-a",
                "accepted-a",
                "tenant-event-a",
                "invite-a",
                "workspace-shared",
                1i64
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO invites_accepted
                 (recorded_by, event_id, tenant_event_id, invite_event_id, workspace_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                "tenant-b",
                "accepted-b",
                "tenant-event-b",
                "invite-b",
                "workspace-shared",
                1i64
            ],
        )
        .unwrap();
        drop(conn);

        let targets =
            load_bootstrap_targets(db_path.to_str().unwrap(), &["tenant-a".to_string()]).unwrap();
        assert!(
            targets.is_empty(),
            "bootstrap targets must be suppressed when the workspace is already local elsewhere"
        );
    }

    #[test]
    fn load_bootstrap_targets_keeps_nonlocal_workspace() {
        let tmpdir = tempfile::tempdir().unwrap();
        let db_path = tmpdir.path().join("nonlocal-bootstrap.db");
        let conn = open_connection(db_path.to_str().unwrap()).unwrap();
        create_tables(&conn).unwrap();

        record_invite_bootstrap_trust(
            &conn,
            "tenant-a",
            "accepted-a",
            "invite-a",
            "workspace-a",
            "127.0.0.1:17778",
            &[0xAC; 32],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO invites_accepted
                 (recorded_by, event_id, tenant_event_id, invite_event_id, workspace_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                "tenant-a",
                "accepted-a",
                "tenant-event-a",
                "invite-a",
                "workspace-a",
                1i64
            ],
        )
        .unwrap();
        drop(conn);

        let targets =
            load_bootstrap_targets(db_path.to_str().unwrap(), &["tenant-a".to_string()]).unwrap();
        assert_eq!(
            targets.len(),
            1,
            "nonlocal workspaces must retain bootstrap targets"
        );
        assert_eq!(targets[0].0, "tenant-a");
        assert_eq!(targets[0].1, hex::encode([0xAC; 32]));
        assert_eq!(targets[0].2, "invite-a");
    }

    #[cfg(feature = "tor-transport")]
    #[test]
    fn tor_transport_load_bootstrap_targets_keeps_onion_hostnames_under_tor() {
        let tmpdir = tempfile::tempdir().unwrap();
        let db_path = tmpdir.path().join("tor-onion-bootstrap.db");
        let conn = open_connection(db_path.to_str().unwrap()).unwrap();
        create_tables(&conn).unwrap();

        record_invite_bootstrap_trust(
            &conn,
            "tenant-a",
            "accepted-a",
            "invite-a",
            "workspace-a",
            "5a3uqymkr67uegvyaxokyhk3xb6yj26ac3tbqik76cseb5buctkexcid.onion:17691",
            &[0xAD; 32],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO invites_accepted
                 (recorded_by, event_id, tenant_event_id, invite_event_id, workspace_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                "tenant-a",
                "accepted-a",
                "tenant-event-a",
                "invite-a",
                "workspace-a",
                1i64
            ],
        )
        .unwrap();
        drop(conn);
        let targets =
            load_bootstrap_targets(db_path.to_str().unwrap(), &["tenant-a".to_string()]).unwrap();
        assert_eq!(targets.len(), 1, "Tor should keep onion bootstrap targets");
        assert_eq!(targets[0].0, "tenant-a");
        assert_eq!(targets[0].1, hex::encode([0xAD; 32]));
        assert_eq!(targets[0].2, "invite-a");
        assert_eq!(
            targets[0].3, None,
            "Tor dials by daemon id, not socket addr"
        );
        assert_eq!(
            targets[0].4, None,
            "Tor invite bootstrap should not require relay URLs"
        );
    }

    #[test]
    fn desired_outbound_targets_gate_lookup_only_known_peers_by_capability() {
        let tmpdir = tempfile::tempdir().unwrap();
        let db_path = tmpdir.path().join("lookup-known-peer.db");
        let conn = open_connection(db_path.to_str().unwrap()).unwrap();
        create_tables(&conn).unwrap();
        conn.execute(
            "INSERT INTO peers_shared (recorded_by, event_id, public_key, transport_fingerprint)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                "tenant-a",
                "peer-shared-1",
                vec![0x11u8; 32],
                vec![0xBCu8; 32]
            ],
        )
        .unwrap();
        drop(conn);

        let allow_lookup = load_desired_outbound_targets(
            db_path.to_str().unwrap(),
            &["tenant-a".to_string()],
            &TargetPlannerOptions {
                include_bootstrap_targets: false,
                allow_lookup_known_peers: true,
                known_peer_target_degree: DEFAULT_HASH_GRAPH_DEGREE,
            },
        )
        .unwrap();
        assert_eq!(
            allow_lookup,
            vec![TargetIngressEvent {
                tenant_id: "tenant-a".to_string(),
                remote: None,
                relay_url: None,
                source: TargetIngressSource::KnownPeer {
                    peer_id: hex::encode([0xBC; 32]),
                },
            }]
        );

        let disallow_lookup = load_desired_outbound_targets(
            db_path.to_str().unwrap(),
            &["tenant-a".to_string()],
            &TargetPlannerOptions {
                include_bootstrap_targets: false,
                allow_lookup_known_peers: false,
                known_peer_target_degree: DEFAULT_HASH_GRAPH_DEGREE,
            },
        )
        .unwrap();
        assert!(
            disallow_lookup.is_empty(),
            "lookup-only known peers must be planner-filtered when address lookup is unavailable"
        );
    }

    #[test]
    fn desired_outbound_targets_bound_large_known_peer_sets_by_mesh_degree() {
        let tmpdir = tempfile::tempdir().unwrap();
        let db_path = tmpdir.path().join("mesh-degree-known-peers.db");
        let conn = open_connection(db_path.to_str().unwrap()).unwrap();
        create_tables(&conn).unwrap();

        let local_transport_peer_id = hex::encode([0xAA; 32]);
        set_local_transport_target(
            &conn,
            "tenant-a",
            &local_transport_peer_id,
            CRED_SOURCE_PEER_SHARED,
        )
        .unwrap();

        for idx in 0u8..10 {
            let mut transport_fingerprint = [0u8; 32];
            transport_fingerprint[31] = idx.saturating_add(1);
            conn.execute(
                "INSERT INTO peers_shared (recorded_by, event_id, public_key, transport_fingerprint)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    "tenant-a",
                    format!("peer-shared-{idx}"),
                    vec![idx; 32],
                    transport_fingerprint.to_vec()
                ],
            )
            .unwrap();
        }
        drop(conn);

        let options = TargetPlannerOptions {
            include_bootstrap_targets: false,
            allow_lookup_known_peers: true,
            known_peer_target_degree: 3,
        };
        let first = load_desired_outbound_targets(
            db_path.to_str().unwrap(),
            &["tenant-a".to_string()],
            &options,
        )
        .unwrap();
        let second = load_desired_outbound_targets(
            db_path.to_str().unwrap(),
            &["tenant-a".to_string()],
            &options,
        )
        .unwrap();

        assert_eq!(first, second, "mesh selection must be deterministic");
        assert_eq!(first.len(), 3, "known-peer dials must be degree-bounded");
        assert!(first.iter().all(|target| {
            matches!(target.source, TargetIngressSource::KnownPeer { .. })
                && target.remote.is_none()
        }));
    }
}
