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

use tracing::warn;

use crate::db::open_connection;
use crate::db::transport_creds::discover_local_tenants;
use crate::db::transport_trust::list_active_invite_bootstrap_targets;
use crate::event_modules::workspace::invite_link::parse_bootstrap_address;
use crate::transport::resolve_bootstrap_inviter_peer_id;

/// Dispatch decision for an outbound target.
#[derive(Debug, PartialEq)]
pub(crate) enum DispatchAction {
    Skip,
    Connect,
    Reconnect,
}

/// Bootstrap dial planning decision from a single query snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BootstrapDialPlan {
    /// The workspace is already present locally under another tenant, so link
    /// bootstrap endpoint/address data must be ignored.
    IgnoreAlreadyLocalWorkspace,
    UseBootstrapTarget,
}

pub(crate) fn decide_bootstrap_dial_plan(
    target: &crate::db::transport_trust::InviteBootstrapTarget,
) -> BootstrapDialPlan {
    if target.workspace_already_local_elsewhere {
        BootstrapDialPlan::IgnoreAlreadyLocalWorkspace
    } else {
        BootstrapDialPlan::UseBootstrapTarget
    }
}

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
        if let Some((prev_addr, prev_relay_url, _)) = self.known.get(key) {
            if *prev_addr == addr && prev_relay_url.as_deref() == relay_url {
                return (DispatchAction::Skip, None);
            }
        }

        let action = if self.known.contains_key(key) {
            DispatchAction::Reconnect
        } else {
            DispatchAction::Connect
        };
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(());
        self.known.insert(
            key.to_string(),
            (addr, relay_url.map(str::to_string), cancel_tx),
        );
        (action, Some(cancel_rx))
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
            if matches!(
                decide_bootstrap_dial_plan(&target),
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
                continue;
            }

            let (remote, relay_url) = if target.bootstrap_addr.trim().is_empty() {
                (None, None)
            } else if target.bootstrap_addr.starts_with("https://")
                || target.bootstrap_addr.starts_with("http://")
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
            } else {
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

pub(crate) fn collect_all_bootstrap_targets(
    db_path: &str,
) -> Result<
    Vec<(String, String, String, Option<SocketAddr>, Option<String>)>,
    Box<dyn std::error::Error + Send + Sync>,
> {
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
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
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

pub(crate) fn collect_all_known_peer_targets(
    db_path: &str,
) -> Result<Vec<(String, String, Option<SocketAddr>)>, Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    let mut tenant_ids: Vec<String> = discover_local_tenants(&db)?
        .into_iter()
        .map(|tenant| tenant.peer_id)
        .collect();
    tenant_ids.sort();
    tenant_ids.dedup();
    drop(db);
    load_known_peer_targets(db_path, &tenant_ids)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::transport_trust::{record_invite_bootstrap_trust, InviteBootstrapTarget};
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
        let direct = InviteBootstrapTarget {
            invite_event_id: "invite-1".to_string(),
            transport_peer_id: "peer-1".to_string(),
            bootstrap_addr: "127.0.0.1:7777".to_string(),
            workspace_already_local_elsewhere: true,
        };
        let relay = InviteBootstrapTarget {
            invite_event_id: "invite-1".to_string(),
            transport_peer_id: "peer-1".to_string(),
            bootstrap_addr: "https://relay.example".to_string(),
            workspace_already_local_elsewhere: true,
        };

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
}
