//! RPC server: Unix domain socket listener that dispatches requests to service functions.
//!
//! Connection count is bounded by a semaphore to prevent local connection-flood
//! pressure (feedback item 2).

use serde::Serialize;
use std::collections::BTreeSet;
use std::io::Write;
use std::net::SocketAddr;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tracing::{info, warn};

use crate::event_modules::{file, message, peer_shared, reaction, user, workspace};
use crate::node::NodeRuntimeNetInfo;
use crate::rpc::protocol::*;
use crate::service;
use crate::state::subscriptions;
use crate::transport::TransportEndpoint;

/// Maximum concurrent RPC connections the server will handle.
/// Additional connections block until a slot is freed.
const MAX_CONCURRENT_CONNECTIONS: usize = 64;
const INVITE_RELAY_WAIT_TIMEOUT: Duration = Duration::from_secs(5);
const INVITE_RELAY_WAIT_POLL_INTERVAL: Duration = Duration::from_millis(100);
const CREATE_WORKSPACE_CREATED_EVENTS_CAP: usize = 32;

#[derive(Debug, Clone)]
struct TimelineReportRow {
    event_id: String,
    content: String,
    created_at_ms: i64,
    first_received_at_ms: Option<i64>,
    first_stored_at_ms: Option<i64>,
    blocked_at_ms: Option<i64>,
    unblocked_at_ms: Option<i64>,
    unblocked_by_event_id: Option<String>,
    projected_at_ms: Option<i64>,
}

fn timeline_delta(start: Option<i64>, end: Option<i64>) -> Option<i64> {
    match (start, end) {
        (Some(start), Some(end)) if end >= start => Some(end - start),
        _ => None,
    }
}

fn timeline_stage_stats(values: &[i64]) -> serde_json::Value {
    if values.is_empty() {
        return serde_json::json!({
            "count": 0,
            "avg_ms": serde_json::Value::Null,
            "p50_ms": serde_json::Value::Null,
            "p95_ms": serde_json::Value::Null,
            "max_ms": serde_json::Value::Null,
        });
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let p50_idx = (sorted.len() - 1) * 50 / 100;
    let p95_idx = (sorted.len() - 1) * 95 / 100;
    let sum: i128 = sorted.iter().map(|value| *value as i128).sum();
    serde_json::json!({
        "count": sorted.len(),
        "avg_ms": sum as f64 / sorted.len() as f64,
        "p50_ms": sorted[p50_idx],
        "p95_ms": sorted[p95_idx],
        "max_ms": sorted[sorted.len() - 1],
    })
}

fn build_event_timeline_report(
    db: &rusqlite::Connection,
    recorded_by: &str,
    content_prefix: Option<&str>,
    limit: usize,
) -> Result<serde_json::Value, rusqlite::Error> {
    let prefix_like = content_prefix.map(|prefix| format!("{prefix}%"));
    let mut stmt = db.prepare(
        "SELECT m.message_id,
                m.content,
                m.created_at,
                t.first_received_at,
                t.first_stored_at,
                t.blocked_at,
                t.unblocked_at,
                t.unblocked_by_event_id,
                t.projected_at
         FROM messages m
         LEFT JOIN event_timeline t ON t.event_id = m.message_id
         WHERE m.recorded_by = ?1
           AND (?2 IS NULL OR m.content LIKE ?2)
         ORDER BY m.created_at DESC, m.message_id DESC",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![recorded_by, prefix_like], |row| {
            Ok(TimelineReportRow {
                event_id: row.get(0)?,
                content: row.get(1)?,
                created_at_ms: row.get(2)?,
                first_received_at_ms: row.get(3)?,
                first_stored_at_ms: row.get(4)?,
                blocked_at_ms: row.get(5)?,
                unblocked_at_ms: row.get(6)?,
                unblocked_by_event_id: row.get(7)?,
                projected_at_ms: row.get(8)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let recv_to_store: Vec<i64> = rows
        .iter()
        .filter_map(|row| timeline_delta(row.first_received_at_ms, row.first_stored_at_ms))
        .collect();
    let store_to_project: Vec<i64> = rows
        .iter()
        .filter_map(|row| timeline_delta(row.first_stored_at_ms, row.projected_at_ms))
        .collect();
    let recv_to_project: Vec<i64> = rows
        .iter()
        .filter_map(|row| timeline_delta(row.first_received_at_ms, row.projected_at_ms))
        .collect();
    let blocked_to_unblocked: Vec<i64> = rows
        .iter()
        .filter_map(|row| timeline_delta(row.blocked_at_ms, row.unblocked_at_ms))
        .collect();
    let unblocked_to_project: Vec<i64> = rows
        .iter()
        .filter_map(|row| timeline_delta(row.unblocked_at_ms, row.projected_at_ms))
        .collect();

    let sample_rows: Vec<serde_json::Value> = rows
        .iter()
        .take(limit)
        .map(|row| {
            serde_json::json!({
                "event_id": row.event_id,
                "content": row.content,
                "created_at_ms": row.created_at_ms,
                "first_received_at_ms": row.first_received_at_ms,
                "first_stored_at_ms": row.first_stored_at_ms,
                "blocked_at_ms": row.blocked_at_ms,
                "unblocked_at_ms": row.unblocked_at_ms,
                "unblocked_by_event_id": row.unblocked_by_event_id,
                "projected_at_ms": row.projected_at_ms,
                "recv_to_store_ms": timeline_delta(row.first_received_at_ms, row.first_stored_at_ms),
                "store_to_project_ms": timeline_delta(row.first_stored_at_ms, row.projected_at_ms),
                "recv_to_project_ms": timeline_delta(row.first_received_at_ms, row.projected_at_ms),
                "blocked_to_unblocked_ms": timeline_delta(row.blocked_at_ms, row.unblocked_at_ms),
                "unblocked_to_project_ms": timeline_delta(row.unblocked_at_ms, row.projected_at_ms),
            })
        })
        .collect();

    Ok(serde_json::json!({
        "content_prefix": content_prefix,
        "match_count": rows.len(),
        "sample_limit": limit,
        "sample_count": sample_rows.len(),
        "received_count": rows.iter().filter(|row| row.first_received_at_ms.is_some()).count(),
        "stored_count": rows.iter().filter(|row| row.first_stored_at_ms.is_some()).count(),
        "blocked_count": rows.iter().filter(|row| row.blocked_at_ms.is_some()).count(),
        "unblocked_count": rows.iter().filter(|row| row.unblocked_at_ms.is_some()).count(),
        "projected_count": rows.iter().filter(|row| row.projected_at_ms.is_some()).count(),
        "stage_stats": {
            "recv_to_store_ms": timeline_stage_stats(&recv_to_store),
            "store_to_project_ms": timeline_stage_stats(&store_to_project),
            "recv_to_project_ms": timeline_stage_stats(&recv_to_project),
            "blocked_to_unblocked_ms": timeline_stage_stats(&blocked_to_unblocked),
            "unblocked_to_project_ms": timeline_stage_stats(&unblocked_to_project),
        },
        "sample_rows": sample_rows,
    }))
}

#[derive(Debug, Clone)]
struct TenantScope {
    tenant_id: String,
}

fn discover_tenant_scopes(
    conn: &rusqlite::Connection,
) -> Result<Vec<TenantScope>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT recorded_by
         FROM invites_accepted
         ORDER BY recorded_by",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok(TenantScope {
                tenant_id: row.get(0)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Daemon-wide shared state: tracks active peer and invite refs.
pub struct DaemonState {
    pub db_path: String,
    pub active_peer: RwLock<Option<String>>,
    /// Runtime lifecycle state.
    pub runtime_state: RwLock<RuntimeState>,
    /// Runtime networking info and live endpoint handle, set once the daemon
    /// runtime has bound its `iroh` endpoint.
    pub runtime_net: RwLock<Option<NodeRuntimeNetInfo>>,
    /// The daemon's resolved bind address, set as soon as startup reserves the
    /// UDP socket. This survives the idle-no-tenants phase before runtime
    /// activation reports `runtime_net.listen_addr`.
    pub resolved_bind_addr: RwLock<Option<SocketAddr>>,
    /// Wake-up trigger for runtime state reevaluation after tenant-changing commands.
    pub runtime_recheck: Notify,
    /// Invite/link strings stored by number (index+1 = invite ref number).
    pub invite_refs: RwLock<Vec<String>>,
    /// Sync control registry for manual sync operations.
    pub sync_control: Arc<crate::runtime::sync_control::SyncControlRegistry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeState {
    IdleNoTenants,
    Active,
}

impl RuntimeState {
    pub fn as_str(self) -> &'static str {
        match self {
            RuntimeState::IdleNoTenants => "IdleNoTenants",
            RuntimeState::Active => "Active",
        }
    }
}

impl DaemonState {
    /// Create state with auto-selected peer if exactly one tenant exists.
    pub fn new(db_path: &str) -> Self {
        let active = match crate::db::open_connection(db_path) {
            Ok(conn) => {
                let _ = crate::transport::ensure_daemon_identity(&conn);
                match discover_tenant_scopes(&conn) {
                    Ok(tenants) if tenants.len() == 1 => Some(tenants[0].tenant_id.clone()),
                    Ok(_) => None,
                    Err(_) => None,
                }
            }
            Err(_) => None,
        };
        DaemonState {
            db_path: db_path.to_string(),
            active_peer: RwLock::new(active),
            // Runtime manager owns lifecycle transitions.
            runtime_state: RwLock::new(RuntimeState::IdleNoTenants),
            runtime_net: RwLock::new(None),
            resolved_bind_addr: RwLock::new(None),
            runtime_recheck: Notify::new(),
            invite_refs: RwLock::new(Vec::new()),
            sync_control: Arc::new(crate::runtime::sync_control::SyncControlRegistry::new()),
        }
    }

    pub fn notify_runtime_recheck(&self) {
        self.runtime_recheck.notify_waiters();
    }

    fn runtime_endpoint(&self) -> Option<TransportEndpoint> {
        self.runtime_net
            .read()
            .unwrap()
            .as_ref()
            .and_then(|info| info.endpoint.clone())
    }

    fn require_active_peer(&self) -> Result<String, String> {
        let cached = self.active_peer.read().unwrap().clone();

        // Discover current tenant scopes from invites_accepted projection state.
        // This keeps control-plane tenant selection independent from transport creds.
        let discovered = if let Ok(conn) = crate::db::open_connection(&self.db_path) {
            discover_tenant_scopes(&conn).ok()
        } else {
            None
        };

        if let Some(peer_id) = cached {
            match discovered.as_ref() {
                Some(tenants) => {
                    if tenants.iter().any(|t| t.tenant_id == peer_id) {
                        return Ok(peer_id);
                    }
                    *self.active_peer.write().unwrap() = None;
                }
                None => {
                    // Preserve previous behavior when discovery is unavailable.
                    return Ok(peer_id);
                }
            }
        }

        if let Some(tenants) = discovered {
            if tenants.len() == 1 {
                let peer_id = tenants[0].tenant_id.clone();
                *self.active_peer.write().unwrap() = Some(peer_id.clone());
                return Ok(peer_id);
            }
        }

        Err("no active tenant — run `topo tenant use <N>`".to_string())
    }

    /// Store an invite/link string and return its 1-based reference number.
    pub fn add_invite_ref(&self, link: String) -> usize {
        let mut refs = self.invite_refs.write().unwrap();
        refs.push(link);
        refs.len()
    }

    /// Resolve an invite ref: numeric string → stored link, otherwise passthrough.
    pub fn resolve_invite_ref(&self, selector: &str) -> Result<String, String> {
        if let Ok(num) = selector.parse::<usize>() {
            let refs = self.invite_refs.read().unwrap();
            if num >= 1 && num <= refs.len() {
                return Ok(refs[num - 1].clone());
            }
            return Err(format!(
                "invalid invite ref #{}; available: 1-{}",
                num,
                refs.len()
            ));
        }
        // Passthrough: treat as a raw invite link
        Ok(selector.to_string())
    }
}

/// Helper: resolve active peer, open its DB, and pass `(peer_id, recorded_by, db)`
/// to the closure. Returns the closure's `RpcResponse` on success, or an error
/// response if the active peer is missing or the DB cannot be opened.
fn with_active_peer_db<F>(state: &DaemonState, f: F) -> RpcResponse
where
    F: FnOnce(&str, &str, &rusqlite::Connection) -> RpcResponse,
{
    match state.require_active_peer() {
        Ok(peer_id) => match service::open_existing_db_for_peer(&state.db_path, &peer_id) {
            Ok((recorded_by, db)) => f(&peer_id, &recorded_by, &db),
            Err(e) => RpcResponse::error(e.to_string()),
        },
        Err(e) => RpcResponse::error(e),
    }
}

/// Tenant info returned by the Tenants command.
#[derive(Debug, Serialize)]
struct TenantItem {
    index: usize,
    peer_id: String,
    username: String,
    workspace_id: String,
    workspace_name: String,
    active: bool,
}

/// Run the RPC server on a Unix socket, dispatching to service functions.
/// Blocks the calling thread. Intended to be run in a background thread.
pub fn run_rpc_server(
    socket_path: &Path,
    state: Arc<DaemonState>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    shutdown_notify: Arc<tokio::sync::Notify>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Remove stale socket file if it exists.
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }

    // Ensure parent directory exists.
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(socket_path)?;
    // Set non-blocking so we can check the shutdown flag periodically.
    listener.set_nonblocking(true)?;

    info!("RPC server listening on {}", socket_path.display());

    // Bounded connection counter (poor-man's semaphore without extra deps).
    let active = Arc::new(AtomicUsize::new(0));

    while !shutdown.load(std::sync::atomic::Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                let current = active.load(AtomicOrdering::Relaxed);
                if current >= MAX_CONCURRENT_CONNECTIONS {
                    warn!(
                        "RPC connection limit reached ({}), rejecting",
                        MAX_CONCURRENT_CONNECTIONS
                    );
                    // Drop `stream` immediately — client gets connection-reset.
                    drop(stream);
                    continue;
                }

                let st = state.clone();
                let active_clone = active.clone();
                let shutdown_clone = shutdown.clone();
                let notify_clone = shutdown_notify.clone();
                active.fetch_add(1, AtomicOrdering::Relaxed);

                std::thread::spawn(move || {
                    if let Err(e) = handle_connection(stream, &st, &shutdown_clone, &notify_clone) {
                        warn!("RPC connection error: {}", e);
                    }
                    active_clone.fetch_sub(1, AtomicOrdering::Relaxed);
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No pending connections — sleep briefly and check shutdown.
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => {
                warn!("RPC accept error: {}", e);
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }

    // Cleanup socket file.
    let _ = std::fs::remove_file(socket_path);
    info!("RPC server shut down");
    Ok(())
}

fn handle_connection(
    mut stream: std::os::unix::net::UnixStream,
    state: &DaemonState,
    shutdown: &std::sync::atomic::AtomicBool,
    shutdown_notify: &tokio::sync::Notify,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Set blocking for this connection.
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;

    let req: RpcRequest = decode_frame(&mut stream)?;

    if req.version != PROTOCOL_VERSION {
        let resp = RpcResponse::error(format!(
            "version mismatch: server={}, client={}",
            PROTOCOL_VERSION, req.version
        ));
        let frame = encode_frame(&resp)?;
        stream.write_all(&frame)?;
        return Ok(());
    }

    let resp = dispatch(state, req.method, shutdown, shutdown_notify);
    let frame = encode_frame(&resp)?;
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(())
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| {
            let lowered = value.to_ascii_lowercase();
            lowered == "1" || lowered == "true" || lowered == "yes"
        })
        .unwrap_or(false)
}

fn is_link_local(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_link_local(),
        std::net::IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
    }
}

fn endpoint_bootstrap_addrs(
    endpoint: &TransportEndpoint,
) -> Vec<crate::event_modules::workspace::invite_link::BootstrapAddress> {
    let include_loopback = env_flag("TOPO_TEST_DISCOVERY_LOOPBACK");
    let mut addrs = Vec::new();
    let mut seen = BTreeSet::new();
    for addr in endpoint.endpoint_addr().ip_addrs().copied() {
        let ip = addr.ip();
        if ip.is_unspecified() {
            continue;
        }
        if ip.is_loopback() && !include_loopback {
            continue;
        }
        if is_link_local(&ip) {
            continue;
        }
        let bootstrap = match ip {
            std::net::IpAddr::V4(ip) => {
                crate::event_modules::workspace::invite_link::BootstrapAddress::Ipv4 {
                    ip,
                    port: addr.port(),
                }
            }
            std::net::IpAddr::V6(ip) => {
                crate::event_modules::workspace::invite_link::BootstrapAddress::Ipv6 {
                    ip,
                    port: addr.port(),
                }
            }
        };
        let key = bootstrap.to_bootstrap_addr_string();
        if seen.insert(key) {
            addrs.push(bootstrap);
        }
    }
    addrs
}

fn runtime_status_value(state: &DaemonState) -> Option<serde_json::Value> {
    if let Some(mut info) = state.runtime_net.read().unwrap().clone() {
        if let Some(endpoint) = info.endpoint.as_ref() {
            if let Ok(listen_addr) = endpoint.local_addr() {
                info.listen_addr = listen_addr.to_string();
            }
            info.daemon_peer_id = endpoint.daemon_peer_id();
            info.published_addrs = endpoint_bootstrap_addrs(endpoint)
                .into_iter()
                .map(|addr| addr.to_bootstrap_addr_string())
                .collect();
            info.mdns_enabled = endpoint.mdns_lookup().is_some();
        }
        let mut value = serde_json::to_value(info).ok()?;
        let endpoint_id = value["daemon_peer_id"]
            .as_str()
            .map(ToString::to_string)
            .unwrap_or_default();
        value["endpoint_id"] = serde_json::json!(endpoint_id);
        value["endpoint_shared_id"] = serde_json::Value::Null;
        if let Ok(db) = crate::db::open_connection(&state.db_path) {
            if let Ok(Some(secret_row)) =
                crate::event_modules::endpoint_secret::load_local_endpoint_secret(&db)
            {
                value["endpoint_secret_event_id"] = serde_json::json!(secret_row.event_id);
            }
            if let Ok(Some(shared_row)) =
                crate::event_modules::endpoint_shared::load_local_endpoint_shared(&db)
            {
                value["endpoint_shared_id"] = serde_json::json!(shared_row.event_id);
            }
        }
        return Some(value);
    }

    let addr = (*state.resolved_bind_addr.read().unwrap())?;
    let mut value = serde_json::json!({
        "listen_addr": addr.to_string(),
        "published_addrs": Vec::<String>::new(),
        "mdns_enabled": false,
        "endpoint_shared_id": serde_json::Value::Null,
    });
    if let Ok(db) = crate::db::open_connection(&state.db_path) {
        if let Ok(Some(secret_row)) =
            crate::event_modules::endpoint_secret::load_local_endpoint_secret(&db)
        {
            value["daemon_peer_id"] = serde_json::json!(secret_row.endpoint_id.clone());
            value["endpoint_id"] = serde_json::json!(secret_row.endpoint_id);
            value["endpoint_secret_event_id"] = serde_json::json!(secret_row.event_id);
        }
        if let Ok(Some(shared_row)) =
            crate::event_modules::endpoint_shared::load_local_endpoint_shared(&db)
        {
            value["endpoint_shared_id"] = serde_json::json!(shared_row.event_id);
        }
    }
    Some(value)
}

fn runtime_relay_url(state: &DaemonState) -> Option<String> {
    state.runtime_endpoint()?.relay_url()
}

fn runtime_relay_url_for_bootstrap(state: &DaemonState) -> Option<String> {
    state.notify_runtime_recheck();
    let deadline = Instant::now() + INVITE_RELAY_WAIT_TIMEOUT;
    loop {
        if let Some(relay_url) = runtime_relay_url(state) {
            return Some(relay_url);
        }
        if Instant::now() >= deadline {
            warn!(
                "timed out waiting {:?} for iroh relay bootstrap info",
                INVITE_RELAY_WAIT_TIMEOUT
            );
            return None;
        }
        std::thread::sleep(INVITE_RELAY_WAIT_POLL_INTERVAL);
    }
}

fn daemon_scope_annotations(
    conn: &rusqlite::Connection,
    daemon_peer_id: &str,
) -> Result<(Vec<String>, Vec<String>, Vec<String>), rusqlite::Error> {
    let daemon_fp = match hex::decode(daemon_peer_id) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return Ok((Vec::new(), Vec::new(), Vec::new())),
    };
    let mut stmt = conn.prepare(
        "SELECT DISTINCT ia.recorded_by, ia.workspace_id, b.peer_id
         FROM peer_transport_bindings b
         JOIN invites_accepted ia
           ON ia.recorded_by = b.recorded_by
         WHERE b.spki_fingerprint = ?1
         ORDER BY ia.workspace_id, ia.recorded_by, b.peer_id",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![daemon_fp], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let mut local_tenants = BTreeSet::new();
    let mut workspace_ids = BTreeSet::new();
    let mut peer_ids = BTreeSet::new();
    for (tenant_id, workspace_id, peer_id) in rows {
        local_tenants.insert(tenant_id);
        workspace_ids.insert(workspace_id);
        peer_ids.insert(peer_id);
    }
    Ok((
        local_tenants.into_iter().collect(),
        workspace_ids.into_iter().collect(),
        peer_ids.into_iter().collect(),
    ))
}

/// Best-effort store of client_op_id → event_id mapping. Failures are logged but don't
/// affect the RPC response since the event was already created successfully.
fn store_client_op(
    db_path: &str,
    peer_id: &str,
    client_op_id: Option<&str>,
    event_id_hex: &str,
    op_kind: &str,
) {
    let Some(cop_id) = client_op_id else { return };
    let Ok(eid_bytes) = hex::decode(event_id_hex) else {
        warn!("store_client_op: bad hex event_id");
        return;
    };
    if eid_bytes.len() != 32 {
        return;
    }
    let eid: [u8; 32] = eid_bytes.try_into().unwrap();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    if let Ok(conn) = crate::db::open_connection(db_path) {
        let _ = crate::db::local_client_ops::insert(&conn, peer_id, cop_id, &eid, op_kind, now_ms);
    }
}

/// Best-effort: inject created_events into an existing RpcResponse JSON.
/// Takes hex event IDs, converts to base64, fetches EventListItems, and
/// merges them into the response data under "created_events".
fn inject_created_events(
    resp: &mut RpcResponse,
    db_path: &str,
    peer_id: &str,
    hex_event_ids: &[&str],
) {
    if hex_event_ids.is_empty() {
        return;
    }
    // Convert hex event IDs to base64 (DB format).
    let b64_ids: Vec<String> = hex_event_ids
        .iter()
        .filter_map(|hex_id| {
            let bytes = hex::decode(hex_id).ok()?;
            if bytes.len() != 32 {
                return None;
            }
            let eid: [u8; 32] = bytes.try_into().ok()?;
            Some(crate::crypto::event_id_to_base64(&eid))
        })
        .collect();
    if b64_ids.is_empty() {
        return;
    }
    let Ok((recorded_by, db)) = service::open_db_for_peer(db_path, peer_id) else {
        return;
    };
    let Ok(list_resp) = service::svc_event_list_by_ids(&db, &recorded_by, &b64_ids) else {
        return;
    };
    if let Some(ref mut data) = resp.data {
        if let Ok(events_json) = serde_json::to_value(&list_resp.events) {
            data["created_events"] = events_json;
        }
    }
}

fn dispatch(
    state: &DaemonState,
    method: RpcMethod,
    shutdown: &std::sync::atomic::AtomicBool,
    shutdown_notify: &tokio::sync::Notify,
) -> RpcResponse {
    let db_path = &state.db_path;

    match method {
        RpcMethod::Shutdown => {
            shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
            shutdown_notify.notify_waiters();
            RpcResponse::success(serde_json::json!({"shutdown": true}))
        }

        // ----- Tenant management (daemon state) -----
        RpcMethod::Tenants => match crate::db::open_connection(db_path) {
            Ok(conn) => {
                let active = state.active_peer.read().unwrap().clone();
                match workspace::list_tenants_for_display(&conn, active.as_deref().unwrap_or("")) {
                    Ok(tenants) => {
                        let items: Vec<TenantItem> = tenants
                            .into_iter()
                            .enumerate()
                            .map(|(i, tenant)| TenantItem {
                                index: i + 1,
                                peer_id: tenant.peer_id,
                                username: tenant.username,
                                workspace_id: tenant.workspace_id,
                                workspace_name: tenant.workspace_name,
                                active: tenant.active,
                            })
                            .collect();
                        RpcResponse::success(serde_json::json!(items))
                    }
                    Err(e) => RpcResponse::error(e.to_string()),
                }
            }
            Err(e) => RpcResponse::error(e.to_string()),
        },

        RpcMethod::UseTenant { index } => match crate::db::open_connection(db_path) {
            Ok(conn) => {
                let active = state.active_peer.read().unwrap().clone();
                match workspace::list_tenants_for_display(&conn, active.as_deref().unwrap_or("")) {
                    Ok(tenants) => {
                        if index == 0 || index > tenants.len() {
                            return RpcResponse::error(format!(
                                "invalid tenant number {}; available: 1-{}",
                                index,
                                tenants.len()
                            ));
                        }
                        let tenant = &tenants[index - 1];
                        *state.active_peer.write().unwrap() = Some(tenant.peer_id.clone());
                        RpcResponse::success(serde_json::json!({
                            "peer_id": tenant.peer_id,
                            "workspace_id": tenant.workspace_id,
                            "workspace_name": tenant.workspace_name,
                        }))
                    }
                    Err(e) => RpcResponse::error(e.to_string()),
                }
            }
            Err(e) => RpcResponse::error(e.to_string()),
        },

        RpcMethod::ActiveTenant => {
            let active = state.active_peer.read().unwrap().clone();
            match active {
                Some(peer_id) => RpcResponse::success(serde_json::json!({"peer_id": peer_id})),
                None => RpcResponse::success(serde_json::json!({"peer_id": null})),
            }
        }

        RpcMethod::CreateWorkspace {
            workspace_name,
            username,
            device_name,
            message_count,
            network_age,
        } => {
            match workspace::commands::create_workspace_for_db_with_seed(
                db_path,
                &workspace_name,
                &username,
                &device_name,
                message_count,
                network_age.as_deref(),
            ) {
                Ok(resp) => {
                    // Creating a workspace establishes a new local tenant.
                    // Make it active immediately so follow-up CLI commands
                    // target the workspace the operator just created.
                    *state.active_peer.write().unwrap() = Some(resp.peer_id.clone());

                    // Auto-create an iroh-first invite. Direct bootstrap
                    // addresses are only embedded when the caller asks for
                    // them explicitly via `--public-addr`.
                    let mut resp_json = serde_json::to_value(&resp).unwrap();
                    if message_count > 0 {
                        resp_json["seeded_message_count"] = serde_json::json!(message_count);
                    }
                    if let Some(ref network_age) = network_age {
                        resp_json["network_age"] = serde_json::json!(network_age);
                    }
                    let relay_url = runtime_relay_url(state);
                    match workspace::commands::create_invite_for_peer(
                        db_path,
                        &resp.peer_id,
                        &[],
                        crate::event_modules::workspace::invite_link::DEFAULT_PORT,
                        None,
                        relay_url.as_deref(),
                    )
                    .map_err(|e| e.to_string())
                    {
                        Ok(invite) => {
                            if let Some(link) = serde_json::to_value(&invite)
                                .ok()
                                .and_then(|v| v["invite_link"].as_str().map(|s| s.to_string()))
                            {
                                let num = state.add_invite_ref(link);
                                resp_json["invite_link"] = serde_json::json!(invite.invite_link);
                                resp_json["invite_ref"] = serde_json::json!(num);
                            }
                        }
                        Err(e) => {
                            resp_json["invite_error"] = serde_json::json!(e);
                        }
                    }
                    let mut rpc_resp = RpcResponse::success(resp_json);
                    if let Ok((recorded_by, db)) = service::open_db_for_peer(db_path, &resp.peer_id)
                    {
                        if let Ok(list_resp) = service::svc_event_list_head(
                            &db,
                            &recorded_by,
                            CREATE_WORKSPACE_CREATED_EVENTS_CAP,
                        ) {
                            if let Some(ref mut data) = rpc_resp.data {
                                if let Ok(events_json) = serde_json::to_value(&list_resp.events) {
                                    data["created_events"] = events_json;
                                    data["created_events_cap"] =
                                        serde_json::json!(CREATE_WORKSPACE_CREATED_EVENTS_CAP);
                                }
                            }
                        }
                    }
                    state.notify_runtime_recheck();
                    rpc_resp
                }
                Err(e) => RpcResponse::error(e.to_string()),
            }
        }

        // ----- Commands that need active peer -----
        RpcMethod::Send {
            content,
            client_op_id,
        } => match state.require_active_peer() {
            Ok(peer_id) => match message::send_for_peer(db_path, &peer_id, &content) {
                Ok(data) => {
                    store_client_op(
                        db_path,
                        &peer_id,
                        client_op_id.as_deref(),
                        &data.event_id,
                        "message",
                    );
                    state.notify_runtime_recheck();
                    let eid = data.event_id.clone();
                    let mut resp = RpcResponse::success(data);
                    inject_created_events(&mut resp, db_path, &peer_id, &[&eid]);
                    resp
                }
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },
        RpcMethod::SendFile {
            content,
            file_path,
            add_bad_slices,
            client_op_id,
        } => match state.require_active_peer() {
            Ok(peer_id) => {
                match message::send_file_for_peer(
                    db_path,
                    &peer_id,
                    &content,
                    &file_path,
                    add_bad_slices,
                ) {
                    Ok(data) => {
                        store_client_op(
                            db_path,
                            &peer_id,
                            client_op_id.as_deref(),
                            &data.event_id,
                            "file",
                        );
                        state.notify_runtime_recheck();
                        let eid = data.event_id.clone();
                        let mut resp = RpcResponse::success(data);
                        inject_created_events(&mut resp, db_path, &peer_id, &[&eid]);
                        resp
                    }
                    Err(e) => RpcResponse::error(e.to_string()),
                }
            }
            Err(e) => RpcResponse::error(e),
        },
        RpcMethod::Files { limit } => {
            with_active_peer_db(
                state,
                |_peer_id, recorded_by, db| match file::queries::list_files(db, recorded_by, limit)
                {
                    Ok(data) => RpcResponse::success(data),
                    Err(e) => RpcResponse::error(e.to_string()),
                },
            )
        }
        RpcMethod::SaveFile {
            target,
            output_path,
        } => with_active_peer_db(state, |_peer_id, recorded_by, db| {
            match file::queries::save_file_by_selector(db, recorded_by, &target, &output_path) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            }
        }),
        RpcMethod::GenerateFiles { count, size_mib } => match state.require_active_peer() {
            Ok(peer_id) => {
                match message::generate_files_for_peer(db_path, &peer_id, count, size_mib) {
                    Ok(data) => {
                        state.notify_runtime_recheck();
                        RpcResponse::success(data)
                    }
                    Err(e) => RpcResponse::error(e.to_string()),
                }
            }
            Err(e) => RpcResponse::error(e),
        },
        RpcMethod::React {
            target,
            emoji,
            client_op_id,
        } => match state.require_active_peer() {
            Ok(peer_id) => match reaction::react_for_peer(db_path, &peer_id, &target, &emoji) {
                Ok(data) => {
                    store_client_op(
                        db_path,
                        &peer_id,
                        client_op_id.as_deref(),
                        &data.event_id,
                        "reaction",
                    );
                    state.notify_runtime_recheck();
                    let eid = data.event_id.clone();
                    let mut resp = RpcResponse::success(data);
                    inject_created_events(&mut resp, db_path, &peer_id, &[&eid]);
                    resp
                }
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },
        RpcMethod::DeleteMessage { target } => match state.require_active_peer() {
            Ok(peer_id) => match message::delete_message_for_peer(db_path, &peer_id, &target) {
                Ok(data) => {
                    state.notify_runtime_recheck();
                    RpcResponse::success(data)
                }
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },

        // ----- Read-only commands (call event modules directly) -----
        RpcMethod::TransportKeys => match crate::db::open_connection(db_path) {
            Ok(db) => {
                match crate::state::db::transport_creds::list_local_peers_with_source(&db) {
                    Ok(keys) => RpcResponse::success(serde_json::json!(keys)),
                    Err(e) => RpcResponse::error(e.to_string()),
                }
            }
            Err(e) => RpcResponse::error(e.to_string()),
        },
        RpcMethod::TransportAuth => with_active_peer_db(state, |_peer_id, recorded_by, db| {
            match crate::state::db::transport_trust::list_authorized_transport_rows(db, recorded_by)
            {
                Ok(rows) => RpcResponse::success(serde_json::json!(rows)),
                Err(e) => RpcResponse::error(e.to_string()),
            }
        }),
        RpcMethod::Messages { limit } => with_active_peer_db(state, |_peer_id, recorded_by, db| {
            match message::list(db, recorded_by, limit) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            }
        }),
        RpcMethod::Status => {
            let with_runtime_state = |data: workspace::StatusResponse| {
                let mut json = serde_json::to_value(data).unwrap_or(serde_json::Value::Null);
                json["daemon_db_path"] = serde_json::json!(db_path);
                json["runtime_state"] =
                    serde_json::json!(state.runtime_state.read().unwrap().as_str());
                if let Some(runtime) = runtime_status_value(state) {
                    json["runtime"] = runtime;
                }
                RpcResponse {
                    version: crate::rpc::protocol::PROTOCOL_VERSION,
                    ok: true,
                    error: None,
                    data: Some(json),
                }
            };

            match state.require_active_peer() {
                Ok(peer_id) => match service::open_existing_db_for_peer(db_path, &peer_id) {
                    Ok((recorded_by, db)) => {
                        let data = workspace::status(&db, &recorded_by);
                        with_runtime_state(data)
                    }
                    Err(e) => RpcResponse::error(e.to_string()),
                },
                Err(no_active_err) => match crate::db::open_connection(db_path) {
                    Ok(db) => {
                        let tenant_count: i64 = db
                            .query_row(
                                "SELECT COUNT(DISTINCT recorded_by) FROM invites_accepted",
                                [],
                                |row| row.get(0),
                            )
                            .unwrap_or(0);
                        if tenant_count > 1 {
                            // Multiple tenants, none selected — return error so
                            // operators know to run `topo tenant use`.
                            RpcResponse::error(no_active_err)
                        } else {
                            // Empty/pre-identity or single-tenant: return status
                            // with zeroed counters so health probes work.
                            let data = workspace::status(&db, "__idle__");
                            with_runtime_state(data)
                        }
                    }
                    Err(e) => RpcResponse::error(e.to_string()),
                },
            }
        }
        RpcMethod::GetTopoLogConfig => match crate::db::open_connection(db_path) {
            Ok(db) => {
                if let Err(e) = crate::db::schema::create_tables(&db) {
                    return RpcResponse::error(e.to_string());
                }
                match crate::state::db::topo_log::load_level(&db) {
                    Ok(level) => RpcResponse::success(serde_json::json!({
                        "level": level.as_str(),
                        "effective_now": crate::runtime::control::logging::topo_log_reload_is_active(),
                    })),
                    Err(e) => RpcResponse::error(e.to_string()),
                }
            }
            Err(e) => RpcResponse::error(e.to_string()),
        },
        RpcMethod::SetTopoLogLevel { level } => match crate::db::open_connection(db_path) {
            Ok(db) => {
                if let Err(e) = crate::db::schema::create_tables(&db) {
                    return RpcResponse::error(e.to_string());
                }
                let Some(level) = crate::state::db::topo_log::TopoLogLevel::from_str(&level) else {
                    return RpcResponse::error(format!(
                        "invalid topo log level `{}`; expected one of: error, warn, info, debug, trace",
                        level
                    ));
                };
                if let Err(e) = crate::state::db::topo_log::save_level(&db, level) {
                    return RpcResponse::error(e.to_string());
                }
                let iroh_log_mode = match crate::state::db::iroh_log::load_mode(&db) {
                    Ok(mode) => mode,
                    Err(e) => return RpcResponse::error(e.to_string()),
                };
                match crate::runtime::control::logging::reload_topo_log_level(level, iroh_log_mode)
                {
                    Ok(()) => RpcResponse::success(serde_json::json!({
                        "level": level.as_str(),
                        "effective_now": true,
                    })),
                    Err(e) => RpcResponse::error(e),
                }
            }
            Err(e) => RpcResponse::error(e.to_string()),
        },
        RpcMethod::ContentKeys { summary } => with_active_peer_db(
            state,
            |_peer_id, recorded_by, db| match workspace::content_keys(db, recorded_by, summary) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            },
        ),
        RpcMethod::RotateKey => match state.require_active_peer() {
            Ok(peer_id) => match workspace::commands::rotate_key_for_peer(db_path, &peer_id) {
                Ok(data) => {
                    state.notify_runtime_recheck();
                    RpcResponse::success(data)
                }
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },
        RpcMethod::AssertNow { predicate } => {
            // Use active tenant if selected, otherwise fall back to
            // transport-scope resolution so pre-workspace daemons work.
            let resolve = match state.require_active_peer() {
                Ok(peer_id) => service::open_db_for_peer(db_path, &peer_id),
                Err(_) => service::open_db_load(db_path),
            };
            match resolve {
                Ok((recorded_by, db)) => match crate::assert::parse_predicate(&predicate) {
                    Ok((field, op, expected)) => {
                        match crate::assert::query_field(&db, &field, &recorded_by) {
                            Ok(actual) => RpcResponse::success(crate::assert::AssertResponse {
                                pass: op.eval(actual, expected),
                                field,
                                actual,
                                op: op.symbol().to_string(),
                                expected,
                                timed_out: false,
                                debug: None,
                            }),
                            Err(e) => RpcResponse::error(e),
                        }
                    }
                    Err(e) => RpcResponse::error(e),
                },
                Err(e) => RpcResponse::error(e.to_string()),
            }
        }
        RpcMethod::AssertEventually {
            predicate,
            timeout_ms,
            interval_ms,
        } => {
            // Use active tenant if selected, otherwise fall back to
            // transport-scope resolution so pre-workspace daemons work.
            match state.require_active_peer() {
                Ok(peer_id) => match crate::assert::assert_eventually_for_peer(
                    db_path,
                    &peer_id,
                    &predicate,
                    timeout_ms,
                    interval_ms,
                ) {
                    Ok(data) => RpcResponse::success(data),
                    Err(e) => RpcResponse::error(e.to_string()),
                },
                Err(_) => {
                    match crate::assert::assert_eventually(
                        db_path,
                        &predicate,
                        timeout_ms,
                        interval_ms,
                    ) {
                        Ok(data) => RpcResponse::success(data),
                        Err(e) => RpcResponse::error(e.to_string()),
                    }
                }
            }
        }
        RpcMethod::Reactions => with_active_peer_db(state, |_peer_id, recorded_by, db| {
            match reaction::list(db, recorded_by) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            }
        }),
        RpcMethod::Users => with_active_peer_db(state, |_peer_id, recorded_by, db| {
            match user::list_items(db, recorded_by) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            }
        }),
        RpcMethod::Keys { summary } => with_active_peer_db(state, |_peer_id, recorded_by, db| {
            match workspace::keys(db, recorded_by, summary) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            }
        }),
        RpcMethod::Peers => {
            with_active_peer_db(
                state,
                |_peer_id, recorded_by, db| match peer_shared::list_peers(db, recorded_by) {
                    Ok(data) => RpcResponse::success(data),
                    Err(e) => RpcResponse::error(e.to_string()),
                },
            )
        }
        RpcMethod::Workspaces => match crate::db::open_connection(db_path) {
            Ok(db) => {
                match workspace::list_all_items(&db) {
                    Ok(data) => RpcResponse::success(data),
                    Err(e) => RpcResponse::error(e.to_string()),
                }
            }
            Err(e) => RpcResponse::error(e.to_string()),
        },
        RpcMethod::CreateInvite {
            public_addr,
            public_spki,
        } => match state.require_active_peer() {
            Ok(peer_id) => {
                let explicit_addrs: Vec<
                    crate::event_modules::workspace::invite_link::BootstrapAddress,
                > = match public_addr {
                    Some(ref addr) => {
                        match crate::event_modules::workspace::invite_link::parse_bootstrap_address(
                            addr,
                        ) {
                            Ok(a) => vec![a],
                            Err(e) => {
                                return RpcResponse::error(format!("invalid public_addr: {}", e));
                            }
                        }
                    }
                    None => vec![],
                };
                let relay_url = runtime_relay_url_for_bootstrap(state);
                let result: Result<
                    workspace::commands::CreateInviteResponse,
                    Box<dyn std::error::Error + Send + Sync>,
                > = workspace::commands::create_invite_for_peer(
                    db_path,
                    &peer_id,
                    &explicit_addrs,
                    crate::event_modules::workspace::invite_link::DEFAULT_PORT,
                    public_spki.as_deref(),
                    relay_url.as_deref(),
                );
                match result {
                    Ok(data) => {
                        let invite_eid_b64 = data.invite_event_id.clone();
                        let mut resp = if let Some(link) = serde_json::to_value(&data)
                            .ok()
                            .and_then(|v| v["invite_link"].as_str().map(|s| s.to_string()))
                        {
                            let num = state.add_invite_ref(link);
                            let mut resp_data = serde_json::to_value(&data).unwrap();
                            resp_data["invite_ref"] = serde_json::json!(num);
                            RpcResponse::success(resp_data)
                        } else {
                            RpcResponse::success(data)
                        };
                        // Inject created_events for the invite event.
                        if let Ok((rb, db)) = service::open_db_for_peer(db_path, &peer_id) {
                            if let Ok(lr) =
                                service::svc_event_list_by_ids(&db, &rb, &[invite_eid_b64])
                            {
                                if let Some(ref mut d) = resp.data {
                                    if let Ok(v) = serde_json::to_value(&lr.events) {
                                        d["created_events"] = v;
                                    }
                                }
                            }
                        }
                        resp
                    }
                    Err(e) => RpcResponse::error(e.to_string()),
                }
            }
            Err(e) => RpcResponse::error(e),
        },
        RpcMethod::CreateDeviceLink {
            public_addr,
            public_spki,
        } => {
            match state.require_active_peer() {
                Ok(peer_id) => {
                    let explicit_addrs: Vec<crate::event_modules::workspace::invite_link::BootstrapAddress> =
                    match public_addr {
                        Some(ref addr) => {
                            match crate::event_modules::workspace::invite_link::parse_bootstrap_address(addr) {
                                Ok(a) => vec![a],
                                Err(e) => return RpcResponse::error(format!("invalid public_addr: {}", e)),
                            }
                        }
                        None => vec![],
                    };
                    let relay_url = runtime_relay_url_for_bootstrap(state);
                    match workspace::commands::create_device_link_for_peer(
                        db_path,
                        &peer_id,
                        &explicit_addrs,
                        crate::event_modules::workspace::invite_link::DEFAULT_PORT,
                        public_spki.as_deref(),
                        relay_url.as_deref(),
                    ) {
                        Ok(data) => {
                            let invite_eid_b64 = data.invite_event_id.clone();
                            let mut resp = if let Some(link) = serde_json::to_value(&data)
                                .ok()
                                .and_then(|v| v["invite_link"].as_str().map(|s| s.to_string()))
                            {
                                let num = state.add_invite_ref(link);
                                let mut resp_data = serde_json::to_value(&data).unwrap();
                                resp_data["invite_ref"] = serde_json::json!(num);
                                RpcResponse::success(resp_data)
                            } else {
                                RpcResponse::success(data)
                            };
                            if let Ok((rb, db)) = service::open_db_for_peer(db_path, &peer_id) {
                                if let Ok(lr) =
                                    service::svc_event_list_by_ids(&db, &rb, &[invite_eid_b64])
                                {
                                    if let Some(ref mut d) = resp.data {
                                        if let Ok(v) = serde_json::to_value(&lr.events) {
                                            d["created_events"] = v;
                                        }
                                    }
                                }
                            }
                            resp
                        }
                        Err(e) => RpcResponse::error(e.to_string()),
                    }
                }
                Err(e) => RpcResponse::error(e),
            }
        }
        RpcMethod::AcceptLink { invite, devicename } => {
            let resolved = match state.resolve_invite_ref(&invite) {
                Ok(link) => link,
                Err(e) => return RpcResponse::error(e),
            };
            match workspace::commands::accept_device_link(db_path, &resolved, &devicename) {
                Ok(data) => {
                    let pid = data.peer_id.clone();
                    *state.active_peer.write().unwrap() = Some(pid.clone());
                    state.notify_runtime_recheck();
                    let mut resp = RpcResponse::success(data);
                    if let Ok((recorded_by, db)) = service::open_db_for_peer(db_path, &pid) {
                        if let Ok(list_resp) = service::svc_event_list(&db, &recorded_by) {
                            if let Some(ref mut d) = resp.data {
                                if let Ok(v) = serde_json::to_value(&list_resp.events) {
                                    d["created_events"] = v;
                                }
                            }
                        }
                    }
                    resp
                }
                Err(e) => RpcResponse::error(e.to_string()),
            }
        }
        RpcMethod::Identity => {
            with_active_peer_db(
                state,
                |peer_id, _recorded_by, db| match peer_shared::identity(db, peer_id) {
                    Ok(data) => RpcResponse::success(data),
                    Err(e) => RpcResponse::error(e.to_string()),
                },
            )
        }
        RpcMethod::AcceptInvite {
            invite,
            username,
            devicename,
        } => match workspace::commands::accept_invite(db_path, &invite, &username, &devicename) {
            Ok(data) => {
                let pid = data.peer_id.clone();
                *state.active_peer.write().unwrap() = Some(pid.clone());
                state.notify_runtime_recheck();
                let mut resp = RpcResponse::success(data);
                if let Ok((recorded_by, db)) = service::open_db_for_peer(db_path, &pid) {
                    if let Ok(list_resp) = service::svc_event_list(&db, &recorded_by) {
                        if let Some(ref mut d) = resp.data {
                            if let Ok(v) = serde_json::to_value(&list_resp.events) {
                                d["created_events"] = v;
                            }
                        }
                    }
                }
                resp
            }
            Err(e) => RpcResponse::error(e.to_string()),
        },
        RpcMethod::View { limit } => match state.require_active_peer() {
            Ok(peer_id) => match workspace::view_for_peer(db_path, &peer_id, limit) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },
        RpcMethod::SyncRoundPeer { peer } => match state.require_active_peer() {
            Ok(tenant_id) => match state.sync_control.trigger_round_for_peer(&tenant_id, &peer) {
                Ok(capture) => RpcResponse::success(capture),
                Err(e) => RpcResponse::error(e),
            },
            Err(e) => RpcResponse::error(e),
        },

        RpcMethod::SyncRoundAll => match state.require_active_peer() {
            Ok(tenant_id) => match state.sync_control.trigger_round_for_all(&tenant_id) {
                Ok(captures) => RpcResponse::success(captures),
                Err(e) => RpcResponse::error(e),
            },
            Err(e) => RpcResponse::error(e),
        },

        RpcMethod::LiveSessions => match state.require_active_peer() {
            Ok(peer_id) => RpcResponse::success(crate::runtime::peering::loops::live_session_peer_ids(
                db_path,
                &peer_id,
            )),
            Err(e) => RpcResponse::error(e),
        },

        RpcMethod::EventBlocked => match state.require_active_peer() {
            Ok(peer_id) => match service::open_db_for_peer(db_path, &peer_id) {
                Ok((recorded_by, db)) => {
                    let mut stmt = db
                        .prepare(
                            "SELECT event_id, blocker_event_id, dep_relationship
                             FROM blocked_event_deps
                             WHERE peer_id = ?1
                             ORDER BY event_id",
                        )
                        .unwrap();
                    let rows = stmt
                        .query_map(rusqlite::params![&recorded_by], |row| {
                            Ok(serde_json::json!({
                                "event_id": row.get::<_, String>(0)?,
                                "blocker_event_id": row.get::<_, String>(1)?,
                                "dep": row.get::<_, String>(2)?,
                            }))
                        })
                        .unwrap()
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap_or_default();
                    RpcResponse::success(rows)
                }
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },

        RpcMethod::EventTimeline { event_id } => match state.require_active_peer() {
            Ok(peer_id) => match service::open_db_for_peer(db_path, &peer_id) {
                Ok((_recorded_by, db)) => {
                    let tl = crate::db::timeline::EventTimeline::new(&db);
                    match tl.load(&event_id) {
                        Ok(Some(row)) => RpcResponse::success(serde_json::json!({
                            "event_id": row.event_id,
                            "first_received_at_ms": row.first_received_at,
                            "first_stored_at_ms": row.first_stored_at,
                            "blocked_at_ms": row.blocked_at,
                            "unblocked_at_ms": row.unblocked_at,
                            "unblocked_by_event_id": row.unblocked_by_event_id,
                            "projected_at_ms": row.projected_at,
                        })),
                        Ok(None) => {
                            RpcResponse::error(format!("no timeline entry for event {}", event_id))
                        }
                        Err(e) => RpcResponse::error(e.to_string()),
                    }
                }
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },

        RpcMethod::EventTimelineReport { content_prefix, limit } => match state.require_active_peer() {
            Ok(peer_id) => match service::open_existing_db_for_peer(db_path, &peer_id) {
                Ok((recorded_by, db)) => match build_event_timeline_report(&db, &recorded_by, content_prefix.as_deref(), limit) {
                    Ok(report) => RpcResponse::success(report),
                    Err(e) => RpcResponse::error(e.to_string()),
                },
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },

        RpcMethod::Stats => match state.require_active_peer() {
            Ok(peer_id) => match service::open_db_for_peer(db_path, &peer_id) {
                Ok((recorded_by, db)) => {
                    let count = |sql: &str, param: &str| -> i64 {
                        db.query_row(sql, rusqlite::params![param], |r| r.get(0))
                            .unwrap_or(0)
                    };
                    let resp = serde_json::json!({
                        "message_count": message::count(&db, &recorded_by).unwrap_or(0),
                        "reaction_count": reaction::count(&db, &recorded_by).unwrap_or(0),
                        "deleted_message_count": count("SELECT COUNT(*) FROM deleted_messages WHERE recorded_by = ?1", &recorded_by),
                        "user_count": user::count(&db, &recorded_by).unwrap_or(0),
                        "peer_count": peer_shared::count(&db, &recorded_by).unwrap_or(0),
                        "admin_count": crate::event_modules::admin::count(&db, &recorded_by).unwrap_or(0),
                        "workspace_count": count("SELECT COUNT(*) FROM workspaces WHERE recorded_by = ?1", &recorded_by),
                        "user_invite_count": count("SELECT COUNT(*) FROM user_invites WHERE recorded_by = ?1", &recorded_by),
                        "device_invite_count": count("SELECT COUNT(*) FROM device_invites WHERE recorded_by = ?1", &recorded_by),
                        "key_secret_count": count("SELECT COUNT(*) FROM key_secrets WHERE recorded_by = ?1", &recorded_by),
                        "event_count": db.query_row("SELECT COUNT(*) FROM events", [], |r| r.get::<_, i64>(0)).unwrap_or(0),
                        "recorded_event_count": count("SELECT COUNT(*) FROM recorded_events WHERE peer_id = ?1", &recorded_by),
                        "valid_event_count": count("SELECT COUNT(*) FROM valid_events WHERE peer_id = ?1", &recorded_by),
                        "blocked_event_count": crate::db::health::blocked_event_count(&db, &recorded_by).unwrap_or(0),
                        "rejected_event_count": count("SELECT COUNT(*) FROM rejected_events WHERE peer_id = ?1", &recorded_by),
                        "endpoint_observation_count": count("SELECT COUNT(*) FROM peer_endpoint_observations WHERE recorded_by = ?1", &recorded_by),
                    });
                    RpcResponse::success(resp)
                }
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },

        RpcMethod::Replay { pass } => match state.require_active_peer() {
            Ok(peer_id) => match service::open_db_for_peer(db_path, &peer_id) {
                Ok((recorded_by, db)) => {
                    match crate::testutil::run_replay_pass(&db, &recorded_by, &pass) {
                        Ok(result) => RpcResponse::success(result),
                        Err(e) => RpcResponse::error(e),
                    }
                }
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },

        RpcMethod::Connections => match state.require_active_peer() {
            Ok(peer_id) => match service::open_db_for_peer(db_path, &peer_id) {
                Ok((recorded_by, db)) => {
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as i64;
                    match crate::db::health::list_live_endpoint_targets(&db, &recorded_by, now_ms) {
                        Ok(targets) => {
                            let items: Vec<serde_json::Value> = targets
                                .into_iter()
                                .map(|t| {
                                    serde_json::json!({
                                        "peer_id": t.via_peer_id,
                                        "addr": format!("{}:{}", t.origin_ip, t.origin_port),
                                    })
                                })
                                .collect();
                            RpcResponse::success(items)
                        }
                        Err(e) => RpcResponse::error(e.to_string()),
                    }
                }
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },

        #[cfg(feature = "discovery")]
        RpcMethod::Discover { timeout_ms } => {
            let Some(endpoint) = state.runtime_endpoint() else {
                return RpcResponse::error("runtime not active — no live iroh endpoint");
            };
            let Some(mdns) = endpoint.mdns_lookup() else {
                return RpcResponse::error("mDNS discovery is disabled for this daemon");
            };
            let db = match crate::db::open_connection(db_path) {
                Ok(db) => db,
                Err(e) => return RpcResponse::error(e.to_string()),
            };

            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => return RpcResponse::error(format!("failed to start runtime: {}", e)),
            };

            use tokio_stream::StreamExt;
            let local_daemon_peer_id = endpoint.daemon_peer_id();
            let result = rt.block_on(async move {
                let mut events = mdns.subscribe().await;
                let deadline =
                    tokio::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
                let mut discovered = std::collections::BTreeMap::new();
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep_until(deadline) => break,
                        event = events.next() => match event {
                            Some(iroh::address_lookup::DiscoveryEvent::Discovered { endpoint_info, .. }) => {
                                let daemon_peer_id = hex::encode(endpoint_info.endpoint_id.as_bytes());
                                if daemon_peer_id != local_daemon_peer_id {
                                    discovered.insert(daemon_peer_id, endpoint_info);
                                }
                            }
                            Some(iroh::address_lookup::DiscoveryEvent::Expired { endpoint_id }) => {
                                discovered.remove(&hex::encode(endpoint_id.as_bytes()));
                            }
                            None => break,
                        }
                    }
                }
                discovered
            });

            let mut results = Vec::new();
            for (daemon_peer_id, endpoint_info) in result {
                let addrs: Vec<String> =
                    endpoint_info.ip_addrs().map(ToString::to_string).collect();
                let primary = endpoint_info.ip_addrs().next().copied();
                let (local_tenant_ids, shared_workspace_ids, known_peer_ids) =
                    match daemon_scope_annotations(&db, &daemon_peer_id) {
                        Ok(scopes) => scopes,
                        Err(e) => return RpcResponse::error(e.to_string()),
                    };
                results.push(serde_json::json!({
                    "peer_id": daemon_peer_id,
                    "daemon_peer_id": daemon_peer_id,
                    "addr": primary.map(|addr| addr.ip().to_string()).unwrap_or_default(),
                    "port": primary.map(|addr| addr.port()).unwrap_or_default(),
                    "addrs": addrs,
                    "local_tenant_ids": local_tenant_ids,
                    "shared_workspace_ids": shared_workspace_ids,
                    "known_peer_ids": known_peer_ids,
                }));
            }
            RpcResponse::success(results)
        }

        RpcMethod::EventList => match crate::db::open_connection(db_path) {
            Ok(db) => {
                let scopes = match discover_tenant_scopes(&db) {
                    Ok(s) => s,
                    Err(e) => return RpcResponse::error(e.to_string()),
                };
                if scopes.is_empty() {
                    return RpcResponse::success(service::EventListResponse { events: vec![] });
                }
                let recorded_by = match state.require_active_peer() {
                    Ok(peer_id) => peer_id,
                    Err(e) => return RpcResponse::error(e),
                };
                match service::svc_event_list(&db, &recorded_by) {
                    Ok(data) => RpcResponse::success(data),
                    Err(e) => RpcResponse::error(e.to_string()),
                }
            }
            Err(e) => RpcResponse::error(e.to_string()),
        },
        RpcMethod::EventListByIds { ids } => {
            with_active_peer_db(state, |_peer_id, recorded_by, db| {
                match service::svc_event_list_by_ids(db, recorded_by, &ids) {
                    Ok(data) => RpcResponse::success(data),
                    Err(e) => RpcResponse::error(e.to_string()),
                }
            })
        }
        RpcMethod::EventShow { prefix } => with_active_peer_db(
            state,
            |_peer_id, recorded_by, db| match service::svc_event_show(db, recorded_by, &prefix) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            },
        ),
        RpcMethod::EventDeps { prefix, depth } => with_active_peer_db(
            state,
            |_peer_id, recorded_by, db| match service::svc_event_deps(
                db,
                recorded_by,
                &prefix,
                depth,
            ) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            },
        ),

        // ----- Subscription commands -----
        RpcMethod::SubCreate {
            name,
            event_type,
            delivery_mode,
            spec_json,
        } => match state.require_active_peer() {
            Ok(peer_id) => {
                // P2: Reject unsupported event types early.
                if !subscriptions::is_supported_event_type(&event_type) {
                    return RpcResponse::error(format!(
                        "unsupported event type '{}'; supported: {}",
                        event_type,
                        subscriptions::supported_event_types().join(", "),
                    ));
                }

                let dm = match subscriptions::DeliveryMode::from_str(&delivery_mode) {
                    Ok(d) => d,
                    Err(e) => return RpcResponse::error(e),
                };
                let mut spec: subscriptions::SubscriptionSpec = if spec_json.is_empty() {
                    subscriptions::SubscriptionSpec {
                        event_type: event_type.clone(),
                        since: None,
                        filters: vec![],
                    }
                } else {
                    match serde_json::from_str(&spec_json) {
                        Ok(s) => s,
                        Err(e) => return RpcResponse::error(format!("invalid spec: {}", e)),
                    }
                };

                // Enforce spec.event_type matches the top-level event_type arg.
                if spec.event_type != event_type {
                    return RpcResponse::error(format!(
                        "spec.event_type '{}' does not match event_type '{}'",
                        spec.event_type, event_type,
                    ));
                }

                // P2b: Validate filter fields and operators against the matcher.
                if let Err(e) = subscriptions::validate_spec(&event_type, &spec) {
                    return RpcResponse::error(format!("invalid spec: {}", e));
                }

                // Normalize since.event_id: accept hex (from CLI) and convert to base64
                // (which is the internal storage format in the events table).
                if let Some(ref mut since) = spec.since {
                    if !since.event_id.is_empty() {
                        // If it looks like hex (64 hex chars = 32 bytes), convert to base64.
                        if since.event_id.len() == 64
                            && since.event_id.chars().all(|c| c.is_ascii_hexdigit())
                        {
                            if let Some(eid) = crate::crypto::event_id_from_hex(&since.event_id) {
                                since.event_id = crate::crypto::event_id_to_base64(&eid);
                            }
                        }
                    }
                }

                // P1: Resolve since_event_id to its created_at_ms when not provided.
                if let Some(ref mut since) = spec.since {
                    if !since.event_id.is_empty() && since.created_at_ms == 0 {
                        match service::open_db_for_peer(db_path, &peer_id) {
                            Ok((_rb, ref db)) => {
                                match subscriptions::resolve_event_created_at(db, &since.event_id) {
                                    Ok(ts) => since.created_at_ms = ts,
                                    Err(e) => {
                                        return RpcResponse::error(format!(
                                            "cannot resolve since_event_id '{}': {}",
                                            since.event_id, e
                                        ));
                                    }
                                }
                            }
                            Err(e) => {
                                return RpcResponse::error(format!(
                                    "cannot resolve since_event_id: {}",
                                    e
                                ));
                            }
                        }
                    }
                }

                match service::open_db_for_peer(db_path, &peer_id) {
                    Ok((recorded_by, db)) => {
                        match subscriptions::create_subscription(
                            &db,
                            &recorded_by,
                            &name,
                            &event_type,
                            dm,
                            &spec,
                        ) {
                            Ok(sub) => RpcResponse::success(sub),
                            Err(e) => RpcResponse::error(e),
                        }
                    }
                    Err(e) => RpcResponse::error(e.to_string()),
                }
            }
            Err(e) => RpcResponse::error(e),
        },
        RpcMethod::SubList => with_active_peer_db(state, |_peer_id, recorded_by, db| {
            match subscriptions::list_subscriptions(db, recorded_by) {
                Ok(subs) => RpcResponse::success(subs),
                Err(e) => RpcResponse::error(e),
            }
        }),
        RpcMethod::SubDisable { subscription_id } => with_active_peer_db(
            state,
            |_peer_id, recorded_by, db| match subscriptions::set_enabled(
                db,
                recorded_by,
                &subscription_id,
                false,
            ) {
                Ok(()) => RpcResponse::success(serde_json::json!({"disabled": true})),
                Err(e) => RpcResponse::error(e),
            },
        ),
        RpcMethod::SubEnable { subscription_id } => with_active_peer_db(
            state,
            |_peer_id, recorded_by, db| match subscriptions::set_enabled(
                db,
                recorded_by,
                &subscription_id,
                true,
            ) {
                Ok(()) => RpcResponse::success(serde_json::json!({"enabled": true})),
                Err(e) => RpcResponse::error(e),
            },
        ),
        RpcMethod::SubPoll {
            subscription_id,
            after_seq,
            limit,
        } => with_active_peer_db(
            state,
            |_peer_id, recorded_by, db| match subscriptions::poll_feed(
                db,
                recorded_by,
                &subscription_id,
                after_seq,
                limit,
            ) {
                Ok(items) => RpcResponse::success(items),
                Err(e) => RpcResponse::error(e),
            },
        ),
        RpcMethod::SubAck {
            subscription_id,
            through_seq,
        } => with_active_peer_db(
            state,
            |_peer_id, recorded_by, db| match subscriptions::ack_feed(
                db,
                recorded_by,
                &subscription_id,
                through_seq,
            ) {
                Ok(()) => RpcResponse::success(serde_json::json!({"acked": true})),
                Err(e) => RpcResponse::error(e),
            },
        ),
        RpcMethod::SubState { subscription_id } => with_active_peer_db(
            state,
            |_peer_id, recorded_by, db| match subscriptions::get_state(
                db,
                recorded_by,
                &subscription_id,
            ) {
                Ok(state) => RpcResponse::success(state),
                Err(e) => RpcResponse::error(e),
            },
        ),
    }
}

/// Invoke the real RPC dispatch path in-process without Unix socket framing.
///
/// This is the seam used by virtual-daemon tests and simulator control code.
pub fn dispatch_rpc_method(state: &DaemonState, method: RpcMethod) -> RpcResponse {
    let shutdown = std::sync::atomic::AtomicBool::new(false);
    let shutdown_notify = tokio::sync::Notify::new();
    dispatch(state, method, &shutdown, &shutdown_notify)
}
