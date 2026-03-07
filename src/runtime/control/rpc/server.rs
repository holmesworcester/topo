//! RPC server: Unix domain socket listener that dispatches requests to service functions.
//!
//! Connection count is bounded by a semaphore to prevent local connection-flood
//! pressure (feedback item 2).

use std::collections::HashSet;
use std::io::Write;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, RwLock};

use serde::Serialize;
use tokio::sync::Notify;
use tracing::{info, warn};

use crate::event_modules::{file, message, peer_shared, reaction, user, workspace};
use crate::node::NodeRuntimeNetInfo;
use crate::rpc::protocol::*;
use crate::service;
use crate::state::subscriptions;

/// Maximum concurrent RPC connections the server will handle.
/// Additional connections block until a slot is freed.
const MAX_CONCURRENT_CONNECTIONS: usize = 64;

#[derive(Debug, Clone)]
struct TenantScope {
    peer_id: String,
    workspace_id: String,
}

fn discover_tenant_scopes(
    conn: &rusqlite::Connection,
) -> Result<Vec<TenantScope>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT recorded_by, workspace_id
         FROM invites_accepted
         ORDER BY recorded_by",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok(TenantScope {
                peer_id: row.get(0)?,
                workspace_id: row.get(1)?,
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
    /// Runtime networking info (listen addr, UPnP result). Set once the
    /// QUIC endpoint is bound; UPnP result is populated while UPnP mode is enabled.
    pub runtime_net: RwLock<Option<NodeRuntimeNetInfo>>,
    /// The daemon's resolved bind address, set early at daemon start before
    /// any tenants exist.
    pub bind_addr: RwLock<Option<std::net::SocketAddr>>,
    /// Whether runtime-managed UPnP mode is enabled for this daemon session.
    pub upnp_enabled: RwLock<bool>,
    /// Last UPnP mapping report for the active runtime session.
    pub upnp_result: RwLock<Option<crate::peering::nat::upnp::UpnpMappingReport>>,
    /// Wake-up trigger for runtime state reevaluation after tenant-changing commands.
    pub runtime_recheck: Notify,
    /// Invite/link strings stored by number (index+1 = invite ref number).
    pub invite_refs: RwLock<Vec<String>>,
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
                let _ = crate::db::schema::create_tables(&conn);
                match discover_tenant_scopes(&conn) {
                    Ok(tenants) if tenants.len() == 1 => Some(tenants[0].peer_id.clone()),
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
            bind_addr: RwLock::new(None),
            upnp_enabled: RwLock::new(false),
            upnp_result: RwLock::new(None),
            runtime_recheck: Notify::new(),
            invite_refs: RwLock::new(Vec::new()),
        }
    }

    pub fn notify_runtime_recheck(&self) {
        self.runtime_recheck.notify_waiters();
    }

    fn require_active_peer(&self) -> Result<String, String> {
        let cached = self.active_peer.read().unwrap().clone();

        // Discover current tenant scopes from invites_accepted projection state.
        // This keeps control-plane tenant selection independent from transport creds.
        let discovered = if let Ok(conn) = crate::db::open_connection(&self.db_path) {
            let _ = crate::db::schema::create_tables(&conn);
            discover_tenant_scopes(&conn).ok()
        } else {
            None
        };

        if let Some(peer_id) = cached {
            match discovered.as_ref() {
                Some(tenants) => {
                    if tenants.iter().any(|t| t.peer_id == peer_id) {
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
                let peer_id = tenants[0].peer_id.clone();
                *self.active_peer.write().unwrap() = Some(peer_id.clone());
                return Ok(peer_id);
            }
        }

        Err("no active tenant — run `topo use-tenant <N>`".to_string())
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

/// Tenant info returned by the Tenants command.
#[derive(Debug, Serialize)]
struct TenantItem {
    index: usize,
    peer_id: String,
    workspace_id: String,
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

fn resolve_bootstrap_from_upnp(
    upnp: &crate::peering::nat::upnp::UpnpMappingReport,
) -> Result<String, String> {
    if upnp.status != crate::peering::nat::upnp::UpnpMappingStatus::Success {
        let status = match &upnp.status {
            crate::peering::nat::upnp::UpnpMappingStatus::Success => "success",
            crate::peering::nat::upnp::UpnpMappingStatus::Failed => "failed",
            crate::peering::nat::upnp::UpnpMappingStatus::NotAttempted => "not_attempted",
        };
        let reason = upnp.error.as_deref().unwrap_or("unknown");
        return Err(format!(
            "no bootstrap address — UPnP status is {} ({}) — provide --bootstrap or run `topo upnp` first",
            status, reason
        ));
    }

    let (ip, port) = match (upnp.external_ip.as_deref(), upnp.mapped_external_port) {
        (Some(ip), Some(port)) => (ip, port),
        _ => {
            return Err(
                "no bootstrap address — provide --bootstrap or run `topo upnp` first".to_string(),
            )
        }
    };

    let parsed_ip: std::net::IpAddr = ip.parse().map_err(|_| {
        format!(
            "UPnP external IP is malformed ({}) — provide --bootstrap explicitly",
            ip
        )
    })?;
    if !crate::peering::nat::upnp::is_public_internet_ip(parsed_ip) {
        return Err(format!(
            "UPnP external IP {} is not publicly routable — provide --bootstrap explicitly",
            ip
        ));
    }

    Ok(std::net::SocketAddr::new(parsed_ip, port).to_string())
}

fn upnp_response_data(
    enabled: bool,
    report: Option<&crate::peering::nat::upnp::UpnpMappingReport>,
    fallback_error: &str,
) -> serde_json::Value {
    let mut data = serde_json::Map::new();
    data.insert("enabled".into(), serde_json::Value::Bool(enabled));
    if let Some(report) = report {
        if let Ok(serde_json::Value::Object(fields)) = serde_json::to_value(report) {
            for (key, value) in fields {
                data.insert(key, value);
            }
        }
    } else {
        data.insert("status".into(), serde_json::json!("not_attempted"));
        data.insert("error".into(), serde_json::json!(fallback_error));
    }
    serde_json::Value::Object(data)
}

fn merge_upnp_bootstrap_addr(
    mut addrs: Vec<crate::event_modules::workspace::invite_link::BootstrapAddress>,
    upnp: Option<&crate::peering::nat::upnp::UpnpMappingReport>,
) -> Vec<crate::event_modules::workspace::invite_link::BootstrapAddress> {
    let mut seen: HashSet<String> = addrs
        .iter()
        .map(|addr| addr.to_bootstrap_addr_string())
        .collect();
    if let Some(report) = upnp {
        match resolve_bootstrap_from_upnp(report) {
            Ok(addr) => {
                match crate::event_modules::workspace::invite_link::parse_bootstrap_address(&addr) {
                    Ok(parsed) => {
                        let key = parsed.to_bootstrap_addr_string();
                        if seen.insert(key) {
                            addrs.push(parsed);
                        }
                    }
                    Err(e) => warn!("ignoring invalid UPnP bootstrap address {}: {}", addr, e),
                }
            }
            Err(e) if report.status == crate::peering::nat::upnp::UpnpMappingStatus::Success => {
                warn!("ignoring unusable UPnP mapping result: {}", e);
            }
            Err(_) => {}
        }
    }
    addrs
}

fn autodetect_bootstrap_addrs(
    state: &DaemonState,
    listen_port: u16,
) -> Result<Vec<crate::event_modules::workspace::invite_link::BootstrapAddress>, String> {
    let detected =
        crate::event_modules::workspace::invite_link::detect_bootstrap_addrs(listen_port);
    let merged = merge_upnp_bootstrap_addr(detected, state.upnp_result.read().unwrap().as_ref());
    if merged.is_empty() {
        return Err(
            "No non-loopback addresses detected and no active UPnP address available. Provide public_addr explicitly."
                .to_string(),
        );
    }
    Ok(merged)
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
        RpcMethod::Tenants => {
            match crate::db::open_connection(db_path) {
                Ok(conn) => {
                    let _ = crate::db::schema::create_tables(&conn);
                    match discover_tenant_scopes(&conn) {
                        Ok(scopes) => {
                            let active = state.active_peer.read().unwrap().clone();
                            let mut items: Vec<TenantItem> = scopes
                                .iter()
                                .enumerate()
                                .map(|(i, t)| TenantItem {
                                    index: i + 1,
                                    peer_id: t.peer_id.clone(),
                                    workspace_id: t.workspace_id.clone(),
                                    active: active.as_deref() == Some(&t.peer_id),
                                })
                                .collect();
                            items.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));
                            // Re-number after sort
                            for (i, item) in items.iter_mut().enumerate() {
                                item.index = i + 1;
                            }
                            RpcResponse::success(serde_json::json!(items))
                        }
                        Err(e) => RpcResponse::error(e.to_string()),
                    }
                }
                Err(e) => RpcResponse::error(e.to_string()),
            }
        }

        RpcMethod::UseTenant { index } => match crate::db::open_connection(db_path) {
            Ok(conn) => {
                let _ = crate::db::schema::create_tables(&conn);
                match discover_tenant_scopes(&conn) {
                    Ok(scopes) => {
                        if index == 0 || index > scopes.len() {
                            return RpcResponse::error(format!(
                                "invalid tenant number {}; available: 1-{}",
                                index,
                                scopes.len()
                            ));
                        }
                        let tenant = &scopes[index - 1];
                        *state.active_peer.write().unwrap() = Some(tenant.peer_id.clone());
                        RpcResponse::success(serde_json::json!({
                            "peer_id": tenant.peer_id,
                            "workspace_id": tenant.workspace_id,
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
        } => {
            match workspace::commands::create_workspace_for_db(
                db_path,
                &workspace_name,
                &username,
                &device_name,
            ) {
                Ok(resp) => {
                    // Auto-select newly created peer if none active
                    let mut ap = state.active_peer.write().unwrap();
                    if ap.is_none() {
                        *ap = Some(resp.peer_id.clone());
                    }
                    drop(ap);
                    state.notify_runtime_recheck();

                    // Auto-create an invite with detected IPs
                    let listen_port = state
                        .runtime_net
                        .read()
                        .unwrap()
                        .as_ref()
                        .and_then(|ni| ni.listen_addr.parse::<std::net::SocketAddr>().ok())
                        .map(|sa| sa.port())
                        .unwrap_or(crate::event_modules::workspace::invite_link::DEFAULT_PORT);
                    let mut resp_json = serde_json::to_value(&resp).unwrap();
                    let bootstrap_addrs = autodetect_bootstrap_addrs(state, listen_port);
                    match bootstrap_addrs.and_then(|addrs| {
                        workspace::commands::create_invite_for_db(db_path, &addrs, listen_port)
                            .map_err(|e| e.to_string())
                    }) {
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
                    RpcResponse::success(resp_json)
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
                    RpcResponse::success(data)
                }
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },
        RpcMethod::SendFile {
            content,
            file_path,
            client_op_id,
        } => match state.require_active_peer() {
            Ok(peer_id) => {
                match message::send_file_for_peer(db_path, &peer_id, &content, &file_path) {
                    Ok(data) => {
                        store_client_op(
                            db_path,
                            &peer_id,
                            client_op_id.as_deref(),
                            &data.event_id,
                            "file",
                        );
                        RpcResponse::success(data)
                    }
                    Err(e) => RpcResponse::error(e.to_string()),
                }
            }
            Err(e) => RpcResponse::error(e),
        },
        RpcMethod::Files { limit } => match state.require_active_peer() {
            Ok(peer_id) => match service::open_db_for_peer(db_path, &peer_id) {
                Ok((recorded_by, db)) => {
                    match file::queries::list_files(&db, &recorded_by, limit) {
                        Ok(data) => RpcResponse::success(data),
                        Err(e) => RpcResponse::error(e.to_string()),
                    }
                }
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },
        RpcMethod::SaveFile {
            target,
            output_path,
        } => match state.require_active_peer() {
            Ok(peer_id) => match service::open_db_for_peer(db_path, &peer_id) {
                Ok((recorded_by, db)) => match file::queries::save_file_by_selector(
                    &db,
                    &recorded_by,
                    &target,
                    &output_path,
                ) {
                    Ok(data) => RpcResponse::success(data),
                    Err(e) => RpcResponse::error(e.to_string()),
                },
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },
        RpcMethod::Generate { count } => match state.require_active_peer() {
            Ok(peer_id) => match message::generate_for_peer(db_path, &peer_id, count) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },
        RpcMethod::GenerateFiles { count, size_mib } => match state.require_active_peer() {
            Ok(peer_id) => {
                match message::generate_files_for_peer(db_path, &peer_id, count, size_mib) {
                    Ok(data) => RpcResponse::success(data),
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
                    RpcResponse::success(data)
                }
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },
        RpcMethod::DeleteMessage { target } => match state.require_active_peer() {
            Ok(peer_id) => match message::delete_message_for_peer(db_path, &peer_id, &target) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },

        // ----- Read-only commands (call event modules directly) -----
        RpcMethod::TransportIdentity => match crate::db::open_connection(db_path) {
            Ok(db) => {
                if let Err(e) = crate::db::schema::create_tables(&db) {
                    return RpcResponse::error(e.to_string());
                }
                match crate::transport::identity::ensure_transport_peer_id(&db) {
                    Ok(fingerprint) => {
                        RpcResponse::success(service::TransportIdentityResponse { fingerprint })
                    }
                    Err(e) => RpcResponse::error(e.to_string()),
                }
            }
            Err(e) => RpcResponse::error(e.to_string()),
        },
        RpcMethod::Messages { limit } => match state.require_active_peer() {
            Ok(peer_id) => match service::open_db_for_peer(db_path, &peer_id) {
                Ok((recorded_by, db)) => match message::list(&db, &recorded_by, limit) {
                    Ok(data) => RpcResponse::success(data),
                    Err(e) => RpcResponse::error(e.to_string()),
                },
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },
        RpcMethod::Status => {
            let with_runtime_state = |data: workspace::StatusResponse| {
                let mut json = serde_json::to_value(data).unwrap_or(serde_json::Value::Null);
                json["daemon_db_path"] = serde_json::json!(db_path);
                json["runtime_state"] =
                    serde_json::json!(state.runtime_state.read().unwrap().as_str());
                if let Some(net_info) = state.runtime_net.read().unwrap().as_ref() {
                    if let Ok(net_val) = serde_json::to_value(net_info) {
                        json["runtime"] = net_val;
                    }
                }
                let upnp_enabled = *state.upnp_enabled.read().unwrap();
                // When the runtime isn't active, synthesize a minimal "runtime"
                // block from early-bound listen addr and UPnP mode state so that
                // `topo status` always shows networking info.
                if json.get("runtime").is_none() {
                    let bind = state.bind_addr.read().unwrap();
                    let upnp = state.upnp_result.read().unwrap();
                    if bind.is_some() || upnp.is_some() || upnp_enabled {
                        let mut rt = serde_json::Map::new();
                        if let Some(addr) = *bind {
                            rt.insert(
                                "listen_addr".into(),
                                serde_json::Value::String(addr.to_string()),
                            );
                        }
                        rt.insert("upnp_enabled".into(), serde_json::Value::Bool(upnp_enabled));
                        if let Some(ref report) = *upnp {
                            if let Ok(v) = serde_json::to_value(report) {
                                rt.insert("upnp".into(), v);
                            }
                        }
                        json["runtime"] = serde_json::Value::Object(rt);
                    }
                } else if let Some(rt) = json.get_mut("runtime") {
                    rt["upnp_enabled"] = serde_json::Value::Bool(upnp_enabled);
                    // Runtime is active but UPnP might only be in daemon-level state
                    // (e.g. while a refresh task is still writing the latest report).
                    // Only inject if the port matches the current listen address.
                    if rt.get("upnp").is_none() {
                        if let Some(ref report) = *state.upnp_result.read().unwrap() {
                            let port_matches = rt["listen_addr"]
                                .as_str()
                                .and_then(|a| a.parse::<std::net::SocketAddr>().ok())
                                .map(|a| a.port() == report.requested_external_port)
                                .unwrap_or(false);
                            if port_matches {
                                if let Ok(v) = serde_json::to_value(report) {
                                    rt["upnp"] = v;
                                }
                            }
                        }
                    }
                }
                RpcResponse {
                    version: crate::rpc::protocol::PROTOCOL_VERSION,
                    ok: true,
                    error: None,
                    data: Some(json),
                }
            };

            match state.require_active_peer() {
                Ok(peer_id) => match service::open_db_for_peer(db_path, &peer_id) {
                    Ok((recorded_by, db)) => {
                        let data = workspace::status(&db, &recorded_by);
                        with_runtime_state(data)
                    }
                    Err(e) => RpcResponse::error(e.to_string()),
                },
                Err(no_active_err) => match crate::db::open_connection(db_path) {
                    Ok(db) => {
                        let _ = crate::db::schema::create_tables(&db);
                        let tenant_count: i64 = db
                            .query_row(
                                "SELECT COUNT(DISTINCT recorded_by) FROM invites_accepted",
                                [],
                                |row| row.get(0),
                            )
                            .unwrap_or(0);
                        if tenant_count > 1 {
                            // Multiple tenants, none selected — return error so
                            // operators know to run `topo use-tenant`.
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
        RpcMethod::Reactions => match state.require_active_peer() {
            Ok(peer_id) => match service::open_db_for_peer(db_path, &peer_id) {
                Ok((recorded_by, db)) => match reaction::list(&db, &recorded_by) {
                    Ok(data) => RpcResponse::success(data),
                    Err(e) => RpcResponse::error(e.to_string()),
                },
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },
        RpcMethod::Users => match state.require_active_peer() {
            Ok(peer_id) => match service::open_db_for_peer(db_path, &peer_id) {
                Ok((recorded_by, db)) => match user::list_items(&db, &recorded_by) {
                    Ok(data) => RpcResponse::success(data),
                    Err(e) => RpcResponse::error(e.to_string()),
                },
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },
        RpcMethod::Keys { summary } => match state.require_active_peer() {
            Ok(peer_id) => match service::open_db_for_peer(db_path, &peer_id) {
                Ok((recorded_by, db)) => match workspace::keys(&db, &recorded_by, summary) {
                    Ok(data) => RpcResponse::success(data),
                    Err(e) => RpcResponse::error(e.to_string()),
                },
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },
        RpcMethod::Peers => match state.require_active_peer() {
            Ok(peer_id) => match service::open_db_for_peer(db_path, &peer_id) {
                Ok((recorded_by, db)) => match peer_shared::list_peers(&db, &recorded_by) {
                    Ok(data) => RpcResponse::success(data),
                    Err(e) => RpcResponse::error(e.to_string()),
                },
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },
        RpcMethod::Workspaces => match crate::db::open_connection(db_path) {
            Ok(db) => {
                let _ = crate::db::schema::create_tables(&db);
                match workspace::list_all_items(&db) {
                    Ok(data) => RpcResponse::success(data),
                    Err(e) => RpcResponse::error(e.to_string()),
                }
            }
            Err(e) => RpcResponse::error(e.to_string()),
        },
        RpcMethod::IntroAttempts { peer } => match state.require_active_peer() {
            Ok(peer_id) => match service::open_db_for_peer(db_path, &peer_id) {
                Ok((recorded_by, db)) => {
                    match crate::db::intro::list_intro_attempts(&db, &recorded_by, peer.as_deref())
                    {
                        Ok(rows) => {
                            let items: Vec<service::IntroAttemptItem> = rows
                                .into_iter()
                                .map(|r| service::IntroAttemptItem {
                                    intro_id: hex::encode(&r.intro_id),
                                    other_peer_id: r.other_peer_id,
                                    introduced_by_peer_id: r.introduced_by_peer_id,
                                    origin_ip: r.origin_ip,
                                    origin_port: r.origin_port,
                                    status: r.status,
                                    error: r.error,
                                    created_at: r.created_at,
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
        RpcMethod::CreateInvite {
            public_addr,
            public_spki,
        } => match state.require_active_peer() {
            Ok(peer_id) => {
                let listen_port = state
                    .runtime_net
                    .read()
                    .unwrap()
                    .as_ref()
                    .and_then(|ni| ni.listen_addr.parse::<std::net::SocketAddr>().ok())
                    .map(|sa| sa.port())
                    .unwrap_or(crate::event_modules::workspace::invite_link::DEFAULT_PORT);
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
                let bootstrap_addrs = if explicit_addrs.is_empty() {
                    match autodetect_bootstrap_addrs(state, listen_port) {
                        Ok(addrs) => addrs,
                        Err(e) => return RpcResponse::error(e),
                    }
                } else {
                    explicit_addrs
                };
                let result: Result<
                    workspace::commands::CreateInviteResponse,
                    Box<dyn std::error::Error + Send + Sync>,
                > = workspace::commands::create_invite_for_peer(
                    db_path,
                    &peer_id,
                    &bootstrap_addrs,
                    listen_port,
                    public_spki.as_deref(),
                );
                match result {
                    Ok(data) => {
                        if let Some(link) = serde_json::to_value(&data)
                            .ok()
                            .and_then(|v| v["invite_link"].as_str().map(|s| s.to_string()))
                        {
                            let num = state.add_invite_ref(link);
                            let mut resp_data = serde_json::to_value(&data).unwrap();
                            resp_data["invite_ref"] = serde_json::json!(num);
                            RpcResponse::success(resp_data)
                        } else {
                            RpcResponse::success(data)
                        }
                    }
                    Err(e) => RpcResponse::error(e.to_string()),
                }
            }
            Err(e) => RpcResponse::error(e),
        },
        RpcMethod::Upnp { action } => match action {
            UpnpAction::Disable => {
                *state.upnp_enabled.write().unwrap() = false;
                *state.upnp_result.write().unwrap() = None;
                if let Some(ref mut info) = *state.runtime_net.write().unwrap() {
                    info.upnp = None;
                }
                RpcResponse::success(upnp_response_data(false, None, "disabled"))
            }
            UpnpAction::Status => {
                let enabled = *state.upnp_enabled.read().unwrap();
                let report = state.upnp_result.read().unwrap().clone();
                let fallback = if enabled {
                    "runtime not active yet; mapping will be attempted when runtime starts"
                } else {
                    "disabled"
                };
                RpcResponse::success(upnp_response_data(enabled, report.as_ref(), fallback))
            }
            UpnpAction::Enable => {
                *state.upnp_enabled.write().unwrap() = true;
                let listen_addr = match state.runtime_net.read().unwrap().as_ref() {
                    Some(info) => match info.listen_addr.parse::<std::net::SocketAddr>() {
                        Ok(addr) => Some(addr),
                        Err(e) => {
                            return RpcResponse::error(format!("invalid listen addr: {}", e));
                        }
                    },
                    None => None,
                };
                let Some(listen_addr) = listen_addr else {
                    *state.upnp_result.write().unwrap() = None;
                    return RpcResponse::success(upnp_response_data(
                        true,
                        None,
                        "runtime not active yet; mapping will be attempted when runtime starts",
                    ));
                };
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => return RpcResponse::error(format!("failed to start runtime: {}", e)),
                };
                let report = rt.block_on(crate::peering::nat::upnp::attempt_udp_port_mapping(
                    listen_addr,
                    std::time::Duration::from_secs(10),
                ));
                *state.upnp_result.write().unwrap() = Some(report.clone());
                if let Some(ref mut ni) = *state.runtime_net.write().unwrap() {
                    let runtime_port = ni
                        .listen_addr
                        .parse::<std::net::SocketAddr>()
                        .map(|a| a.port())
                        .unwrap_or(0);
                    if runtime_port == listen_addr.port() {
                        ni.upnp = Some(report.clone());
                    }
                }
                RpcResponse::success(upnp_response_data(true, Some(&report), "enabled"))
            }
        },
        RpcMethod::CreateDeviceLink {
            public_addr,
            public_spki,
        } => {
            match state.require_active_peer() {
                Ok(peer_id) => {
                    let listen_port = state
                        .runtime_net
                        .read()
                        .unwrap()
                        .as_ref()
                        .and_then(|ni| ni.listen_addr.parse::<std::net::SocketAddr>().ok())
                        .map(|sa| sa.port())
                        .unwrap_or(crate::event_modules::workspace::invite_link::DEFAULT_PORT);
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
                    let bootstrap_addrs = if explicit_addrs.is_empty() {
                        match autodetect_bootstrap_addrs(state, listen_port) {
                            Ok(addrs) => addrs,
                            Err(e) => return RpcResponse::error(e),
                        }
                    } else {
                        explicit_addrs
                    };
                    match workspace::commands::create_device_link_for_peer(
                        db_path,
                        &peer_id,
                        &bootstrap_addrs,
                        listen_port,
                        public_spki.as_deref(),
                    ) {
                        Ok(data) => {
                            if let Some(link) = serde_json::to_value(&data)
                                .ok()
                                .and_then(|v| v["invite_link"].as_str().map(|s| s.to_string()))
                            {
                                let num = state.add_invite_ref(link);
                                let mut resp_data = serde_json::to_value(&data).unwrap();
                                resp_data["invite_ref"] = serde_json::json!(num);
                                RpcResponse::success(resp_data)
                            } else {
                                RpcResponse::success(data)
                            }
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
                    // Auto-select if no active peer
                    let mut ap = state.active_peer.write().unwrap();
                    if ap.is_none() {
                        *ap = Some(data.peer_id.clone());
                    }
                    state.notify_runtime_recheck();
                    RpcResponse::success(data)
                }
                Err(e) => RpcResponse::error(e.to_string()),
            }
        }
        RpcMethod::Ban { target } => match state.require_active_peer() {
            Ok(peer_id) => match user::ban_for_peer(db_path, &peer_id, &target) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },
        RpcMethod::Identity => match state.require_active_peer() {
            Ok(peer_id) => match service::open_db_for_peer(db_path, &peer_id) {
                Ok((_recorded_by, db)) => match peer_shared::identity(&db, &peer_id) {
                    Ok(data) => RpcResponse::success(data),
                    Err(e) => RpcResponse::error(e.to_string()),
                },
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },
        RpcMethod::AcceptInvite {
            invite,
            username,
            devicename,
        } => match workspace::commands::accept_invite(db_path, &invite, &username, &devicename) {
            Ok(data) => {
                let mut ap = state.active_peer.write().unwrap();
                if ap.is_none() {
                    *ap = Some(data.peer_id.clone());
                }
                state.notify_runtime_recheck();
                RpcResponse::success(data)
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

        RpcMethod::Intro {
            peer_a,
            peer_b,
            ttl_ms,
            attempt_window_ms,
        } => match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                match handle.block_on(service::svc_intro(
                    db_path,
                    &peer_a,
                    &peer_b,
                    ttl_ms,
                    attempt_window_ms,
                )) {
                    Ok(true) => RpcResponse::success(serde_json::json!({"sent_to_both": true})),
                    Ok(false) => RpcResponse::error("partial send"),
                    Err(e) => RpcResponse::error(e.to_string()),
                }
            }
            Err(_) => RpcResponse::error("no tokio runtime available for async intro"),
        },

        RpcMethod::EventList => match crate::db::open_connection(db_path) {
            Ok(db) => {
                if let Err(e) = crate::db::schema::create_tables(&db) {
                    return RpcResponse::error(e.to_string());
                }
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
        RpcMethod::SubList => match state.require_active_peer() {
            Ok(peer_id) => match service::open_db_for_peer(db_path, &peer_id) {
                Ok((recorded_by, db)) => {
                    match subscriptions::list_subscriptions(&db, &recorded_by) {
                        Ok(subs) => RpcResponse::success(subs),
                        Err(e) => RpcResponse::error(e),
                    }
                }
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },
        RpcMethod::SubDisable { subscription_id } => match state.require_active_peer() {
            Ok(peer_id) => match service::open_db_for_peer(db_path, &peer_id) {
                Ok((recorded_by, db)) => {
                    match subscriptions::set_enabled(&db, &recorded_by, &subscription_id, false) {
                        Ok(()) => RpcResponse::success(serde_json::json!({"disabled": true})),
                        Err(e) => RpcResponse::error(e),
                    }
                }
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },
        RpcMethod::SubEnable { subscription_id } => match state.require_active_peer() {
            Ok(peer_id) => match service::open_db_for_peer(db_path, &peer_id) {
                Ok((recorded_by, db)) => {
                    match subscriptions::set_enabled(&db, &recorded_by, &subscription_id, true) {
                        Ok(()) => RpcResponse::success(serde_json::json!({"enabled": true})),
                        Err(e) => RpcResponse::error(e),
                    }
                }
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },
        RpcMethod::SubPoll {
            subscription_id,
            after_seq,
            limit,
        } => match state.require_active_peer() {
            Ok(peer_id) => match service::open_db_for_peer(db_path, &peer_id) {
                Ok((recorded_by, db)) => {
                    match subscriptions::poll_feed(
                        &db,
                        &recorded_by,
                        &subscription_id,
                        after_seq,
                        limit,
                    ) {
                        Ok(items) => RpcResponse::success(items),
                        Err(e) => RpcResponse::error(e),
                    }
                }
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },
        RpcMethod::SubAck {
            subscription_id,
            through_seq,
        } => match state.require_active_peer() {
            Ok(peer_id) => match service::open_db_for_peer(db_path, &peer_id) {
                Ok((recorded_by, db)) => {
                    match subscriptions::ack_feed(&db, &recorded_by, &subscription_id, through_seq)
                    {
                        Ok(()) => RpcResponse::success(serde_json::json!({"acked": true})),
                        Err(e) => RpcResponse::error(e),
                    }
                }
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },
        RpcMethod::SubState { subscription_id } => match state.require_active_peer() {
            Ok(peer_id) => match service::open_db_for_peer(db_path, &peer_id) {
                Ok((recorded_by, db)) => {
                    match subscriptions::get_state(&db, &recorded_by, &subscription_id) {
                        Ok(state) => RpcResponse::success(state),
                        Err(e) => RpcResponse::error(e),
                    }
                }
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{merge_upnp_bootstrap_addr, resolve_bootstrap_from_upnp};
    use crate::event_modules::workspace::invite_link::parse_bootstrap_address;
    use crate::peering::nat::upnp::{UpnpMappingReport, UpnpMappingStatus};

    fn mk_report(
        status: UpnpMappingStatus,
        external_ip: Option<&str>,
        mapped_external_port: Option<u16>,
        error: Option<&str>,
    ) -> UpnpMappingReport {
        UpnpMappingReport {
            status,
            protocol: "udp".to_string(),
            local_addr: "192.168.1.20:4433".to_string(),
            requested_external_port: 4433,
            mapped_external_port,
            external_ip: external_ip.map(|s| s.to_string()),
            gateway: Some("192.168.1.1:1900".to_string()),
            error: error.map(|s| s.to_string()),
            double_nat: false,
        }
    }

    #[test]
    fn bootstrap_resolution_rejects_non_success_status() {
        let report = mk_report(
            UpnpMappingStatus::NotAttempted,
            None,
            None,
            Some("listen address is loopback"),
        );
        let err = resolve_bootstrap_from_upnp(&report).unwrap_err();
        assert!(err.contains("UPnP status is not_attempted"));
    }

    #[test]
    fn bootstrap_resolution_formats_ipv6_with_brackets() {
        let report = mk_report(
            UpnpMappingStatus::Success,
            Some("2001:4860:4860::8888"),
            Some(4433),
            None,
        );
        let addr = resolve_bootstrap_from_upnp(&report).unwrap();
        assert_eq!(addr, "[2001:4860:4860::8888]:4433");
    }

    #[test]
    fn bootstrap_resolution_rejects_non_public_ip() {
        let report = mk_report(
            UpnpMappingStatus::Success,
            Some("10.0.0.8"),
            Some(4433),
            None,
        );
        let err = resolve_bootstrap_from_upnp(&report).unwrap_err();
        assert!(err.contains("not publicly routable"));
    }

    #[test]
    fn upnp_bootstrap_addr_is_appended_to_detected_addrs() {
        let report = mk_report(
            UpnpMappingStatus::Success,
            Some("8.8.4.4"),
            Some(55000),
            None,
        );
        let detected = vec![parse_bootstrap_address("192.168.1.20:4433").unwrap()];
        let merged = merge_upnp_bootstrap_addr(detected, Some(&report));
        let addr_strings: Vec<String> = merged
            .into_iter()
            .map(|addr| addr.to_bootstrap_addr_string())
            .collect();
        assert_eq!(addr_strings, vec!["192.168.1.20", "8.8.4.4:55000"]);
    }

    #[test]
    fn upnp_bootstrap_addr_is_deduplicated_against_detected_addrs() {
        let report = mk_report(
            UpnpMappingStatus::Success,
            Some("8.8.4.4"),
            Some(55000),
            None,
        );
        let detected = vec![parse_bootstrap_address("8.8.4.4:55000").unwrap()];
        let merged = merge_upnp_bootstrap_addr(detected, Some(&report));
        assert_eq!(merged.len(), 1, "UPnP address should not be duplicated");
    }
}
