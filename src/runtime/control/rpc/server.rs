//! RPC server: Unix domain socket listener that dispatches requests to service functions.
//!
//! Connection count is bounded by a semaphore to prevent local connection-flood
//! pressure (feedback item 2).

use std::io::Write;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, RwLock};

use serde::Serialize;
use tokio::sync::Notify;
use tracing::{info, warn};

use crate::db::transport_creds::discover_local_tenants;
use crate::event_modules::{message, peer_shared, reaction, user, workspace};
use crate::node::NodeRuntimeNetInfo;
use crate::rpc::protocol::*;
use crate::service;

/// Maximum concurrent RPC connections the server will handle.
/// Additional connections block until a slot is freed.
const MAX_CONCURRENT_CONNECTIONS: usize = 64;

/// Daemon-wide shared state: tracks active peer and invite refs.
pub struct DaemonState {
    pub db_path: String,
    pub active_peer: RwLock<Option<String>>,
    /// Runtime lifecycle state.
    pub runtime_state: RwLock<RuntimeState>,
    /// Runtime networking info (listen addr, UPnP result). Set once the
    /// QUIC endpoint is bound; UPnP result is populated by `topo upnp`.
    pub runtime_net: RwLock<Option<NodeRuntimeNetInfo>>,
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
                match discover_local_tenants(&conn) {
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
            runtime_recheck: Notify::new(),
            invite_refs: RwLock::new(Vec::new()),
        }
    }

    pub fn notify_runtime_recheck(&self) {
        self.runtime_recheck.notify_waiters();
    }

    fn require_active_peer(&self) -> Result<String, String> {
        let cached = self.active_peer.read().unwrap().clone();

        // Discover current tenant set so we can reject stale cached peers after
        // identity finalization (old peer_id -> new peer_id transition).
        let discovered = if let Ok(conn) = crate::db::open_connection(&self.db_path) {
            let _ = crate::db::schema::create_tables(&conn);
            discover_local_tenants(&conn).ok()
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

        Err("no active peer — run `topo use-peer <N>`".to_string())
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

/// Peer info returned by the Peers command.
#[derive(Debug, Serialize)]
struct PeerItem {
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

#[allow(dead_code)] // used by tests; will be called when auto-UPnP bootstrap is re-enabled
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

        // ----- Peer management (daemon state) -----
        RpcMethod::Peers => {
            match crate::db::open_connection(db_path) {
                Ok(conn) => {
                    let _ = crate::db::schema::create_tables(&conn);
                    match discover_local_tenants(&conn) {
                        Ok(tenants) => {
                            let active = state.active_peer.read().unwrap().clone();
                            let mut items: Vec<PeerItem> = tenants
                                .iter()
                                .enumerate()
                                .map(|(i, t)| PeerItem {
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

        RpcMethod::UsePeer { index } => match crate::db::open_connection(db_path) {
            Ok(conn) => {
                let _ = crate::db::schema::create_tables(&conn);
                match discover_local_tenants(&conn) {
                    Ok(mut tenants) => {
                        tenants.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));
                        if index == 0 || index > tenants.len() {
                            return RpcResponse::error(format!(
                                "invalid peer number {}; available: 1-{}",
                                index,
                                tenants.len()
                            ));
                        }
                        let tenant = &tenants[index - 1];
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

        RpcMethod::ActivePeer => {
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
                    state.notify_runtime_recheck();
                    RpcResponse::success(resp)
                }
                Err(e) => RpcResponse::error(e.to_string()),
            }
        }

        // ----- Commands that need active peer -----
        RpcMethod::Send { content } => match state.require_active_peer() {
            Ok(peer_id) => match message::send_for_peer(db_path, &peer_id, &content) {
                Ok(data) => RpcResponse::success(data),
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
            Ok(peer_id) => match message::generate_files_for_peer(
                db_path,
                &peer_id,
                count,
                size_mib,
            ) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },
        RpcMethod::React { target, emoji } => match state.require_active_peer() {
            Ok(peer_id) => match reaction::react_for_peer(db_path, &peer_id, &target, &emoji) {
                Ok(data) => RpcResponse::success(data),
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
        RpcMethod::TransportIdentity => match service::open_db_load(db_path) {
            Ok((fingerprint, _db)) => {
                RpcResponse::success(service::TransportIdentityResponse { fingerprint })
            }
            Err(e) => RpcResponse::error(e.to_string()),
        },
        RpcMethod::Messages { limit } => match service::open_db_load(db_path) {
            Ok((recorded_by, db)) => match message::list(&db, &recorded_by, limit) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e.to_string()),
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
                RpcResponse {
                    version: crate::rpc::protocol::PROTOCOL_VERSION,
                    ok: true,
                    error: None,
                    data: Some(json),
                }
            };

            match service::open_db_load(db_path) {
                Ok((recorded_by, db)) => {
                    let data = workspace::status(&db, &recorded_by);
                    with_runtime_state(data)
                }
                Err(_) => match crate::db::open_connection(db_path) {
                    Ok(db) => {
                        let _ = crate::db::schema::create_tables(&db);
                        // Empty DB / pre-identity state: report control-plane readiness
                        // with tenant-scoped counters at zero.
                        let data = workspace::status(&db, "__idle__");
                        with_runtime_state(data)
                    }
                    Err(e) => RpcResponse::error(e.to_string()),
                },
            }
        }
        RpcMethod::AssertNow { predicate } => match service::open_db_load(db_path) {
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
        },
        RpcMethod::AssertEventually {
            predicate,
            timeout_ms,
            interval_ms,
        } => match crate::assert::assert_eventually(db_path, &predicate, timeout_ms, interval_ms) {
            Ok(data) => RpcResponse::success(data),
            Err(e) => RpcResponse::error(e.to_string()),
        },
        RpcMethod::Reactions => match service::open_db_load(db_path) {
            Ok((recorded_by, db)) => match reaction::list(&db, &recorded_by) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e.to_string()),
        },
        RpcMethod::Users => match service::open_db_load(db_path) {
            Ok((recorded_by, db)) => match user::list_items(&db, &recorded_by) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e.to_string()),
        },
        RpcMethod::Keys { summary } => match service::open_db_load(db_path) {
            Ok((recorded_by, db)) => match workspace::keys(&db, &recorded_by, summary) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e.to_string()),
        },
        RpcMethod::Workspaces => match service::open_db_load(db_path) {
            Ok((recorded_by, db)) => match workspace::list_items(&db, &recorded_by) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e.to_string()),
        },
        RpcMethod::IntroAttempts { peer } => match service::open_db_load(db_path) {
            Ok((recorded_by, db)) => {
                match crate::db::intro::list_intro_attempts(&db, &recorded_by, peer.as_deref()) {
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
        RpcMethod::CreateInvite {
            public_addr,
            public_spki,
        } => {
            let result = match public_spki {
                Some(ref spki) => {
                    workspace::commands::create_invite_with_spki(db_path, &public_addr, spki)
                }
                None => workspace::commands::create_invite_for_db(db_path, &public_addr),
            };
            match result {
                Ok(data) => {
                    // Store invite ref
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
        RpcMethod::Upnp => {
            let net_info = state.runtime_net.read().unwrap().clone();
            match net_info {
                None => RpcResponse::error("daemon not ready — listen address not yet known"),
                Some(info) => {
                    let listen_addr: std::net::SocketAddr = match info.listen_addr.parse() {
                        Ok(a) => a,
                        Err(e) => return RpcResponse::error(format!("invalid listen addr: {}", e)),
                    };
                    let rt = match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(rt) => rt,
                        Err(e) => {
                            return RpcResponse::error(format!("failed to start runtime: {}", e))
                        }
                    };
                    let report = rt.block_on(crate::peering::nat::upnp::attempt_udp_port_mapping(
                        listen_addr,
                        std::time::Duration::from_secs(10),
                    ));
                    // Store result in daemon state.
                    let mut net = state.runtime_net.write().unwrap();
                    if let Some(ref mut ni) = *net {
                        ni.upnp = Some(report.clone());
                    }
                    RpcResponse::success(report)
                }
            }
        }
        RpcMethod::CreateDeviceLink {
            public_addr,
            public_spki,
        } => match state.require_active_peer() {
            Ok(peer_id) => {
                match workspace::commands::create_device_link_for_peer(
                    db_path,
                    &peer_id,
                    &public_addr,
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
        },
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
    }
}

#[cfg(test)]
mod tests {
    use super::resolve_bootstrap_from_upnp;
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
}
