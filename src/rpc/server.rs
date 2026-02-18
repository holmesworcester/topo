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
use tracing::{info, warn};

use crate::db::transport_creds::discover_local_tenants;
use crate::node::NodeRuntimeNetInfo;
use crate::rpc::protocol::*;
use crate::service;

/// Maximum concurrent RPC connections the server will handle.
/// Additional connections block until a slot is freed.
const MAX_CONCURRENT_CONNECTIONS: usize = 64;

/// Daemon-wide shared state: tracks active peer for CLI commands.
pub struct DaemonState {
    pub db_path: String,
    pub active_peer: RwLock<Option<String>>,
    /// Runtime networking info (listen addr, UPnP result). Set once the
    /// QUIC endpoint is bound; UPnP result is populated by `topo upnp`.
    pub runtime_net: RwLock<Option<NodeRuntimeNetInfo>>,
}

impl DaemonState {
    /// Create state with auto-selected peer if exactly one tenant exists.
    pub fn new(db_path: &str) -> Self {
        let active = match crate::db::open_connection(db_path) {
            Ok(conn) => {
                let _ = crate::db::schema::create_tables(&conn);
                match discover_local_tenants(&conn) {
                    Ok(tenants) if tenants.len() == 1 => Some(tenants[0].peer_id.clone()),
                    _ => None,
                }
            }
            Err(_) => None,
        };
        DaemonState {
            db_path: db_path.to_string(),
            active_peer: RwLock::new(active),
            runtime_net: RwLock::new(None),
        }
    }

    fn require_active_peer(&self) -> Result<String, String> {
        self.active_peer
            .read()
            .unwrap()
            .clone()
            .ok_or_else(|| "no active peer — run `topo use-peer <N>`".to_string())
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

fn resolve_bootstrap_from_upnp(upnp: &crate::upnp::UpnpMappingReport) -> Result<String, String> {
    if upnp.status != crate::upnp::UpnpMappingStatus::Success {
        let status = match &upnp.status {
            crate::upnp::UpnpMappingStatus::Success => "success",
            crate::upnp::UpnpMappingStatus::Failed => "failed",
            crate::upnp::UpnpMappingStatus::NotAttempted => "not_attempted",
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
    if !crate::upnp::is_public_internet_ip(parsed_ip) {
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
            shutdown_notify.notify_one();
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

        RpcMethod::CreateWorkspace => {
            match service::svc_create_workspace(db_path) {
                Ok(resp) => {
                    // Auto-select newly created peer if none active
                    let mut ap = state.active_peer.write().unwrap();
                    if ap.is_none() {
                        *ap = Some(resp.peer_id.clone());
                    }
                    RpcResponse::success(resp)
                }
                Err(e) => RpcResponse::error(e.to_string()),
            }
        }

        // ----- Commands that need active peer -----
        RpcMethod::Send { content } => match state.require_active_peer() {
            Ok(peer_id) => match service::svc_send_for_peer(db_path, &peer_id, &content) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },
        RpcMethod::Generate { count } => match state.require_active_peer() {
            Ok(peer_id) => match service::svc_generate_for_peer(db_path, &peer_id, count) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },
        RpcMethod::React { target, emoji } => match state.require_active_peer() {
            Ok(peer_id) => match service::svc_react_for_peer(db_path, &peer_id, &target, &emoji) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },
        RpcMethod::DeleteMessage { target } => match state.require_active_peer() {
            Ok(peer_id) => match service::svc_delete_message_for_peer(db_path, &peer_id, &target) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },

        // ----- Read-only commands (no active peer needed) -----
        RpcMethod::TransportIdentity => match service::svc_transport_identity(db_path) {
            Ok(data) => RpcResponse::success(data),
            Err(e) => RpcResponse::error(e.to_string()),
        },
        RpcMethod::Messages { limit } => match service::svc_messages(db_path, limit) {
            Ok(data) => RpcResponse::success(data),
            Err(e) => RpcResponse::error(e.to_string()),
        },
        RpcMethod::Status => match service::svc_status(db_path) {
            Ok(data) => {
                let mut json = serde_json::to_value(data).unwrap_or(serde_json::Value::Null);
                // Merge runtime networking info if available.
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
            }
            Err(e) => RpcResponse::error(e.to_string()),
        },
        RpcMethod::AssertNow { predicate } => match service::svc_assert_now(db_path, &predicate) {
            Ok(data) => RpcResponse::success(data),
            Err(e) => RpcResponse::error(e.to_string()),
        },
        RpcMethod::AssertEventually {
            predicate,
            timeout_ms,
            interval_ms,
        } => match service::svc_assert_eventually(db_path, &predicate, timeout_ms, interval_ms) {
            Ok(data) => RpcResponse::success(data),
            Err(e) => RpcResponse::error(e.to_string()),
        },
        RpcMethod::Reactions => match service::svc_reactions(db_path) {
            Ok(data) => RpcResponse::success(data),
            Err(e) => RpcResponse::error(e.to_string()),
        },
        RpcMethod::Users => match service::svc_users(db_path) {
            Ok(data) => RpcResponse::success(data),
            Err(e) => RpcResponse::error(e.to_string()),
        },
        RpcMethod::Keys { summary } => match service::svc_keys(db_path, summary) {
            Ok(data) => RpcResponse::success(data),
            Err(e) => RpcResponse::error(e.to_string()),
        },
        RpcMethod::Workspaces => match service::svc_workspaces(db_path) {
            Ok(data) => RpcResponse::success(data),
            Err(e) => RpcResponse::error(e.to_string()),
        },
        RpcMethod::IntroAttempts { peer } => {
            match service::svc_intro_attempts(db_path, peer.as_deref()) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            }
        }
        RpcMethod::CreateInvite { bootstrap } => {
            let resolved = match bootstrap {
                Some(addr) => addr,
                None => {
                    // Derive from UPnP result stored in daemon state.
                    let net = state.runtime_net.read().unwrap();
                    match net.as_ref().and_then(|n| n.upnp.as_ref()) {
                        Some(upnp) => match resolve_bootstrap_from_upnp(upnp) {
                            Ok(addr) => addr,
                            Err(msg) => return RpcResponse::error(msg),
                        },
                        None => {
                            return RpcResponse::error(
                                "no bootstrap address — provide --bootstrap or run `topo upnp` first",
                            );
                        }
                    }
                }
            };
            match service::svc_create_invite(db_path, &resolved) {
                Ok(data) => {
                    let mut val = serde_json::to_value(&data).unwrap_or(serde_json::Value::Null);
                    val["bootstrap"] = serde_json::Value::String(resolved);
                    RpcResponse::success(val)
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
                    let report = rt.block_on(crate::upnp::attempt_udp_port_mapping(
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

        RpcMethod::AcceptInvite {
            invite,
            username,
            devicename,
        } => {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => return RpcResponse::error(format!("failed to start runtime: {}", e)),
            };
            match rt.block_on(service::svc_accept_invite(
                db_path,
                &invite,
                &username,
                &devicename,
            )) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::resolve_bootstrap_from_upnp;
    use crate::upnp::{UpnpMappingReport, UpnpMappingStatus};

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
        let report = mk_report(UpnpMappingStatus::Success, Some("10.0.0.8"), Some(4433), None);
        let err = resolve_bootstrap_from_upnp(&report).unwrap_err();
        assert!(err.contains("not publicly routable"));
    }
}
