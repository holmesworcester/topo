//! RPC server: Unix domain socket listener that dispatches requests to service functions.
//!
//! Connection count is bounded by a semaphore to prevent local connection-flood
//! pressure (feedback item 2).

use std::io::Write;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::Arc;

use tracing::{info, warn};

use crate::rpc::protocol::*;
use crate::service;

/// Maximum concurrent RPC connections the server will handle.
/// Additional connections block until a slot is freed.
const MAX_CONCURRENT_CONNECTIONS: usize = 64;

/// Run the RPC server on a Unix socket, dispatching to service functions.
/// Blocks the calling thread. Intended to be run in a background thread.
///
/// When a Shutdown RPC is received, the server sets the `shutdown` flag and
/// notifies `shutdown_notify` so the daemon main loop can exit cleanly.
pub fn run_rpc_server(
    socket_path: &Path,
    db_path: Arc<String>,
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

                let db = db_path.clone();
                let active_clone = active.clone();
                let shutdown_clone = shutdown.clone();
                let notify_clone = shutdown_notify.clone();
                active.fetch_add(1, AtomicOrdering::Relaxed);

                std::thread::spawn(move || {
                    if let Err(e) = handle_connection(stream, &db, &shutdown_clone, &notify_clone) {
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
    db_path: &str,
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

    let resp = dispatch(db_path, req.method, shutdown, shutdown_notify);
    let frame = encode_frame(&resp)?;
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(())
}

fn dispatch(
    db_path: &str,
    method: RpcMethod,
    shutdown: &std::sync::atomic::AtomicBool,
    shutdown_notify: &tokio::sync::Notify,
) -> RpcResponse {
    match method {
        RpcMethod::Shutdown => {
            // Signal the server and daemon to shut down, then reply success.
            shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
            shutdown_notify.notify_one();
            RpcResponse::success(serde_json::json!({"shutdown": true}))
        }
        RpcMethod::TransportIdentity => match service::svc_transport_identity(db_path) {
            Ok(data) => RpcResponse::success(data),
            Err(e) => RpcResponse::error(e.to_string()),
        },
        RpcMethod::Messages { limit } => match service::svc_messages(db_path, limit) {
            Ok(data) => RpcResponse::success(data),
            Err(e) => RpcResponse::error(e.to_string()),
        },
        RpcMethod::Send { workspace, content } => {
            match service::svc_send(db_path, &workspace, &content) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            }
        }
        RpcMethod::Status => match service::svc_status(db_path) {
            Ok(data) => RpcResponse::success(data),
            Err(e) => RpcResponse::error(e.to_string()),
        },
        RpcMethod::Generate { count, workspace } => {
            match service::svc_generate(db_path, count, &workspace) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            }
        }
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
        RpcMethod::React { target, emoji } => match service::svc_react(db_path, &target, &emoji) {
            Ok(data) => RpcResponse::success(data),
            Err(e) => RpcResponse::error(e.to_string()),
        },
        RpcMethod::DeleteMessage { target } => {
            match service::svc_delete_message(db_path, &target) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            }
        }
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
            match service::svc_create_invite(db_path, &bootstrap) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
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
