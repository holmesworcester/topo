#[cfg(all(target_os = "linux", target_env = "gnu"))]
use std::os::unix::process::CommandExt;
use std::path::Path;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{parser::ValueSource, CommandFactory, FromArgMatches};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use topo::db::{friendly_db_error, open_connection, schema::create_tables};
use topo::rpc::catalog;
use topo::rpc::client::{rpc_call, rpc_call_raw, RpcClientError};
use topo::rpc::protocol::{ForwardAction, RpcMethod, UpnpAction, PROTOCOL_VERSION};
use topo::rpc::server::{run_rpc_server, DaemonState};
use topo::service;
use topo::tuning::apply_low_mem_allocator_tuning;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use topo::tuning::low_mem_mode;

mod cli;
mod commands;
mod format;
mod runtime_manager;

use cli::*;
use commands::*;
use format::*;
use runtime_manager::*;

// ---------------------------------------------------------------------------
// Low-mem allocator re-exec
// ---------------------------------------------------------------------------

#[cfg(all(target_os = "linux", target_env = "gnu"))]
const GLIBC_TCACHE_COUNT_OFF: &str = "glibc.malloc.tcache_count=0";
#[cfg(all(target_os = "linux", target_env = "gnu"))]
const GLIBC_TCACHE_MAX_OFF: &str = "glibc.malloc.tcache_max=0";

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn has_glibc_tunable(existing: &str, needle: &str) -> bool {
    existing.split(':').any(|part| part.trim() == needle)
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn merged_low_mem_glibc_tunables(existing: &str) -> String {
    let mut tunables = existing.to_string();
    if !has_glibc_tunable(&tunables, GLIBC_TCACHE_COUNT_OFF) {
        if !tunables.is_empty() {
            tunables.push(':');
        }
        tunables.push_str(GLIBC_TCACHE_COUNT_OFF);
    }
    if !has_glibc_tunable(&tunables, GLIBC_TCACHE_MAX_OFF) {
        if !tunables.is_empty() {
            tunables.push(':');
        }
        tunables.push_str(GLIBC_TCACHE_MAX_OFF);
    }
    tunables
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn maybe_reexec_low_mem_with_allocator_env() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    if !low_mem_mode() {
        return Ok(());
    }
    if std::env::var_os("_TOPO_LOW_MEM_ALLOC_READY").is_some() {
        return Ok(());
    }
    let tunables = std::env::var("GLIBC_TUNABLES").unwrap_or_default();
    if std::env::var_os("MALLOC_ARENA_MAX").is_some()
        && std::env::var_os("MALLOC_TRIM_THRESHOLD_").is_some()
        && std::env::var_os("MALLOC_MMAP_THRESHOLD_").is_some()
        && has_glibc_tunable(&tunables, GLIBC_TCACHE_COUNT_OFF)
        && has_glibc_tunable(&tunables, GLIBC_TCACHE_MAX_OFF)
    {
        return Ok(());
    }

    let exe = std::env::current_exe()?;
    let mut cmd = Command::new(exe);
    cmd.args(std::env::args_os().skip(1));
    cmd.env("MALLOC_ARENA_MAX", "1");
    cmd.env("MALLOC_TRIM_THRESHOLD_", "0");
    cmd.env("MALLOC_MMAP_THRESHOLD_", "16384");
    cmd.env("MALLOC_TOP_PAD_", "0");
    cmd.env("GLIBC_TUNABLES", merged_low_mem_glibc_tunables(&tunables));
    cmd.env("_TOPO_LOW_MEM_ALLOC_READY", "1");
    let err = cmd.exec();
    Err(format!("low-mem allocator re-exec failed: {err}").into())
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn maybe_reexec_low_mem_with_allocator_env() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    Ok(())
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    maybe_reexec_low_mem_with_allocator_env()?;
    apply_low_mem_allocator_tuning();
    let matches = Cli::command().get_matches();
    let start_uses_default_bind = matches
        .subcommand()
        .map(|(name, sub)| {
            name == "start" && matches!(sub.value_source("bind"), Some(ValueSource::DefaultValue))
        })
        .unwrap_or(false);
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|err| err.exit());
    let db = &cli.db;
    let socket_override = cli.socket.clone();

    // Init tracing for commands that need it
    match &cli.command {
        Commands::Start { .. } => {
            let level = match std::env::var("RUST_LOG").ok().as_deref() {
                Some("trace") => Level::TRACE,
                Some("debug") => Level::DEBUG,
                Some("info") => Level::INFO,
                Some("error") => Level::ERROR,
                _ => Level::WARN,
            };
            let subscriber = FmtSubscriber::builder().with_max_level(level).finish();
            let _ = tracing::subscriber::set_global_default(subscriber);
        }
        _ => {}
    }

    match cli.command {
        // ---------------------------------------------------------------
        // Daemon lifecycle
        // ---------------------------------------------------------------
        Commands::Start { bind } => {
            let socket_path = socket_override
                .as_ref()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| service::socket_path_for_db(db));

            // Validate socket path length before doing anything else.
            // Unix domain sockets are limited to 107 bytes (108 including NUL).
            // Failing late leaves an orphaned QUIC listener (bug #13).
            let socket_path_str = socket_path.to_string_lossy();
            if socket_path_str.len() > 107 {
                return Err(format!(
                    "socket path too long ({} chars, max 107): {}\n\
                     Use --socket <shorter-path> to specify a shorter path.",
                    socket_path_str.len(),
                    socket_path_str
                )
                .into());
            }

            // Idempotent: check if daemon is already running
            if socket_path.exists() {
                match rpc_call(&socket_path, RpcMethod::Status) {
                    Ok(_) => {
                        println!("daemon already running for {}", db);
                        return Ok(());
                    }
                    Err(RpcClientError::DaemonNotRunning(_)) | Err(_) => {
                        // Stale socket — remove it
                        let _ = std::fs::remove_file(&socket_path);
                    }
                }
            }

            // Initialize DB eagerly
            {
                let conn = open_connection(db).map_err(|e| friendly_db_error(db, e))?;
                create_tables(&conn)?;
            }

            // Reserve the UDP bind immediately so startup fails fast on conflicts
            // and the daemon keeps its chosen port even while idle.
            let (idle_bind_reservation, resolved_bind) =
                reserve_idle_bind(bind, start_uses_default_bind)?;

            topo::state::live_hints::init_forward_on_have_from_env();

            let shutdown = Arc::new(AtomicBool::new(false));
            let shutdown_notify = Arc::new(tokio::sync::Notify::new());
            let state = Arc::new(DaemonState::new(db));
            *state.resolved_bind_addr.write().unwrap() = Some(resolved_bind);

            // Start RPC server in a background thread
            let rpc_shutdown = shutdown.clone();
            let rpc_notify = shutdown_notify.clone();
            let rpc_socket = socket_path.clone();
            let rpc_state = state.clone();
            let rpc_handle = std::thread::spawn(move || {
                if let Err(e) = run_rpc_server(&rpc_socket, rpc_state, rpc_shutdown, rpc_notify) {
                    tracing::error!("RPC server error: {}", e);
                }
            });

            info!(
                "\u{1f42d} Topo daemon started (db={}, socket={})",
                db,
                socket_path.display()
            );
            info!("Build: {}", env!("TOPO_GIT_HASH"));

            // Foreground Ctrl-C uses the same daemon shutdown path as RPC Shutdown.
            let ctrlc_notify = shutdown_notify.clone();
            tokio::spawn(async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    info!("Shutdown requested via Ctrl-C");
                    ctrlc_notify.notify_waiters();
                }
            });

            // Runtime manager keeps control daemon alive with explicit lifecycle:
            // IdleNoTenants <-> Active.
            let manager_state = state.clone();
            let manager_shutdown = shutdown_notify.clone();
            let manager_shutdown_flag = shutdown.clone();
            let manager_db = db.to_string();
            let fatal_shutdown = shutdown_notify.clone();
            let fatal_error = Arc::new(AtomicBool::new(false));
            let fatal_error_flag = fatal_error.clone();
            let runtime_manager = tokio::spawn(async move {
                if let Err(e) = run_runtime_manager(
                    &manager_db,
                    resolved_bind,
                    manager_state,
                    manager_shutdown_flag,
                    manager_shutdown,
                    idle_bind_reservation,
                )
                .await
                {
                    tracing::error!("runtime manager error: {}", e);
                    // Non-retriable runtime failure — shut down the daemon.
                    fatal_error_flag.store(true, Ordering::Relaxed);
                    fatal_shutdown.notify_waiters();
                }
            });

            // Wait until shutdown is requested by RPC stop or Ctrl-C.
            shutdown_notify.notified().await;

            // Signal RPC server to stop
            shutdown.store(true, Ordering::Relaxed);
            shutdown_notify.notify_waiters();
            let _ = runtime_manager.await;
            let _ = rpc_handle.join();

            if fatal_error.load(Ordering::Relaxed) {
                return Err("daemon exiting due to non-retriable runtime error".into());
            }

            info!("\u{1f42d} Topo daemon shut down cleanly");
        }

        Commands::Stop => {
            let socket_path = socket_override
                .as_ref()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| service::socket_path_for_db(db));
            let request_deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match rpc_call(&socket_path, RpcMethod::Shutdown) {
                    Ok(_) => {
                        break;
                    }
                    Err(RpcClientError::DaemonNotRunning(_)) if !socket_path.exists() => {
                        println!("no daemon running for {}", db);
                        return Ok(());
                    }
                    Err(RpcClientError::DaemonNotRunning(_)) => {}
                    Err(RpcClientError::Protocol(msg))
                        if msg.contains("Connection reset by peer")
                            || msg.contains("Broken pipe") => {}
                    Err(RpcClientError::Io(e))
                        if e.kind() == std::io::ErrorKind::ConnectionReset
                            || e.kind() == std::io::ErrorKind::ConnectionRefused
                            || e.kind() == std::io::ErrorKind::BrokenPipe => {}
                    Err(e) => {
                        eprintln!("error stopping daemon: {}", e);
                        std::process::exit(1);
                    }
                }

                if Instant::now() >= request_deadline {
                    eprintln!(
                        "error stopping daemon: timed out sending shutdown to {}",
                        socket_path.display()
                    );
                    std::process::exit(1);
                }
                std::thread::sleep(Duration::from_millis(100));
            }

            let down_deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < down_deadline {
                match rpc_call(&socket_path, RpcMethod::Status) {
                    Err(RpcClientError::DaemonNotRunning(_)) if !socket_path.exists() => {
                        println!("daemon stopped");
                        return Ok(());
                    }
                    _ => std::thread::sleep(Duration::from_millis(100)),
                }
            }
            eprintln!(
                "error stopping daemon: timed out waiting for daemon exit ({})",
                socket_path.display()
            );
            std::process::exit(1);
        }

        Commands::CreateWorkspace {
            workspace_name,
            username,
            device_name,
            public_addr,
        } => {
            let device_name = device_name.unwrap_or_else(system_hostname);
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::CreateWorkspace {
                    workspace_name,
                    username,
                    device_name,
                },
            )?;
            println!(
                "peer_id:      {}",
                short_id(data["peer_id"].as_str().unwrap_or(""))
            );
            println!(
                "workspace_id: {}",
                short_id(data["workspace_id"].as_str().unwrap_or(""))
            );

            // Server auto-creates an invite with detected IPs
            if let Some(link) = data["invite_link"].as_str() {
                println!("invite:       {}", link);
            } else if let Some(err) = data["invite_error"].as_str() {
                eprintln!("warning: workspace created but auto-invite failed: {}", err);
            }

            maybe_show_created_events(db, &data);

            // If --public-addr was given, create an additional invite with that address
            if let Some(addr) = public_addr {
                let sock = target_socket_path(db, socket_override.as_deref());
                match rpc_call(
                    &sock,
                    RpcMethod::CreateInvite {
                        public_addr: Some(addr),
                        public_spki: None,
                    },
                ) {
                    Ok(resp) if resp.ok => {
                        if let Some(link) =
                            resp.data.as_ref().and_then(|d| d["invite_link"].as_str())
                        {
                            println!("invite:       {}", link);
                        }
                    }
                    _ => {
                        eprintln!("warning: explicit-addr invite generation failed");
                    }
                }
            }
        }

        Commands::AcceptInvite {
            invite,
            username,
            devicename,
        } => {
            let devicename = devicename.unwrap_or_else(system_hostname);
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::AcceptInvite {
                    invite,
                    username,
                    devicename,
                },
            )?;
            println!("Accepted invite");
            println!(
                "  peer_id: {}",
                short_id(data["peer_id"].as_str().unwrap_or(""))
            );
            println!(
                "  user:    {}",
                short_id(data["user_event_id"].as_str().unwrap_or(""))
            );
            println!(
                "  peer:    {}",
                short_id(data["peer_shared_event_id"].as_str().unwrap_or(""))
            );
            maybe_show_created_events(db, &data);
        }

        // ---------------------------------------------------------------
        // Daemon-only commands (require running daemon)
        // ---------------------------------------------------------------
        Commands::Tenant { action } => {
            let action = action.unwrap_or(TenantAction::List);
            run_tenant_action(db, socket_override.as_deref(), action)?;
        }

        Commands::TransportKeys => {
            let data =
                rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::TransportKeys)?;
            if let Some(keys) = data.as_array() {
                if keys.is_empty() {
                    println!("(no transport keys)");
                } else {
                    println!("TRANSPORT KEYS ({}):", keys.len());
                    for key in keys {
                        let peer_id = key["peer_id"].as_str().unwrap_or("");
                        let source = key["source"].as_str().unwrap_or("unknown");
                        println!("  {} ({})", peer_id, source);
                    }
                }
            }
        }

        Commands::TransportAuth => {
            let data =
                rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::TransportAuth)?;
            if let Some(rows) = data.as_array() {
                if rows.is_empty() {
                    println!("(no authorized transport fingerprints)");
                } else {
                    println!("AUTHORIZED TRANSPORT FINGERPRINTS ({}):", rows.len());
                    for row in rows {
                        let transport_peer_id = row["transport_peer_id"]
                            .as_str()
                            .unwrap_or("<missing-spki>");
                        let source = row["source"].as_str().unwrap_or("unknown");
                        println!("  {} [{}]", transport_peer_id, source);
                        if let Some(event_id) = row["peer_shared_event_id"].as_str() {
                            println!("    peer_shared_event: {}", short_id(event_id));
                        }
                        if let Some(user_event_id) = row["user_event_id"].as_str() {
                            println!("    user_event: {}", short_id(user_event_id));
                        }
                        if let Some(device_name) = row["device_name"].as_str() {
                            println!("    device: {}", device_name);
                        }
                        if let Some(invite_event_id) = row["invite_event_id"].as_str() {
                            println!("    invite_event: {}", short_id(invite_event_id));
                        }
                        if let Some(invite_accepted_event_id) =
                            row["invite_accepted_event_id"].as_str()
                        {
                            println!(
                                "    invite_accepted_event: {}",
                                short_id(invite_accepted_event_id)
                            );
                        }
                        if let Some(workspace_id) = row["workspace_id"].as_str() {
                            println!("    workspace: {}", short_id(workspace_id));
                        }
                        if let Some(expires_at) = row["expires_at"].as_i64() {
                            println!("    expires_at_ms: {}", expires_at);
                        }
                    }
                }
            }
        }

        Commands::View { limit } => {
            let data =
                rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::View { limit })?;
            show_view(&data);
        }

        Commands::Messages { limit } => {
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::Messages { limit },
            )?;
            show_messages_from_json(db, &data);
        }

        Commands::Files { limit } => {
            let data =
                rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::Files { limit })?;
            show_files_from_json(&data);
        }

        Commands::Send {
            content,
            client_op_id,
        } => {
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::Send {
                    content: content.clone(),
                    client_op_id,
                },
            )?;
            let event_id = data["event_id"].as_str().unwrap_or("");
            println!("Sent: {}", data["content"].as_str().unwrap_or(&content));
            println!("event_id:{}", event_id);
            maybe_show_created_events(db, &data);
        }

        Commands::SendFile {
            content,
            file,
            client_op_id,
        } => {
            let file_path = resolve_send_file_path(file)?;
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::SendFile {
                    content: content.clone(),
                    file_path,
                    client_op_id,
                },
            )?;
            let event_id = data["event_id"].as_str().unwrap_or("");
            let filename = data["filename"].as_str().unwrap_or("");
            let file_size = data["file_size"].as_i64().unwrap_or(0);
            println!("Sent: {}", data["content"].as_str().unwrap_or(&content));
            println!("\u{1f4ce} {} ({})", filename, format_byte_size(file_size));
            println!("event_id:{}", event_id);
            maybe_show_created_events(db, &data);
        }

        Commands::SaveFile {
            target,
            target_flag,
            out,
        } => {
            let target = resolve_target_selector(target, target_flag, "save-file", Some("1"))?;
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::SaveFile {
                    target,
                    output_path: out,
                },
            )?;
            println!(
                "saved {} bytes to {}",
                data["bytes_written"].as_u64().unwrap_or(0),
                data["output_path"].as_str().unwrap_or("")
            );
            println!(
                "file_event_id:{}",
                data["file_event_id"].as_str().unwrap_or("")
            );
        }

        Commands::Status => {
            let data = rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::Status)?;
            println!("STATUS ({}):", db);
            println!("  Events:    {} total", data["events_count"]);
            println!("  Messages:  {} projected", data["messages_count"]);
            println!("  Reactions: {} projected", data["reactions_count"]);
            println!("  Recorded:  {} events", data["recorded_events_count"]);
            println!(
                "  SharedEventIndex:  {} indexed",
                data["shared_event_index_count"]
            );
            println!(
                "  Runtime:   {}",
                data["runtime_state"].as_str().unwrap_or("unknown")
            );
            // Runtime networking info.
            if let Some(rt) = data.get("runtime") {
                println!(
                    "  Listen:    {}",
                    rt["listen_addr"].as_str().unwrap_or("unknown")
                );
                let upnp_enabled = rt["upnp_enabled"].as_bool().unwrap_or(false);
                if let Some(upnp) = rt.get("upnp") {
                    let status = upnp["status"].as_str().unwrap_or("not_attempted");
                    match status {
                        "success" => {
                            let ext_port = upnp["mapped_external_port"]
                                .as_u64()
                                .map(|p| p.to_string())
                                .unwrap_or_else(|| "?".into());
                            let ext_ip = upnp["external_ip"].as_str().unwrap_or("unknown");
                            let nat_tag = if upnp["double_nat"].as_bool().unwrap_or(false) {
                                " (double-NAT!)"
                            } else {
                                ""
                            };
                            println!(
                                "  UPnP:      {} success udp external_port={} external_ip={}{}",
                                if upnp_enabled { "enabled" } else { "disabled" },
                                ext_port,
                                ext_ip,
                                nat_tag
                            );
                        }
                        "failed" => {
                            let err = upnp["error"].as_str().unwrap_or("unknown");
                            println!(
                                "  UPnP:      {} failed ({})",
                                if upnp_enabled { "enabled" } else { "disabled" },
                                err
                            );
                        }
                        "not_attempted" => {
                            let err = upnp["error"].as_str().unwrap_or("unknown");
                            println!(
                                "  UPnP:      {} not attempted ({})",
                                if upnp_enabled { "enabled" } else { "disabled" },
                                err
                            );
                        }
                        _ => {
                            println!(
                                "  UPnP:      {} not attempted",
                                if upnp_enabled { "enabled" } else { "disabled" }
                            );
                        }
                    }
                } else if upnp_enabled {
                    println!("  UPnP:      enabled (awaiting active runtime)");
                } else {
                    println!("  UPnP:      disabled");
                }
            }
            if data.get("runtime").is_none() {
                let state = data["runtime_state"].as_str().unwrap_or("");
                if state == "IdleNoTenants" {
                    println!("  Listen:    (idle; no tenants)");
                } else {
                    println!("  Listen:    (starting)");
                }
                println!("  UPnP:      not attempted");
            }
            if let Some(tenants) = data["tenants"].as_array() {
                if !tenants.is_empty() {
                    println!("  Tenants:");
                    for (idx, tenant) in tenants.iter().enumerate() {
                        let marker = if tenant["active"].as_bool().unwrap_or(false) {
                            "*"
                        } else {
                            " "
                        };
                        let username = tenant["username"].as_str().unwrap_or("");
                        let workspace_name = tenant["workspace_name"].as_str().unwrap_or("");
                        let peer_id = tenant["peer_id"].as_str().unwrap_or("");
                        let workspace_id = tenant["workspace_id"].as_str().unwrap_or("");
                        let user_display = if username.is_empty() {
                            short_id(peer_id).to_string()
                        } else {
                            username.to_string()
                        };
                        let workspace_display = if workspace_name.is_empty() {
                            short_id(workspace_id).to_string()
                        } else {
                            workspace_name.to_string()
                        };
                        let joining_tag = if tenant["ready"].as_bool().unwrap_or(false) {
                            ""
                        } else {
                            " [still joining]"
                        };
                        println!(
                            "    {}. {} {}@{}{}",
                            idx + 1,
                            marker,
                            user_display,
                            workspace_display,
                            joining_tag
                        );
                    }
                }
            }
        }

        Commands::Generate {
            count,
            history_span,
        } => {
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::Generate {
                    count,
                    history_span: Some(history_span),
                },
            )?;
            println!("Generated {} messages in {}", data["count"], db);
        }

        Commands::GenerateFiles { count, size_mib } => {
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::GenerateFiles { count, size_mib },
            )?;
            println!(
                "Generated {} files ({} MiB each, {} slices/file, total slices {}) in {}",
                data["files"],
                data["file_size_mib"],
                data["slices_per_file"],
                data["total_slices"],
                db
            );
        }

        Commands::AssertNow { predicate } => {
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::AssertNow {
                    predicate: predicate.clone(),
                },
            )?;
            let pass = data["pass"].as_bool().unwrap_or(false);
            let field = data["field"].as_str().unwrap_or("");
            let actual = data["actual"].as_i64().unwrap_or(0);
            let op = data["op"].as_str().unwrap_or("");
            let expected = data["expected"].as_i64().unwrap_or(0);
            if pass {
                println!(
                    "PASS: {} = {} (expected {} {})",
                    field, actual, op, expected
                );
                std::process::exit(0);
            } else {
                println!(
                    "FAIL: {} = {} (expected {} {})",
                    field, actual, op, expected
                );
                std::process::exit(1);
            }
        }

        Commands::AssertEventually {
            predicate,
            timeout_ms,
            interval_ms,
        } => {
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::AssertEventually {
                    predicate: predicate.clone(),
                    timeout_ms,
                    interval_ms,
                },
            )?;
            let pass = data["pass"].as_bool().unwrap_or(false);
            let field = data["field"].as_str().unwrap_or("");
            let actual = data["actual"].as_i64().unwrap_or(0);
            let op = data["op"].as_str().unwrap_or("");
            let expected = data["expected"].as_i64().unwrap_or(0);
            if pass {
                println!(
                    "PASS: {} = {} (expected {} {})",
                    field, actual, op, expected
                );
                std::process::exit(0);
            } else {
                println!(
                    "TIMEOUT: {} = {} (expected {} {}) after {}ms",
                    field, actual, op, expected, timeout_ms
                );
                std::process::exit(1);
            }
        }

        Commands::React {
            emoji,
            target,
            target_flag,
            client_op_id,
        } => {
            let target = resolve_target_selector(target, target_flag, "react", None)?;
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::React {
                    target,
                    emoji: emoji.clone(),
                    client_op_id,
                },
            )?;
            let event_id = data["event_id"].as_str().unwrap_or("");
            let short = &event_id[..event_id.len().min(8)];
            println!(
                "Reacted {} ({})",
                data["emoji"].as_str().unwrap_or(&emoji),
                short
            );
            maybe_show_created_events(db, &data);
        }

        Commands::DeleteMessage {
            target,
            target_flag,
        } => {
            let target = resolve_target_selector(target, target_flag, "delete-message", None)?;
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::DeleteMessage { target },
            )?;
            let target_str = data["target"].as_str().unwrap_or("");
            println!(
                "Deleted message {}",
                &target_str[..target_str.len().min(16)]
            );
        }

        Commands::Reactions => {
            let data = rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::Reactions)?;
            println!("REACTIONS ({}):", db);
            if let Some(items) = data.as_array() {
                if items.is_empty() {
                    println!("  (none)");
                } else {
                    for item in items {
                        println!(
                            "  {} -> {} {}",
                            short_id(item["event_id"].as_str().unwrap_or("")),
                            short_id(item["target_event_id"].as_str().unwrap_or("")),
                            item["emoji"].as_str().unwrap_or("")
                        );
                    }
                }
            } else {
                println!("  (none)");
            }
        }

        Commands::Users => {
            let data = rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::Users)?;
            println!("USERS:");
            if let Some(items) = data.as_array() {
                if items.is_empty() {
                    println!("  (none)");
                } else {
                    for (i, item) in items.iter().enumerate() {
                        let username = item["username"].as_str().unwrap_or("");
                        let eid = item["event_id"].as_str().unwrap_or("");
                        let display = if username.is_empty() {
                            format!("user_{}", short_id(eid))
                        } else {
                            username.to_string()
                        };
                        println!("  {}. {}", i + 1, display);
                    }
                }
            } else {
                println!("  (none)");
            }
        }

        Commands::Keys { summary } => {
            let data =
                rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::Keys { summary })?;
            println!("KEYS ({}):", db);
            println!("  Users: {}", data["user_count"]);
            println!("  Peers: {}", data["peer_count"]);
            println!("  Admins: {}", data["admin_count"]);
            if !summary {
                if let Some(users) = data["users"].as_array() {
                    for eid in users {
                        println!("    user {}", short_id(eid.as_str().unwrap_or("")));
                    }
                }
                if let Some(peers) = data["peers"].as_array() {
                    for eid in peers {
                        println!("    peer {}", short_id(eid.as_str().unwrap_or("")));
                    }
                }
            }
        }

        Commands::Stats { json } => {
            let data = rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::Stats)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&data).unwrap_or_default()
                );
            } else {
                println!("STATS ({}):", db);
                let f = |key: &str| data[key].as_i64().unwrap_or(0);
                println!("  Messages:              {}", f("message_count"));
                println!("  Reactions:             {}", f("reaction_count"));
                println!("  Deleted messages:      {}", f("deleted_message_count"));
                println!("  Users:                 {}", f("user_count"));
                println!("  Peers:                 {}", f("peer_count"));
                println!("  Admins:                {}", f("admin_count"));
                println!("  Workspaces:            {}", f("workspace_count"));
                println!("  User invites:          {}", f("user_invite_count"));
                println!("  Device invites:        {}", f("device_invite_count"));
                println!("  Key secrets:           {}", f("key_secret_count"));
                println!("  Events:                {}", f("event_count"));
                println!("  Recorded events:       {}", f("recorded_event_count"));
                println!("  Valid events:          {}", f("valid_event_count"));
                println!("  Blocked events:        {}", f("blocked_event_count"));
                println!("  Rejected events:       {}", f("rejected_event_count"));
                println!("  Endpoint observations: {}", f("endpoint_observation_count"));
            }
        }

        Commands::Replay { pass, json } => {
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::Replay { pass: pass.clone() },
            )?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&data).unwrap_or_default()
                );
            } else {
                println!("REPLAY {} ({}):", pass, db);
                println!(
                    "  Events:      {}",
                    data["event_count"].as_u64().unwrap_or(0)
                );
                println!(
                    "  Fingerprint: {}",
                    data["fingerprint"].as_str().unwrap_or("unknown")
                );
            }
        }

        Commands::Workspaces => {
            let data = rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::Workspaces)?;
            println!("WORKSPACES ({}):", db);
            if let Some(items) = data.as_array() {
                if items.is_empty() {
                    println!("  (none)");
                } else {
                    for (i, item) in items.iter().enumerate() {
                        println!(
                            "  {}. {} ({})",
                            i + 1,
                            item["name"].as_str().unwrap_or(""),
                            short_id(item["event_id"].as_str().unwrap_or(""))
                        );
                    }
                }
            } else {
                println!("  (none)");
            }
        }

        Commands::Peers => {
            let data = rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::Peers)?;
            println!("PEERS ({}):", db);
            if let Some(items) = data.as_array() {
                if items.is_empty() {
                    println!("  (none)");
                } else {
                    for (i, item) in items.iter().enumerate() {
                        let peer_id = item["peer_id"].as_str().unwrap_or("");
                        let device_name = item["device_name"].as_str().unwrap_or("");
                        let username = item["username"].as_str().unwrap_or("");
                        let is_local = item["local"].as_bool().unwrap_or(false);
                        let endpoint = item["endpoint"].as_str();

                        let label = if !username.is_empty() && !device_name.is_empty() {
                            format!("{}@{}", username, device_name)
                        } else if !username.is_empty() {
                            username.to_string()
                        } else if !device_name.is_empty() {
                            device_name.to_string()
                        } else {
                            String::new()
                        };

                        let location = if is_local {
                            "local".to_string()
                        } else if let Some(ep) = endpoint {
                            ep.to_string()
                        } else {
                            "remote".to_string()
                        };

                        if label.is_empty() {
                            println!("  {}. {} [{}]", i + 1, short_id(peer_id), location);
                        } else {
                            println!(
                                "  {}. {} ({}) [{}]",
                                i + 1,
                                label,
                                short_id(peer_id),
                                location
                            );
                        }
                    }
                }
            } else {
                println!("  (none)");
            }
        }

        Commands::Event { action } => {
            run_event_action(db, socket_override.as_deref(), action)?;
        }

        Commands::Intro {
            peer_a,
            peer_b,
            ttl_ms,
            attempt_window_ms,
        } => {
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::Intro {
                    peer_a,
                    peer_b,
                    ttl_ms,
                    attempt_window_ms,
                },
            )?;
            if data
                .get("sent_to_both")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                println!("Intro sent to both peers");
            } else {
                eprintln!("Intro failed: {}", data);
                std::process::exit(1);
            }
        }

        Commands::IntroAttempts { peer } => {
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::IntroAttempts { peer },
            )?;
            if let Some(items) = data.as_array() {
                if items.is_empty() {
                    println!("No intro attempts recorded.");
                } else {
                    for r in items {
                        let intro_id = r["intro_id"].as_str().unwrap_or("");
                        println!("  intro_id:  {}...", &intro_id[..intro_id.len().min(16)]);
                        let peer_id = r["other_peer_id"].as_str().unwrap_or("");
                        println!("  peer:      {}", &peer_id[..peer_id.len().min(16)]);
                        let intro_by = r["introduced_by_peer_id"].as_str().unwrap_or("");
                        println!("  via:       {}", &intro_by[..intro_by.len().min(16)]);
                        println!(
                            "  endpoint:  {}:{}",
                            r["origin_ip"].as_str().unwrap_or(""),
                            r["origin_port"]
                        );
                        println!("  status:    {}", r["status"].as_str().unwrap_or(""));
                        if let Some(err) = r["error"].as_str() {
                            println!("  error:     {}", err);
                        }
                        println!("  created:   {}", r["created_at"]);
                        println!();
                    }
                }
            } else {
                println!("No intro attempts recorded.");
            }
        }

        Commands::CreateInvite {
            public_addr,
            public_spki,
        } => {
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::CreateInvite {
                    public_addr,
                    public_spki,
                },
            )?;
            println!("{}", data["invite_link"].as_str().unwrap_or(""));
            if let Some(num) = data["invite_ref"].as_u64() {
                eprintln!("Created invite #{}", num);
            }
            maybe_show_created_events(db, &data);
        }

        Commands::Link {
            public_addr,
            public_spki,
        } => {
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::CreateDeviceLink {
                    public_addr,
                    public_spki,
                },
            )?;
            println!("{}", data["invite_link"].as_str().unwrap_or(""));
            if let Some(num) = data["invite_ref"].as_u64() {
                eprintln!("Created device link #{}", num);
            }
            maybe_show_created_events(db, &data);
        }

        Commands::AcceptLink { invite, devicename } => {
            let devicename = devicename.unwrap_or_else(system_hostname);
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::AcceptLink { invite, devicename },
            )?;
            let peer_id = data["peer_id"].as_str().unwrap_or("");
            println!("Accepted device link");
            println!("  peer_id: {}", short_id(peer_id));
            maybe_show_created_events(db, &data);
        }

        Commands::Identity => {
            let data = rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::Identity)?;
            println!("IDENTITY:");
            println!(
                "  Transport: {}",
                data["transport_fingerprint"].as_str().unwrap_or("")
            );
            match data["user_event_id"].as_str() {
                Some(uid) => println!("  User:      {}", &uid[..uid.len().min(16)]),
                None => println!("  User:      (none)"),
            }
            match data["peer_shared_event_id"].as_str() {
                Some(pid) => println!("  Peer:      {}", &pid[..pid.len().min(16)]),
                None => println!("  Peer:      (none)"),
            }
        }

        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "topo", &mut std::io::stdout());
        }

        // ---------------------------------------------------------------
        // Subscription commands
        // ---------------------------------------------------------------
        Commands::Sub { action } => {
            let action = action.unwrap_or(SubAction::List);
            run_sub_action(db, socket_override.as_deref(), action)?;
        }

        Commands::SyncLog {
            limit,
            run,
            peer,
            all,
            action,
        } => {
            let action = action.unwrap_or(SyncLogAction::Show {
                limit,
                run,
                peer,
                all,
            });
            run_sync_log_action(db, action)?;
        }

        // ---------------------------------------------------------------
        // RPC demo surface
        // ---------------------------------------------------------------
        Commands::Rpc { action } => match action {
            RpcAction::Methods { json } => {
                let methods = catalog::all_methods();
                if json {
                    println!("{}", serde_json::to_string_pretty(&methods).unwrap());
                } else {
                    println!("RPC METHODS ({}):\n", methods.len());
                    for m in methods {
                        println!("  {:<22} {}", m.name, m.purpose);
                    }
                }
            }
            RpcAction::Describe { method, json } => {
                let method = method.trim();
                match catalog::describe(method) {
                    Some(info) => {
                        if json {
                            println!("{}", serde_json::to_string_pretty(&info).unwrap());
                        } else {
                            println!("{}:", info.name);
                            println!("  {}\n", info.purpose);
                            if info.params.is_empty() {
                                println!("  Parameters: (none)");
                            } else {
                                println!("  Parameters:");
                                for p in info.params {
                                    let req = if p.required { "required" } else { "optional" };
                                    let default = match p.default {
                                        Some(d) => format!(", default={}", d),
                                        None => String::new(),
                                    };
                                    println!(
                                        "    {:<20} {} ({}{})",
                                        p.name, p.param_type, req, default
                                    );
                                }
                            }
                            println!("\n  Example:");
                            println!("    {}", info.example_json);
                        }
                    }
                    None => {
                        eprintln!("error: unknown method {:?}", method);
                        eprintln!("  Run `topo rpc methods` to see available methods.");
                        std::process::exit(1);
                    }
                }
            }
            RpcAction::Call {
                method_json,
                request_json,
                file,
                stdin,
            } => {
                let sock = target_socket_path(db, socket_override.as_deref());

                // Parse the input into a JSON value representing a full RpcRequest.
                let request_value: serde_json::Value = if let Some(mj) = method_json {
                    // method_json: parse as RpcMethod, wrap in request envelope.
                    // Pre-validate by deserializing as RpcMethod — gives specific
                    // serde errors (missing field, wrong type, unknown variant)
                    // instead of a generic "daemon closed connection" later.
                    let _method: RpcMethod = serde_json::from_str(&mj).map_err(|e| {
                        eprintln!("error: invalid method JSON: {}", e);
                        if let Some(type_name) = serde_json::from_str::<serde_json::Value>(&mj)
                            .ok()
                            .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(String::from))
                        {
                            eprintln!("  Hint: run `topo rpc describe {}` to see required parameters", type_name);
                        } else {
                            eprintln!("  Hint: method JSON must have a \"type\" field (e.g. {{\"type\":\"Status\"}})");
                        }
                        std::process::exit(1);
                    }).unwrap();
                    let method_val: serde_json::Value = serde_json::from_str(&mj).unwrap();
                    serde_json::json!({
                        "version": PROTOCOL_VERSION,
                        "method": method_val
                    })
                } else if let Some(rj) = request_json {
                    let v: serde_json::Value = serde_json::from_str(&rj)
                        .map_err(|e| {
                            eprintln!("error: invalid request JSON: {}", e);
                            std::process::exit(1);
                        })
                        .unwrap();
                    validate_request_envelope(&v);
                    v
                } else if let Some(path) = file {
                    let contents = std::fs::read_to_string(&path)
                        .map_err(|e| {
                            eprintln!("error: cannot read file {:?}: {}", path, e);
                            std::process::exit(1);
                        })
                        .unwrap();
                    let v: serde_json::Value = serde_json::from_str(&contents)
                        .map_err(|e| {
                            eprintln!("error: invalid JSON in file {:?}: {}", path, e);
                            std::process::exit(1);
                        })
                        .unwrap();
                    validate_request_envelope(&v);
                    v
                } else if stdin {
                    let mut buf = String::new();
                    std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
                        .map_err(|e| {
                            eprintln!("error: failed to read stdin: {}", e);
                            std::process::exit(1);
                        })
                        .unwrap();
                    let v: serde_json::Value = serde_json::from_str(&buf)
                        .map_err(|e| {
                            eprintln!("error: invalid JSON from stdin: {}", e);
                            std::process::exit(1);
                        })
                        .unwrap();
                    validate_request_envelope(&v);
                    v
                } else {
                    eprintln!(
                        "error: specify one of --method-json, --request-json, --file, or --stdin"
                    );
                    std::process::exit(1);
                };

                match rpc_call_raw(&sock, &request_value) {
                    Ok(resp) => {
                        println!("{}", serde_json::to_string_pretty(&resp).unwrap());
                        if !resp.ok {
                            std::process::exit(1);
                        }
                    }
                    Err(RpcClientError::DaemonNotRunning(_)) => {
                        eprintln!(
                            "daemon is not running for {} — start it with: topo --db {} start",
                            db, db
                        );
                        std::process::exit(1);
                    }
                    Err(RpcClientError::Protocol(msg))
                        if msg.contains("fill whole buffer") || msg.contains("unexpected eof") =>
                    {
                        eprintln!("error: daemon closed connection — the request JSON was likely malformed or unrecognized");
                        eprintln!("  Hint: use --method-json for method-only JSON (auto-wraps in request envelope)");
                        eprintln!("  Hint: use --request-json for full {{\"version\":1,\"method\":...}} envelopes");
                        std::process::exit(1);
                    }
                    Err(e) => {
                        eprintln!("error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        },

        Commands::Upnp { action } => {
            let action = match action.unwrap_or(UpnpCommand::Enable) {
                UpnpCommand::Enable => UpnpAction::Enable,
                UpnpCommand::Disable => UpnpAction::Disable,
                UpnpCommand::Status => UpnpAction::Status,
            };
            let data =
                rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::Upnp { action })?;
            let enabled = data["enabled"].as_bool().unwrap_or(false);
            let status = data["status"].as_str().unwrap_or("unknown");
            match status {
                "success" => {
                    let ext_port = data["mapped_external_port"]
                        .as_u64()
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "?".into());
                    let ext_ip = data["external_ip"].as_str().unwrap_or("unknown");
                    println!(
                        "upnp: {} success udp external_port={} external_ip={}",
                        if enabled { "enabled" } else { "disabled" },
                        ext_port,
                        ext_ip
                    );
                    if data["double_nat"].as_bool().unwrap_or(false) {
                        println!("warning: double-NAT detected \u{2014} external IP {} is not publicly routable; port forwarding may not be reachable from the internet", ext_ip);
                    }
                }
                "failed" => {
                    let err = data["error"].as_str().unwrap_or("unknown reason");
                    println!(
                        "upnp: {} failed ({})",
                        if enabled { "enabled" } else { "disabled" },
                        err
                    );
                }
                "not_attempted" => {
                    let err = data["error"].as_str().unwrap_or("unknown reason");
                    if enabled {
                        println!("upnp: enabled ({})", err);
                    } else {
                        println!("upnp: disabled");
                    }
                }
                other => {
                    println!(
                        "upnp: {} {}",
                        if enabled { "enabled" } else { "disabled" },
                        other
                    );
                }
            }
        }

        Commands::Forward { action } => {
            let action = match action.unwrap_or(ForwardCommand::Status) {
                ForwardCommand::Enable => ForwardAction::Enable,
                ForwardCommand::Disable => ForwardAction::Disable,
                ForwardCommand::Status => ForwardAction::Status,
            };
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::Forward { action },
            )?;
            let enabled = data["forward_on_have"].as_bool().unwrap_or(false);
            println!(
                "forward-on-have: {}",
                if enabled { "enabled" } else { "disabled" }
            );
        }

        Commands::Sync { action } => {
            let sock_ref = socket_override.as_deref();
            match action {
                SyncAction::Policy {
                    action: SyncPolicyAction::Show,
                } => {
                    let data = rpc_require_daemon(db, sock_ref, RpcMethod::SyncPolicyShow)?;
                    println!("SYNC POLICY:");
                    println!(
                        "  requests:        {}",
                        data["requests"].as_str().unwrap_or("auto")
                    );
                    println!(
                        "  responses:       {}",
                        data["responses"].as_str().unwrap_or("auto")
                    );
                    println!(
                        "  forward_on_have: {}",
                        data["forward_on_have"].as_str().unwrap_or("auto")
                    );
                }
                SyncAction::Policy {
                    action:
                        SyncPolicyAction::Set {
                            requests,
                            responses,
                            forward_on_have,
                        },
                } => {
                    let data = rpc_require_daemon(
                        db,
                        sock_ref,
                        RpcMethod::SyncPolicySet {
                            requests,
                            responses,
                            forward_on_have,
                        },
                    )?;
                    println!("SYNC POLICY (updated):");
                    println!(
                        "  requests:        {}",
                        data["requests"].as_str().unwrap_or("auto")
                    );
                    println!(
                        "  responses:       {}",
                        data["responses"].as_str().unwrap_or("auto")
                    );
                    println!(
                        "  forward_on_have: {}",
                        data["forward_on_have"].as_str().unwrap_or("auto")
                    );
                }
                SyncAction::Round { target } => match target {
                    SyncTarget::Peer { peer } => {
                        let data =
                            rpc_require_daemon(db, sock_ref, RpcMethod::SyncRoundPeer { peer })?;
                        print_round_capture(&data);
                    }
                    SyncTarget::All => {
                        let data = rpc_require_daemon(db, sock_ref, RpcMethod::SyncRoundAll)?;
                        if let Some(arr) = data.as_array() {
                            for item in arr {
                                print_round_capture(item);
                            }
                        } else {
                            print_round_capture(&data);
                        }
                    }
                },
                SyncAction::Request { target } => match target {
                    SyncTarget::Peer { peer } => {
                        let data =
                            rpc_require_daemon(db, sock_ref, RpcMethod::SyncRequestPeer { peer })?;
                        print_request_result(&data);
                    }
                    SyncTarget::All => {
                        let data = rpc_require_daemon(db, sock_ref, RpcMethod::SyncRequestAll)?;
                        if let Some(arr) = data.as_array() {
                            for item in arr {
                                print_request_result(item);
                            }
                        } else {
                            print_request_result(&data);
                        }
                    }
                },
            }
        }

        Commands::Reset => {
            let socket_path = socket_override
                .as_ref()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| service::socket_path_for_db(db));

            // Try to stop the daemon if running
            if socket_path.exists() {
                print!("stopping daemon... ");
                let request_deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    match rpc_call(&socket_path, RpcMethod::Shutdown) {
                        Ok(_) => break,
                        Err(RpcClientError::DaemonNotRunning(_)) if !socket_path.exists() => break,
                        Err(RpcClientError::DaemonNotRunning(_)) => {}
                        Err(RpcClientError::Protocol(msg))
                            if msg.contains("Connection reset by peer")
                                || msg.contains("Broken pipe") =>
                        {
                            break;
                        }
                        Err(RpcClientError::Io(e))
                            if e.kind() == std::io::ErrorKind::ConnectionReset
                                || e.kind() == std::io::ErrorKind::ConnectionRefused
                                || e.kind() == std::io::ErrorKind::BrokenPipe =>
                        {
                            break;
                        }
                        Err(e) => {
                            eprintln!("warning: error stopping daemon: {}", e);
                            break;
                        }
                    }
                    if Instant::now() >= request_deadline {
                        eprintln!("warning: timed out stopping daemon");
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }

                // Wait for daemon to fully exit
                let down_deadline = Instant::now() + Duration::from_secs(5);
                while socket_path.exists() && Instant::now() < down_deadline {
                    std::thread::sleep(Duration::from_millis(100));
                }
                println!("done");
            }

            // Delete DB file and associated WAL/SHM files, plus socket
            let db_path = Path::new(db);
            let mut deleted = Vec::new();
            for path in [
                db_path.to_path_buf(),
                db_path.with_extension("db-wal"),
                db_path.with_extension("db-shm"),
                socket_path.clone(),
            ] {
                if path.exists() {
                    match std::fs::remove_file(&path) {
                        Ok(_) => deleted.push(path.display().to_string()),
                        Err(e) => eprintln!("warning: failed to delete {}: {}", path.display(), e),
                    }
                }
            }

            if deleted.is_empty() {
                println!("nothing to clean up");
            } else {
                for f in &deleted {
                    println!("deleted {}", f);
                }
                println!("reset complete");
            }
        }
    }

    Ok(())
}
