use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use topo::db::transport_creds::discover_local_tenants;
use topo::db::{open_connection, schema::create_tables};
use topo::rpc::server::{DaemonState, RuntimeState};

pub(crate) struct ManagedRuntime {
    pub tenant_states: Vec<RuntimeTenantState>,
    pub shutdown_notify: Arc<tokio::sync::Notify>,
    pub handle: tokio::task::JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct RuntimeTenantState {
    pub peer_id: String,
    pub workspace_id: String,
    pub transport_peer_id: String,
}

pub(crate) fn discover_runtime_tenant_states(
    db_path: &str,
) -> Result<Vec<RuntimeTenantState>, Box<dyn std::error::Error + Send + Sync>> {
    let conn = open_connection(db_path)?;
    create_tables(&conn)?;
    let mut tenants = discover_local_tenants(&conn)?
        .into_iter()
        .map(|t| RuntimeTenantState {
            peer_id: t.peer_id,
            workspace_id: t.workspace_id,
            transport_peer_id: t.transport_peer_id,
        })
        .collect::<Vec<_>>();
    tenants.sort();
    tenants.dedup();
    Ok(tenants)
}

/// Classifies what changed between the current and new tenant sets.
pub(crate) enum TenantChangeKind {
    /// No change at all.
    NoChange,
    /// No runtime exists yet — need a fresh start.
    NeedsFreshStart,
    /// Runtime can stay up and just refresh its discovered tenant metadata.
    NewTenantsAdded {
        new_tenants: Vec<RuntimeTenantState>,
    },
    /// Existing tenant changed transport identity or the tenant set shrank.
    /// With a daemon-scoped Iroh endpoint this no longer requires a runtime
    /// restart; loops consult current DB state on refresh.
    TransportIdentityChanged,
}

pub(crate) fn classify_tenant_change(
    current: &[RuntimeTenantState],
    discovered: &[RuntimeTenantState],
) -> TenantChangeKind {
    if current == discovered {
        return TenantChangeKind::NoChange;
    }

    let current_set: std::collections::HashSet<&str> =
        current.iter().map(|t| t.peer_id.as_str()).collect();

    // Check if any existing tenant changed transport identity.
    for new_t in discovered {
        if let Some(old_t) = current.iter().find(|t| t.peer_id == new_t.peer_id) {
            if old_t.transport_peer_id != new_t.transport_peer_id {
                return TenantChangeKind::TransportIdentityChanged;
            }
        }
    }

    // Check if any existing tenants were removed.
    for old_t in current {
        if !discovered.iter().any(|t| t.peer_id == old_t.peer_id) {
            // Tenant removed — for now, restart. (Removal is rare.)
            return TenantChangeKind::TransportIdentityChanged;
        }
    }

    // Pure additions.
    let new_tenants: Vec<RuntimeTenantState> = discovered
        .iter()
        .filter(|t| !current_set.contains(t.peer_id.as_str()))
        .cloned()
        .collect();
    if new_tenants.is_empty() {
        TenantChangeKind::NoChange
    } else {
        TenantChangeKind::NewTenantsAdded { new_tenants }
    }
}

pub(crate) async fn stop_runtime(runtime: ManagedRuntime) {
    runtime.shutdown_notify.notify_one();
    match tokio::time::timeout(Duration::from_secs(5), runtime.handle).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(e))) => tracing::warn!("runtime exited with error during stop: {}", e),
        Ok(Err(e)) => tracing::warn!("runtime task join error during stop: {}", e),
        Err(_) => tracing::warn!("timed out waiting for runtime to stop"),
    }
}

pub(crate) fn reserve_idle_bind(
    bind: SocketAddr,
    allow_default_port_fallback: bool,
) -> Result<(UdpSocket, SocketAddr), Box<dyn std::error::Error + Send + Sync>> {
    match UdpSocket::bind(bind) {
        Ok(socket) => {
            let resolved = socket.local_addr()?;
            Ok((socket, resolved))
        }
        Err(err)
            if allow_default_port_fallback
                && err.kind() == std::io::ErrorKind::AddrInUse
                && bind.port() != 0 =>
        {
            let fallback_bind = SocketAddr::new(bind.ip(), 0);
            let socket = UdpSocket::bind(fallback_bind)?;
            let resolved = socket.local_addr()?;
            tracing::warn!(
                "default listen address {} is already in use; falling back to {}",
                bind,
                resolved
            );
            Ok((socket, resolved))
        }
        Err(err) => Err(err.into()),
    }
}

fn resolve_runtime_state_for_net_ready(db_path: &str, fallback: RuntimeState) -> RuntimeState {
    discover_runtime_tenant_states(db_path)
        .map(|states| {
            if states.is_empty() {
                RuntimeState::IdleNoTenants
            } else {
                RuntimeState::Active
            }
        })
        .unwrap_or(fallback)
}

pub(crate) fn spawn_runtime(
    db_path: &str,
    bind: SocketAddr,
    state: Arc<DaemonState>,
    tenant_states: Vec<RuntimeTenantState>,
) -> ManagedRuntime {
    // Runtime is Active only after listen_addr is reported.
    *state.runtime_state.write().unwrap() = RuntimeState::IdleNoTenants;
    *state.runtime_net.write().unwrap() = None;

    let runtime_shutdown = Arc::new(tokio::sync::Notify::new());
    let runtime_shutdown_for_task = runtime_shutdown.clone();
    let runtime_shutdown_for_warmup = runtime_shutdown.clone();
    let db_for_task = db_path.to_string();
    let db_for_net = db_path.to_string();

    let (net_tx, net_rx) = tokio::sync::oneshot::channel::<topo::node::NodeRuntimeNetInfo>();
    let state_for_net = state.clone();
    let next_runtime_state = if tenant_states.is_empty() {
        RuntimeState::IdleNoTenants
    } else {
        RuntimeState::Active
    };
    tokio::spawn(async move {
        if let Ok(info) = net_rx.await {
            if let Some(endpoint) = info.endpoint.clone() {
                let shutdown = runtime_shutdown_for_warmup.clone();
                tokio::spawn(async move {
                    tokio::select! {
                        _ = endpoint.warm_networking() => {}
                        _ = shutdown.notified() => {}
                    }
                });
            }
            println!("Build: {}", env!("TOPO_GIT_HASH"));
            println!("listen: {}", info.listen_addr);
            *state_for_net.runtime_net.write().unwrap() = Some(info);
            let discovered_state =
                resolve_runtime_state_for_net_ready(&db_for_net, next_runtime_state);
            *state_for_net.runtime_state.write().unwrap() = discovered_state;
        }
    });

    let sync_control_for_task = state.sync_control.clone();
    let handle = tokio::spawn(async move {
        topo::node::run_node(
            &db_for_task,
            bind,
            net_tx,
            runtime_shutdown_for_task,
            Some(sync_control_for_task),
        )
        .await
    });

    ManagedRuntime {
        tenant_states,
        shutdown_notify: runtime_shutdown,
        handle,
    }
}

pub(crate) async fn reevaluate_runtime(
    db_path: &str,
    bind: SocketAddr,
    state: Arc<DaemonState>,
    active_runtime: &mut Option<ManagedRuntime>,
    idle_bind_reservation: &mut Option<UdpSocket>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if active_runtime
        .as_ref()
        .map(|runtime| runtime.handle.is_finished())
        .unwrap_or(false)
    {
        let finished = active_runtime.take().unwrap();
        match finished.handle.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let msg = e.to_string();
                let m = msg.to_ascii_lowercase();
                if m.contains("address already in use")
                    || m.contains("os error 98")  // Linux EADDRINUSE
                    || m.contains("os error 48")  // macOS EADDRINUSE
                    || m.contains("os error 10048")
                // Windows WSAEADDRINUSE
                {
                    tracing::warn!(
                        "Runtime bind failed (port {} in use), will retry on next evaluation. (error: {})",
                        bind.port(),
                        msg,
                    );
                    // Treat as retriable — the port may be transiently held
                    // during a runtime restart (transport identity change).
                    return Ok(());
                } else if m.contains("permission denied") || m.contains("os error 13") {
                    tracing::error!(
                        "Runtime cannot start: permission denied binding to {}. \
                         Try a port above 1024 or run with appropriate privileges. \
                         (error: {})",
                        bind,
                        msg,
                    );
                    return Err(e);
                } else {
                    tracing::warn!(
                        "Runtime exited unexpectedly: {}. Will restart on next evaluation.",
                        msg
                    );
                }
            }
            Err(e) => tracing::warn!("Runtime task join error: {}", e),
        }
        *state.runtime_net.write().unwrap() = None;
    }

    let tenant_states = match discover_runtime_tenant_states(db_path) {
        Ok(states) => states,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("database is locked") || msg.contains("SQLITE_BUSY") {
                tracing::debug!("database busy during tenant discovery, will retry");
                return Ok(());
            }
            return Err(e);
        }
    };

    let change = match active_runtime.as_ref() {
        Some(runtime) => classify_tenant_change(&runtime.tenant_states, &tenant_states),
        None => TenantChangeKind::NeedsFreshStart,
    };

    match change {
        TenantChangeKind::NoChange => {}
        TenantChangeKind::NeedsFreshStart => {
            if let Some(runtime) = active_runtime.take() {
                stop_runtime(runtime).await;
            }
            let _ = idle_bind_reservation.take();
            tracing::info!(
                "activating peering runtime ({} tenant(s))",
                tenant_states.len()
            );
            *active_runtime = Some(spawn_runtime(db_path, bind, state, tenant_states));
        }
        TenantChangeKind::NewTenantsAdded { new_tenants } => {
            if let Some(runtime) = active_runtime.as_mut() {
                runtime.tenant_states = tenant_states;
                *state.runtime_state.write().unwrap() = if runtime.tenant_states.is_empty() {
                    RuntimeState::IdleNoTenants
                } else {
                    RuntimeState::Active
                };
                tracing::info!(
                    "runtime tenant set grew by {} tenant(s) without restart ({} total)",
                    new_tenants.len(),
                    runtime.tenant_states.len()
                );
            }
        }
        TenantChangeKind::TransportIdentityChanged => {
            if let Some(runtime) = active_runtime.as_mut() {
                runtime.tenant_states = tenant_states;
                *state.runtime_state.write().unwrap() = if runtime.tenant_states.is_empty() {
                    RuntimeState::IdleNoTenants
                } else {
                    RuntimeState::Active
                };
                tracing::info!(
                    "runtime tenant transport identities changed; refreshed metadata in-place ({} tenant(s))",
                    runtime.tenant_states.len()
                );
            }
        }
    }

    Ok(())
}

pub(crate) async fn run_runtime_manager(
    db_path: &str,
    bind: SocketAddr,
    state: Arc<DaemonState>,
    shutdown_flag: Arc<AtomicBool>,
    daemon_shutdown: Arc<tokio::sync::Notify>,
    idle_bind_reservation: UdpSocket,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut active_runtime: Option<ManagedRuntime> = None;
    let mut idle_bind_reservation = Some(idle_bind_reservation);
    let mut interval = tokio::time::interval(Duration::from_millis(500));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    reevaluate_runtime(
        db_path,
        bind,
        state.clone(),
        &mut active_runtime,
        &mut idle_bind_reservation,
    )
    .await?;

    loop {
        if shutdown_flag.load(Ordering::Relaxed) {
            if let Some(runtime) = active_runtime.take() {
                stop_runtime(runtime).await;
            }
            return Ok(());
        }
        tokio::select! {
            _ = daemon_shutdown.notified() => {
                if let Some(runtime) = active_runtime.take() {
                    stop_runtime(runtime).await;
                }
                return Ok(());
            }
            _ = state.runtime_recheck.notified() => {
                reevaluate_runtime(
                    db_path,
                    bind,
                    state.clone(),
                    &mut active_runtime,
                    &mut idle_bind_reservation,
                )
                .await?;
            }
            _ = interval.tick() => {
                reevaluate_runtime(
                    db_path,
                    bind,
                    state.clone(),
                    &mut active_runtime,
                    &mut idle_bind_reservation,
                )
                .await?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use topo::crypto::spki_fingerprint_from_ed25519_pubkey;
    use topo::db::transport_creds::{
        set_local_transport_target, store_local_creds_with_source, CRED_SOURCE_BOOTSTRAP,
        CRED_SOURCE_PEER_SHARED,
    };

    #[test]
    fn runtime_tenant_states_switch_to_peershared_transport_identity_when_available() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let db_path = tmpdir.path().join("runtime-tenant-state.db");
        let db_path = db_path.to_str().expect("db path").to_string();

        let conn = open_connection(&db_path).expect("open db");
        create_tables(&conn).expect("create tables");

        let tenant_peer_id = "tenant-final-peer".to_string();
        let workspace_id = "workspace-1";
        let invite_event_id = "invite-1";
        let invite_key = SigningKey::from_bytes(&[0x44; 32]);
        let bootstrap_peer_id = hex::encode(spki_fingerprint_from_ed25519_pubkey(
            &invite_key.verifying_key().to_bytes(),
        ));

        conn.execute(
            "INSERT INTO invites_accepted
             (recorded_by, event_id, tenant_event_id, invite_event_id, workspace_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                &tenant_peer_id,
                "ia-1",
                "tenant-evt-1",
                invite_event_id,
                workspace_id,
                1i64
            ],
        )
        .expect("insert invites_accepted");
        conn.execute(
            "INSERT INTO invite_secrets
             (recorded_by, event_id, invite_event_id, private_key, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                &tenant_peer_id,
                "is-1",
                invite_event_id,
                invite_key.to_bytes().to_vec(),
                1i64
            ],
        )
        .expect("insert invite_secret");
        store_local_creds_with_source(
            &conn,
            &bootstrap_peer_id,
            b"bootstrap-cert",
            b"bootstrap-key",
            CRED_SOURCE_BOOTSTRAP,
        )
        .expect("store bootstrap creds");
        set_local_transport_target(
            &conn,
            &tenant_peer_id,
            &bootstrap_peer_id,
            CRED_SOURCE_BOOTSTRAP,
        )
        .expect("set bootstrap transport target");

        let states = discover_runtime_tenant_states(&db_path).expect("discover bootstrap state");
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].peer_id, tenant_peer_id);
        assert_eq!(states[0].workspace_id, workspace_id);
        assert_eq!(
            states[0].transport_peer_id, bootstrap_peer_id,
            "runtime should initially track the invite-derived bootstrap transport identity"
        );

        store_local_creds_with_source(
            &conn,
            &tenant_peer_id,
            b"peershared-cert",
            b"peershared-key",
            CRED_SOURCE_PEER_SHARED,
        )
        .expect("store peershared creds");
        // Projection pipeline updates the target mapping when InstallPeerSharedIdentityFromSigner runs.
        set_local_transport_target(
            &conn,
            &tenant_peer_id,
            &tenant_peer_id,
            CRED_SOURCE_PEER_SHARED,
        )
        .expect("update transport target to peershared");

        let states = discover_runtime_tenant_states(&db_path).expect("discover peershared state");
        assert_eq!(states.len(), 1);
        assert_eq!(
            states[0].transport_peer_id, tenant_peer_id,
            "runtime should switch to the final PeerShared transport identity once it exists"
        );
    }

    #[test]
    fn runtime_state_resolution_prefers_current_tenant_discovery_over_spawn_snapshot() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let db_path = tmpdir.path().join("runtime-state-current-tenants.db");
        let db_path = db_path.to_str().expect("db path").to_string();

        let conn = open_connection(&db_path).expect("open db");
        create_tables(&conn).expect("create tables");

        let tenant_peer_id = "tenant-active-peer".to_string();
        let workspace_id = "workspace-1";
        conn.execute(
            "INSERT INTO invites_accepted
             (recorded_by, event_id, tenant_event_id, invite_event_id, workspace_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                &tenant_peer_id,
                "ia-1",
                "tenant-evt-1",
                "invite-1",
                workspace_id,
                1i64
            ],
        )
        .expect("insert invites_accepted");
        store_local_creds_with_source(
            &conn,
            &tenant_peer_id,
            b"tenant-cert",
            b"tenant-key",
            CRED_SOURCE_PEER_SHARED,
        )
        .expect("store tenant creds");
        set_local_transport_target(
            &conn,
            &tenant_peer_id,
            &tenant_peer_id,
            CRED_SOURCE_PEER_SHARED,
        )
        .expect("set tenant transport target");

        let resolved = resolve_runtime_state_for_net_ready(&db_path, RuntimeState::IdleNoTenants);
        assert_eq!(
            resolved,
            RuntimeState::Active,
            "runtime net readiness should not keep the stale IdleNoTenants snapshot once tenants exist"
        );
    }
}
