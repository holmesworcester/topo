//! Connect-side loops: outbound daemon connections and initiator sync runs.

use std::net::SocketAddr;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::contracts::event_pipeline_contract::IngestFns;
use crate::contracts::peering_contract::SessionDirection;
use crate::db::health::{purge_expired_endpoints, record_endpoint_observation};
use crate::db::open_connection;
use crate::db::transport_trust::record_transport_binding;
use crate::runtime::build_mismatch::note_build_mismatch;
use crate::runtime::repeated_warning::{should_emit_globally, RepeatedWarningGate};
use crate::sync::session::dependency_session::spawn_outbound_dependency_session;
use crate::sync::session::windowing::reset_outbound_window_state;
use crate::sync::SyncConnectionHandler;
use crate::transport::session_factory::extract_build_mismatch_reason;
use crate::transport::{
    derive_bootstrap_dial_context, dial_daemon_connection, load_daemon_identity_from_db,
    resolve_outbound_session_auth_plan, send_outbound_session_auth, BootstrapDialMode,
    ConnectionLifecycleError, DaemonConnection, OutboundSessionAuthPlan, SessionClass,
    TransportClientConfig, TransportEndpoint, COVER_SERVER_NAME,
};

use super::supervisor::{run_startup_preflight, supervise_inbound_daemon_connection};
use super::{
    claim_live_daemon_connection_slot, claim_live_session_peer, current_timestamp_ms,
    live_daemon_connection, peer_fingerprint_from_hex, IntroSpawnerFn, CONNECT_RETRY_DELAY,
    ENDPOINT_TTL_MS, SYNC_SESSION_TIMEOUT_SECS,
};

pub(crate) const STALE_DIAL_TARGET_MARKER: &str = "stale_dial_target";
const STALE_DIAL_FAILURE_THRESHOLD: u32 = 8;
const REPEATED_WARNING_WINDOW: Duration = Duration::from_secs(300);

pub struct ConnectLoopConfig {
    pub db_path: String,
    pub recorded_by: String,
    pub endpoint: TransportEndpoint,
    pub remote: SocketAddr,
    pub remote_session_peer_id: String,
    pub client_config: Option<TransportClientConfig>,
    pub intro_spawner: IntroSpawnerFn,
    pub ingest: IngestFns,
    pub shutdown: Option<CancellationToken>,
    pub bootstrap_fallback_client_config: Option<TransportClientConfig>,
    pub sync_control: Option<std::sync::Arc<crate::runtime::sync_control::SyncControlRegistry>>,
    pub auth_plan: Option<OutboundSessionAuthPlan>,
    pub expected_remote_daemon_peer_id: Option<String>,
}

pub async fn connect_loop(
    config: ConnectLoopConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tenants = vec![config.recorded_by.clone()];
    run_startup_preflight(&config.db_path, &tenants, config.ingest)?;

    let shutdown = config.shutdown.unwrap_or_default();
    let (local_daemon_peer_id, _cert, _key) = load_daemon_identity_from_db(&config.db_path)?;
    let local = tokio::task::LocalSet::new();
    local
        .run_until(connect_loop_inner(
            &config.db_path,
            &config.recorded_by,
            &local_daemon_peer_id,
            config.endpoint,
            config.remote,
            &config.remote_session_peer_id,
            config
                .expected_remote_daemon_peer_id
                .as_deref()
                .unwrap_or(&config.remote_session_peer_id),
            config.auth_plan.unwrap_or_else(|| OutboundSessionAuthPlan::PeerShared {
                target_peer_id: config.remote_session_peer_id.clone(),
            }),
            config.client_config,
            config.intro_spawner,
            shutdown,
            config.bootstrap_fallback_client_config,
            config.sync_control,
        ))
        .await
}

#[allow(clippy::too_many_arguments)]
async fn connect_loop_inner(
    db_path: &str,
    recorded_by: &str,
    local_daemon_peer_id: &str,
    endpoint: TransportEndpoint,
    remote: SocketAddr,
    remote_session_peer_id: &str,
    expected_remote_daemon_peer_id: &str,
    auth_plan: OutboundSessionAuthPlan,
    client_config: Option<TransportClientConfig>,
    intro_spawner: IntroSpawnerFn,
    shutdown: CancellationToken,
    bootstrap_fallback_client_config: Option<TransportClientConfig>,
    sync_control: Option<std::sync::Arc<crate::runtime::sync_control::SyncControlRegistry>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut has_connected_once = false;
    let mut announced_connecting = false;
    let mut consecutive_stale_dial_failures: u32 = 0;
    let mut warning_gate = RepeatedWarningGate::new(REPEATED_WARNING_WINDOW);
    let mut last_outbound_window_scope = None;
    let mut live_session_peer_registration = None;

    loop {
        if shutdown.is_cancelled() {
            break;
        }

        let daemon_connection =
            if let Some(existing) = live_daemon_connection(db_path, expected_remote_daemon_peer_id)
        {
            existing
        } else {
            if !announced_connecting {
                info!(
                    "Connecting daemon {} at {}...",
                    super::short_peer_id(expected_remote_daemon_peer_id),
                    remote
                );
                announced_connecting = true;
            }

            let dial_outcome = match tokio::select! {
                _ = shutdown.cancelled() => {
                    break;
                }
                outcome = dial_daemon_ongoing_first(
                    &endpoint,
                    remote,
                    COVER_SERVER_NAME,
                    client_config.as_ref(),
                    bootstrap_fallback_client_config.as_ref(),
                ) => outcome,
            } {
                Ok(outcome) => outcome,
                Err(e) => {
                    let message = describe_connect_failure(remote, &e);
                    let warn_on_startup_stale_failure = bootstrap_fallback_client_config.is_some()
                        || matches!(auth_plan, OutboundSessionAuthPlan::InviteBootstrap { .. });
                    if (should_warn_for_connect_failure(has_connected_once, &e)
                        || warn_on_startup_stale_failure)
                        && warning_gate.should_emit(message.clone())
                        && should_emit_globally(format!("connect:{message}"))
                    {
                        warn!("{}", message);
                    }
                    if is_stale_dial_failure(&e) {
                        consecutive_stale_dial_failures += 1;
                        if consecutive_stale_dial_failures >= STALE_DIAL_FAILURE_THRESHOLD {
                            if warning_gate.should_emit(message.clone())
                                && should_emit_globally(format!("connect:{message}"))
                            {
                                warn!("{}", message);
                            }
                            return Err(std::io::Error::other(format!(
                                "{} remote={} failures={} last_error={}",
                                STALE_DIAL_TARGET_MARKER, remote, consecutive_stale_dial_failures, e
                            ))
                            .into());
                        }
                    } else {
                        consecutive_stale_dial_failures = 0;
                    }
                    tokio::select! {
                        _ = shutdown.cancelled() => break,
                        _ = tokio::time::sleep(CONNECT_RETRY_DELAY) => {}
                    }
                    continue;
                }
            };
            announced_connecting = false;
            has_connected_once = true;
            consecutive_stale_dial_failures = 0;
            warning_gate.clear();

            let daemon_connection = dial_outcome.daemon_connection;
            match claim_live_daemon_connection_slot(
                db_path,
                local_daemon_peer_id,
                daemon_connection.remote_daemon_peer_id(),
                SessionDirection::Outbound,
                daemon_connection.clone(),
            ) {
                super::LiveDaemonConnectionClaim::Acquired(connection_lease) => {
                    spawn_daemon_connection_worker(
                        daemon_connection.clone(),
                        db_path.to_string(),
                        endpoint.clone(),
                        intro_spawner,
                        shutdown.child_token(),
                        sync_control.clone(),
                        connection_lease,
                    );
                    daemon_connection
                }
                super::LiveDaemonConnectionClaim::Occupied(occupied) => {
                    daemon_connection
                        .connection()
                        .close(0u32.into(), b"duplicate daemon connection");
                    occupied.daemon_connection
                }
            }
        };

        let connection_id = daemon_connection.connection().stable_id();
        let initiator_handler =
            SyncConnectionHandler::outbound(db_path.to_string(), SYNC_SESSION_TIMEOUT_SECS)
                .with_sync_control(sync_control.clone());
        let dependency_shutdown = shutdown.child_token();
        let _dependency_handle = spawn_outbound_dependency_session(
            daemon_connection.clone(),
            db_path.to_string(),
            recorded_by.to_string(),
            remote_session_peer_id.to_string(),
            auth_plan.clone(),
            dependency_shutdown.clone(),
        );

        loop {
            if shutdown.is_cancelled() {
                dependency_shutdown.cancel();
                break;
            }

            let mut session = match daemon_connection
                .open_outbound_session(SessionClass::Range)
                .await
            {
                Ok(session) => session,
                Err(err) => {
                    if let Some(reason) = extract_build_mismatch_reason(&err.to_string()) {
                        note_build_mismatch(daemon_connection.remote_daemon_peer_id(), reason);
                    }
                    dependency_shutdown.cancel();
                    break;
                }
            };

            let effective_auth_plan = open_connection(db_path)
                .ok()
                .and_then(|conn| {
                    resolve_outbound_session_auth_plan(
                        &conn,
                        recorded_by,
                        remote_session_peer_id,
                        daemon_connection.remote_daemon_peer_id(),
                        &auth_plan,
                    )
                    .ok()
                })
                .unwrap_or_else(|| auth_plan.clone());

            let auth_result = match send_outbound_session_auth(
                session.io.as_mut(),
                db_path,
                recorded_by,
                daemon_connection.remote_daemon_peer_id(),
                Some(expected_remote_daemon_peer_id),
                &effective_auth_plan,
            )
            .await
            {
                Ok(auth_result) => auth_result,
                Err(e) => {
                    let message = describe_session_auth_failure(remote, remote_session_peer_id, &*e);
                    if warning_gate.should_emit(message.clone())
                        && should_emit_globally(format!("connect:{message}"))
                    {
                        warn!("{}", message);
                    }
                    dependency_shutdown.cancel();
                    break;
                }
            };

            let peer_id = auth_result.session_peer_id.clone();
            let peer_fp = match peer_fingerprint_from_hex(&peer_id) {
                Some(peer_fp) => peer_fp,
                None => {
                    warn!(
                        "Invalid authenticated session peer id {} on daemon {}",
                        super::short_peer_id(&peer_id),
                        super::short_peer_id(daemon_connection.remote_daemon_peer_id())
                    );
                    dependency_shutdown.cancel();
                    break;
                }
            };

            let should_refresh_live_peer_registration = live_session_peer_registration
                .as_ref()
                .map(|(registered_peer_id, _lease)| registered_peer_id != &peer_id)
                .unwrap_or(true);
            if should_refresh_live_peer_registration {
                live_session_peer_registration = Some((
                    peer_id.clone(),
                    claim_live_session_peer(db_path, recorded_by, &peer_id),
                ));
            }

            // Preserve range-window progress across repeated logical sessions on
            // the same daemon connection. Reset only when this tenant starts
            // using a different daemon connection or authenticates as a
            // different remote session peer.
            let should_reset_outbound_window = last_outbound_window_scope
                .as_ref()
                .map(|(last_connection_id, last_peer_id)| {
                    *last_connection_id != connection_id || last_peer_id != &peer_id
                })
                .unwrap_or(true);
            if should_reset_outbound_window {
                reset_outbound_window_state(db_path, recorded_by, &peer_id);
                last_outbound_window_scope = Some((connection_id, peer_id.clone()));
            }
            record_authenticated_outbound_session(
                db_path,
                recorded_by,
                &auth_result,
                &session.remote_addr,
            );

            let session_ok = super::run_session(
                &initiator_handler,
                session.session_id,
                session.io,
                recorded_by,
                peer_fp,
                session.remote_addr,
                SessionDirection::Outbound,
                db_path,
            )
            .await;

            if !session_ok {
                tokio::select! {
                    _ = shutdown.cancelled() => {
                        dependency_shutdown.cancel();
                        break;
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => {}
                }
            }
        }

        live_session_peer_registration = None;

        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(CONNECT_RETRY_DELAY) => {}
        }
    }

    Ok(())
}

fn spawn_daemon_connection_worker(
    daemon_connection: DaemonConnection,
    db_path: String,
    endpoint: TransportEndpoint,
    intro_spawner: IntroSpawnerFn,
    shutdown: CancellationToken,
    sync_control: Option<std::sync::Arc<crate::runtime::sync_control::SyncControlRegistry>>,
    connection_lease: super::LiveDaemonConnectionLease,
) {
    std::thread::spawn(move || {
        let _connection_lease = connection_lease;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("connect daemon worker runtime");
        let local = tokio::task::LocalSet::new();
        runtime.block_on(local.run_until(async move {
            intro_spawner(
                daemon_connection.connection(),
                db_path.clone(),
                daemon_connection.remote_daemon_peer_id().to_string(),
                endpoint,
            );

            let responder_handler =
                SyncConnectionHandler::responder(db_path.clone(), SYNC_SESSION_TIMEOUT_SECS)
                    .with_sync_control(sync_control.clone());
            supervise_inbound_daemon_connection(
                &db_path,
                &daemon_connection,
                &responder_handler,
                shutdown,
            )
            .await;
        }));
    });
}

fn record_authenticated_outbound_session(
    db_path: &str,
    recorded_by: &str,
    auth_result: &crate::transport::OutboundSessionAuthResult,
    remote_addr: &SocketAddr,
) {
    let now = current_timestamp_ms();
    if let Ok(db) = open_connection(db_path) {
        let _ = record_endpoint_observation(
            &db,
            recorded_by,
            &auth_result.session_peer_id,
            &remote_addr.ip().to_string(),
            remote_addr.port(),
            now,
            ENDPOINT_TTL_MS,
        );
        if let Some(ref canonical_remote_peer_id) = auth_result.canonical_remote_peer_id {
            if let Some(remote_daemon_fp) = peer_fingerprint_from_hex(&auth_result.remote_daemon_peer_id)
            {
                let _ = record_transport_binding(
                    &db,
                    recorded_by,
                    canonical_remote_peer_id,
                    &remote_daemon_fp,
                );
            }
        }
        let _ = purge_expired_endpoints(&db, now);
    }
}

fn describe_connect_failure(remote: SocketAddr, err: &ConnectionLifecycleError) -> String {
    match err {
        ConnectionLifecycleError::DialTrustRejected(msg) => {
            let fp = msg
                .split("peer fingerprint ")
                .nth(1)
                .and_then(|s| s.split_whitespace().next())
                .unwrap_or("unknown");
            format!(
                "Certificate mismatch connecting to {}: TLS fingerprint {} is not trusted.",
                remote, fp
            )
        }
        ConnectionLifecycleError::Dial(msg) => {
            let m = msg.to_ascii_lowercase();
            if m.contains("connection refused") {
                format!("Connection refused by {}: nothing is listening there", remote)
            } else if m.contains("timed out") || m.contains("timeout") {
                format!(
                    "Connection to {} timed out: the peer may be offline or unreachable",
                    remote
                )
            } else if m.contains("network is unreachable") || m.contains("no route to host") {
                format!("Cannot reach {}: network is unreachable", remote)
            } else if m.contains("host unreachable") || m.contains("unreachable") {
                format!("Host {} is unreachable", remote)
            } else {
                format!("Failed to connect to {}: {}", remote, msg)
            }
        }
        ConnectionLifecycleError::Accept(msg) => {
            format!("Unexpected accept error during outbound dial to {}: {}", remote, msg)
        }
        ConnectionLifecycleError::MissingPeerIdentity => {
            format!(
                "Connected to {} but peer did not present a TLS certificate",
                remote
            )
        }
    }
}

fn describe_session_auth_failure(
    remote: SocketAddr,
    remote_peer_id: &str,
    err: &(dyn std::error::Error + Send + Sync),
) -> String {
    let msg = err.to_string();
    if let Some((expected, presented)) = msg
        .strip_prefix("connected daemon fingerprint mismatch: expected ")
        .and_then(|rest| rest.split_once(", got "))
    {
        return format!(
            "Certificate mismatch connecting to {}: expected daemon fingerprint {}, got {}.",
            remote, expected, presented
        );
    }
    format!(
        "Failed to authenticate session to {} for remote principal {}: {}",
        remote, remote_peer_id, msg
    )
}

fn is_stale_dial_failure(err: &ConnectionLifecycleError) -> bool {
    match err {
        ConnectionLifecycleError::Dial(msg) => {
            let m = msg.to_ascii_lowercase();
            m.contains("timed out")
                || m.contains("timeout")
                || m.contains("connection refused")
                || m.contains("network is unreachable")
                || m.contains("no route to host")
                || m.contains("unreachable")
        }
        ConnectionLifecycleError::DialTrustRejected(_) => false,
        ConnectionLifecycleError::Accept(_) | ConnectionLifecycleError::MissingPeerIdentity => {
            false
        }
    }
}

fn should_warn_for_connect_failure(
    has_connected_once: bool,
    err: &ConnectionLifecycleError,
) -> bool {
    has_connected_once || !is_stale_dial_failure(err)
}

struct DialOutcome {
    daemon_connection: DaemonConnection,
}

async fn dial_daemon_ongoing_first(
    endpoint: &TransportEndpoint,
    remote: SocketAddr,
    sni: &str,
    ongoing_client_config: Option<&TransportClientConfig>,
    bootstrap_fallback_client_config: Option<&TransportClientConfig>,
) -> Result<DialOutcome, ConnectionLifecycleError> {
    match dial_daemon_connection(endpoint, remote, sni, ongoing_client_config).await {
        Ok(daemon_connection) => Ok(DialOutcome { daemon_connection }),
        Err(primary_err) => {
            let decision = derive_bootstrap_dial_context(
                Some(&primary_err),
                bootstrap_fallback_client_config.is_some(),
            );
            if decision.mode != BootstrapDialMode::BootstrapFallback {
                return Err(primary_err);
            }
            let Some(fallback_cfg) = bootstrap_fallback_client_config else {
                return Err(primary_err);
            };
            let daemon_connection =
                dial_daemon_connection(endpoint, remote, sni, Some(fallback_cfg)).await?;
            Ok(DialOutcome { daemon_connection })
        }
    }
}
