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
    dial_daemon_connection_target, load_daemon_identity_from_db,
    resolve_outbound_session_auth_plan, send_outbound_session_auth, ConnectionLifecycleError,
    DaemonConnection, OutboundSessionAuthPlan, SessionClass, TransportEndpoint,
};

use super::supervisor::{run_startup_preflight, supervise_inbound_daemon_connection};
use super::{
    claim_live_daemon_connection_slot, claim_live_session_peer, current_timestamp_ms,
    evict_live_daemon_connection, live_daemon_connection, peer_fingerprint_from_hex,
    CONNECT_RETRY_DELAY, ENDPOINT_TTL_MS, SYNC_SESSION_TIMEOUT_SECS,
};

pub(crate) const STALE_DIAL_TARGET_MARKER: &str = "stale_dial_target";
const STALE_DIAL_FAILURE_THRESHOLD: u32 = 8;
const REPEATED_WARNING_WINDOW: Duration = Duration::from_secs(300);

fn is_connection_lost_message(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("connection lost")
        || lower.contains("closed by peer")
        || lower.contains("application closed")
        || lower.contains("broken pipe")
        || lower.contains("reset by peer")
}

fn should_evict_closed_daemon_connection(
    daemon_connection: &DaemonConnection,
    message: &str,
) -> bool {
    is_connection_lost_message(message) && daemon_connection.connection().close_reason().is_some()
}

pub struct ConnectLoopConfig {
    pub db_path: String,
    pub recorded_by: String,
    pub endpoint: TransportEndpoint,
    pub remote: Option<SocketAddr>,
    pub remote_session_peer_id: String,
    pub ingest: IngestFns,
    pub shutdown: Option<CancellationToken>,
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
            config
                .auth_plan
                .unwrap_or_else(|| OutboundSessionAuthPlan::PeerShared {
                    target_peer_id: config.remote_session_peer_id.clone(),
                }),
            shutdown,
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
    remote: Option<SocketAddr>,
    remote_session_peer_id: &str,
    expected_remote_daemon_peer_id: &str,
    auth_plan: OutboundSessionAuthPlan,
    shutdown: CancellationToken,
    sync_control: Option<std::sync::Arc<crate::runtime::sync_control::SyncControlRegistry>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut has_connected_once = false;
    let mut announced_connecting = false;
    let mut consecutive_stale_dial_failures: u32 = 0;
    let mut warning_gate = RepeatedWarningGate::new(REPEATED_WARNING_WINDOW);
    let mut last_outbound_window_scope = None;
    let mut live_session_peer_registration = None;

    let remote_target = describe_remote_target(remote, expected_remote_daemon_peer_id);

    loop {
        if shutdown.is_cancelled() {
            break;
        }

        let daemon_connection = if let Some(existing) =
            live_daemon_connection(db_path, expected_remote_daemon_peer_id)
        {
            existing
        } else {
            if !announced_connecting {
                info!(
                    "Connecting daemon {} via {}...",
                    super::short_peer_id(expected_remote_daemon_peer_id),
                    remote_target
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
                    expected_remote_daemon_peer_id,
                ) => outcome,
            } {
                Ok(outcome) => outcome,
                Err(e) => {
                    let message = describe_connect_failure(&remote_target, &e);
                    let warn_on_startup_stale_failure =
                        matches!(auth_plan, OutboundSessionAuthPlan::InviteBootstrap { .. });
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
                                STALE_DIAL_TARGET_MARKER,
                                remote_target,
                                consecutive_stale_dial_failures,
                                e
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
                    if should_evict_closed_daemon_connection(&daemon_connection, &err.to_string()) {
                        daemon_connection
                            .connection()
                            .close(0u32.into(), b"outbound session open lost connection");
                        evict_live_daemon_connection(
                            db_path,
                            daemon_connection.remote_daemon_peer_id(),
                            connection_id,
                        );
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
                Some(&daemon_connection),
                daemon_connection.remote_daemon_peer_id(),
                Some(expected_remote_daemon_peer_id),
                &effective_auth_plan,
            )
            .await
            {
                Ok(auth_result) => auth_result,
                Err(e) => {
                    if should_evict_closed_daemon_connection(&daemon_connection, &e.to_string()) {
                        daemon_connection
                            .connection()
                            .close(0u32.into(), b"outbound session auth lost connection");
                        evict_live_daemon_connection(
                            db_path,
                            daemon_connection.remote_daemon_peer_id(),
                            connection_id,
                        );
                    }
                    let message =
                        describe_session_auth_failure(&remote_target, remote_session_peer_id, &*e);
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

pub(super) fn spawn_daemon_connection_worker(
    daemon_connection: DaemonConnection,
    db_path: String,
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
            if let Some(remote_daemon_fp) =
                peer_fingerprint_from_hex(&auth_result.remote_daemon_peer_id)
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

fn describe_remote_target(
    remote: Option<SocketAddr>,
    expected_remote_daemon_peer_id: &str,
) -> String {
    match remote {
        Some(remote) => remote.to_string(),
        None => format!(
            "iroh lookup for {}",
            super::short_peer_id(expected_remote_daemon_peer_id)
        ),
    }
}

fn describe_connect_failure(remote: &str, err: &ConnectionLifecycleError) -> String {
    match err {
        ConnectionLifecycleError::Dial(msg) => {
            let m = msg.to_ascii_lowercase();
            if m.contains("connection refused") {
                format!(
                    "Connection refused by {}: nothing is listening there",
                    remote
                )
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
            format!(
                "Unexpected accept error during outbound dial to {}: {}",
                remote, msg
            )
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
    remote: &str,
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
    remote: Option<SocketAddr>,
    sni: &str,
) -> Result<DialOutcome, ConnectionLifecycleError> {
    let daemon_connection = dial_daemon_connection_target(endpoint, remote, sni).await?;
    Ok(DialOutcome { daemon_connection })
}
