//! Connect-side loops: outbound QUIC connections and initiator sync runs.

use std::net::SocketAddr;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::contracts::event_pipeline_contract::IngestFns;
use crate::contracts::peering_contract::SessionDirection;
use crate::db::health::{purge_expired_endpoints, record_endpoint_observation};
use crate::db::open_connection;
use crate::db::transport_trust::record_transport_binding;
use crate::runtime::repeated_warning::{should_emit_globally, RepeatedWarningGate};
use crate::sync::session::dependency_session::spawn_outbound_dependency_session;
use crate::sync::session::windowing::reset_outbound_window_state;
use crate::sync::SyncConnectionHandler;
use crate::transport::{
    derive_bootstrap_dial_context, dial_session_provider, resolve_bootstrap_inviter_peer_id,
    send_outbound_session_auth, BootstrapDialMode, ConnectionLifecycleError,
    OutboundSessionAuthPlan, SessionProvider, TransportClientConfig, TransportEndpoint,
    COVER_SERVER_NAME,
};

use super::supervisor::{
    run_startup_preflight, supervise_connection_sessions, SessionTenantResolver,
};
use super::{
    claim_live_connection_slot, current_timestamp_ms, peer_fingerprint_from_hex, IntroSpawnerFn,
    CONNECT_RETRY_DELAY, ENDPOINT_TTL_MS, SYNC_SESSION_TIMEOUT_SECS,
};

pub(crate) const STALE_DIAL_TARGET_MARKER: &str = "stale_dial_target";
const STALE_DIAL_FAILURE_THRESHOLD: u32 = 8;
const REPEATED_WARNING_WINDOW: Duration = Duration::from_secs(300);

// ---------------------------------------------------------------------------
// Connect loop
// ---------------------------------------------------------------------------

/// Configuration for the outbound connect loop.
///
/// Required fields describe the peer to connect to. Optional fields control
/// cancellation, bootstrap fallback, and sync control integration.
pub struct ConnectLoopConfig {
    pub db_path: String,
    pub recorded_by: String,
    pub endpoint: TransportEndpoint,
    pub remote: SocketAddr,
    pub remote_transport_peer_id: String,
    pub client_config: Option<TransportClientConfig>,
    pub intro_spawner: IntroSpawnerFn,
    pub ingest: IngestFns,
    /// Cancellation token; if omitted a no-op token is used.
    pub shutdown: Option<CancellationToken>,
    /// Fallback TLS config for bootstrap-phase dials.
    pub bootstrap_fallback_client_config: Option<TransportClientConfig>,
    /// Sync control registry for manual trigger support.
    pub sync_control: Option<std::sync::Arc<crate::runtime::sync_control::SyncControlRegistry>>,
    /// Session auth plan; defaults to PeerShared targeting remote_transport_peer_id.
    pub auth_plan: Option<OutboundSessionAuthPlan>,
    /// Expected remote daemon peer ID; defaults to remote_transport_peer_id.
    pub expected_remote_daemon_peer_id: Option<String>,
}

/// Connect to a remote peer and run initiator sync over that connection.
///
/// Outer loop reconnects on connection drop. Each authenticated connection
/// runs one long-lived sync control/data lane set with repeated discovery
/// rounds inside it.
///
/// When `client_config` is `Some`, outbound dials present the correct per-tenant
/// cert and tenant-scoped trust.
pub async fn connect_loop(
    config: ConnectLoopConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tenants = vec![config.recorded_by.clone()];
    run_startup_preflight(&config.db_path, &tenants, config.ingest)?;

    let shutdown = config.shutdown.unwrap_or_default();
    // Use LocalSet so the intro listener (spawn_intro_listener uses spawn_local)
    // can run on the same runtime that drives the endpoint I/O.
    let local = tokio::task::LocalSet::new();
    local
        .run_until(connect_loop_inner(
            &config.db_path,
            &config.recorded_by,
            config.endpoint,
            config.remote,
            &config.remote_transport_peer_id,
            config.expected_remote_daemon_peer_id.as_deref().unwrap_or(&config.remote_transport_peer_id),
            config.auth_plan.unwrap_or_else(|| OutboundSessionAuthPlan::PeerShared {
                target_peer_id: config.remote_transport_peer_id.clone(),
            }),
            config.client_config,
            config.intro_spawner,
            shutdown,
            config.bootstrap_fallback_client_config,
            config.sync_control,
        ))
        .await
}

async fn connect_loop_inner(
    db_path: &str,
    recorded_by: &str,
    endpoint: TransportEndpoint,
    remote: SocketAddr,
    remote_peer_id: &str,
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
    loop {
        if shutdown.is_cancelled() {
            break;
        }

        if !announced_connecting {
            info!("Connecting to {}...", remote);
            announced_connecting = true;
        }
        let dial_outcome = match tokio::select! {
            _ = shutdown.cancelled() => {
                break;
            }
            outcome = dial_provider_ongoing_first(
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
                        // Startup dials suppress noisy one-off stale-target warnings before the
                        // first successful connection, but once we decide the target is stale we
                        // still need to emit the human-readable diagnosis once.
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
        has_connected_once = true;
        announced_connecting = false;
        consecutive_stale_dial_failures = 0;
        warning_gate.clear();
        let mut provider = dial_outcome.provider;
        let used_bootstrap_fallback = dial_outcome.used_bootstrap_fallback;
        let connection = provider.connection();
        let auth_result = match send_outbound_session_auth(
            &connection,
            db_path,
            recorded_by,
            Some(expected_remote_daemon_peer_id),
            &auth_plan,
        )
        .await
        {
            Ok(auth_result) => auth_result,
            Err(e) => {
                let message = describe_session_auth_failure(remote, remote_peer_id, &*e);
                if warning_gate.should_emit(message.clone())
                    && should_emit_globally(format!("connect:{message}"))
                {
                    warn!("{}", message);
                }
                connection.close(1u32.into(), b"session auth failed");
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(CONNECT_RETRY_DELAY) => {}
                }
                continue;
            }
        };
        provider = provider.with_peer_id(auth_result.session_peer_id.clone());
        let peer_id = provider.peer_id().to_string();
        let peer_fp = match peer_fingerprint_from_hex(&peer_id) {
            Some(fp) => fp,
            None => {
                let message = format!(
                    "Could not decode peer fingerprint from identity {}, retrying...",
                    &peer_id[..16.min(peer_id.len())]
                );
                if warning_gate.should_emit(message.clone())
                    && should_emit_globally(format!("connect:{message}"))
                {
                    warn!("{}", message);
                }
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(CONNECT_RETRY_DELAY) => {}
                }
                continue;
            }
        };
        let connection_lease = match claim_live_connection_slot(
            db_path,
            recorded_by,
            &peer_id,
            SessionDirection::Outbound,
            connection.clone(),
        ) {
            super::LiveConnectionClaim::Acquired(lease) => Some(lease),
            super::LiveConnectionClaim::Occupied(occupied) => {
                info!(
                    "Closing duplicate outbound connection to {} (active_direction={:?}, preferred_direction={:?})",
                    peer_id,
                    occupied.active_direction,
                    occupied.preferred_direction
                );
                connection.close(0u32.into(), b"duplicate peer connection");
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = occupied.released.notified() => {}
                    _ = tokio::time::sleep(CONNECT_RETRY_DELAY) => {}
                }
                continue;
            }
        };
        info!(
            "Connected to {} on connection {}",
            peer_id,
            connection.stable_id()
        );
        // Handler state is scoped to this authenticated connection so any
        // connection-lifetime sync state is dropped when the connection is.
        let initiator_handler =
            SyncConnectionHandler::outbound(db_path.to_string(), SYNC_SESSION_TIMEOUT_SECS)
                .with_sync_control(sync_control.clone());
        reset_outbound_window_state(db_path, recorded_by, &peer_id);

        // Record endpoint observation, transport binding, and purge expired
        {
            let remote_addr = connection.remote_address();
            let now = current_timestamp_ms();
            if let Ok(db) = open_connection(db_path) {
                let _ = record_endpoint_observation(
                    &db,
                    recorded_by,
                    &peer_id,
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
                let purged = purge_expired_endpoints(&db, now).unwrap_or(0);
                if purged > 0 {
                    info!("Purged {} expired endpoint observations", purged);
                }
            }
        }

        // Spawn intro listener for uni-streams on this connection
        let _intro_handle = intro_spawner(
            connection.clone(),
            db_path.to_string(),
            recorded_by.to_string(),
            peer_id.clone(),
            endpoint.clone(),
            if used_bootstrap_fallback {
                bootstrap_fallback_client_config.clone()
            } else {
                client_config.clone()
            },
        );

        let _dependency_handle = spawn_outbound_dependency_session(
            connection.clone(),
            db_path.to_string(),
            recorded_by.to_string(),
            peer_id.clone(),
            connection.remote_address(),
            shutdown.child_token(),
        );

        // Keep session scope pinned to the planner-assigned tenant.
        // Transport cert rotation can lag tenant scoping during bootstrap.
        let tenant_resolver = SessionTenantResolver::Fixed(recorded_by.to_string());
        supervise_connection_sessions(
            db_path,
            &peer_id,
            peer_fp,
            &provider,
            &initiator_handler,
            SessionDirection::Outbound,
            &tenant_resolver,
            shutdown.clone(),
        )
        .await;

        if let OutboundSessionAuthPlan::InviteBootstrap { invite_event_id } = &auth_plan {
            if let Ok(db) = open_connection(db_path) {
                if let Ok(Some(canonical_remote_peer_id)) =
                    resolve_bootstrap_inviter_peer_id(&db, recorded_by, invite_event_id)
                {
                    let remote_addr = connection.remote_address();
                    let now = current_timestamp_ms();
                    let _ = record_endpoint_observation(
                        &db,
                        recorded_by,
                        &canonical_remote_peer_id,
                        &remote_addr.ip().to_string(),
                        remote_addr.port(),
                        now,
                        ENDPOINT_TTL_MS,
                    );
                    if let Some(remote_daemon_fp) =
                        peer_fingerprint_from_hex(&auth_result.remote_daemon_peer_id)
                    {
                        let _ = record_transport_binding(
                            &db,
                            recorded_by,
                            &canonical_remote_peer_id,
                            &remote_daemon_fp,
                        );
                    }
                }
            }
        }
        drop(connection_lease);
    }

    Ok(())
}

/// Produce a human-readable diagnosis for a connection failure.
fn describe_connect_failure(remote: SocketAddr, err: &ConnectionLifecycleError) -> String {
    match err {
        ConnectionLifecycleError::DialTrustRejected(msg) => {
            // Extract the fingerprint from "trust_rejected: peer fingerprint <hex> not in authorized set"
            let fp = msg
                .split("peer fingerprint ")
                .nth(1)
                .and_then(|s| s.split_whitespace().next())
                .unwrap_or("unknown");
            format!(
                "Certificate mismatch connecting to {}: TLS fingerprint {} is not trusted. \
                 Either (a) the remote peer's certificate does not match the expected fingerprint, \
                 or (b) the remote rejected our certificate. This usually means: (1) transport \
                 identity has not been derived yet (bootstrap in progress), (2) the invite was \
                 created by a different peer, or (3) a certificate was rotated",
                remote, fp
            )
        }
        ConnectionLifecycleError::Dial(msg) => {
            let m = msg.to_ascii_lowercase();
            if m.contains("connection refused") {
                format!(
                    "Connection refused by {}: nothing is listening on that address. \
                     Is the peer's daemon running? (start it with: topo start)",
                    remote
                )
            } else if m.contains("timed out") || m.contains("timeout") {
                format!(
                    "Connection to {} timed out: the peer may be offline, \
                     behind a firewall, or the address may be stale",
                    remote
                )
            } else if m.contains("network is unreachable") || m.contains("no route to host") {
                format!(
                    "Cannot reach {}: network is unreachable. Check that the peer's \
                     address is correct and that you have network connectivity to it",
                    remote
                )
            } else if m.contains("host unreachable") || m.contains("unreachable") {
                format!(
                    "Host {} is unreachable. The address may be on a different network \
                     or the peer may be offline",
                    remote
                )
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
                "Connected to {} but peer did not present a TLS certificate. \
                 This should not happen with a topo peer — the remote may not be a topo node",
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
            "Certificate mismatch connecting to {}: expected daemon fingerprint {}, got {}. \
             The invite/bootstrap link may point at the wrong daemon or carry stale daemon identity.",
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
    provider: SessionProvider,
    used_bootstrap_fallback: bool,
}

async fn dial_provider_ongoing_first(
    endpoint: &TransportEndpoint,
    remote: SocketAddr,
    sni: &str,
    ongoing_client_config: Option<&TransportClientConfig>,
    bootstrap_fallback_client_config: Option<&TransportClientConfig>,
) -> Result<DialOutcome, ConnectionLifecycleError> {
    match dial_session_provider(endpoint, remote, sni, ongoing_client_config).await {
        Ok(provider) => Ok(DialOutcome {
            provider,
            used_bootstrap_fallback: false,
        }),
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
            info!(
                "Primary mTLS dial to {} rejected by trust policy; retrying with bootstrap fallback cert",
                remote
            );
            match dial_session_provider(endpoint, remote, sni, Some(fallback_cfg)).await {
                Ok(provider) => Ok(DialOutcome {
                    provider,
                    used_bootstrap_fallback: true,
                }),
                Err(fallback_err) => {
                    // If the fallback error is a stale-dial indicator (timeout,
                    // unreachable, etc.), return it so is_stale_dial_failure()
                    // can count it toward the threshold.  Otherwise prefer the
                    // primary trust-rejection for human-readable diagnostics.
                    if is_stale_dial_failure(&fallback_err) {
                        Err(ConnectionLifecycleError::Dial(format!(
                            "primary and bootstrap-fallback dials both failed to {}: \
                             primary: {}, fallback: {}",
                            remote, primary_err, fallback_err
                        )))
                    } else if matches!(primary_err, ConnectionLifecycleError::DialTrustRejected(_))
                    {
                        Err(primary_err)
                    } else {
                        Err(ConnectionLifecycleError::Dial(format!(
                            "primary and bootstrap-fallback dials both failed to {}: \
                             primary: {}, fallback: {}",
                            remote, primary_err, fallback_err
                        )))
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_policy_allows_typed_trust_rejection_with_fallback_cfg() {
        let err = ConnectionLifecycleError::DialTrustRejected(
            "handshake to 127.0.0.1:4433: trust_rejected: peer fingerprint deadbeef not in authorized set".to_string()
        );
        let decision = derive_bootstrap_dial_context(Some(&err), true);
        assert_eq!(decision.mode, BootstrapDialMode::BootstrapFallback);
    }

    #[test]
    fn fallback_policy_denies_generic_dial_errors() {
        let err = ConnectionLifecycleError::Dial(
            "handshake to 127.0.0.1:4433: connection refused".to_string(),
        );
        let decision = derive_bootstrap_dial_context(Some(&err), true);
        assert_eq!(decision.mode, BootstrapDialMode::Deny);
    }

    #[test]
    fn fallback_policy_denies_trust_rejection_without_cfg() {
        let err = ConnectionLifecycleError::DialTrustRejected(
            "handshake to 127.0.0.1:4433: trust_rejected: peer fingerprint deadbeef not in authorized set".to_string()
        );
        let decision = derive_bootstrap_dial_context(Some(&err), false);
        assert_eq!(decision.mode, BootstrapDialMode::Deny);
    }

    #[test]
    fn stale_classifier_marks_timeout_like_dial_errors() {
        let err =
            ConnectionLifecycleError::Dial("handshake to 127.0.0.1:4433: timed out".to_string());
        assert!(is_stale_dial_failure(&err));
    }

    #[test]
    fn stale_classifier_does_not_mark_trust_rejections() {
        let err = ConnectionLifecycleError::DialTrustRejected(
            "handshake to 127.0.0.1:4433: trust_rejected".to_string(),
        );
        assert!(!is_stale_dial_failure(&err));
    }

    #[test]
    fn startup_stale_dial_failures_do_not_warn_before_first_connection() {
        let err = ConnectionLifecycleError::Dial(
            "handshake to 127.0.0.1:4433: connection refused".to_string(),
        );
        assert!(!should_warn_for_connect_failure(false, &err));
    }

    #[test]
    fn post_connect_stale_dial_failures_warn() {
        let err = ConnectionLifecycleError::Dial(
            "handshake to 127.0.0.1:4433: connection refused".to_string(),
        );
        assert!(should_warn_for_connect_failure(true, &err));
    }

    #[test]
    fn non_stale_connect_failures_still_warn_at_startup() {
        let err = ConnectionLifecycleError::DialTrustRejected(
            "handshake to 127.0.0.1:4433: trust_rejected".to_string(),
        );
        assert!(should_warn_for_connect_failure(false, &err));
    }
}
