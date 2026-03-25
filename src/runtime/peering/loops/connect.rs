//! Connect-side loops: outbound QUIC connections and initiator sync runs.

use std::net::SocketAddr;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::contracts::event_pipeline_contract::IngestFns;
use crate::contracts::peering_contract::SessionDirection;
use crate::event_modules::operational::outbound_connection_closed::record_outbound_connection_closed;
use crate::event_modules::operational::outbound_connection_failed::{
    check_stale_dial_state, describe_connect_failure, dial_provider_with_bootstrap_policy,
    failure_kind, is_stale_dial_failure, observe_outbound_authenticated_connection,
    record_outbound_connection_failed, should_warn_for_connect_failure,
    OutboundConnectionObservation,
};
use crate::runtime::repeated_warning::{should_emit_globally, RepeatedWarningGate};
use crate::state::startup_reconcile::run_startup_preflight;
use crate::sync::session::dependency_session::spawn_outbound_dependency_session;
use crate::sync::session::windowing::reset_outbound_window_state;
use crate::sync::SyncConnectionHandler;
use crate::transport::multi_workspace::transport_sni;
use crate::transport::{TransportClientConfig, TransportEndpoint};

use super::supervisor::{supervise_connection_sessions, SessionTenantResolver};
use super::{IntroSpawnerFn, CONNECT_RETRY_DELAY, SYNC_SESSION_TIMEOUT_SECS};

const STALE_DIAL_TARGET_MARKER: &str = "stale_dial_target";
const STALE_DIAL_FAILURE_THRESHOLD: u32 = 8;
const REPEATED_WARNING_WINDOW: Duration = Duration::from_secs(300);

// ---------------------------------------------------------------------------
// Connect loops
// ---------------------------------------------------------------------------

/// Connect to a remote peer and run initiator sync over that connection.
///
/// Outer loop reconnects on connection drop. Each authenticated connection
/// runs one long-lived sync control/data lane set with repeated discovery
/// rounds inside it.
///
/// When `client_config` is `Some`, outbound dials present the correct per-tenant
/// cert and tenant-scoped trust.
///
pub async fn connect_loop(
    db_path: &str,
    recorded_by: &str,
    endpoint: TransportEndpoint,
    remote: SocketAddr,
    remote_transport_peer_id: &str,
    client_config: Option<TransportClientConfig>,
    intro_spawner: IntroSpawnerFn,
    ingest: IngestFns,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    connect_loop_with_coordination(
        db_path,
        recorded_by,
        endpoint,
        remote,
        remote_transport_peer_id,
        client_config,
        intro_spawner,
        ingest,
    )
    .await
}

pub async fn connect_loop_with_coordination(
    db_path: &str,
    recorded_by: &str,
    endpoint: TransportEndpoint,
    remote: SocketAddr,
    remote_transport_peer_id: &str,
    client_config: Option<TransportClientConfig>,
    intro_spawner: IntroSpawnerFn,
    ingest: IngestFns,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    connect_loop_with_coordination_until_cancel(
        db_path,
        recorded_by,
        endpoint,
        remote,
        remote_transport_peer_id,
        client_config,
        intro_spawner,
        ingest,
        CancellationToken::new(),
    )
    .await
}

pub async fn connect_loop_with_coordination_until_cancel(
    db_path: &str,
    recorded_by: &str,
    endpoint: TransportEndpoint,
    remote: SocketAddr,
    remote_transport_peer_id: &str,
    client_config: Option<TransportClientConfig>,
    intro_spawner: IntroSpawnerFn,
    ingest: IngestFns,
    shutdown: CancellationToken,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    connect_loop_with_coordination_until_cancel_with_fallback(
        db_path,
        recorded_by,
        endpoint,
        remote,
        remote_transport_peer_id,
        client_config,
        intro_spawner,
        ingest,
        shutdown,
        None,
        None,
        None,
    )
    .await
}

/// Coordinated connect loop with explicit cancellation and an optional
/// bootstrap-fallback client config.
pub async fn connect_loop_with_coordination_until_cancel_with_fallback(
    db_path: &str,
    recorded_by: &str,
    endpoint: TransportEndpoint,
    remote: SocketAddr,
    remote_transport_peer_id: &str,
    client_config: Option<TransportClientConfig>,
    intro_spawner: IntroSpawnerFn,
    ingest: IngestFns,
    shutdown: CancellationToken,
    bootstrap_fallback_client_config: Option<TransportClientConfig>,
    connection_plan_id: Option<String>,
    sync_control: Option<std::sync::Arc<crate::runtime::sync_control::SyncControlRegistry>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tenants = vec![recorded_by.to_string()];
    run_startup_preflight(db_path, &tenants, ingest)?;

    // Use LocalSet so the intro listener (spawn_intro_listener uses spawn_local)
    // can run on the same runtime that drives the endpoint I/O.
    let local = tokio::task::LocalSet::new();
    local
        .run_until(connect_loop_inner(
            db_path,
            recorded_by,
            endpoint,
            remote,
            remote_transport_peer_id,
            client_config,
            intro_spawner,
            shutdown,
            bootstrap_fallback_client_config,
            connection_plan_id,
            sync_control,
        ))
        .await
}

async fn connect_loop_inner(
    db_path: &str,
    recorded_by: &str,
    endpoint: TransportEndpoint,
    remote: SocketAddr,
    remote_transport_peer_id: &str,
    client_config: Option<TransportClientConfig>,
    intro_spawner: IntroSpawnerFn,
    shutdown: CancellationToken,
    bootstrap_fallback_client_config: Option<TransportClientConfig>,
    connection_plan_id: Option<String>,
    sync_control: Option<std::sync::Arc<crate::runtime::sync_control::SyncControlRegistry>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let sni = transport_sni(remote_transport_peer_id);
    // In-memory counters are a fallback for the legacy path (no connection_plan_id).
    // When a plan id is present, stale-dial state is derived from projected history.
    let mut fallback_has_connected_once = false;
    let mut fallback_stale_failures: u32 = 0;
    let mut warning_gate = RepeatedWarningGate::new(REPEATED_WARNING_WINDOW);
    loop {
        if shutdown.is_cancelled() {
            break;
        }

        let dial_outcome = match tokio::select! {
            _ = shutdown.cancelled() => {
                break;
            }
            outcome = dial_provider_with_bootstrap_policy(
                &endpoint,
                remote,
                &sni,
                client_config.as_ref(),
                bootstrap_fallback_client_config.as_ref(),
            ) => outcome,
        } {
            Ok(outcome) => outcome,
            Err(failure) => {
                let message = describe_connect_failure(remote, &failure.error);
                if let Some(connection_plan_id) = connection_plan_id.as_deref() {
                    if let Err(err) = record_outbound_connection_failed(
                        db_path,
                        connection_plan_id,
                        failure_kind(&failure.error),
                        Some(message.as_str()),
                        failure.used_bootstrap_fallback,
                    ) {
                        warn!(
                            "failed to record outbound_connection_failed for {}: {}",
                            connection_plan_id, err
                        );
                    }
                }

                // Derive stale-dial state from projected history when plan is available,
                // otherwise fall back to in-memory counters.
                let (has_connected_once, stale_terminal) =
                    if let Some(connection_plan_id) = connection_plan_id.as_deref() {
                        match check_stale_dial_state(
                            db_path,
                            connection_plan_id,
                            STALE_DIAL_FAILURE_THRESHOLD,
                        ) {
                            Ok(state) => (state.has_connected_once, state.terminal_stale_count),
                            Err(err) => {
                                warn!(
                                    "failed to check stale dial state for {}: {}",
                                    connection_plan_id, err
                                );
                                // Degrade gracefully to in-memory counters
                                if is_stale_dial_failure(&failure.error) {
                                    fallback_stale_failures += 1;
                                } else {
                                    fallback_stale_failures = 0;
                                }
                                let terminal = if fallback_stale_failures
                                    >= STALE_DIAL_FAILURE_THRESHOLD
                                {
                                    Some(fallback_stale_failures)
                                } else {
                                    None
                                };
                                (fallback_has_connected_once, terminal)
                            }
                        }
                    } else {
                        // Legacy path: no plan id, use in-memory counters
                        if is_stale_dial_failure(&failure.error) {
                            fallback_stale_failures += 1;
                        } else {
                            fallback_stale_failures = 0;
                        }
                        let terminal =
                            if fallback_stale_failures >= STALE_DIAL_FAILURE_THRESHOLD {
                                Some(fallback_stale_failures)
                            } else {
                                None
                            };
                        (fallback_has_connected_once, terminal)
                    };

                let warn_on_startup_stale_failure = bootstrap_fallback_client_config.is_some();
                if (should_warn_for_connect_failure(has_connected_once, &failure.error)
                    || warn_on_startup_stale_failure)
                    && warning_gate.should_emit(message.clone())
                    && should_emit_globally(format!("connect:{message}"))
                {
                    warn!("{}", message);
                }
                if let Some(stale_count) = stale_terminal {
                    if warning_gate.should_emit(message.clone())
                        && should_emit_globally(format!("connect:{message}"))
                    {
                        warn!("{}", message);
                    }
                    return Err(std::io::Error::other(format!(
                        "{} remote={} failures={} last_error={}",
                        STALE_DIAL_TARGET_MARKER, remote, stale_count, failure.error
                    ))
                    .into());
                }
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(CONNECT_RETRY_DELAY) => {}
                }
                continue;
            }
        };
        fallback_has_connected_once = true;
        fallback_stale_failures = 0;
        warning_gate.clear();
        let provider = dial_outcome.provider;
        let used_bootstrap_fallback = dial_outcome.used_bootstrap_fallback;
        let connection = provider.connection();
        let peer_id = provider.peer_id().to_string();
        let (connection_lease, peer_fp) = match observe_outbound_authenticated_connection(
            db_path,
            recorded_by,
            &peer_id,
            &connection,
            connection_plan_id.as_deref(),
            used_bootstrap_fallback,
        ) {
            Ok(OutboundConnectionObservation::Authenticated { lease, peer_fp }) => (lease, peer_fp),
            Ok(OutboundConnectionObservation::Occupied { released }) => {
                connection.close(0u32.into(), b"duplicate peer connection");
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = released.notified() => {}
                    _ = tokio::time::sleep(CONNECT_RETRY_DELAY) => {}
                }
                continue;
            }
            Ok(OutboundConnectionObservation::Retry { detail }) => {
                if warning_gate.should_emit(detail.clone())
                    && should_emit_globally(format!("connect:{detail}"))
                {
                    warn!("{}", detail);
                }
                connection.close(1u32.into(), b"invalid peer fingerprint");
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(CONNECT_RETRY_DELAY) => {}
                }
                continue;
            }
            Err(err) => {
                warn!(
                    "failed to observe outbound authenticated connection remote={} plan={:?}: {}",
                    remote, connection_plan_id, err
                );
                connection.close(1u32.into(), b"outbound connection event authoring failed");
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(CONNECT_RETRY_DELAY) => {}
                }
                continue;
            }
        };
        // Handler state is scoped to this authenticated connection so any
        // connection-lifetime sync state is dropped when the connection is.
        let initiator_handler =
            SyncConnectionHandler::outbound(db_path.to_string(), SYNC_SESSION_TIMEOUT_SECS)
                .with_sync_control(sync_control.clone());
        reset_outbound_window_state(db_path, recorded_by, &peer_id);

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
        let outcome = supervise_connection_sessions(
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
        if let Some(connection_plan_id) = connection_plan_id.as_deref() {
            if let Err(err) = record_outbound_connection_closed(
                db_path,
                connection_plan_id,
                &peer_id,
                connection.remote_address(),
                outcome.close_reason(),
            ) {
                warn!(
                    "failed to record outbound_connection_closed for {}: {}",
                    connection_plan_id, err
                );
            }
        }
        drop(connection_lease);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_policy_allows_typed_trust_rejection_with_fallback_cfg() {
        let err = crate::transport::ConnectionLifecycleError::DialTrustRejected(
            "handshake to 127.0.0.1:4433: trust_rejected: peer fingerprint deadbeef not in authorized set".to_string()
        );
        assert_eq!(
            crate::event_modules::operational::outbound_connection_failed::bootstrap_fallback_mode(
                Some(&err),
                true,
            ),
            crate::transport::BootstrapDialMode::BootstrapFallback
        );
    }

    #[test]
    fn fallback_policy_denies_generic_dial_errors() {
        let err = crate::transport::ConnectionLifecycleError::Dial(
            "handshake to 127.0.0.1:4433: connection refused".to_string(),
        );
        assert_eq!(
            crate::event_modules::operational::outbound_connection_failed::bootstrap_fallback_mode(
                Some(&err),
                true,
            ),
            crate::transport::BootstrapDialMode::Deny
        );
    }

    #[test]
    fn fallback_policy_denies_trust_rejection_without_cfg() {
        let err = crate::transport::ConnectionLifecycleError::DialTrustRejected(
            "handshake to 127.0.0.1:4433: trust_rejected: peer fingerprint deadbeef not in authorized set".to_string()
        );
        assert_eq!(
            crate::event_modules::operational::outbound_connection_failed::bootstrap_fallback_mode(
                Some(&err),
                false,
            ),
            crate::transport::BootstrapDialMode::Deny
        );
    }

    #[test]
    fn stale_classifier_marks_timeout_like_dial_errors() {
        let err = crate::transport::ConnectionLifecycleError::Dial(
            "handshake to 127.0.0.1:4433: timed out".to_string(),
        );
        assert!(is_stale_dial_failure(&err));
    }

    #[test]
    fn stale_classifier_does_not_mark_trust_rejections() {
        let err = crate::transport::ConnectionLifecycleError::DialTrustRejected(
            "handshake to 127.0.0.1:4433: trust_rejected".to_string(),
        );
        assert!(!is_stale_dial_failure(&err));
    }

    #[test]
    fn startup_stale_dial_failures_do_not_warn_before_first_connection() {
        let err = crate::transport::ConnectionLifecycleError::Dial(
            "handshake to 127.0.0.1:4433: connection refused".to_string(),
        );
        assert!(!should_warn_for_connect_failure(false, &err));
    }

    #[test]
    fn post_connect_stale_dial_failures_warn() {
        let err = crate::transport::ConnectionLifecycleError::Dial(
            "handshake to 127.0.0.1:4433: connection refused".to_string(),
        );
        assert!(should_warn_for_connect_failure(true, &err));
    }

    #[test]
    fn non_stale_connect_failures_still_warn_at_startup() {
        let err = crate::transport::ConnectionLifecycleError::DialTrustRejected(
            "handshake to 127.0.0.1:4433: trust_rejected".to_string(),
        );
        assert!(should_warn_for_connect_failure(false, &err));
    }
}
