//! Connect-side loops: outbound daemon connections and initiator sync runs.

use std::net::SocketAddr;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::contracts::event_pipeline_contract::IngestFns;
use crate::contracts::peering_contract::SessionDirection;
use crate::db::health::{purge_expired_endpoints, record_endpoint_observation};
use crate::db::open_connection;
use crate::db::transport_trust::record_transport_binding;
use crate::runtime::build_mismatch::note_build_mismatch;
use crate::runtime::repeated_warning::{should_emit_globally, RepeatedWarningGate};
use crate::sync::session::windowing::reset_outbound_window_state;
use crate::sync::SyncConnectionHandler;
use crate::transport::session_factory::extract_build_mismatch_reason;
use crate::transport::{
    dial_daemon_connection_target, load_daemon_identity_from_db,
    resolve_bootstrap_fallback_invite_for_daemon, resolve_outbound_session_auth_plan,
    send_outbound_session_auth, ConnectionLifecycleError, DaemonConnection,
    OutboundSessionAuthPlan, SessionClass, TransportEndpoint,
};

use super::supervisor::{
    run_startup_preflight, supervise_inbound_daemon_connection, DaemonConnectionAdmission,
};
use super::{
    claim_live_daemon_connection_slot, claim_live_session_peer, current_timestamp_ms,
    evict_live_daemon_connection, live_daemon_connection, peer_fingerprint_from_hex,
    CONNECT_RETRY_DELAY, ENDPOINT_TTL_MS, SYNC_SESSION_TIMEOUT_SECS,
};

pub(crate) const STALE_DIAL_TARGET_MARKER: &str = "stale_dial_target";
const REPEATED_WARNING_WINDOW: Duration = Duration::from_secs(300);

pub use topo_verus_proofs::runtime::peering::loops::connect::{
    decide_dial_failure_plan, decide_session_open_failure_plan, decide_session_retry_plan,
    normalize_dial_failure_decision_context, normalize_session_open_failure_decision_context,
    normalize_session_retry_decision_context, DialFailurePlan, DialFailureRawRows,
    SessionOpenFailurePlan, SessionOpenFailureRawRows, SessionRetryPlan, SessionRetryRawRows,
};
#[cfg(test)]
use topo_verus_proofs::runtime::peering::loops::connect::{
    should_warn_for_connect_failure, DialFailureDecisionContext,
    SessionOpenFailureDecisionContext, SessionRetryDecisionContext, STALE_DIAL_FAILURE_THRESHOLD,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionAuthFailureRawRows {
    connection_lost: bool,
    bootstrap_retry_invite: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionAuthFailureDecisionContext {
    connection_lost: bool,
    bootstrap_retry_invite: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionAuthFailurePlan {
    next_auth_plan_override: Option<OutboundSessionAuthPlan>,
    evict_live_connection: bool,
}
fn describe_outbound_session_auth_plan(plan: &OutboundSessionAuthPlan) -> String {
    match plan {
        OutboundSessionAuthPlan::PeerShared { target_peer_id } => {
            format!("peer_shared(peer={})", super::short_peer_id(target_peer_id))
        }
        OutboundSessionAuthPlan::InviteBootstrap { invite_event_id } => {
            let short_invite = &invite_event_id[..16.min(invite_event_id.len())];
            format!("invite_bootstrap(invite={short_invite})")
        }
    }
}

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
    let _ = daemon_connection;
    is_connection_lost_message(message)
}

fn normalize_session_auth_failure_decision_context(
    raw_rows: SessionAuthFailureRawRows,
) -> SessionAuthFailureDecisionContext {
    SessionAuthFailureDecisionContext {
        connection_lost: raw_rows.connection_lost,
        bootstrap_retry_invite: raw_rows.bootstrap_retry_invite,
    }
}

/// Runtime wrapper: delegates the core flag/flag decision to the Verus-verified
/// `decide_session_auth_failure_core_plan`, then rehydrates the `Option<String>` invite id
/// into a concrete `OutboundSessionAuthPlan::InviteBootstrap` if the verified plan says to
/// override. The core logic (override ↔ has_retry_invite, evict ↔ connection_lost) is SMT-checked.
fn decide_session_auth_failure_plan(
    context: SessionAuthFailureDecisionContext,
) -> SessionAuthFailurePlan {
    let core = topo_verus_proofs::runtime::peering::loops::connect::decide_session_auth_failure_core_plan(
        topo_verus_proofs::runtime::peering::loops::connect::SessionAuthFailureCoreContext {
            connection_lost: context.connection_lost,
            has_bootstrap_retry_invite: context.bootstrap_retry_invite.is_some(),
        },
    );
    let next_auth_plan_override = if core.next_auth_plan_override {
        context
            .bootstrap_retry_invite
            .map(|invite_event_id| OutboundSessionAuthPlan::InviteBootstrap { invite_event_id })
    } else {
        None
    };
    SessionAuthFailurePlan {
        next_auth_plan_override,
        evict_live_connection: core.evict_live_connection,
    }
}

fn load_session_retry_raw_rows(
    session_stats: Option<&crate::runtime::SyncStats>,
) -> SessionRetryRawRows {
    SessionRetryRawRows {
        session_stats_present: session_stats.is_some(),
    }
}

pub struct ConnectLoopConfig {
    pub db_path: String,
    pub recorded_by: String,
    pub endpoint: TransportEndpoint,
    pub remote: Option<SocketAddr>,
    pub relay_url: Option<String>,
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
            config.relay_url.as_deref(),
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
    relay_url: Option<&str>,
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
    let mut next_auth_plan_override: Option<OutboundSessionAuthPlan> = None;

    let remote_target = describe_remote_target(remote, relay_url, expected_remote_daemon_peer_id);

    loop {
        if shutdown.is_cancelled() {
            break;
        }

        let daemon_connection = if let Some(existing) =
            live_daemon_connection(db_path, expected_remote_daemon_peer_id)
        {
            debug!(
                target: "topo::connection",
                "connect_loop reusing live daemon connection remote={} addr={:?}",
                super::short_peer_id(existing.remote_daemon_peer_id()),
                existing.remote_addr(),
            );
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
                    relay_url,
                    expected_remote_daemon_peer_id,
                ) => outcome,
            } {
                Ok(outcome) => outcome,
                Err(e) => {
                    let message = describe_connect_failure(&remote_target, &e);
                    let dial_failure_plan = decide_dial_failure_plan(
                        &normalize_dial_failure_decision_context(DialFailureRawRows {
                            has_connected_once,
                            stale_dial_failure: is_stale_dial_failure(&e),
                            consecutive_stale_dial_failures,
                            warn_on_startup_stale_failure: matches!(
                                auth_plan,
                                OutboundSessionAuthPlan::InviteBootstrap { .. }
                            ),
                        }),
                    );
                    let (should_warn, next_consecutive_stale_dial_failures, terminal_stale_target) =
                        match dial_failure_plan {
                            DialFailurePlan::ReturnStaleTarget {
                                should_warn,
                                next_consecutive_stale_dial_failures,
                            } => (should_warn, next_consecutive_stale_dial_failures, true),
                            DialFailurePlan::Retry {
                                should_warn,
                                next_consecutive_stale_dial_failures,
                            } => (should_warn, next_consecutive_stale_dial_failures, false),
                        };
                    if should_warn
                        && warning_gate.should_emit(message.clone())
                        && should_emit_globally(format!("connect:{message}"))
                    {
                        warn!("{}", message);
                    }
                    consecutive_stale_dial_failures = next_consecutive_stale_dial_failures;
                    if terminal_stale_target {
                        return Err(std::io::Error::other(format!(
                            "{} remote={} failures={} last_error={}",
                            STALE_DIAL_TARGET_MARKER,
                            remote_target,
                            consecutive_stale_dial_failures,
                            e
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
                    debug!(
                        target: "topo::connection",
                        "connect_loop acquired outbound daemon={} addr={:?}",
                        super::short_peer_id(daemon_connection.remote_daemon_peer_id()),
                        daemon_connection.remote_addr(),
                    );
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
                    debug!(
                        target: "topo::connection",
                        "connect_loop closing duplicate outbound daemon={} active_direction={:?} preferred_direction={:?}",
                        super::short_peer_id(daemon_connection.remote_daemon_peer_id()),
                        occupied.active_direction,
                        occupied.preferred_direction,
                    );
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

        loop {
            if shutdown.is_cancelled() {
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
                    let plan = decide_session_open_failure_plan(
                        &normalize_session_open_failure_decision_context(
                            SessionOpenFailureRawRows {
                                connection_lost: should_evict_closed_daemon_connection(
                                    &daemon_connection,
                                    &err.to_string(),
                                ),
                            },
                        ),
                    );
                    if matches!(plan, SessionOpenFailurePlan::EvictAndBreak) {
                        daemon_connection
                            .connection()
                            .close(0u32.into(), b"outbound session open lost connection");
                        evict_live_daemon_connection(
                            db_path,
                            daemon_connection.remote_daemon_peer_id(),
                            connection_id,
                        );
                    }
                    break;
                }
            };

            let db = open_connection(db_path).ok();
            let effective_auth_plan = next_auth_plan_override.take().unwrap_or_else(|| {
                db.as_ref()
                    .and_then(|conn| {
                        resolve_outbound_session_auth_plan(
                            conn,
                            Some(&daemon_connection),
                            recorded_by,
                            remote_session_peer_id,
                            daemon_connection.remote_daemon_peer_id(),
                            &auth_plan,
                        )
                        .ok()
                    })
                    .unwrap_or_else(|| auth_plan.clone())
            });
            let bootstrap_retry_invite = match &effective_auth_plan {
                OutboundSessionAuthPlan::PeerShared { .. }
                    if !daemon_connection
                        .admits_session_route(recorded_by, remote_session_peer_id) =>
                {
                    db.as_ref()
                        .and_then(|conn| {
                            resolve_bootstrap_fallback_invite_for_daemon(
                                conn,
                                recorded_by,
                                daemon_connection.remote_daemon_peer_id(),
                            )
                            .ok()
                        })
                        .flatten()
                }
                _ => None,
            };

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
                Ok(auth_result) => {
                    debug!(
                        target: "topo::connection",
                        "connect_loop authenticated outbound session daemon={} session_peer={} auth_plan={}",
                        super::short_peer_id(daemon_connection.remote_daemon_peer_id()),
                        super::short_peer_id(&auth_result.session_peer_id),
                        describe_outbound_session_auth_plan(&effective_auth_plan),
                    );
                    next_auth_plan_override = None;
                    auth_result
                }
                Err(e) => {
                    let plan = decide_session_auth_failure_plan(
                        normalize_session_auth_failure_decision_context(
                            SessionAuthFailureRawRows {
                                connection_lost: should_evict_closed_daemon_connection(
                                    &daemon_connection,
                                    &e.to_string(),
                                ),
                                bootstrap_retry_invite,
                            },
                        ),
                    );
                    next_auth_plan_override = plan.next_auth_plan_override.clone();
                    if plan.evict_live_connection {
                        daemon_connection
                            .connection()
                            .close(0u32.into(), b"outbound session auth lost connection");
                        evict_live_daemon_connection(
                            db_path,
                            daemon_connection.remote_daemon_peer_id(),
                            connection_id,
                        );
                    }
                    let message = format!(
                        "{} [auth_plan={}, expected_daemon={}, actual_daemon={}]",
                        describe_session_auth_failure(&remote_target, remote_session_peer_id, &*e),
                        describe_outbound_session_auth_plan(&effective_auth_plan),
                        super::short_peer_id(expected_remote_daemon_peer_id),
                        super::short_peer_id(daemon_connection.remote_daemon_peer_id()),
                    );
                    if warning_gate.should_emit(message.clone())
                        && should_emit_globally(format!("connect:{message}"))
                    {
                        warn!("{}", message);
                    }
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
                session.remote_addr,
            );
            let session_remote_label = session.remote_label.clone();

            let session_stats = super::run_session(
                &initiator_handler,
                session.session_id,
                session.io,
                recorded_by,
                peer_fp,
                session_remote_label,
                SessionDirection::Outbound,
                db_path,
            )
            .await;

            let session_retry_context = normalize_session_retry_decision_context(
                load_session_retry_raw_rows(session_stats.as_ref()),
            );
            let session_retry_plan = decide_session_retry_plan(&session_retry_context);
            let session_retry_delay = match session_retry_plan {
                SessionRetryPlan::NoDelay => Duration::ZERO,
                SessionRetryPlan::DelayMs(ms) => Duration::from_millis(ms as u64),
            };
            if !session_retry_delay.is_zero() {
                tokio::select! {
                    _ = shutdown.cancelled() => {
                        break;
                    }
                    _ = tokio::time::sleep(session_retry_delay) => {}
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
                DaemonConnectionAdmission::KnownDaemonRoute,
            )
            .await;
        }));
    });
}

fn record_authenticated_outbound_session(
    db_path: &str,
    recorded_by: &str,
    auth_result: &crate::transport::OutboundSessionAuthResult,
    remote_addr: Option<SocketAddr>,
) {
    let now = current_timestamp_ms();
    if let Ok(db) = open_connection(db_path) {
        if let Some(remote_addr) = remote_addr {
            let _ = record_endpoint_observation(
                &db,
                recorded_by,
                &auth_result.session_peer_id,
                &remote_addr.ip().to_string(),
                remote_addr.port(),
                now,
                ENDPOINT_TTL_MS,
            );
        }
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
    relay_url: Option<&str>,
    expected_remote_daemon_peer_id: &str,
) -> String {
    match remote {
        Some(remote) => remote.to_string(),
        None => match relay_url {
            Some(relay_url) => format!(
                "iroh relay {relay_url} for {}",
                super::short_peer_id(expected_remote_daemon_peer_id)
            ),
            None => format!(
                "iroh lookup for {}",
                super::short_peer_id(expected_remote_daemon_peer_id)
            ),
        },
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

struct DialOutcome {
    daemon_connection: DaemonConnection,
}

async fn dial_daemon_ongoing_first(
    endpoint: &TransportEndpoint,
    remote: Option<SocketAddr>,
    relay_url: Option<&str>,
    sni: &str,
) -> Result<DialOutcome, ConnectionLifecycleError> {
    let daemon_connection = dial_daemon_connection_target(endpoint, remote, relay_url, sni).await?;
    Ok(DialOutcome { daemon_connection })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::SyncStats;

    #[test]
    fn dial_failure_plan_terminates_after_threshold_stale_failures() {
        assert_eq!(
            decide_dial_failure_plan(&DialFailureDecisionContext {
                has_connected_once: false,
                stale_dial_failure: true,
                consecutive_stale_dial_failures: STALE_DIAL_FAILURE_THRESHOLD - 1,
                warn_on_startup_stale_failure: false,
            }),
            DialFailurePlan::ReturnStaleTarget {
                should_warn: false,
                next_consecutive_stale_dial_failures: STALE_DIAL_FAILURE_THRESHOLD,
            }
        );
    }

    #[test]
    fn connection_lost_classifier_accepts_transport_close_messages() {
        for message in [
            "connection lost during session open",
            "closed by peer while authenticating",
            "application closed by remote daemon",
            "broken pipe while writing auth frame",
            "reset by peer during range sync",
        ] {
            assert!(
                is_connection_lost_message(message),
                "expected transport-close classifier hit for: {message}"
            );
        }
    }

    #[test]
    fn connection_lost_classifier_rejects_nontransport_failures() {
        for message in [
            "permission denied by remote peer",
            "certificate mismatch for daemon fingerprint",
            "session auth rejected by policy",
        ] {
            assert!(
                !is_connection_lost_message(message),
                "unexpected transport-close classifier hit for: {message}"
            );
        }
    }

    #[test]
    fn stale_dial_classifier_accepts_unreachable_dial_errors() {
        for err in [
            ConnectionLifecycleError::Dial("timed out".to_string()),
            ConnectionLifecycleError::Dial("connection refused".to_string()),
            ConnectionLifecycleError::Dial("network is unreachable".to_string()),
            ConnectionLifecycleError::Dial("no route to host".to_string()),
        ] {
            assert!(
                is_stale_dial_failure(&err),
                "expected stale dial classifier hit for: {err}"
            );
        }
    }

    #[test]
    fn stale_dial_classifier_rejects_nonstale_failures() {
        for err in [
            ConnectionLifecycleError::Dial("certificate mismatch".to_string()),
            ConnectionLifecycleError::Accept("listener closed".to_string()),
            ConnectionLifecycleError::MissingPeerIdentity,
        ] {
            assert!(
                !is_stale_dial_failure(&err),
                "unexpected stale dial classifier hit for: {err}"
            );
        }
    }

    #[test]
    fn dial_failure_normalizer_preserves_raw_rows_for_planner() {
        let raw = DialFailureRawRows {
            has_connected_once: true,
            stale_dial_failure: false,
            consecutive_stale_dial_failures: 3,
            warn_on_startup_stale_failure: false,
        };

        let context = normalize_dial_failure_decision_context(raw.clone());

        assert_eq!(
            context,
            DialFailureDecisionContext {
                has_connected_once: raw.has_connected_once,
                stale_dial_failure: raw.stale_dial_failure,
                consecutive_stale_dial_failures: raw.consecutive_stale_dial_failures,
                warn_on_startup_stale_failure: raw.warn_on_startup_stale_failure,
            }
        );
        assert_eq!(
            decide_dial_failure_plan(&context),
            DialFailurePlan::Retry {
                should_warn: true,
                next_consecutive_stale_dial_failures: 0,
            }
        );
    }

    #[test]
    fn session_open_failure_normalizer_preserves_raw_rows_for_planner() {
        for raw in [
            SessionOpenFailureRawRows {
                connection_lost: true,
            },
            SessionOpenFailureRawRows {
                connection_lost: false,
            },
        ] {
            let context = normalize_session_open_failure_decision_context(raw.clone());
            assert_eq!(
                context,
                SessionOpenFailureDecisionContext {
                    connection_lost: raw.connection_lost,
                }
            );
            assert_eq!(
                decide_session_open_failure_plan(&context),
                if raw.connection_lost {
                    SessionOpenFailurePlan::EvictAndBreak
                } else {
                    SessionOpenFailurePlan::Break
                }
            );
        }
    }

    #[test]
    fn session_auth_failure_plan_preserves_bootstrap_retry_override() {
        assert_eq!(
            decide_session_auth_failure_plan(SessionAuthFailureDecisionContext {
                connection_lost: true,
                bootstrap_retry_invite: Some("invite-1".to_string()),
            }),
            SessionAuthFailurePlan {
                next_auth_plan_override: Some(OutboundSessionAuthPlan::InviteBootstrap {
                    invite_event_id: "invite-1".to_string(),
                }),
                evict_live_connection: true,
            }
        );
    }

    #[test]
    fn session_auth_failure_plan_does_not_override_without_retry_invite() {
        for connection_lost in [false, true] {
            assert_eq!(
                decide_session_auth_failure_plan(SessionAuthFailureDecisionContext {
                    connection_lost,
                    bootstrap_retry_invite: None,
                }),
                SessionAuthFailurePlan {
                    next_auth_plan_override: None,
                    evict_live_connection: connection_lost,
                }
            );
        }
    }

    #[test]
    fn session_auth_failure_normalizer_preserves_raw_rows_for_planner() {
        let raw = SessionAuthFailureRawRows {
            connection_lost: false,
            bootstrap_retry_invite: Some("invite-1".to_string()),
        };

        let context = normalize_session_auth_failure_decision_context(raw.clone());

        assert_eq!(
            context,
            SessionAuthFailureDecisionContext {
                connection_lost: raw.connection_lost,
                bootstrap_retry_invite: raw.bootstrap_retry_invite.clone(),
            }
        );
        assert_eq!(
            decide_session_auth_failure_plan(context),
            SessionAuthFailurePlan {
                next_auth_plan_override: Some(OutboundSessionAuthPlan::InviteBootstrap {
                    invite_event_id: "invite-1".to_string(),
                }),
                evict_live_connection: false,
            }
        );
    }

    #[test]
    fn session_retry_normalizer_preserves_raw_rows_for_planner() {
        for raw in [
            SessionRetryRawRows {
                session_stats_present: true,
            },
            SessionRetryRawRows {
                session_stats_present: false,
            },
        ] {
            let context = normalize_session_retry_decision_context(raw.clone());
            assert_eq!(
                context,
                SessionRetryDecisionContext {
                    session_stats_present: raw.session_stats_present,
                }
            );
            assert_eq!(
                decide_session_retry_plan(&context),
                if raw.session_stats_present {
                    SessionRetryPlan::NoDelay
                } else {
                    SessionRetryPlan::DelayMs(250)
                }
            );
        }
    }

    #[test]
    fn session_retry_plan_quiescent_sessions_do_not_back_off() {
        let stats = SyncStats {
            events_sent: 0,
            events_received: 0,
            neg_rounds: 0,
            bytes_sent: 0,
            bytes_received: 0,
            duration_ms: 0,
        };
        assert_eq!(
            decide_session_retry_plan(&normalize_session_retry_decision_context(
                load_session_retry_raw_rows(Some(&stats))
            )),
            SessionRetryPlan::NoDelay
        );
    }
}
