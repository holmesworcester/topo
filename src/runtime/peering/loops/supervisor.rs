//! Unified connect/accept supervision core.
//!
//! This module owns shared loop orchestration:
//! - one long-lived sync connection scope per authenticated connection

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::contracts::peering_contract::SessionDirection;
use crate::runtime::build_mismatch::note_build_mismatch;
use crate::runtime::repeated_warning::should_emit_globally;
use crate::sync::session::dependency_session::run_dependency_session;
use crate::sync::SyncConnectionHandler;
use crate::transport::session_factory::extract_build_mismatch_reason;
use crate::transport::{SessionClass, SessionProvider};

use super::run_session;

/// How a session loop resolves the tenant (`recorded_by`) for each session.
pub(super) enum SessionTenantResolver {
    /// Use a fixed tenant for all sessions on this connection.
    Fixed(String),
}

impl SessionTenantResolver {
    fn resolve(&self, _db_path: &str) -> String {
        match self {
            Self::Fixed(tenant_id) => tenant_id.clone(),
        }
    }
}

/// Typed outcome from `supervise_connection_sessions`. Callers use this to
/// select the appropriate close reason for the operational event instead of
/// hardcoding `"session_ended"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SessionOutcome {
    /// The runtime shutdown token was cancelled.
    Shutdown,
    /// The connection was dropped while opening a session (QUIC connection lost).
    ConnectionDropped { detail: String },
    /// The remote peer rejected the session due to a build/version mismatch.
    BuildMismatch { reason: String },
}

impl SessionOutcome {
    /// Map this outcome to a close_reason string for operational events.
    pub fn close_reason(&self) -> &str {
        match self {
            Self::Shutdown => "runtime_shutdown",
            Self::ConnectionDropped { .. } => "connection_dropped",
            Self::BuildMismatch { .. } => "build_mismatch",
        }
    }
}

/// Shared per-connection supervision loop for both connect and accept modes.
///
/// Returns a typed [`SessionOutcome`] so callers can record the specific
/// close reason in operational events.
pub(super) async fn supervise_connection_sessions(
    db_path: &str,
    peer_id: &str,
    peer_fp: [u8; 32],
    provider: &SessionProvider,
    handler: &SyncConnectionHandler,
    direction: SessionDirection,
    tenant_resolver: &SessionTenantResolver,
    shutdown: CancellationToken,
) -> SessionOutcome {
    let connection = provider.connection();
    let recorded_by = tenant_resolver.resolve(db_path);
    loop {
        if shutdown.is_cancelled() {
            connection.close(0u32.into(), b"runtime shutdown");
            return SessionOutcome::Shutdown;
        }

        let session = match tokio::select! {
            _ = shutdown.cancelled() => {
                connection.close(0u32.into(), b"runtime shutdown");
                return SessionOutcome::Shutdown;
            }
            session = provider.next_session() => session,
        } {
            Ok(session) => session,
            Err(e) => {
                if let Some(reason) = extract_build_mismatch_reason(&e.to_string()) {
                    note_build_mismatch(peer_id, reason);
                    let key = format!(
                        "session-build-mismatch:{:?}:{}:{}",
                        direction, recorded_by, peer_id
                    );
                    if should_emit_globally(key) {
                        warn!(
                            "Peer {} rejected {:?} session on connection {}: {}",
                            short_peer_id(peer_id),
                            direction,
                            connection.stable_id(),
                            reason
                        );
                    }
                    return SessionOutcome::BuildMismatch {
                        reason: reason.to_string(),
                    };
                } else {
                    info!(
                        "Connection {} dropped while opening {:?} session: {}",
                        connection.stable_id(),
                        direction,
                        e
                    );
                    return SessionOutcome::ConnectionDropped {
                        detail: e.to_string(),
                    };
                }
            }
        };

        let session_start = std::time::Instant::now();
        if session.class == SessionClass::Dependency {
            let db_path = db_path.to_string();
            let recorded_by = recorded_by.clone();
            let peer_id = peer_id.to_string();
            let remote_addr = session.remote_addr;
            let dep_shutdown = shutdown.child_token();
            tokio::task::spawn_local(async move {
                if let Err(err) = run_dependency_session(
                    session.io,
                    db_path,
                    recorded_by,
                    peer_id.clone(),
                    remote_addr,
                    dep_shutdown,
                )
                .await
                {
                    warn!(
                        "Dependency session {} error peer={}: {}",
                        session.session_id,
                        short_peer_id(&peer_id),
                        err
                    );
                }
            });
            continue;
        }
        info!(
            "Starting session {} ({:?}) on connection {}",
            session.session_id,
            direction,
            connection.stable_id()
        );

        let session_ok = run_session(
            handler,
            session.session_id,
            session.io,
            &recorded_by,
            peer_fp,
            session.remote_addr,
            direction,
            db_path,
        )
        .await;

        info!(
            "Session {} ({:?}) on connection {} finished in {}ms",
            session.session_id,
            direction,
            connection.stable_id(),
            session_start.elapsed().as_millis()
        );

        if !session_ok {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    connection.close(0u32.into(), b"runtime shutdown");
                    return SessionOutcome::Shutdown;
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => {}
            }
        }
    }
}

fn short_peer_id(peer_id: &str) -> &str {
    &peer_id[..16.min(peer_id.len())]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_tenant_resolver_always_returns_same_value() {
        let resolver = SessionTenantResolver::Fixed("tenant-fixed".to_string());
        assert_eq!(resolver.resolve("/tmp/does-not-matter"), "tenant-fixed");
    }

    #[test]
    fn short_peer_id_truncates_to_sixteen_chars() {
        assert_eq!(
            short_peer_id("0123456789abcdefdeadbeef"),
            "0123456789abcdef"
        );
        assert_eq!(short_peer_id("short"), "short");
    }

    #[test]
    fn session_outcome_close_reason_maps_correctly() {
        assert_eq!(SessionOutcome::Shutdown.close_reason(), "runtime_shutdown");
        assert_eq!(
            SessionOutcome::ConnectionDropped {
                detail: "reset".to_string()
            }
            .close_reason(),
            "connection_dropped"
        );
        assert_eq!(
            SessionOutcome::BuildMismatch {
                reason: "version 2 != 3".to_string()
            }
            .close_reason(),
            "build_mismatch"
        );
    }
}
