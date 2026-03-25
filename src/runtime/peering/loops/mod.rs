//! Connection-level orchestration: accept, connect, and download loops.
//!
//! These functions manage the lifecycle of individual QUIC connections and
//! the sync sessions running on them. Session execution is delegated to
//! `SessionHandler` -- no protocol logic lives here.
//!
//! The transport↔peering seam is [`run_session`]: both accept and connect
//! loops call it to wire QUIC streams into session handler invocations,
//! centralizing DualConnection / SessionMeta / QuicTransportSessionIo
//! construction (R4/SC4 of the peering readability plan).
//!
//! Sub-modules:
//!  - `accept`   -- accept_loop, accept_loop_until_cancel
//!  - `connect`  -- connect_loop, connect_loop_with_coordination
//!  - `supervisor` -- shared session lifecycle supervision

mod accept;
mod connect;
mod supervisor;

// Re-export public API so callers can still `use crate::peering::loops::*`.
pub use accept::{accept_loop, accept_loop_until_cancel};
pub use connect::{
    connect_loop, connect_loop_with_coordination, connect_loop_with_coordination_until_cancel,
    connect_loop_with_coordination_until_cancel_with_fallback,
};

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::contracts::peering_contract::{
    PeerFingerprint, SessionDirection, SessionHandler, SessionMeta, TenantId, TransportSessionIo,
};
use crate::runtime::repeated_warning::should_emit_globally;
use crate::sync::SyncConnectionHandler;
use crate::transport::session_factory::extract_build_mismatch_reason;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Function that spawns an intro listener for holepunch handling on a QUIC connection.
/// Injected by the composition root so peering/ doesn't depend on sync::punch.
///
pub type IntroSpawnerFn = fn(
    crate::transport::TransportConnection,
    String,
    String,
    String,
    crate::transport::TransportEndpoint,
    Option<crate::transport::TransportClientConfig>,
) -> tokio::task::JoinHandle<()>;

// ---------------------------------------------------------------------------
// Tuning constants (orchestration-level only; session constants live in
// sync::session)
// ---------------------------------------------------------------------------

/// Long-lived sync-session activity timeout for initiator and responder (seconds).
pub const SYNC_SESSION_TIMEOUT_SECS: u64 = 60;

/// Sleep after a failed QUIC connection attempt before retrying.
pub(super) const CONNECT_RETRY_DELAY: Duration = Duration::from_secs(1);

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

pub(crate) fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

// ---------------------------------------------------------------------------
// Transport↔peering session seam
// ---------------------------------------------------------------------------

/// Run a single sync session using a pre-built `TransportSessionIo`.
///
/// This is the peering orchestration seam: it wires session metadata,
/// cancellation, and the session handler together. Transport
/// details (stream opening, `DualConnection`, `QuicTransportSessionIo`)
/// are handled by `transport::session_factory` before this is called.
pub(super) async fn run_session(
    handler: &SyncConnectionHandler,
    session_id: u64,
    io: Box<dyn TransportSessionIo>,
    tenant_id: &str,
    peer_fp: [u8; 32],
    remote_addr: SocketAddr,
    direction: SessionDirection,
    _db_path: &str,
) -> bool {
    let meta = SessionMeta {
        session_id,
        tenant: TenantId(tenant_id.to_string()),
        peer: PeerFingerprint(peer_fp),
        remote_addr,
        direction,
    };
    let cancel = CancellationToken::new();

    if let Err(e) = handler.on_session(meta, io, cancel.clone()).await {
        let label = match direction {
            SessionDirection::Outbound => "Initiator",
            SessionDirection::Inbound => "Responder",
        };
        if let Some(reason) = extract_build_mismatch_reason(&e) {
            let peer_id = hex::encode(peer_fp);
            let key = format!("session-build-mismatch:{label}:{peer_id}:{direction:?}");
            if should_emit_globally(key) {
                warn!(
                    "{} session rejected by peer {}: {}",
                    label,
                    &peer_id[..16.min(peer_id.len())],
                    reason
                );
            }
        } else {
            warn!("{} session error: {}", label, e);
        }
        cancel.cancel();
        return false;
    }
    cancel.cancel();
    true
}
