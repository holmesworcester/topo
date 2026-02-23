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
//!  - `accept`   -- accept_loop, accept_loop_with_ingest, resolve_tenant_for_peer
//!  - `connect`  -- connect_loop, connect_loop_inner
//!  - `download` -- download_from_sources

mod accept;
mod connect;
mod download;

// Re-export public API so callers can still `use crate::peering::loops::*`.
pub use accept::{accept_loop, accept_loop_with_ingest};
pub use connect::connect_loop;
pub use download::download_from_sources;

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::contracts::peering_contract::{
    PeerFingerprint, SessionDirection, SessionHandler, SessionMeta, TenantId, TransportSessionIo,
};
use crate::db::open_connection;
use crate::db::removal_watch::is_peer_removed;
use crate::sync::SyncSessionHandler;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Function that spawns an intro listener for holepunch handling on a QUIC connection.
/// Injected by the composition root so peering/ doesn't depend on sync::punch.
///
/// The last parameter is a shared ingest sender — punch sessions reuse the
/// parent loop's batch_writer instead of spawning their own.
pub type IntroSpawnerFn = fn(
    quinn::Connection,
    String,
    String,
    String,
    quinn::Endpoint,
    Option<quinn::ClientConfig>,
    tokio::sync::mpsc::Sender<crate::contracts::event_pipeline_contract::IngestItem>,
) -> tokio::task::JoinHandle<()>;

// ---------------------------------------------------------------------------
// Tuning constants (orchestration-level only; session constants live in
// sync::session)
// ---------------------------------------------------------------------------

/// Endpoint observation TTL: 24 hours in milliseconds.
pub(super) const ENDPOINT_TTL_MS: i64 = 24 * 60 * 60 * 1000;

/// Negentropy session timeout for initiator and responder (seconds).
pub const SYNC_SESSION_TIMEOUT_SECS: u64 = 60;

/// Sleep between consecutive sync sessions on the same connection.
pub(super) const SESSION_GAP: Duration = Duration::from_millis(100);

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

pub(crate) fn peer_fingerprint_from_hex(peer_id: &str) -> Option<[u8; 32]> {
    let peer_fp_bytes = hex::decode(peer_id).ok()?;
    if peer_fp_bytes.len() != 32 {
        return None;
    }
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&peer_fp_bytes);
    Some(fp)
}

pub(super) fn spawn_peer_removal_cancellation_watch(
    db_path: String,
    recorded_by: String,
    peer_fp: [u8; 32],
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_local(async move {
        loop {
            if cancel.is_cancelled() {
                break;
            }
            if let Ok(db) = open_connection(&db_path) {
                if is_peer_removed(&db, &recorded_by, &peer_fp).unwrap_or(false) {
                    cancel.cancel();
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
}

// ---------------------------------------------------------------------------
// Transport↔peering session seam
// ---------------------------------------------------------------------------

/// Run a single sync session using a pre-built `TransportSessionIo`.
///
/// This is the peering orchestration seam: it wires session metadata,
/// peer-removal cancellation, and the session handler together. Transport
/// details (stream opening, `DualConnection`, `QuicTransportSessionIo`)
/// are handled by `transport::session_factory` before this is called.
pub(super) async fn run_session(
    handler: &SyncSessionHandler,
    session_id: u64,
    io: Box<dyn TransportSessionIo>,
    tenant_id: &str,
    peer_fp: [u8; 32],
    remote_addr: SocketAddr,
    direction: SessionDirection,
    db_path: &str,
) {
    let meta = SessionMeta {
        session_id,
        tenant: TenantId(tenant_id.to_string()),
        peer: PeerFingerprint(peer_fp),
        remote_addr,
        direction,
    };
    let cancel = CancellationToken::new();
    let watch = spawn_peer_removal_cancellation_watch(
        db_path.to_string(),
        tenant_id.to_string(),
        peer_fp,
        cancel.clone(),
    );

    if let Err(e) = handler
        .on_session(meta, io, cancel.clone())
        .await
    {
        let label = match direction {
            SessionDirection::Outbound => "Initiator",
            SessionDirection::Inbound => "Responder",
        };
        warn!("{} session error: {}", label, e);
    }
    cancel.cancel();
    let _ = watch.await;
}

pub(super) use crate::tuning::drain_batch_size;
pub(super) use crate::tuning::shared_ingest_cap;
