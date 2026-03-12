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
//!  - `connect`  -- connect_loop, connect_loop_with_coordination
//!  - `supervisor` -- shared preflight + session lifecycle supervision

mod accept;
mod connect;
mod supervisor;

// Re-export public API so callers can still `use crate::peering::loops::*`.
pub use accept::accept_loop_with_ingest_until_cancel;
pub use accept::{accept_loop, accept_loop_with_ingest};
pub(crate) use connect::connect_loop_with_coordination_until_cancel_with_target_fingerprint_and_fallback;
pub use connect::{
    connect_loop, connect_loop_with_coordination, connect_loop_with_coordination_until_cancel,
    connect_loop_with_coordination_until_cancel_with_fallback, connect_loop_with_shared_ingest,
    connect_loop_with_shared_ingest_until_cancel,
};

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::contracts::peering_contract::{
    PeerFingerprint, SessionDirection, SessionHandler, SessionMeta, TenantId, TransportSessionIo,
};
use crate::runtime::repeated_warning::should_emit_globally;
use crate::sync::SyncSessionHandler;
use crate::transport::session_factory::extract_build_mismatch_reason;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Function that spawns an intro listener for holepunch handling on a QUIC connection.
/// Injected by the composition root so peering/ doesn't depend on sync::punch.
///
/// The last parameter is a shared ingest sender — punch sessions reuse the
/// parent loop's batch_writer instead of spawning their own.
pub type IntroSpawnerFn = fn(
    crate::transport::TransportConnection,
    String,
    String,
    String,
    crate::transport::TransportEndpoint,
    Option<crate::transport::TransportClientConfig>,
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

<<<<<<< HEAD
=======
pub(crate) fn preferred_connection_direction(
    local_peer_id: &str,
    remote_peer_id: &str,
) -> Option<SessionDirection> {
    let local = peer_fingerprint_from_hex(local_peer_id)?;
    let remote = peer_fingerprint_from_hex(remote_peer_id)?;
    Some(match local.cmp(&remote) {
        std::cmp::Ordering::Less | std::cmp::Ordering::Equal => SessionDirection::Outbound,
        std::cmp::Ordering::Greater => SessionDirection::Inbound,
    })
}

fn connection_direction_rank(
    local_peer_id: &str,
    remote_peer_id: &str,
    direction: SessionDirection,
) -> u8 {
    match preferred_connection_direction(local_peer_id, remote_peer_id) {
        Some(preferred) if preferred == direction => 2,
        Some(_) => 0,
        None => 1,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct LiveConnectionKey {
    db_path: String,
    recorded_by: String,
    peer_id: String,
}

struct LiveConnectionSlot {
    claim_id: u64,
    direction: SessionDirection,
    direction_rank: u8,
    connection: crate::transport::TransportConnection,
    released: Arc<tokio::sync::Notify>,
}

fn live_connection_slots() -> &'static Mutex<HashMap<LiveConnectionKey, LiveConnectionSlot>> {
    static LIVE_CONNECTION_SLOTS: OnceLock<Mutex<HashMap<LiveConnectionKey, LiveConnectionSlot>>> =
        OnceLock::new();
    LIVE_CONNECTION_SLOTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_live_connection_claim_id() -> u64 {
    static NEXT_CLAIM_ID: AtomicU64 = AtomicU64::new(1);
    NEXT_CLAIM_ID.fetch_add(1, Ordering::Relaxed)
}

pub(crate) struct LiveConnectionLease {
    key: LiveConnectionKey,
    claim_id: u64,
}

impl Drop for LiveConnectionLease {
    fn drop(&mut self) {
        let released = {
            let mut slots = live_connection_slots()
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            match slots.get(&self.key) {
                Some(slot) if slot.claim_id == self.claim_id => {
                    let slot = slots
                        .remove(&self.key)
                        .expect("live connection slot missing");
                    Some(slot.released)
                }
                _ => None,
            }
        };
        if let Some(released) = released {
            released.notify_waiters();
        }
    }
}

pub(crate) struct LiveConnectionOccupied {
    pub preferred_direction: Option<SessionDirection>,
    pub active_direction: SessionDirection,
    pub released: Arc<tokio::sync::Notify>,
}

pub(crate) enum LiveConnectionClaim {
    Acquired(LiveConnectionLease),
    Occupied(LiveConnectionOccupied),
}

pub(crate) fn claim_live_connection_slot(
    db_path: &str,
    recorded_by: &str,
    peer_id: &str,
    direction: SessionDirection,
    connection: crate::transport::TransportConnection,
) -> LiveConnectionClaim {
    let key = LiveConnectionKey {
        db_path: db_path.to_string(),
        recorded_by: recorded_by.to_string(),
        peer_id: peer_id.to_string(),
    };
    let direction_rank = connection_direction_rank(recorded_by, peer_id, direction);
    let preferred_direction = preferred_connection_direction(recorded_by, peer_id);
    let claim_id = next_live_connection_claim_id();

    let mut replaced: Option<(
        crate::transport::TransportConnection,
        Arc<tokio::sync::Notify>,
    )> = None;
    let claim = {
        let mut slots = live_connection_slots()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        match slots.get_mut(&key) {
            None => {
                let released = Arc::new(tokio::sync::Notify::new());
                slots.insert(
                    key.clone(),
                    LiveConnectionSlot {
                        claim_id,
                        direction,
                        direction_rank,
                        connection,
                        released,
                    },
                );
                LiveConnectionClaim::Acquired(LiveConnectionLease { key, claim_id })
            }
            Some(existing) if direction_rank > existing.direction_rank => {
  