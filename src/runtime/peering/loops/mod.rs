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
//!  - `accept`   -- accept_loop, accept_loop_until_cancel, resolve_inbound_auth_context
//!  - `connect`  -- connect_loop, ConnectLoopConfig
//!  - `supervisor` -- shared preflight + session lifecycle supervision

mod accept;
mod connect;
mod supervisor;

// Re-export public API so callers can still `use crate::peering::loops::*`.
pub use accept::{accept_loop, accept_loop_until_cancel};
pub use connect::{connect_loop, ConnectLoopConfig};
pub(crate) use connect::STALE_DIAL_TARGET_MARKER;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

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

/// Endpoint observation TTL: 24 hours in milliseconds.
pub(super) const ENDPOINT_TTL_MS: i64 = 24 * 60 * 60 * 1000;

/// Long-lived sync-session activity timeout for initiator and responder (seconds).
pub const SYNC_SESSION_TIMEOUT_SECS: u64 = 60;

/// Sleep after a failed QUIC connection attempt before retrying.
pub(super) const CONNECT_RETRY_DELAY: Duration = Duration::from_secs(1);

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

pub(crate) use crate::db::queue::current_timestamp_ms;

pub(crate) fn short_peer_id(peer_id: &str) -> &str {
    &peer_id[..16.min(peer_id.len())]
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
                let released = Arc::new(tokio::sync::Notify::new());
                replaced = Some((existing.connection.clone(), existing.released.clone()));
                *existing = LiveConnectionSlot {
                    claim_id,
                    direction,
                    direction_rank,
                    connection,
                    released,
                };
                LiveConnectionClaim::Acquired(LiveConnectionLease { key, claim_id })
            }
            Some(existing) => LiveConnectionClaim::Occupied(LiveConnectionOccupied {
                preferred_direction,
                active_direction: existing.direction,
                released: existing.released.clone(),
            }),
        }
    };

    if let Some((existing_connection, released)) = replaced {
        existing_connection.close(0u32.into(), b"replaced by preferred peer connection");
        released.notify_waiters();
    }

    claim
}

pub(crate) fn live_connection_peer_ids(db_path: &str, recorded_by: &str) -> Vec<String> {
    let slots = live_connection_slots()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let mut peer_ids: Vec<String> = slots
        .keys()
        .filter(|key| key.db_path == db_path && key.recorded_by == recorded_by)
        .map(|key| key.peer_id.clone())
        .collect();
    peer_ids.sort();
    peer_ids.dedup();
    peer_ids
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

pub(super) use crate::tuning::drain_batch_size;

#[cfg(test)]
mod tests {
    use super::{preferred_connection_direction, SessionDirection};

    #[test]
    fn preferred_connection_direction_is_symmetric() {
        let lower = format!("{:064x}", 1);
        let higher = format!("{:064x}", 2);

        assert_eq!(
            preferred_connection_direction(&lower, &higher),
            Some(SessionDirection::Outbound)
        );
        assert_eq!(
            preferred_connection_direction(&higher, &lower),
            Some(SessionDirection::Inbound)
        );
    }

    #[test]
    fn preferred_connection_direction_defaults_to_outbound_for_equal_ids() {
        let peer = format!("{:064x}", 9);
        assert_eq!(
            preferred_connection_direction(&peer, &peer),
            Some(SessionDirection::Outbound)
        );
    }

    #[test]
    fn preferred_connection_direction_returns_none_for_invalid_peer_ids() {
        assert_eq!(preferred_connection_direction("not-hex", "also-bad"), None);
    }
}
