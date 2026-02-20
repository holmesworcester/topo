//! Connection-level orchestration: accept, connect, and download loops.
//!
//! Extracted from sync/engine.rs (Phase 4 of Option B refactor).
//! These functions manage the lifecycle of individual QUIC connections and
//! the sync sessions running on them. Session execution is delegated to
//! `SessionHandler` -- no protocol logic lives here.
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

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio_util::sync::CancellationToken;
use crate::db::open_connection;
use crate::db::removal_watch::is_peer_removed;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Function that spawns an intro listener for holepunch handling on a QUIC connection.
/// Injected by the composition root so network/ doesn't depend on sync::punch.
pub type IntroSpawnerFn = fn(
    quinn::Connection,
    String,
    String,
    String,
    quinn::Endpoint,
    Option<quinn::ClientConfig>,
    crate::contracts::event_pipeline_contract::BatchWriterFn,
) -> tokio::task::JoinHandle<()>;

// ---------------------------------------------------------------------------
// Tuning constants (orchestration-level only; session constants live in
// replication::session)
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

pub(super) fn low_mem_mode() -> bool {
    read_bool_env("LOW_MEM_IOS") || read_bool_env("LOW_MEM")
}

fn read_bool_env(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => v != "0" && v.to_lowercase() != "false",
        Err(_) => false,
    }
}

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

/// Batch writer drain batch size: 100 normal, 50 in low_mem.
pub(super) fn drain_batch_size() -> usize {
    if low_mem_mode() {
        50
    } else {
        100
    }
}

/// Async channel capacity for shared ingest (accept_loop / download_from_sources).
pub(super) fn shared_ingest_cap() -> usize {
    if low_mem_mode() {
        1000
    } else {
        10000
    }
}
