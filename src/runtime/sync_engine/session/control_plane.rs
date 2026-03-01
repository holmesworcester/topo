//! Control-plane helpers for sync sessions.
//!
//! Owns control-stream message handling concerns:
//! - Negentropy control messages (`NegOpen` / `NegMsg`)
//! - Pull signaling (`HaveList`) with deterministic ownership
//! - Session completion control markers (`Done` / `DoneAck`)

use std::sync::atomic::Ordering;

use negentropy::Id;
use tracing::info;

use crate::crypto::EventId;
use crate::db::wanted::WantedEvents;
use crate::protocol::{neg_id_to_event_id, Frame};
use crate::transport::StreamConn;

use super::coordinator::PeerCoord;
use super::NEED_CHUNK;

pub type SyncError = Box<dyn std::error::Error + Send + Sync>;

pub async fn send_initial_neg_open<C>(
    control: &mut C,
    initial_msg: Vec<u8>,
) -> Result<(), SyncError>
where
    C: StreamConn,
{
    control.send(&Frame::NegOpen { msg: initial_msg }).await?;
    control.flush().await?;
    Ok(())
}

pub fn append_have_ids_to_pending(have_ids: &mut Vec<Id>, pending_have: &mut Vec<EventId>) {
    if have_ids.is_empty() {
        return;
    }
    pending_have.reserve(have_ids.len());
    for neg_id in have_ids.drain(..) {
        pending_have.push(neg_id_to_event_id(&neg_id));
    }
}

/// Deterministic ownership predicate for multi-source download.
///
/// Uses the first 8 bytes of `event_id` as a hash, modulo `total_peers`.
/// Returns true if this session (identified by `peer_idx`) owns the event.
/// With `total_peers <= 1`, always returns true (single-peer degenerates naturally).
pub fn is_event_owned(event_id: &EventId, peer_idx: usize, total_peers: usize) -> bool {
    if total_peers <= 1 {
        return true;
    }
    let hash = u64::from_le_bytes(event_id[..8].try_into().unwrap());
    (hash as usize % total_peers) == peer_idx
}

/// Dispatch need_ids discovered during a reconciliation round.
///
/// When need_ids count is large (bulk transfer), uses deterministic ownership
/// to split work across peers — each session claims `hash(event_id) % total_peers
/// == peer_idx`. Non-owned events go to `fallback_need_ids`.
///
/// When need_ids count is small (below `total_peers * FALLBACK_THRESHOLD_FACTOR`),
/// claims ALL events regardless of ownership. This handles source-unique events
/// (identity chains, markers) that only exist at this particular source and
/// cannot be downloaded by their deterministic "owner" peer.
const FALLBACK_THRESHOLD_FACTOR: usize = 20;

pub async fn dispatch_owned_need_ids<C>(
    control: &mut C,
    wanted: &WantedEvents<'_>,
    need_ids: &mut Vec<Id>,
    fallback_need_ids: &mut Vec<EventId>,
    coordination: &PeerCoord,
) -> Result<(), SyncError>
where
    C: StreamConn,
{
    if need_ids.is_empty() {
        return Ok(());
    }

    let peer_idx = coordination.peer_idx;
    let total_peers = coordination.total_peers.load(Ordering::Relaxed);

    // When need_ids are few, claim all — these are likely source-unique events
    // that can only be fetched from this specific source.
    let claim_all = need_ids.len() <= total_peers * FALLBACK_THRESHOLD_FACTOR;

    let mut batch: Vec<EventId> = Vec::with_capacity(NEED_CHUNK);
    let mut owned_count = 0usize;

    for neg_id in need_ids.drain(..) {
        let event_id = neg_id_to_event_id(&neg_id);
        if claim_all || is_event_owned(&event_id, peer_idx, total_peers) {
            let _ = wanted.insert(&event_id);
            batch.push(event_id);
            owned_count += 1;
            if batch.len() >= NEED_CHUNK {
                control.send(&Frame::HaveList { ids: batch }).await?;
                control.flush().await?;
                batch = Vec::with_capacity(NEED_CHUNK);
            }
        } else {
            fallback_need_ids.push(event_id);
        }
    }

    if !batch.is_empty() {
        control.send(&Frame::HaveList { ids: batch }).await?;
        control.flush().await?;
    }

    if owned_count > 0 || !fallback_need_ids.is_empty() {
        info!(
            "Ownership dispatch: {} claimed (sent), {} deferred, peer_idx={}, total={}, claim_all={}",
            owned_count,
            fallback_need_ids.len(),
            peer_idx,
            total_peers,
            claim_all
        );
    }

    Ok(())
}

/// Drain non-owned fallback events, discarding them.
///
/// In a healthy multi-source scenario, each session only requests its
/// deterministically owned events. Non-owned events are handled by their
/// respective owners. Source-unique events are handled by the threshold
/// logic in `dispatch_owned_need_ids` (claim_all when need_ids are few).
pub fn drain_fallback_need_ids(fallback_need_ids: &mut Vec<EventId>) {
    if !fallback_need_ids.is_empty() {
        info!(
            "Discarding {} non-owned need_ids (handled by other sources)",
            fallback_need_ids.len()
        );
        fallback_need_ids.clear();
    }
}

pub async fn send_done<C>(control: &mut C) -> Result<(), SyncError>
where
    C: StreamConn,
{
    control.send(&Frame::Done).await?;
    control.flush().await?;
    Ok(())
}

pub async fn send_done_ack<C>(control: &mut C) -> Result<(), SyncError>
where
    C: StreamConn,
{
    control.send(&Frame::DoneAck).await?;
    control.flush().await?;
    Ok(())
}
