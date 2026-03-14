//! Control-plane helpers for sync sessions.
//!
//! Owns control-stream message handling concerns:
//! - Negentropy control messages (`NegOpen` / `NegMsg`)
//! - Sink-side observation of missing IDs into SQL-backed `wanted` state
//! - Request-window refill (`HaveList`) from that SQL-backed state
//! - Session completion control markers (`Done` / `DoneAck`)

use negentropy::Id;
use tracing::info;

use crate::crypto::EventId;
use crate::db::wanted::WantedEvents;
use crate::protocol::{neg_id_to_event_id, Frame};
use crate::transport::StreamConn;
use crate::tuning::{wanted_high_watermark, wanted_low_watermark, wanted_refill_quantum};

use super::{need_chunk, EGRESS_LEASE_MS};

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

/// Persist reconciliation-discovered `need_ids` as sink demand plus candidate
/// source membership for this peer.
pub fn observe_need_ids_for_peer(
    wanted: &WantedEvents<'_>,
    peer_id: &str,
    need_ids: &mut Vec<Id>,
) -> Result<usize, SyncError> {
    if need_ids.is_empty() {
        return Ok(0);
    }

    let batch_cap = need_chunk().max(1);
    let mut observed_total = 0usize;
    let mut batch: Vec<EventId> = Vec::with_capacity(batch_cap);
    for neg_id in need_ids.drain(..) {
        batch.push(neg_id_to_event_id(&neg_id));
        if batch.len() >= batch_cap {
            observed_total += wanted.observe_many_for_peer(peer_id, &batch)?;
            batch.clear();
        }
    }
    if !batch.is_empty() {
        observed_total += wanted.observe_many_for_peer(peer_id, &batch)?;
    }
    if need_ids.capacity() > (batch_cap * 16) {
        need_ids.shrink_to(0);
    }
    Ok(observed_total)
}

/// Keep the peer's request window topped up from durable `wanted` state.
///
/// This is the sink-side scheduler: it chooses the next IDs this peer should
/// serve and sends `HaveList` requests for them. Balancing is implicit in the
/// lease table: each peer can only claim unleased/expired wanted rows for
/// which it is a candidate source.
pub async fn refill_wanted_requests<C>(
    control: &mut C,
    wanted: &WantedEvents<'_>,
    peer_id: &str,
    session_owner: &str,
) -> Result<usize, SyncError>
where
    C: StreamConn,
{
    let outstanding = wanted
        .count_outstanding_for_peer(peer_id, session_owner)
        .ok()
        .and_then(|v| usize::try_from(v).ok())
        .unwrap_or(0);
    let high = wanted_high_watermark().max(1);
    let low = wanted_low_watermark().min(high.saturating_sub(1));
    if outstanding > low {
        return Ok(0);
    }

    let quantum = wanted_refill_quantum().max(1);
    let credit = high.saturating_sub(outstanding).min(quantum);
    if credit == 0 {
        return Ok(0);
    }

    let claimed = wanted.claim_for_peer(peer_id, session_owner, credit, EGRESS_LEASE_MS)?;
    if claimed.is_empty() {
        return Ok(0);
    }

    let batch_size = need_chunk().max(1);
    let mut batch = Vec::with_capacity(batch_size);
    for event_id in claimed {
        batch.push(event_id);
        if batch.len() >= batch_size {
            control.send(&Frame::HaveList { ids: batch }).await?;
            batch = Vec::with_capacity(batch_size);
        }
    }
    if !batch.is_empty() {
        control.send(&Frame::HaveList { ids: batch }).await?;
    }
    control.flush().await?;

    info!(
        "Requested more wanted IDs from peer {} (outstanding_before={}, high={}, low={}, quantum={})",
        peer_id, outstanding, high, low, quantum
    );
    Ok(credit)
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
