//! Control-plane helpers for sync sessions.
//!
//! Owns control-stream message handling concerns:
//! - Negentropy control messages (`NegOpen` / `NegMsg`)
//! - Sink-side observation of missing IDs into SQL-backed `wanted` state
//! - Request-window refill (`HaveList`) via the shared in-memory coordinator
//! - Session completion control markers (`Done` / `DoneAck`)

use negentropy::Id;
use std::collections::HashMap;
use tracing::info;

use crate::crypto::EventId;
use crate::db::wanted::WantedEvents;
use crate::protocol::{neg_id_to_event_id, Frame};
use crate::transport::StreamConn;
use crate::tuning::request_inflight_ttl_ms;

use super::{coordinator::PeerCoord, need_chunk};

pub type SyncError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Default)]
pub struct PeerRequestWindow {
    remote_credit: usize,
    inflight_requested: HashMap<EventId, i64>,
}

impl PeerRequestWindow {
    pub fn add_credit(&mut self, credits: usize) {
        self.remote_credit = self.remote_credit.saturating_add(credits);
    }

    pub fn inflight_len(&self) -> usize {
        self.inflight_requested.len()
    }

    pub fn available_credit(&self) -> usize {
        self.remote_credit
    }

    pub fn inflight_requested(&self) -> &HashMap<EventId, i64> {
        &self.inflight_requested
    }

    fn expire_stale(&mut self, now_ms: i64) {
        let ttl_ms = request_inflight_ttl_ms();
        self.inflight_requested
            .retain(|_, requested_at| now_ms.saturating_sub(*requested_at) < ttl_ms);
    }

    fn note_requested(&mut self, ids: &[EventId], now_ms: i64) {
        for event_id in ids {
            self.inflight_requested.insert(*event_id, now_ms);
        }
        self.remote_credit = self.remote_credit.saturating_sub(ids.len());
    }
}

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
/// This is the sink-side scheduler: the shared per-tenant coordinator chooses
/// the next IDs this peer should serve and sends `HaveList` requests for them.
/// Durable truth lives in `wanted` + `wanted_sources`; duplicate suppression is
/// bounded in-memory coordinator state across all active peers for the tenant.
pub async fn refill_wanted_requests<C>(
    control: &mut C,
    wanted: &WantedEvents<'_>,
    coordination: &PeerCoord,
    peer_id: &str,
    request_window: &mut PeerRequestWindow,
) -> Result<usize, SyncError>
where
    C: StreamConn,
{
    if request_window.available_credit() == 0 {
        return Ok(0);
    }

    let now_ms = crate::db::queue::current_timestamp_ms();
    request_window.expire_stale(now_ms);

    let credit = request_window.available_credit();
    if credit == 0 {
        return Ok(0);
    }

    let candidate_limit = credit
        .saturating_add(request_window.inflight_len())
        .saturating_add(need_chunk());
    let selected = coordination.plan_requests(
        wanted,
        peer_id,
        credit,
        request_window.inflight_requested(),
        candidate_limit,
        now_ms,
    )?;
    if selected.is_empty() {
        return Ok(0);
    }

    let batch_size = need_chunk().max(1);
    let mut batch = Vec::with_capacity(batch_size);
    for event_id in &selected {
        batch.push(*event_id);
        if batch.len() >= batch_size {
            control
                .send(&Frame::HaveList {
                    ids: std::mem::take(&mut batch),
                })
                .await?;
            batch = Vec::with_capacity(batch_size);
        }
    }
    if !batch.is_empty() {
        control.send(&Frame::HaveList { ids: batch }).await?;
    }
    control.flush().await?;
    request_window.note_requested(&selected, now_ms);

    info!(
        "Requested more wanted IDs from peer {} (requested_now={}, inflight={}, remaining_credit={}, candidate_limit={})",
        peer_id,
        selected.len(),
        request_window.inflight_len(),
        request_window.available_credit(),
        candidate_limit
    );
    Ok(selected.len())
}

pub async fn send_request_credit<C>(control: &mut C, credits: usize) -> Result<(), SyncError>
where
    C: StreamConn,
{
    if credits == 0 {
        return Ok(());
    }
    let credits = u32::try_from(credits).unwrap_or(u32::MAX);
    control.send(&Frame::RequestCredit { credits }).await?;
    control.flush().await?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_request_window_expires_stale_entries() {
        let mut window = PeerRequestWindow::default();
        let mut id = [0u8; 32];
        id[0] = 7;
        window.inflight_requested.insert(id, 0);
        window.expire_stale(request_inflight_ttl_ms() + 1);
        assert_eq!(window.inflight_len(), 0);
    }
}
