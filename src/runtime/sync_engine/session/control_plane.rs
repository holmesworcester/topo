//! Control-plane helpers for sync sessions.
//!
//! Owns control-stream message handling concerns:
//! - Negentropy control messages (`NegOpen` / `NegMsg`)
//! - Sink-side observation of missing IDs into SQL-backed `wanted` state
//! - Request-window refill (`HaveList`) from that SQL-backed state
//! - Session completion control markers (`Done` / `DoneAck`)

use negentropy::Id;
use std::collections::HashMap;
use tracing::info;

use crate::crypto::EventId;
use crate::db::wanted::{WantedCandidate, WantedEvents};
use crate::protocol::{neg_id_to_event_id, Frame};
use crate::transport::StreamConn;
use crate::tuning::{request_inflight_ttl_ms, wanted_refill_quantum};

use super::need_chunk;

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

pub fn select_request_ids(
    candidates: &[WantedCandidate],
    inflight_requested: &HashMap<EventId, i64>,
    credit: usize,
) -> Vec<EventId> {
    if credit == 0 {
        return Vec::new();
    }

    let mut selected = Vec::with_capacity(credit);
    for candidate in candidates {
        if inflight_requested.contains_key(&candidate.event_id) {
            continue;
        }
        selected.push(candidate.event_id);
        if selected.len() >= credit {
            break;
        }
    }
    selected
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
/// This is the sink-side scheduler: it chooses the next IDs this peer should
/// serve and sends `HaveList` requests for them. Durable truth lives in
/// `wanted` + `wanted_sources`; duplicate suppression is only in-memory and
/// bounded to this peer/session.
pub async fn refill_wanted_requests<C>(
    control: &mut C,
    wanted: &WantedEvents<'_>,
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

    let quantum = wanted_refill_quantum().max(1);
    let credit = request_window.available_credit().min(quantum);
    if credit == 0 {
        return Ok(0);
    }

    let candidate_limit = credit
        .saturating_add(request_window.inflight_len())
        .saturating_add(need_chunk());
    let candidates = wanted.list_candidates_for_peer(peer_id, candidate_limit)?;
    let selected = select_request_ids(&candidates, &request_window.inflight_requested, credit);
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
        "Requested more wanted IDs from peer {} (requested_now={}, inflight={}, remaining_credit={}, quantum={})",
        peer_id,
        selected.len(),
        request_window.inflight_len(),
        request_window.available_credit(),
        quantum
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

    fn candidate(byte: u8, lane: i64, ts: i64) -> WantedCandidate {
        let mut event_id = [0u8; 32];
        event_id[0] = byte;
        WantedCandidate {
            event_id,
            priority_lane: lane,
            priority_ts: ts,
            first_seen_at: ts,
        }
    }

    #[test]
    fn select_request_ids_skips_same_peer_inflight() {
        let mut inflight = HashMap::new();
        let id = candidate(2, 1, 20).event_id;
        inflight.insert(id, 1);
        let candidates = vec![candidate(1, 1, 30), candidate(2, 1, 20), candidate(3, 1, 10)];

        let selected = select_request_ids(&candidates, &inflight, 3);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0][0], 1);
        assert_eq!(selected[1][0], 3);
    }

    #[test]
    fn select_request_ids_respects_credit_and_order() {
        let inflight = HashMap::new();
        let candidates = vec![candidate(9, 1, 50), candidate(8, 1, 40), candidate(7, 2, 30)];

        let selected = select_request_ids(&candidates, &inflight, 2);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0][0], 9);
        assert_eq!(selected[1][0], 8);
    }
}
