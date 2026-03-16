//! Control-plane helpers for sync sessions.
//!
//! Owns control-stream message handling concerns:
//! - Negentropy control messages (`NegOpen` / `NegMsg`)
//! - Sink-side observation of missing IDs into SQL-backed `wanted` state
//! - Discovery hints (`NeedList`) and request-window refill (`HaveList`)
//!   via the shared in-memory coordinator

use negentropy::Id;
use tracing::info;

use crate::crypto::EventId;
use crate::db::timeline::EventTimeline;
use crate::db::wanted::WantedEvents;
use crate::protocol::{neg_id_to_event_id, Frame};
use crate::transport::StreamConn;

use super::{connection_scope::ConnectionRequestState, coordinator::PeerCoord, need_chunk};

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

/// Persist reconciliation-discovered `need_ids` as sink demand plus candidate
/// source membership for this peer.
pub fn observe_need_ids_for_peer(
    wanted: &WantedEvents<'_>,
    timeline: &EventTimeline<'_>,
    local_peer_id: &str,
    peer_id: &str,
    discovery_round_started_at: i64,
    need_ids: &mut Vec<Id>,
    observed_ids: &mut Vec<EventId>,
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
            observed_total += observe_event_ids_for_peer(
                wanted,
                timeline,
                local_peer_id,
                peer_id,
                discovery_round_started_at,
                &batch,
                observed_ids,
            )?;
            batch.clear();
        }
    }
    if !batch.is_empty() {
        observed_total += observe_event_ids_for_peer(
            wanted,
            timeline,
            local_peer_id,
            peer_id,
            discovery_round_started_at,
            &batch,
            observed_ids,
        )?;
    }
    if need_ids.capacity() > (batch_cap * 16) {
        need_ids.shrink_to(0);
    }
    Ok(observed_total)
}

pub fn observe_event_ids_for_peer(
    wanted: &WantedEvents<'_>,
    timeline: &EventTimeline<'_>,
    local_peer_id: &str,
    peer_id: &str,
    discovery_round_started_at: i64,
    ids: &[EventId],
    observed_ids: &mut Vec<EventId>,
) -> Result<usize, SyncError> {
    if ids.is_empty() {
        return Ok(0);
    }
    observed_ids.extend_from_slice(ids);
    Ok(wanted.observe_many_for_peer(
        local_peer_id,
        peer_id,
        ids,
        discovery_round_started_at,
        timeline,
    )?)
}

/// Send discovery hints for IDs the peer is missing.
///
/// These are not data sends. They only let the remote side populate durable
/// `wanted` state and then pull the blobs under request credit.
pub async fn send_need_list_from_have_ids<C>(
    control: &mut C,
    timeline: &EventTimeline<'_>,
    have_ids: &mut Vec<Id>,
    sent_ids_out: &mut Vec<EventId>,
) -> Result<usize, SyncError>
where
    C: StreamConn,
{
    if have_ids.is_empty() {
        return Ok(0);
    }

    let batch_size = need_chunk().max(1);
    let mut sent = 0usize;
    while !have_ids.is_empty() {
        let drain_count = have_ids.len().min(batch_size);
        let mut ids: Vec<EventId> = Vec::with_capacity(drain_count);
        for neg_id in have_ids.drain(..drain_count) {
            ids.push(neg_id_to_event_id(&neg_id));
        }
        sent_ids_out.extend_from_slice(&ids);
        let sent_at = crate::db::queue::current_timestamp_ms();
        sent += ids.len();
        let _ = timeline.mark_need_list_sent_many(&ids, sent_at);
        control.send(&Frame::NeedList { ids }).await?;
    }
    control.flush().await?;
    Ok(sent)
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
    timeline: &EventTimeline<'_>,
    coordination: &PeerCoord,
    peer_id: &str,
    request_state: &ConnectionRequestState,
) -> Result<usize, SyncError>
where
    C: StreamConn,
{
    let now_ms = crate::db::queue::current_timestamp_ms();
    let snapshot = request_state.snapshot(now_ms);
    if snapshot.remote_credit == 0 {
        return Ok(0);
    }

    let credit = snapshot.remote_credit;
    if credit == 0 {
        return Ok(0);
    }

    let candidate_limit = credit
        .saturating_add(snapshot.inflight_requested.len())
        .saturating_add(need_chunk());
    let selected = coordination.plan_requests(
        wanted,
        peer_id,
        credit,
        &snapshot.inflight_requested,
        candidate_limit,
        now_ms,
    )?;
    if selected.is_empty() {
        return Ok(0);
    }
    if let Some(credit_received_at) = snapshot.last_credit_received_at {
        let _ = timeline.mark_request_credit_received_many(&selected, credit_received_at);
    }
    let _ = timeline.mark_request_selected_many(&selected, now_ms);

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
    request_state.note_requested(&selected, now_ms);
    let _ = timeline.mark_request_sent_many(&selected, now_ms);
    let stats = request_state.stats(now_ms);

    info!(
        "Requested more wanted IDs from peer {} (requested_now={}, inflight={}, remaining_credit={}, candidate_limit={})",
        peer_id,
        selected.len(),
        stats.inflight_len,
        stats.remote_credit,
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

#[cfg(test)]
mod tests {
    use super::super::connection_scope::ConnectionRequestState;
    use crate::tuning::request_inflight_ttl_ms;

    #[test]
    fn connection_request_state_expires_stale_entries() {
        let state = ConnectionRequestState::default();
        let mut id = [0u8; 32];
        id[0] = 7;
        state.add_credit(1, 9);
        state.note_requested(&[id], 0);
        assert_eq!(state.stats(request_inflight_ttl_ms() + 1).inflight_len, 0);
    }
}
