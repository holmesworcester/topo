//! Control-plane helpers for long-lived sync connections.
//!
//! Owns control-stream message handling concerns:
//! - Negentropy control messages (`NegOpen` / `NegMsg`)
//! - Sink-side observation of missing IDs into SQL-backed `wanted` state
//! - Discovery hints and byte-budgeted request refill
//!   via the shared in-memory coordinator

use negentropy::Id;
use tracing::info;

use crate::crypto::EventId;
use crate::db::timeline::EventTimeline;
use crate::db::wanted::WantedEvents;
use crate::db::store::Store;
use crate::protocol::{neg_id_to_event_id, DiscoveryHint, Frame};
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
pub fn observe_discovery_hints_for_peer(
    wanted: &WantedEvents<'_>,
    timeline: &EventTimeline<'_>,
    local_peer_id: &str,
    peer_id: &str,
    discovery_round_started_at: i64,
    hints: &[DiscoveryHint],
    observed_ids: &mut Vec<EventId>,
) -> Result<usize, SyncError> {
    if hints.is_empty() {
        return Ok(0);
    }
    observed_ids.extend(hints.iter().map(|hint| hint.event_id));
    Ok(wanted.observe_many_for_peer(
        local_peer_id,
        peer_id,
        hints,
        discovery_round_started_at,
        timeline,
    )?)
}

/// Send discovery hints for IDs the peer is missing.
///
/// These are not data sends. They only let the remote side populate durable
/// `wanted` state and then pull the blobs under request credit.
pub async fn send_discovery_hints_from_have_ids<C>(
    control: &mut C,
    timeline: &EventTimeline<'_>,
    store: &Store<'_>,
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
        let mut hints = Vec::with_capacity(drain_count);
        for neg_id in have_ids.drain(..drain_count) {
            let event_id = neg_id_to_event_id(&neg_id);
            let Some(summary) = store.get_shared_summary(&event_id)? else {
                continue;
            };
            hints.push(DiscoveryHint {
                event_id: summary.event_id,
                semantic_type_code: summary.semantic_type_code,
                encoded_size_bytes: summary.encoded_size_bytes,
            });
        }
        if hints.is_empty() {
            continue;
        }
        let ids: Vec<EventId> = hints.iter().map(|hint| hint.event_id).collect();
        sent_ids_out.extend_from_slice(&ids);
        let sent_at = crate::db::queue::current_timestamp_ms();
        sent += hints.len();
        let _ = timeline.mark_need_list_sent_many(&ids, sent_at);
        control.send(&Frame::DiscoveryHints { hints }).await?;
    }
    control.flush().await?;
    Ok(sent)
}

/// Keep the peer's request window topped up from durable `wanted` state.
///
/// This is the sink-side scheduler: the shared per-tenant coordinator chooses
/// the next IDs this peer should serve and sends exact `RequestIds` for them.
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
    if snapshot.remote_credit_bytes == 0 {
        return Ok(0);
    }

    let credit_bytes = snapshot.remote_credit_bytes;
    if credit_bytes == 0 {
        return Ok(0);
    }

    let candidate_limit = candidate_limit_for_credit_bytes(credit_bytes, snapshot.inflight_requested.len());
    let selected = coordination.plan_requests(
        wanted,
        peer_id,
        credit_bytes,
        &snapshot.inflight_requested,
        candidate_limit,
        now_ms,
    )?;
    if selected.is_empty() {
        return Ok(0);
    }
    if let Some(credit_received_at) = snapshot.last_credit_received_at {
        let selected_ids: Vec<EventId> = selected.iter().map(|candidate| candidate.event_id).collect();
        let _ = timeline.mark_request_credit_received_many(&selected_ids, credit_received_at);
    }
    let selected_ids: Vec<EventId> = selected.iter().map(|candidate| candidate.event_id).collect();
    let _ = timeline.mark_request_selected_many(&selected_ids, now_ms);
    let reserved_bytes: usize = selected
        .iter()
        .map(|candidate| candidate.credit_cost())
        .sum();

    let batch_size = need_chunk().max(1);
    let mut batch = Vec::with_capacity(batch_size);
    for candidate in &selected {
        batch.push(candidate.event_id);
        if batch.len() >= batch_size {
            control
                .send(&Frame::RequestIds {
                    ids: std::mem::take(&mut batch),
                })
                .await?;
            batch = Vec::with_capacity(batch_size);
        }
    }
    if !batch.is_empty() {
        control.send(&Frame::RequestIds { ids: batch }).await?;
    }
    control.flush().await?;
    request_state.note_requested(&selected_ids, reserved_bytes, now_ms);
    let _ = timeline.mark_request_sent_many(&selected_ids, now_ms);
    let stats = request_state.stats(now_ms);

    info!(
        "Requested more wanted IDs from peer {} (requested_now={}, requested_bytes={}, inflight={}, remaining_credit_bytes={}, candidate_limit={})",
        peer_id,
        selected_ids.len(),
        reserved_bytes,
        stats.inflight_len,
        stats.remote_credit_bytes,
        candidate_limit
    );
    Ok(selected_ids.len())
}

pub async fn send_response_credit_bytes<C>(control: &mut C, bytes: usize) -> Result<(), SyncError>
where
    C: StreamConn,
{
    if bytes == 0 {
        return Ok(());
    }
    let bytes = u32::try_from(bytes).unwrap_or(u32::MAX);
    control.send(&Frame::ResponseCredit { bytes }).await?;
    control.flush().await?;
    Ok(())
}

fn candidate_limit_for_credit_bytes(credit_bytes: usize, inflight_count: usize) -> usize {
    let by_bytes = credit_bytes.div_ceil(128);
    by_bytes.max(need_chunk()).saturating_add(inflight_count)
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
        state.add_credit_bytes(256, 9);
        state.note_requested(&[id], 128, 0);
        assert_eq!(state.stats(request_inflight_ttl_ms() + 1).inflight_len, 0);
    }
}
