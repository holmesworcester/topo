//! Control-plane helpers for sync sessions.
//!
//! Owns control-stream message handling concerns:
//! - Negentropy control messages (`NegOpen` / `NegMsg`)
//! - Pull signaling (`HaveList`)
//! - Multi-source coordinator report/assignment
//! - Session completion control markers (`Done` / `DoneAck`)

use negentropy::Id;

use crate::crypto::EventId;
use crate::db::wanted::WantedEvents;
use crate::protocol::{neg_id_to_event_id, Frame};
use crate::transport::StreamConn;

use super::{coordinator::PeerCoord, NEED_CHUNK};

pub type SyncError = Box<dyn std::error::Error + Send + Sync>;

pub enum CoordinationAssignment {
    Assigned(Vec<EventId>),
    Pending,
    Disconnected,
    NotReady,
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

/// Dispatch need_ids discovered during a reconciliation round.
///
/// Sends HaveList frames immediately (streaming pull — events start flowing
/// during reconciliation) AND buffers need_ids for coordinator reporting.
/// The `wanted` table deduplicates: when the coordinator later assigns events
/// that were already dispatched here, `dispatch_assigned_need_ids` skips them.
pub async fn dispatch_need_ids_after_reconcile<C>(
    control: &mut C,
    wanted: &WantedEvents<'_>,
    need_ids: &mut Vec<Id>,
    coordinated_need_ids: &mut Vec<EventId>,
) -> Result<(), SyncError>
where
    C: StreamConn,
{
    if need_ids.is_empty() {
        return Ok(());
    }

    // Stream HaveList immediately AND buffer for coordinator
    let mut batch: Vec<EventId> = Vec::with_capacity(NEED_CHUNK);
    coordinated_need_ids.reserve(need_ids.len());
    for neg_id in need_ids.drain(..) {
        let event_id = neg_id_to_event_id(&neg_id);
        coordinated_need_ids.push(event_id);
        if wanted.insert(&event_id)? {
            batch.push(event_id);
        }
        if batch.len() >= NEED_CHUNK {
            control.send(&Frame::HaveList { ids: batch }).await?;
            control.flush().await?;
            batch = Vec::with_capacity(NEED_CHUNK);
        }
    }
    if !batch.is_empty() {
        control.send(&Frame::HaveList { ids: batch }).await?;
        control.flush().await?;
    }

    Ok(())
}

pub fn maybe_report_coordination_need_ids(
    coordination: &PeerCoord,
    reconciliation_done: bool,
    coordination_reported: &mut bool,
    coordinated_need_ids: &mut Vec<EventId>,
) -> Result<(), SyncError> {
    if !reconciliation_done || *coordination_reported {
        return Ok(());
    }

    let report = std::mem::take(coordinated_need_ids);
    coordination
        .report_tx
        .send(report)
        .map_err(|_| "coordinator report channel disconnected".to_string())?;
    coordination
        .wake_tx
        .send(())
        .map_err(|_| "coordinator wake channel disconnected".to_string())?;
    *coordination_reported = true;
    Ok(())
}

pub fn maybe_take_coordination_assignment(
    coordination: &PeerCoord,
    coordination_pending: bool,
    coordination_reported: bool,
) -> CoordinationAssignment {
    if !coordination_pending || !coordination_reported {
        return CoordinationAssignment::NotReady;
    }

    let assign_result = match coordination.assign_rx.lock() {
        Ok(rx) => rx.try_recv(),
        Err(_) => Err(std::sync::mpsc::TryRecvError::Disconnected),
    };

    match assign_result {
        Ok(assigned) => CoordinationAssignment::Assigned(assigned),
        Err(std::sync::mpsc::TryRecvError::Empty) => CoordinationAssignment::Pending,
        Err(std::sync::mpsc::TryRecvError::Disconnected) => CoordinationAssignment::Disconnected,
    }
}

pub async fn dispatch_assigned_need_ids<C>(
    control: &mut C,
    wanted: &WantedEvents<'_>,
    assigned: Vec<EventId>,
) -> Result<(), SyncError>
where
    C: StreamConn,
{
    let mut batch: Vec<EventId> = Vec::with_capacity(NEED_CHUNK);
    for event_id in assigned {
        if wanted.insert(&event_id)? {
            batch.push(event_id);
        }
        if batch.len() >= NEED_CHUNK {
            control.send(&Frame::HaveList { ids: batch }).await?;
            control.flush().await?;
            batch = Vec::with_capacity(NEED_CHUNK);
        }
    }
    if !batch.is_empty() {
        control.send(&Frame::HaveList { ids: batch }).await?;
        control.flush().await?;
    }
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
