//! Control-plane helpers for sync sessions.
//!
//! Owns control-stream message handling concerns:
//! - Negentropy control messages (`NegOpen` / `NegMsg`)
//! - Pull signaling (`HaveList`)
//! - Multi-source coordinator report/assignment
//! - Session completion control markers (`Done` / `DoneAck`)

use negentropy::Id;
use tracing::info;

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

pub async fn dispatch_need_ids_after_reconcile<C>(
    control: &mut C,
    wanted: &WantedEvents<'_>,
    need_ids: &mut Vec<Id>,
    coordination_enabled: bool,
    coordinated_need_ids: &mut Vec<EventId>,
) -> Result<(), SyncError>
where
    C: StreamConn,
{
    if need_ids.is_empty() {
        return Ok(());
    }

    if coordination_enabled {
        for neg_id in need_ids.drain(..) {
            coordinated_need_ids.push(neg_id_to_event_id(&neg_id));
        }
        return Ok(());
    }

    let mut batch: Vec<EventId> = Vec::with_capacity(NEED_CHUNK);
    for neg_id in need_ids.drain(..) {
        let event_id = neg_id_to_event_id(&neg_id);
        if wanted.insert(&event_id).unwrap_or(false) {
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
    coordination: Option<&PeerCoord>,
    reconciliation_done: bool,
    coordination_reported: &mut bool,
    coordinated_need_ids: &mut Vec<EventId>,
) {
    let Some(coord) = coordination else {
        return;
    };
    if !reconciliation_done || *coordination_reported {
        return;
    }

    let report = std::mem::take(coordinated_need_ids);
    info!(
        "Reporting {} need_ids to coordinator (peer {})",
        report.len(),
        coord.peer_idx
    );
    let _ = coord.report_tx.send(report);
    *coordination_reported = true;
}

pub fn maybe_take_coordination_assignment(
    coordination: Option<&PeerCoord>,
    coordination_pending: bool,
    coordination_reported: bool,
) -> CoordinationAssignment {
    let Some(coord) = coordination else {
        return CoordinationAssignment::NotReady;
    };
    if !coordination_pending || !coordination_reported {
        return CoordinationAssignment::NotReady;
    }

    let assign_result = match coord.assign_rx.lock() {
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
) where
    C: StreamConn,
{
    let mut batch: Vec<EventId> = Vec::with_capacity(NEED_CHUNK);
    for event_id in assigned {
        if wanted.insert(&event_id).unwrap_or(false) {
            batch.push(event_id);
        }
        if batch.len() >= NEED_CHUNK {
            let _ = control.send(&Frame::HaveList { ids: batch }).await;
            let _ = control.flush().await;
            batch = Vec::with_capacity(NEED_CHUNK);
        }
    }
    if !batch.is_empty() {
        let _ = control.send(&Frame::HaveList { ids: batch }).await;
        let _ = control.flush().await;
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
