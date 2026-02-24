//! Multi-source download coordinator and greedy event assignment.
//!
//! The coordinator thread collects need_ids from all peers after
//! reconciliation, then uses greedy load-balanced assignment to distribute
//! download work across peers.
//!
//! `CoordinationManager` spawns a dynamic coordinator thread where peers
//! register at runtime as bootstrap/mDNS targets are discovered.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::crypto::EventId;

use super::{
    COORDINATOR_COLLECTION_POLL, COORDINATOR_COLLECTION_WINDOW, COORDINATOR_POLL_INTERVAL,
};

/// Per-peer coordination handles for coordinated multi-source download.
///
/// Held by the peer thread, reused across sessions. The peer sends its
/// discovered need_ids to the coordinator via `report_tx`, then polls
/// `assign_rx` for its assigned subset.
pub struct PeerCoord {
    pub peer_idx: usize,
    pub report_tx: std::sync::mpsc::Sender<Vec<EventId>>,
    pub assign_rx: std::sync::Mutex<std::sync::mpsc::Receiver<Vec<EventId>>>,
    /// Signal the coordinator to wake up immediately after reporting need_ids.
    pub(crate) wake_tx: std::sync::mpsc::Sender<()>,
}

/// Assign events to peers using greedy load balancing.
///
/// Takes `(peer_idx, Vec<EventId>)` pairs from all reporting peers.
/// Builds an `event_id -> Vec<peer_idx>` availability map, sorts by
/// availability ascending (unique events first), then assigns each event
/// to the least-loaded peer that has it.
///
/// Returns indexed `Vec` where `result[peer_idx]` = events assigned to that peer.
fn assign_events(reports: &[(usize, Vec<EventId>)], total_peers: usize) -> Vec<Vec<EventId>> {
    use std::collections::HashMap;

    // Build event -> available peers map
    let mut availability: HashMap<EventId, Vec<usize>> = HashMap::new();
    for (peer_idx, events) in reports {
        for eid in events {
            availability.entry(*eid).or_default().push(*peer_idx);
        }
    }

    // Sort by availability ascending (unique events assigned first)
    let mut events_sorted: Vec<(EventId, Vec<usize>)> = availability.into_iter().collect();
    events_sorted.sort_by_key(|(_, peers)| peers.len());

    // Greedy assignment: least-loaded peer that has the event
    let mut loads = vec![0usize; total_peers];
    let mut assignments: Vec<Vec<EventId>> = vec![Vec::new(); total_peers];

    for (eid, peers) in events_sorted {
        let best = peers.iter().copied().min_by_key(|&p| loads[p]).unwrap();
        assignments[best].push(eid);
        loads[best] += 1;
    }

    assignments
}

// ---------------------------------------------------------------------------
// Dynamic coordinator: peers register at runtime
// ---------------------------------------------------------------------------

/// Internal registration message sent to the dynamic coordinator thread.
struct PeerRegistration {
    report_rx: std::sync::mpsc::Receiver<Vec<EventId>>,
    assign_tx: std::sync::mpsc::Sender<Vec<EventId>>,
}

/// Tenant-scoped coordination manager for dynamic peer membership.
///
/// Spawns a background coordinator thread that accepts new peers via
/// `register_peer()`. Newly discovered peers (bootstrap, mDNS) join the
/// coordinated download without restarting the daemon.
///
/// When only one peer is registered, the coordinator degenerates to
/// pass-through assignment (all need_ids go to the sole source).
pub struct CoordinationManager {
    register_tx: std::sync::mpsc::Sender<PeerRegistration>,
    next_idx: Arc<AtomicUsize>,
    wake_tx: std::sync::mpsc::Sender<()>,
}

impl CoordinationManager {
    /// Create a new coordination manager and spawn its coordinator thread.
    pub fn new() -> Self {
        let (register_tx, register_rx) = std::sync::mpsc::channel();
        let (wake_tx, wake_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            run_dynamic_coordinator(register_rx, wake_rx);
        });
        CoordinationManager {
            register_tx,
            next_idx: Arc::new(AtomicUsize::new(0)),
            wake_tx,
        }
    }

    /// Register a new peer and return its coordination handles.
    ///
    /// The returned `PeerCoord` is passed into `connect_loop` so the
    /// initiator session reports need_ids and receives assignments.
    pub fn register_peer(&self) -> Arc<PeerCoord> {
        let idx = self.next_idx.fetch_add(1, Ordering::Relaxed);
        let (report_tx, report_rx) = std::sync::mpsc::channel();
        let (assign_tx, assign_rx) = std::sync::mpsc::channel();
        // Best-effort: if coordinator thread is gone, the PeerCoord's
        // report_tx.send() will fail gracefully and the session falls
        // back to requesting all need_ids (coordinator disconnect path
        // in initiator.rs sets coordination_pending = false).
        let _ = self.register_tx.send(PeerRegistration {
            report_rx,
            assign_tx,
        });
        Arc::new(PeerCoord {
            peer_idx: idx,
            report_tx,
            assign_rx: std::sync::Mutex::new(assign_rx),
            wake_tx: self.wake_tx.clone(),
        })
    }
}

/// Dynamic coordinator thread: accepts peers at runtime and runs
/// coordinated round-based assignment with variable membership.
fn run_dynamic_coordinator(
    register_rx: std::sync::mpsc::Receiver<PeerRegistration>,
    wake_rx: std::sync::mpsc::Receiver<()>,
) {
    let mut report_rxs: Vec<std::sync::mpsc::Receiver<Vec<EventId>>> = Vec::new();
    let mut assign_txs: Vec<std::sync::mpsc::Sender<Vec<EventId>>> = Vec::new();
    // Track which slots are still alive (sender not disconnected)
    let mut alive: Vec<bool> = Vec::new();

    loop {
        // Accept all pending registrations
        loop {
            match register_rx.try_recv() {
                Ok(reg) => {
                    report_rxs.push(reg.report_rx);
                    assign_txs.push(reg.assign_tx);
                    alive.push(true);
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    // Manager dropped — no new peers will arrive.
                    // Continue coordinating existing peers until they disconnect.
                    break;
                }
            }
        }

        // If no peers registered yet, block until the first one arrives.
        if report_rxs.is_empty() {
            match register_rx.recv() {
                Ok(reg) => {
                    report_rxs.push(reg.report_rx);
                    assign_txs.push(reg.assign_tx);
                    alive.push(true);
                }
                Err(_) => return, // Manager dropped, no peers ever registered
            }
        }

        let total = report_rxs.len();

        // Phase 1: Block until at least one alive peer reports
        let mut reports: Vec<Option<Vec<EventId>>> = vec![None; total];
        let mut reported_count = 0;
        let mut any_alive = false;

        loop {
            // Accept new registrations while waiting
            while let Ok(reg) = register_rx.try_recv() {
                report_rxs.push(reg.report_rx);
                assign_txs.push(reg.assign_tx);
                alive.push(true);
                reports.push(None);
            }

            let mut all_disconnected = true;
            for i in 0..report_rxs.len() {
                if !alive[i] || reports[i].is_some() {
                    continue;
                }
                match report_rxs[i].try_recv() {
                    Ok(need_ids) => {
                        reports[i] = Some(need_ids);
                        reported_count += 1;
                        any_alive = true;
                        all_disconnected = false;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        all_disconnected = false;
                    }
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        alive[i] = false;
                    }
                }
            }
            if reported_count > 0 || all_disconnected {
                break;
            }
            // Wait for a peer to signal a report, with poll fallback
            let _ = wake_rx.recv_timeout(COORDINATOR_POLL_INTERVAL);
            // Drain any extra wake signals
            while wake_rx.try_recv().is_ok() {}
        }

        if !any_alive && reported_count == 0 {
            // All peers disconnected and manager may still be alive.
            // Check if manager is still alive; if so, wait for new peers.
            match register_rx.try_recv() {
                Ok(reg) => {
                    // A new peer registered while all others disconnected — accept it.
                    report_rxs.push(reg.report_rx);
                    assign_txs.push(reg.assign_tx);
                    alive.push(true);
                    reports.push(None);
                    continue; // Restart round with the new peer
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    // Manager alive but no new peers yet — block until one arrives.
                    match register_rx.recv() {
                        Ok(reg) => {
                            report_rxs.push(reg.report_rx);
                            assign_txs.push(reg.assign_tx);
                            alive.push(true);
                            reports.push(None);
                            continue; // Restart round
                        }
                        Err(_) => return,
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    // Manager dropped and no alive peers — exit coordinator.
                    return;
                }
            }
        }

        // Phase 2: Collection window for remaining alive peers
        let alive_count = alive.iter().filter(|&&a| a).count();
        let deadline = Instant::now() + COORDINATOR_COLLECTION_WINDOW;
        while reported_count < alive_count && Instant::now() < deadline {
            // Accept new registrations during collection window
            while let Ok(reg) = register_rx.try_recv() {
                report_rxs.push(reg.report_rx);
                assign_txs.push(reg.assign_tx);
                alive.push(true);
                reports.push(None);
            }

            for i in 0..report_rxs.len() {
                if !alive[i] || reports[i].is_some() {
                    continue;
                }
                match report_rxs[i].try_recv() {
                    Ok(need_ids) => {
                        reports[i] = Some(need_ids);
                        reported_count += 1;
                    }
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        alive[i] = false;
                    }
                    Err(_) => {}
                }
            }
            if reported_count < alive_count {
                std::thread::sleep(COORDINATOR_COLLECTION_POLL);
            }
        }

        // Phase 3: Assign events
        let current_total = report_rxs.len();
        let collected: Vec<(usize, Vec<EventId>)> = reports
            .iter()
            .enumerate()
            .filter_map(|(i, r)| r.as_ref().map(|ids| (i, ids.clone())))
            .collect();
        let assignments = assign_events(&collected, current_total);

        // Phase 4: Send assignments to reporting peers
        for i in 0..current_total {
            if reports[i].is_some() {
                let assigned = assignments[i].clone();
                if assign_txs[i].send(assigned).is_err() {
                    alive[i] = false;
                }
            }
        }
    }
}
