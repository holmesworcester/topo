//! Multi-source download coordinator and greedy event assignment.
//!
//! The coordinator thread collects need_ids from all peers after
//! reconciliation, then uses greedy load-balanced assignment to distribute
//! download work across peers.

use std::time::Instant;

use crate::crypto::EventId;

use super::{COORDINATOR_COLLECTION_POLL, COORDINATOR_COLLECTION_WINDOW, COORDINATOR_POLL_INTERVAL};

/// Per-peer coordination handles for coordinated multi-source download.
///
/// Held by the peer thread, reused across sessions. The peer sends its
/// discovered need_ids to the coordinator via `report_tx`, then polls
/// `assign_rx` for its assigned subset.
pub struct PeerCoord {
    pub peer_idx: usize,
    pub report_tx: std::sync::mpsc::Sender<Vec<EventId>>,
    pub assign_rx: std::sync::Mutex<std::sync::mpsc::Receiver<Vec<EventId>>>,
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

/// Coordinator thread for multi-source download rounds.
///
/// Each iteration is one round:
/// 1. Block until the first peer reports its need_ids.
/// 2. Start a 500ms collection window for remaining peers.
/// 3. Call assign_events with collected reports.
/// 4. Send assigned Vec<EventId> to each reporting peer.
/// 5. Send empty Vec to non-reporting peers (unblocks their session).
pub fn run_coordinator(
    report_rxs: Vec<std::sync::mpsc::Receiver<Vec<EventId>>>,
    assign_txs: Vec<std::sync::mpsc::Sender<Vec<EventId>>>,
) {
    let total_peers = report_rxs.len();
    loop {
        // Phase 1: Block until at least one peer reports
        let mut reports: Vec<Option<Vec<EventId>>> = vec![None; total_peers];
        let mut reported_count = 0;
        let mut any_alive = false;

        loop {
            let mut all_disconnected = true;
            for (i, rx) in report_rxs.iter().enumerate() {
                if reports[i].is_some() {
                    continue;
                }
                match rx.try_recv() {
                    Ok(need_ids) => {
                        reports[i] = Some(need_ids);
                        reported_count += 1;
                        any_alive = true;
                        all_disconnected = false;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        all_disconnected = false;
                    }
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {}
                }
            }
            if reported_count > 0 || all_disconnected {
                break;
            }
            std::thread::sleep(COORDINATOR_POLL_INTERVAL);
        }

        if !any_alive && reported_count == 0 {
            return;
        }

        // Phase 2: Collection window for remaining peers
        let deadline = Instant::now() + COORDINATOR_COLLECTION_WINDOW;
        while reported_count < total_peers && Instant::now() < deadline {
            for (i, rx) in report_rxs.iter().enumerate() {
                if reports[i].is_some() {
                    continue;
                }
                match rx.try_recv() {
                    Ok(need_ids) => {
                        reports[i] = Some(need_ids);
                        reported_count += 1;
                    }
                    Err(_) => {}
                }
            }
            if reported_count < total_peers {
                std::thread::sleep(COORDINATOR_COLLECTION_POLL);
            }
        }

        // Phase 3: Assign events
        let collected: Vec<(usize, Vec<EventId>)> = reports
            .iter()
            .enumerate()
            .filter_map(|(i, r)| r.as_ref().map(|ids| (i, ids.clone())))
            .collect();
        let assignments = assign_events(&collected, total_peers);

        // Phase 4: Send assignments only to peers that reported this round
        for (i, tx) in assign_txs.iter().enumerate() {
            if reports[i].is_some() {
                let assigned = assignments[i].clone();
                if tx.send(assigned).is_err() {
                    // Peer disconnected; continue with remaining peers
                }
            }
        }
    }
}
