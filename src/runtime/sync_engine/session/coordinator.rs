//! Tenant-scoped in-memory pull coordinator.
//!
//! Discovery still persists durable sink truth in SQLite (`wanted` +
//! `wanted_sources`). Request assignment is now bounded in-memory state:
//! each registered peer slot reports its current credit and in-flight pulls,
//! and the coordinator assigns request IDs across all currently known peers.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex, Weak};

use rusqlite::Result as SqliteResult;

use crate::crypto::EventId;
use crate::db::wanted::{WantedCandidate, WantedEvents};
use crate::tuning::request_inflight_ttl_ms;

#[derive(Default)]
struct CoordinatorState {
    peers: HashMap<usize, PeerRequestState>,
}

#[derive(Clone, Default)]
struct PeerRequestState {
    source_peer_id: String,
    available_credit: usize,
    candidate_limit: usize,
    inflight_requested: HashMap<EventId, i64>,
}

impl PeerRequestState {
    fn expire_stale(&mut self, now_ms: i64) {
        let ttl_ms = request_inflight_ttl_ms();
        self.inflight_requested
            .retain(|_, requested_at| now_ms.saturating_sub(*requested_at) < ttl_ms);
    }
}

#[derive(Clone)]
struct PeerRequestReport {
    peer_idx: usize,
    available_credit: usize,
    inflight_requested: HashMap<EventId, i64>,
    candidates: Vec<WantedCandidate>,
}

/// Per-peer coordination handle, reused across reconnecting sessions.
pub struct PeerCoord {
    pub peer_idx: usize,
    /// Snapshot of total registered peers. This is still useful for debug
    /// output and tests, even though pull ownership is no longer hash-based.
    pub total_peers: Arc<AtomicUsize>,
    state: Arc<Mutex<CoordinatorState>>,
    state_weak: Weak<Mutex<CoordinatorState>>,
}

impl PeerCoord {
    /// Plan the next request IDs for this peer using the latest known state of
    /// all registered peers under the same tenant-scoped coordinator.
    pub fn plan_requests(
        &self,
        wanted: &WantedEvents<'_>,
        peer_id: &str,
        available_credit: usize,
        inflight_requested: &HashMap<EventId, i64>,
        candidate_limit: usize,
        now_ms: i64,
    ) -> SqliteResult<Vec<EventId>> {
        let mut state = self.state.lock().expect("coordination mutex poisoned");
        let entry = state.peers.entry(self.peer_idx).or_default();
        entry.source_peer_id = peer_id.to_string();
        entry.available_credit = available_credit;
        entry.candidate_limit = candidate_limit.max(available_credit).max(1);
        entry.inflight_requested = inflight_requested.clone();

        for peer_state in state.peers.values_mut() {
            peer_state.expire_stale(now_ms);
        }

        let reports = state.load_reports(wanted)?;
        let assignments = plan_requests_across_peers(&reports);
        let selected = assignments.get(&self.peer_idx).cloned().unwrap_or_default();

        if let Some(peer_state) = state.peers.get_mut(&self.peer_idx) {
            peer_state.available_credit =
                peer_state.available_credit.saturating_sub(selected.len());
            for event_id in &selected {
                peer_state.inflight_requested.insert(*event_id, now_ms);
            }
        }

        Ok(selected)
    }

    /// Clear request reservations for this peer/session. The durable source of
    /// truth remains `wanted`; lost in-memory reservations simply lead to
    /// re-request on the next sync.
    pub fn clear_request_state(&self) {
        if let Some(state) = self.state_weak.upgrade() {
            if let Ok(mut state) = state.lock() {
                if let Some(peer_state) = state.peers.get_mut(&self.peer_idx) {
                    peer_state.available_credit = 0;
                    peer_state.inflight_requested.clear();
                }
            }
        }
    }
}

impl Drop for PeerCoord {
    fn drop(&mut self) {
        if let Some(state) = self.state_weak.upgrade() {
            if let Ok(mut state) = state.lock() {
                state.peers.remove(&self.peer_idx);
            }
        }
        self.total_peers.fetch_sub(1, AtomicOrdering::Relaxed);
    }
}

impl CoordinatorState {
    fn load_reports(&self, wanted: &WantedEvents<'_>) -> SqliteResult<Vec<PeerRequestReport>> {
        let mut reports = Vec::with_capacity(self.peers.len());
        for (&peer_idx, peer_state) in &self.peers {
            if peer_state.source_peer_id.is_empty()
                || (peer_state.available_credit == 0 && peer_state.inflight_requested.is_empty())
            {
                continue;
            }

            let candidates = if peer_state.available_credit == 0 {
                Vec::new()
            } else {
                wanted.list_candidates_for_peer(
                    &peer_state.source_peer_id,
                    peer_state.candidate_limit,
                )?
            };
            reports.push(PeerRequestReport {
                peer_idx,
                available_credit: peer_state.available_credit,
                inflight_requested: peer_state.inflight_requested.clone(),
                candidates,
            });
        }
        Ok(reports)
    }
}

/// Tenant-scoped coordination manager shared by all peer slots for the same
/// tenant/workspace runtime context.
pub struct CoordinationManager {
    state: Arc<Mutex<CoordinatorState>>,
    next_idx: AtomicUsize,
    total_peers: Arc<AtomicUsize>,
}

impl CoordinationManager {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(CoordinatorState::default())),
            next_idx: AtomicUsize::new(0),
            total_peers: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn register_peer(&self) -> Arc<PeerCoord> {
        let peer_idx = self.next_idx.fetch_add(1, AtomicOrdering::Relaxed);
        self.total_peers.fetch_add(1, AtomicOrdering::Relaxed);
        Arc::new(PeerCoord {
            peer_idx,
            total_peers: self.total_peers.clone(),
            state: self.state.clone(),
            state_weak: Arc::downgrade(&self.state),
        })
    }
}

fn compare_candidates(left: &WantedCandidate, right: &WantedCandidate) -> Ordering {
    left.priority_lane
        .cmp(&right.priority_lane)
        .then_with(|| right.priority_ts.cmp(&left.priority_ts))
        .then_with(|| left.first_seen_at.cmp(&right.first_seen_at))
        .then_with(|| left.event_id.cmp(&right.event_id))
}

fn plan_requests_across_peers(reports: &[PeerRequestReport]) -> HashMap<usize, Vec<EventId>> {
    if reports.is_empty() {
        return HashMap::new();
    }

    let mut assignments: HashMap<usize, Vec<EventId>> = HashMap::with_capacity(reports.len());
    let mut credits: HashMap<usize, usize> = HashMap::with_capacity(reports.len());
    let mut peer_seen: HashMap<usize, HashSet<EventId>> = HashMap::with_capacity(reports.len());
    let mut cursors: HashMap<usize, usize> = HashMap::with_capacity(reports.len());
    let mut globally_inflight: HashSet<EventId> = HashSet::new();

    for report in reports {
        credits.insert(report.peer_idx, report.available_credit);
        peer_seen.insert(
            report.peer_idx,
            report.inflight_requested.keys().copied().collect(),
        );
        cursors.insert(report.peer_idx, 0);
        assignments.insert(report.peer_idx, Vec::new());
        globally_inflight.extend(report.inflight_requested.keys().copied());
    }

    while let Some((peer_idx, event_id, next_cursor)) = next_assignment(
        reports,
        &credits,
        &peer_seen,
        &cursors,
        Some(&globally_inflight),
    ) {
        assignments.entry(peer_idx).or_default().push(event_id);
        if let Some(credit) = credits.get_mut(&peer_idx) {
            *credit = credit.saturating_sub(1);
        }
        if let Some(seen) = peer_seen.get_mut(&peer_idx) {
            seen.insert(event_id);
        }
        globally_inflight.insert(event_id);
        cursors.insert(peer_idx, next_cursor);
    }

    let mut duplicate_cursors: HashMap<usize, usize> = reports
        .iter()
        .map(|report| (report.peer_idx, 0usize))
        .collect();
    while let Some((peer_idx, event_id, next_cursor)) =
        next_assignment(reports, &credits, &peer_seen, &duplicate_cursors, None)
    {
        assignments.entry(peer_idx).or_default().push(event_id);
        if let Some(credit) = credits.get_mut(&peer_idx) {
            *credit = credit.saturating_sub(1);
        }
        if let Some(seen) = peer_seen.get_mut(&peer_idx) {
            seen.insert(event_id);
        }
        duplicate_cursors.insert(peer_idx, next_cursor);
    }

    assignments
}

fn next_assignment(
    reports: &[PeerRequestReport],
    credits: &HashMap<usize, usize>,
    peer_seen: &HashMap<usize, HashSet<EventId>>,
    cursors: &HashMap<usize, usize>,
    global_exclude: Option<&HashSet<EventId>>,
) -> Option<(usize, EventId, usize)> {
    let mut best: Option<(usize, EventId, usize, WantedCandidate)> = None;

    for report in reports {
        let remaining_credit = credits.get(&report.peer_idx).copied().unwrap_or(0);
        if remaining_credit == 0 {
            continue;
        }
        let seen = peer_seen
            .get(&report.peer_idx)
            .expect("peer_seen must exist for every report");
        let start = cursors.get(&report.peer_idx).copied().unwrap_or(0);
        let mut idx = start;
        while let Some(candidate) = report.candidates.get(idx) {
            if seen.contains(&candidate.event_id) {
                idx += 1;
                continue;
            }
            if global_exclude.is_some_and(|exclude| exclude.contains(&candidate.event_id)) {
                idx += 1;
                continue;
            }
            match &best {
                Some((_, _, _, best_candidate))
                    if compare_candidates(best_candidate, candidate) != Ordering::Greater => {}
                _ => {
                    best = Some((report.peer_idx, candidate.event_id, idx + 1, *candidate));
                }
            }
            break;
        }
    }

    best.map(|(peer_idx, event_id, next_cursor, _)| (peer_idx, event_id, next_cursor))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_in_memory, schema::create_tables};
    use std::collections::HashMap;

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
    fn planner_avoids_duplicates_until_unique_candidates_exhausted() {
        let reports = vec![
            PeerRequestReport {
                peer_idx: 0,
                available_credit: 2,
                inflight_requested: HashMap::new(),
                candidates: vec![candidate(1, 1, 100), candidate(2, 1, 90)],
            },
            PeerRequestReport {
                peer_idx: 1,
                available_credit: 2,
                inflight_requested: HashMap::new(),
                candidates: vec![candidate(1, 1, 100), candidate(3, 1, 80)],
            },
        ];

        let assignments = plan_requests_across_peers(&reports);
        let mut all = assignments.values().flatten().copied().collect::<Vec<_>>();
        all.sort();
        all.dedup();
        assert_eq!(
            all.len(),
            3,
            "first pass should cover all three unique IDs before duplicates"
        );
        let total: usize = assignments.values().map(Vec::len).sum();
        assert_eq!(
            total, 4,
            "remaining credit should be used aggressively after first pass"
        );
    }

    #[test]
    fn planner_respects_existing_inflight_across_peers() {
        let mut inflight = HashMap::new();
        inflight.insert(candidate(1, 1, 100).event_id, 1);
        let reports = vec![
            PeerRequestReport {
                peer_idx: 0,
                available_credit: 1,
                inflight_requested: inflight,
                candidates: vec![candidate(1, 1, 100), candidate(2, 1, 90)],
            },
            PeerRequestReport {
                peer_idx: 1,
                available_credit: 1,
                inflight_requested: HashMap::new(),
                candidates: vec![candidate(1, 1, 100), candidate(3, 1, 80)],
            },
        ];

        let assignments = plan_requests_across_peers(&reports);
        assert_eq!(
            assignments.get(&0).cloned().unwrap_or_default(),
            vec![candidate(2, 1, 90).event_id]
        );
        assert_eq!(
            assignments.get(&1).cloned().unwrap_or_default(),
            vec![candidate(3, 1, 80).event_id]
        );
    }

    #[test]
    fn peer_coord_tracks_global_inflight_across_calls() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let wanted = WantedEvents::new(&conn);

        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        let mut c = [0u8; 32];
        a[0] = 1;
        b[0] = 2;
        c[0] = 3;

        wanted.observe_many_for_peer("peer-a", &[a, b]).unwrap();
        wanted.observe_many_for_peer("peer-b", &[a, c]).unwrap();

        let manager = CoordinationManager::new();
        let coord_a = manager.register_peer();
        let coord_b = manager.register_peer();
        let now_ms = 1_000;

        let first = coord_a
            .plan_requests(&wanted, "peer-a", 2, &HashMap::new(), 8, now_ms)
            .unwrap();
        assert_eq!(first.len(), 2);

        let second = coord_b
            .plan_requests(&wanted, "peer-b", 2, &HashMap::new(), 8, now_ms)
            .unwrap();
        assert_eq!(
            second[0], c,
            "peer-b should consume the still-unrequested unique candidate first"
        );
    }
}
