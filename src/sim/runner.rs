use std::cmp::Ordering;
use std::collections::BinaryHeap;

use serde::Serialize;

use super::clock::SimTime;
use super::knowledge::{exact_matrix_bytes, SparseKnowledge};
use super::scenario::{IngestPolicy, PeerId, Scenario};

#[derive(Clone, Debug)]
struct PeerState {
    online: bool,
    knowledge: SparseKnowledge,
    ingested_messages: SparseKnowledge,
}

#[derive(Clone, Debug)]
enum SimEventKind {
    PublishMessage { message_id: u32, author: PeerId },
    SyncPair { left: PeerId, right: PeerId },
}

#[derive(Clone, Debug)]
struct SimEvent {
    at: SimTime,
    seq: u64,
    kind: SimEventKind,
}

impl PartialEq for SimEvent {
    fn eq(&self, other: &Self) -> bool {
        self.at == other.at && self.seq == other.seq
    }
}

impl Eq for SimEvent {}

impl PartialOrd for SimEvent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SimEvent {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .at
            .cmp(&self.at)
            .then_with(|| other.seq.cmp(&self.seq))
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct SimulationSummary {
    pub published_messages: u32,
    pub delivered_messages: u64,
    pub ingested_messages: u64,
    pub delivered_without_ingest: u64,
    pub sync_events: u64,
    pub key_need_events: u64,
    pub key_repair_events: u64,
    pub range_bytes: u64,
    pub key_need_bytes: u64,
    pub key_repair_bytes: u64,
    pub total_bytes: u64,
    pub simulated_time_ms: u64,
    pub online_peer_samples: u64,
    pub exact_matrix_bytes_estimate: u64,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PeerSimulationState {
    pub peer_id: u32,
    pub known_contiguous_prefix: u32,
    pub ingested_contiguous_prefix: u32,
    pub sparse_known_tail: usize,
    pub sparse_ingested_tail: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct SimulationReport {
    pub summary: SimulationSummary,
    pub peers: Vec<PeerSimulationState>,
}

pub struct Simulation {
    scenario: Scenario,
    peers: Vec<PeerState>,
    queue: BinaryHeap<SimEvent>,
    now: SimTime,
    next_seq: u64,
    published_message_upper: u32,
    summary: SimulationSummary,
}

impl Simulation {
    pub fn new(scenario: Scenario) -> Result<Self, String> {
        scenario.validate()?;
        let peers = scenario
            .peers
            .iter()
            .map(|_| PeerState {
                online: false,
                knowledge: SparseKnowledge::new(),
                ingested_messages: SparseKnowledge::new(),
            })
            .collect();

        let mut sim = Self {
            scenario,
            peers,
            queue: BinaryHeap::new(),
            now: SimTime::from_millis(0),
            next_seq: 0,
            published_message_upper: 0,
            summary: SimulationSummary::default(),
        };
        sim.bootstrap();
        Ok(sim)
    }

    pub fn run(self) -> SimulationSummary {
        self.run_detailed().summary
    }

    pub fn run_detailed(mut self) -> SimulationReport {
        while let Some(event) = self.queue.pop() {
            self.now = event.at;
            self.handle_event(event.kind);
        }
        self.summary.exact_matrix_bytes_estimate = exact_matrix_bytes(
            self.scenario.peers.len() as u64,
            self.scenario.message_count as u64,
        );
        self.summary.simulated_time_ms = self.now.millis();
        self.summary.total_bytes =
            self.summary.range_bytes + self.summary.key_need_bytes + self.summary.key_repair_bytes;
        self.summary.delivered_without_ingest = self
            .summary
            .delivered_messages
            .saturating_sub(self.summary.ingested_messages);
        let peers = self
            .peers
            .iter()
            .enumerate()
            .map(|(idx, peer)| PeerSimulationState {
                peer_id: self.scenario.peers[idx].id.0,
                known_contiguous_prefix: peer.knowledge.known_contiguous_prefix(),
                ingested_contiguous_prefix: peer.ingested_messages.known_contiguous_prefix(),
                sparse_known_tail: peer.knowledge.sparse_tail_count(),
                sparse_ingested_tail: peer.ingested_messages.sparse_tail_count(),
            })
            .collect();
        SimulationReport {
            summary: self.summary.clone(),
            peers,
        }
    }

    fn bootstrap(&mut self) {
        for peer in &mut self.peers {
            peer.online = true;
        }

        for message_id in 0..self.scenario.message_count {
            let at = SimTime::from_millis(
                self.scenario
                    .message_interval_ms
                    .saturating_mul(message_id as u64),
            );
            let author = self.scenario.author_for(message_id);
            self.push_event(at, SimEventKind::PublishMessage { message_id, author });
        }

        let edges = self.scenario.topology.edges(self.scenario.peers.len());
        for round in 0..self.scenario.sync_rounds {
            let at = SimTime::from_millis(
                self.scenario
                    .sync
                    .interval_ms
                    .saturating_mul(round as u64 + 1),
            );
            for (left, right) in &edges {
                self.push_event(
                    at,
                    SimEventKind::SyncPair {
                        left: *left,
                        right: *right,
                    },
                );
            }
        }
    }

    fn push_event(&mut self, at: SimTime, kind: SimEventKind) {
        self.next_seq = self.next_seq.saturating_add(1);
        self.queue.push(SimEvent {
            at,
            seq: self.next_seq,
            kind,
        });
    }

    fn handle_event(&mut self, kind: SimEventKind) {
        match kind {
            SimEventKind::PublishMessage { message_id, author } => {
                self.summary.published_messages = self.summary.published_messages.saturating_add(1);
                self.published_message_upper = self
                    .published_message_upper
                    .max(message_id.saturating_add(1));
                if let Some(author_state) = self.peer_state_mut(author) {
                    author_state.knowledge.mark_known(message_id);
                    author_state.ingested_messages.mark_known(message_id);
                }
            }
            SimEventKind::SyncPair { left, right } => {
                self.handle_sync_pair(left, right);
            }
        }
    }

    fn handle_sync_pair(&mut self, left: PeerId, right: PeerId) {
        let Some((left_idx, right_idx)) = self.peer_indices(left, right) else {
            return;
        };

        let left_online = self.peers[left_idx].online
            && self.scenario.peers[left_idx]
                .activity
                .is_online_at(self.now.millis());
        let right_online = self.peers[right_idx].online
            && self.scenario.peers[right_idx]
                .activity
                .is_online_at(self.now.millis());

        if !left_online || !right_online {
            return;
        }

        self.summary.online_peer_samples = self.summary.online_peer_samples.saturating_add(2);
        self.summary.sync_events = self.summary.sync_events.saturating_add(1);

        let message_bytes = self.scenario.message_bytes as u64;
        let need_bytes = self.scenario.key_need_bytes as u64;
        let repair_bytes = self.scenario.key_repair_bytes as u64;

        let (delivered, ingested) = self.exchange_peer_knowledge(left_idx, right_idx);

        if delivered > 0 {
            self.summary.delivered_messages =
                self.summary.delivered_messages.saturating_add(delivered);
            self.summary.range_bytes = self
                .summary
                .range_bytes
                .saturating_add(delivered.saturating_mul(message_bytes));
        }

        if ingested > 0 {
            self.summary.ingested_messages =
                self.summary.ingested_messages.saturating_add(ingested);
            self.summary.key_need_events = self.summary.key_need_events.saturating_add(ingested);
            self.summary.key_repair_events =
                self.summary.key_repair_events.saturating_add(ingested);
            self.summary.key_need_bytes = self
                .summary
                .key_need_bytes
                .saturating_add(ingested.saturating_mul(need_bytes));
            self.summary.key_repair_bytes = self
                .summary
                .key_repair_bytes
                .saturating_add(ingested.saturating_mul(repair_bytes));
        }

        let sync_cost = self.scenario.sync.link_rtt_ms.saturating_add(
            (delivered.saturating_mul(message_bytes))
                .saturating_div(self.scenario.sync.bandwidth_bytes_per_ms.max(1)),
        );
        self.now = self.now.advance_by(sync_cost);
    }

    fn peer_indices(&self, left: PeerId, right: PeerId) -> Option<(usize, usize)> {
        let left_idx = self
            .scenario
            .peers
            .iter()
            .position(|peer| peer.id == left)?;
        let right_idx = self
            .scenario
            .peers
            .iter()
            .position(|peer| peer.id == right)?;
        Some((left_idx, right_idx))
    }

    fn peer_state_mut(&mut self, peer: PeerId) -> Option<&mut PeerState> {
        let idx = self
            .scenario
            .peers
            .iter()
            .position(|candidate| candidate.id == peer)?;
        self.peers.get_mut(idx)
    }

    fn exchange_peer_knowledge(&mut self, left_idx: usize, right_idx: usize) -> (u64, u64) {
        if left_idx == right_idx {
            return (0, 0);
        }

        let (left_peer, right_peer) = if left_idx < right_idx {
            let (head, tail) = self.peers.split_at_mut(right_idx);
            (&mut head[left_idx], &mut tail[0])
        } else {
            let (head, tail) = self.peers.split_at_mut(left_idx);
            (&mut tail[0], &mut head[right_idx])
        };

        let left_snapshot = left_peer.knowledge.clone();
        let right_snapshot = right_peer.knowledge.clone();

        let learned_by_left = left_peer.knowledge.merge_from(&right_snapshot);
        let learned_by_right = right_peer.knowledge.merge_from(&left_snapshot);
        let ingested_by_left = Self::selective_ingest_count(
            &self.scenario.ingest,
            self.published_message_upper,
            &mut left_peer.ingested_messages,
            &right_snapshot,
            learned_by_left,
        );
        let ingested_by_right = Self::selective_ingest_count(
            &self.scenario.ingest,
            self.published_message_upper,
            &mut right_peer.ingested_messages,
            &left_snapshot,
            learned_by_right,
        );

        (
            learned_by_left.saturating_add(learned_by_right),
            ingested_by_left.saturating_add(ingested_by_right),
        )
    }

    fn selective_ingest_count(
        policy: &IngestPolicy,
        published_upper: u32,
        recipient_ingested: &mut SparseKnowledge,
        donor_knowledge: &SparseKnowledge,
        delivered_count: u64,
    ) -> u64 {
        match policy {
            IngestPolicy::EagerAll => recipient_ingested.merge_from(donor_knowledge),
            IngestPolicy::HotMessageWindow {
                recent_message_count,
            } => {
                let window_start = published_upper.saturating_sub(*recent_message_count);
                let ingested = recipient_ingested.learn_window_from(
                    donor_knowledge,
                    window_start,
                    published_upper,
                );
                ingested.min(delivered_count)
            }
        }
    }
}
