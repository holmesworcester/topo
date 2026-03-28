use std::collections::BTreeMap;

use serde::Serialize;

use super::hash_graph::{connected_hash_graph_neighbors, DEFAULT_HASH_GRAPH_DEGREE};
use super::pair_sync::{
    apply_prepared_pair_sync_session, plan_pair_sync_intents, prepare_pair_sync_session,
    PairSyncIntent, PairSyncSessionStats, SimPeerNode,
};
use super::query_snapshot::import_local_tenants_from_db;
use crate::runtime::peering::engine::should_initiate_connect_for_source_with_db;
use crate::runtime::peering::engine::target_dispatch::TargetIngressSource;
use crate::shared::crypto::event_id_from_hex;

type PlannerResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum PlannerMode {
    RealConnectTargets,
    NearestNeighborNoAuth,
}

impl Default for PlannerMode {
    fn default() -> Self {
        Self::RealConnectTargets
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum FakeTopologyPreference {
    Star,
    Graph,
}

impl Default for FakeTopologyPreference {
    fn default() -> Self {
        Self::Graph
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct PairEndpoint {
    db_path: String,
    recorded_by: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct PairKey {
    left: PairEndpoint,
    right: PairEndpoint,
}

impl PairKey {
    fn from_intent(intent: &PairSyncIntent) -> Self {
        let initiator = PairEndpoint {
            db_path: intent.initiator_db_path.clone(),
            recorded_by: intent.initiator_recorded_by.clone(),
        };
        let target = PairEndpoint {
            db_path: intent.target_db_path.clone(),
            recorded_by: intent.target_recorded_by.clone(),
        };
        if initiator <= target {
            Self {
                left: initiator,
                right: target,
            }
        } else {
            Self {
                left: target,
                right: initiator,
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PlannerImportedNode {
    pub db_path: String,
    pub recorded_by: String,
    pub connect_target_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PlannedPairSession {
    pub left_db_path: String,
    pub left_recorded_by: String,
    pub right_db_path: String,
    pub right_recorded_by: String,
    pub source_intents: Vec<PairSyncIntent>,
    pub stats: PairSyncSessionStats,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PlannerRoundReport {
    pub mode: PlannerMode,
    pub fake_topology: Option<FakeTopologyPreference>,
    pub imported_nodes: usize,
    pub planned_intents: usize,
    pub unique_pairs: usize,
    pub sessions_executed: usize,
    pub transferred_events: usize,
    pub transferred_bytes: u64,
    pub nodes: Vec<PlannerImportedNode>,
    pub pairs: Vec<PlannedPairSession>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PlannerRunReport {
    pub rounds: Vec<PlannerRoundReport>,
    pub imported_nodes: usize,
    pub planned_intents: usize,
    pub unique_pairs: usize,
    pub sessions_executed: usize,
    pub transferred_events: usize,
    pub transferred_bytes: u64,
}

pub struct PlannerSimulation {
    db_paths: Vec<String>,
    mode: PlannerMode,
    fake_topology: FakeTopologyPreference,
}

impl PlannerSimulation {
    pub fn new<I, S>(db_paths: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::with_mode(db_paths, PlannerMode::RealConnectTargets)
    }

    pub fn with_mode<I, S>(db_paths: I, mode: PlannerMode) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::with_mode_and_topology(db_paths, mode, FakeTopologyPreference::Graph)
    }

    pub fn with_mode_and_topology<I, S>(
        db_paths: I,
        mode: PlannerMode,
        fake_topology: FakeTopologyPreference,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut seen = std::collections::BTreeSet::new();
        let mut out = Vec::new();
        for db_path in db_paths.into_iter().map(Into::into) {
            if seen.insert(db_path.clone()) {
                out.push(db_path);
            }
        }
        Self {
            db_paths: out,
            mode,
            fake_topology,
        }
    }

    pub fn imported_nodes(&self) -> PlannerResult<Vec<SimPeerNode>> {
        let mut nodes = Vec::new();
        for db_path in &self.db_paths {
            for tenant in import_local_tenants_from_db(db_path)? {
                nodes.push(SimPeerNode::from_imported(db_path, &tenant));
            }
        }
        Ok(nodes)
    }

    pub fn tick(&self) -> PlannerResult<PlannerRoundReport> {
        let nodes = self.imported_nodes()?;
        let intents = match self.mode {
            PlannerMode::RealConnectTargets => plan_pair_sync_intents(&nodes)
                .into_iter()
                .filter(|intent| {
                    pair_intent_source(intent).is_some_and(|source| {
                        should_initiate_connect_for_source_with_db(
                            &intent.initiator_db_path,
                            &intent.initiator_recorded_by,
                            &source,
                        )
                    })
                })
                .collect::<Vec<_>>(),
            PlannerMode::NearestNeighborNoAuth => fake_no_auth_intents(&nodes, self.fake_topology),
        };
        let mut grouped = BTreeMap::<PairKey, Vec<PairSyncIntent>>::new();
        for intent in intents {
            grouped
                .entry(PairKey::from_intent(&intent))
                .or_default()
                .push(intent);
        }

        let mut prepared_pairs = Vec::new();
        for (pair, source_intents) in grouped {
            let prepared = prepare_pair_sync_session(
                &pair.left.db_path,
                &pair.left.recorded_by,
                &pair.right.db_path,
                &pair.right.recorded_by,
            )?;
            prepared_pairs.push((pair, source_intents, prepared));
        }

        let mut pairs = Vec::new();
        let mut transferred_events = 0usize;
        let mut transferred_bytes = 0u64;

        for (pair, source_intents, prepared) in prepared_pairs {
            let stats = apply_prepared_pair_sync_session(prepared)?;
            transferred_events = transferred_events
                .saturating_add(stats.left_to_right.transferred_events)
                .saturating_add(stats.right_to_left.transferred_events);
            transferred_bytes = transferred_bytes
                .saturating_add(stats.left_to_right.transferred_bytes)
                .saturating_add(stats.right_to_left.transferred_bytes);
            pairs.push(PlannedPairSession {
                left_db_path: pair.left.db_path,
                left_recorded_by: pair.left.recorded_by,
                right_db_path: pair.right.db_path,
                right_recorded_by: pair.right.recorded_by,
                source_intents,
                stats,
            });
        }

        let nodes = nodes
            .into_iter()
            .map(|node| PlannerImportedNode {
                db_path: node.db_path,
                recorded_by: node.recorded_by,
                connect_target_count: node.connect_targets.len(),
            })
            .collect::<Vec<_>>();

        Ok(PlannerRoundReport {
            mode: self.mode,
            fake_topology: matches!(self.mode, PlannerMode::NearestNeighborNoAuth)
                .then_some(self.fake_topology),
            imported_nodes: nodes.len(),
            planned_intents: pairs
                .iter()
                .map(|pair| pair.source_intents.len())
                .sum::<usize>(),
            unique_pairs: pairs.len(),
            sessions_executed: pairs.len(),
            transferred_events,
            transferred_bytes,
            nodes,
            pairs,
        })
    }

    pub fn run_rounds(&self, rounds: u32) -> PlannerResult<PlannerRunReport> {
        let mut out = PlannerRunReport::default();
        for _ in 0..rounds {
            let round = self.tick()?;
            out.imported_nodes = out.imported_nodes.saturating_add(round.imported_nodes);
            out.planned_intents = out.planned_intents.saturating_add(round.planned_intents);
            out.unique_pairs = out.unique_pairs.saturating_add(round.unique_pairs);
            out.sessions_executed = out
                .sessions_executed
                .saturating_add(round.sessions_executed);
            out.transferred_events = out
                .transferred_events
                .saturating_add(round.transferred_events);
            out.transferred_bytes = out
                .transferred_bytes
                .saturating_add(round.transferred_bytes);
            out.rounds.push(round);
        }
        Ok(out)
    }
}

fn pair_intent_source(intent: &PairSyncIntent) -> Option<TargetIngressSource> {
    match intent.source.as_str() {
        "bootstrap" => Some(TargetIngressSource::Bootstrap {
            daemon_peer_id: intent.target_transport_peer_id.clone(),
            invite_event_id: intent.invite_event_id.clone().unwrap_or_default(),
        }),
        "observed" => Some(TargetIngressSource::ObservedPeer {
            peer_id: intent.target_transport_peer_id.clone(),
        }),
        "discovery" => Some(TargetIngressSource::Discovery {
            peer_id: intent.target_transport_peer_id.clone(),
        }),
        _ => None,
    }
}

fn fake_no_auth_intents(
    nodes: &[SimPeerNode],
    topology: FakeTopologyPreference,
) -> Vec<PairSyncIntent> {
    match topology {
        FakeTopologyPreference::Star => fake_star_intents(nodes),
        FakeTopologyPreference::Graph => fake_graph_intents(nodes, DEFAULT_HASH_GRAPH_DEGREE),
    }
}

fn fake_star_intents(nodes: &[SimPeerNode]) -> Vec<PairSyncIntent> {
    let Some(hub) = nodes.first() else {
        return Vec::new();
    };
    nodes
        .iter()
        .skip(1)
        .map(|node| fake_intent(node, hub, "fake_star_no_auth"))
        .collect()
}

fn fake_graph_intents(nodes: &[SimPeerNode], degree: usize) -> Vec<PairSyncIntent> {
    let keys = nodes.iter().map(fake_graph_key).collect::<Vec<_>>();
    let neighbors = connected_hash_graph_neighbors(&keys, degree);
    let mut intents = Vec::new();
    for (idx, node) in nodes.iter().enumerate() {
        for other_idx in &neighbors[idx] {
            let other = &nodes[*other_idx];
            intents.push(fake_intent(node, other, "fake_graph_no_auth"));
        }
    }
    intents
}

fn fake_intent(initiator: &SimPeerNode, target: &SimPeerNode, source: &str) -> PairSyncIntent {
    PairSyncIntent {
        initiator_db_path: initiator.db_path.clone(),
        initiator_recorded_by: initiator.recorded_by.clone(),
        target_db_path: target.db_path.clone(),
        target_recorded_by: target.recorded_by.clone(),
        target_transport_peer_id: target.recorded_by.clone(),
        source: source.into(),
        invite_event_id: None,
    }
}

fn fake_graph_key(node: &SimPeerNode) -> [u8; 32] {
    event_id_from_hex(&node.recorded_by).unwrap_or_else(|| {
        panic!(
            "recorded_by must be a 32-byte hex peer id: {}",
            node.recorded_by
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(peer_hex: &str) -> SimPeerNode {
        SimPeerNode {
            db_path: format!("/tmp/{peer_hex}.db"),
            recorded_by: peer_hex.to_string(),
            daemon_peer_id: None,
            local_transport_peer_id: None,
            connect_targets: Vec::new(),
        }
    }

    fn hex_id(last_byte: u8) -> String {
        let mut bytes = [0u8; 32];
        bytes[31] = last_byte;
        hex::encode(bytes)
    }

    #[test]
    fn fake_graph_uses_connected_hash_ring_neighbors() {
        let nodes = (0u8..16)
            .map(hex_id)
            .map(|id| node(&id))
            .collect::<Vec<_>>();

        let intents = fake_graph_intents(&nodes, DEFAULT_HASH_GRAPH_DEGREE);
        let center_id = hex_id(0);
        let center_neighbors = intents
            .iter()
            .filter(|intent| intent.initiator_recorded_by == center_id)
            .map(|intent| intent.target_recorded_by.clone())
            .collect::<Vec<_>>();

        assert!(
            center_neighbors.contains(&hex_id(15)),
            "ring predecessor must be present"
        );
        assert!(
            center_neighbors.contains(&hex_id(1)),
            "ring successor must be present"
        );
        assert!(
            center_neighbors.len() >= 4,
            "graph neighbors should include ring edges plus deterministic shortcuts"
        );
    }

    #[test]
    fn fake_star_assigns_each_non_hub_node_to_the_hub() {
        let nodes = vec![node(&hex_id(0)), node(&hex_id(1)), node(&hex_id(2))];
        let intents = fake_star_intents(&nodes);

        assert_eq!(intents.len(), 2);
        assert_eq!(intents[0].initiator_recorded_by, hex_id(1));
        assert_eq!(intents[0].target_recorded_by, hex_id(0));
        assert_eq!(intents[1].initiator_recorded_by, hex_id(2));
        assert_eq!(intents[1].target_recorded_by, hex_id(0));
    }
}
