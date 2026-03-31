use std::collections::BTreeMap;

use serde::Serialize;

use super::fake_topology::{fake_pair_sync_intents, FakeTopologyNode, FakeTopologyPreference};
use super::pair_sync::{
    apply_prepared_pair_sync_session, plan_pair_sync_intents, prepare_pair_sync_session,
    PairSyncIntent, PairSyncSessionStats, SimPeerNode,
};
use super::query_snapshot::import_local_tenants_from_db;
use crate::runtime::peering::engine::should_initiate_connect_for_source_with_db;
use crate::runtime::peering::engine::target_dispatch::TargetIngressSource;

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
    explicit_fake_pairs: Option<Vec<(String, String)>>,
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
            explicit_fake_pairs: None,
        }
    }

    pub fn with_explicit_fake_pairs<I, S, P, L, R>(db_paths: I, explicit_fake_pairs: P) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
        P: IntoIterator<Item = (L, R)>,
        L: Into<String>,
        R: Into<String>,
    {
        let mut sim = Self::with_mode_and_topology(
            db_paths,
            PlannerMode::NearestNeighborNoAuth,
            FakeTopologyPreference::Graph,
        );
        sim.explicit_fake_pairs = Some(
            explicit_fake_pairs
                .into_iter()
                .map(|(left, right)| (left.into(), right.into()))
                .collect(),
        );
        sim
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
            PlannerMode::NearestNeighborNoAuth => fake_pair_sync_intents(
                &nodes
                    .iter()
                    .map(|node| FakeTopologyNode {
                        db_path: node.db_path.clone(),
                        recorded_by: node.recorded_by.clone(),
                    })
                    .collect::<Vec<_>>(),
                self.fake_topology,
                self.explicit_fake_pairs.as_deref(),
            ),
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
        "observed" | "discovery" => Some(TargetIngressSource::KnownPeer {
            peer_id: intent.target_transport_peer_id.clone(),
        }),
        _ => None,
    }
}
