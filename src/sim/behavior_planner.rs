use std::collections::BTreeMap;

use super::behavior_pair_sync::{run_behavior_pair_sync_session, BehaviorSimPeerNode};
use super::fake_topology::{fake_pair_sync_intents, FakeTopologyNode, FakeTopologyPreference};
use super::node_behavior::EventProjectionFilter;
use super::pair_sync::PairSyncIntent;
use super::planner_runner::{
    PlannedPairSession, PlannerImportedNode, PlannerMode, PlannerRoundReport, PlannerRunReport,
};
use super::query_snapshot::import_local_tenants_from_db;

type BehaviorPlannerResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn sync_error<E: std::fmt::Display>(err: E) -> Box<dyn std::error::Error + Send + Sync> {
    std::io::Error::other(err.to_string()).into()
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

pub struct BehaviorPlannerSimulation {
    nodes: Vec<BehaviorSimPeerNode>,
    fake_topology: FakeTopologyPreference,
    explicit_fake_pairs: Option<Vec<(String, String)>>,
}

impl BehaviorPlannerSimulation {
    pub fn with_mode_and_topology<I, S>(
        db_paths: I,
        fake_topology: FakeTopologyPreference,
        filter: EventProjectionFilter,
    ) -> BehaviorPlannerResult<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut seen = std::collections::BTreeSet::new();
        let mut nodes = Vec::new();
        for db_path in db_paths.into_iter().map(Into::into) {
            if !seen.insert(db_path.clone()) {
                continue;
            }
            for imported in import_local_tenants_from_db(&db_path).map_err(sync_error)? {
                nodes.push(
                    BehaviorSimPeerNode::from_imported(&imported, filter.clone())
                        .map_err(sync_error)?,
                );
            }
        }
        Ok(Self {
            nodes,
            fake_topology,
            explicit_fake_pairs: None,
        })
    }

    pub fn with_explicit_fake_pairs<I, S, P, L, R>(
        db_paths: I,
        explicit_fake_pairs: P,
        filter: EventProjectionFilter,
    ) -> BehaviorPlannerResult<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
        P: IntoIterator<Item = (L, R)>,
        L: Into<String>,
        R: Into<String>,
    {
        let mut sim =
            Self::with_mode_and_topology(db_paths, FakeTopologyPreference::Graph, filter)?;
        sim.explicit_fake_pairs = Some(
            explicit_fake_pairs
                .into_iter()
                .map(|(left, right)| (left.into(), right.into()))
                .collect(),
        );
        Ok(sim)
    }

    pub fn tick(&self) -> BehaviorPlannerResult<PlannerRoundReport> {
        let node_views = self
            .nodes
            .iter()
            .map(|node| FakeTopologyNode {
                db_path: node.db_path.clone(),
                recorded_by: node.recorded_by.clone(),
            })
            .collect::<Vec<_>>();
        let intents = fake_pair_sync_intents(
            &node_views,
            self.fake_topology,
            self.explicit_fake_pairs.as_deref(),
        );

        let mut grouped = BTreeMap::<PairKey, Vec<PairSyncIntent>>::new();
        for intent in intents {
            grouped
                .entry(PairKey::from_intent(&intent))
                .or_default()
                .push(intent);
        }

        let node_index = self
            .nodes
            .iter()
            .enumerate()
            .map(|(idx, node)| ((node.db_path.clone(), node.recorded_by.clone()), idx))
            .collect::<BTreeMap<_, _>>();

        let mut pairs = Vec::new();
        let mut transferred_events = 0usize;
        let mut transferred_bytes = 0u64;

        for (pair, source_intents) in grouped {
            let left_idx = *node_index
                .get(&(pair.left.db_path.clone(), pair.left.recorded_by.clone()))
                .ok_or("missing left behavior node")?;
            let right_idx = *node_index
                .get(&(pair.right.db_path.clone(), pair.right.recorded_by.clone()))
                .ok_or("missing right behavior node")?;
            let left = &self.nodes[left_idx];
            let right = &self.nodes[right_idx];
            let stats = run_behavior_pair_sync_session(left, right).map_err(sync_error)?;
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

        let nodes = self
            .nodes
            .iter()
            .map(|node| PlannerImportedNode {
                db_path: node.db_path.clone(),
                recorded_by: node.recorded_by.clone(),
                connect_target_count: node.connect_targets.len(),
            })
            .collect::<Vec<_>>();

        Ok(PlannerRoundReport {
            mode: PlannerMode::NearestNeighborNoAuth,
            fake_topology: Some(self.fake_topology),
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

    pub fn run_rounds(&self, rounds: u32) -> BehaviorPlannerResult<PlannerRunReport> {
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

    pub fn node_summaries(&self) -> BTreeMap<(String, String), crate::sim::NodeBehaviorSummary> {
        self.nodes
            .iter()
            .map(|node| {
                (
                    (node.db_path.clone(), node.recorded_by.clone()),
                    node.behavior.summary(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::workspace::commands::CreateInviteResponse;
    use crate::rpc::protocol::RpcMethod;
    use crate::sim::{sqlite_behavior_summary, PlannerSimulation, VirtualDaemon};

    fn active_peer_id(daemon: &VirtualDaemon) -> String {
        daemon
            .call_ok_value(RpcMethod::ActiveTenant)
            .expect("active tenant")["peer_id"]
            .as_str()
            .expect("peer id")
            .to_string()
    }

    fn subset_summary(
        summary: &crate::sim::NodeBehaviorSummary,
        tables: &[&str],
    ) -> crate::sim::NodeBehaviorSummary {
        let wanted = tables
            .iter()
            .map(|table| (*table).to_string())
            .collect::<std::collections::BTreeSet<_>>();
        crate::sim::NodeBehaviorSummary {
            recorded_by: summary.recorded_by.clone(),
            tables: summary
                .tables
                .iter()
                .filter(|(table, _)| wanted.contains(*table))
                .map(|(table, rows)| (table.clone(), rows.clone()))
                .collect(),
        }
    }

    fn summary_delta(
        before: &crate::sim::NodeBehaviorSummary,
        after: &crate::sim::NodeBehaviorSummary,
        tables: &[&str],
    ) -> crate::sim::NodeBehaviorSummary {
        let before_subset = subset_summary(before, tables);
        let after_subset = subset_summary(after, tables);
        let mut out = std::collections::BTreeMap::new();
        for (table, after_rows) in &after_subset.tables {
            let before_rows = before_subset.tables.get(table).cloned().unwrap_or_default();
            let before_set = before_rows
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>();
            let delta_rows = after_rows
                .iter()
                .filter(|row| !before_set.contains(*row))
                .cloned()
                .collect::<Vec<_>>();
            if !delta_rows.is_empty() {
                out.insert(table.clone(), delta_rows);
            }
        }
        crate::sim::NodeBehaviorSummary {
            recorded_by: after.recorded_by.clone(),
            tables: out,
        }
    }

    #[test]
    fn behavior_planner_matches_sqlite_planner_for_fake_star_rotation_round() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let creator = VirtualDaemon::new(tmpdir.path().join("creator.db").to_str().unwrap());
        let joiner = VirtualDaemon::new(tmpdir.path().join("joiner.db").to_str().unwrap());

        creator
            .call_ok_value(RpcMethod::CreateWorkspace {
                workspace_name: "sim".into(),
                username: "alice".into(),
                device_name: "laptop".into(),
            })
            .expect("create workspace");
        let invite: CreateInviteResponse = creator
            .call_ok(RpcMethod::CreateInvite {
                public_addr: Some("127.0.0.1:9001".into()),
                public_spki: None,
            })
            .expect("create invite");
        joiner
            .call_ok_value(RpcMethod::AcceptInvite {
                invite: invite.invite_link,
                username: "bob".into(),
                devicename: "phone".into(),
            })
            .expect("accept invite");

        let db_paths = vec![creator.db_path().to_string(), joiner.db_path().to_string()];
        let _creator_peer = active_peer_id(&creator);
        let joiner_peer = active_peer_id(&joiner);

        PlannerSimulation::new(db_paths.clone())
            .tick()
            .expect("sqlite bootstrap");
        creator
            .call_ok_value(RpcMethod::RotateKey)
            .expect("rotate key");

        let sqlite_before =
            sqlite_behavior_summary(joiner.db_path(), &joiner_peer).expect("sqlite before");
        let behavior_sim = BehaviorPlannerSimulation::with_mode_and_topology(
            db_paths.clone(),
            FakeTopologyPreference::Star,
            EventProjectionFilter::default(),
        )
        .expect("behavior sim");
        let behavior_before = behavior_sim
            .node_summaries()
            .get(&(joiner.db_path().to_string(), joiner_peer.clone()))
            .cloned()
            .expect("behavior before");

        let sqlite_report = PlannerSimulation::with_mode_and_topology(
            db_paths.clone(),
            PlannerMode::NearestNeighborNoAuth,
            FakeTopologyPreference::Star,
        )
        .tick()
        .expect("sqlite round");
        let behavior_report = behavior_sim.tick().expect("behavior round");

        assert_eq!(behavior_report.pairs.len(), sqlite_report.pairs.len());
        assert_eq!(
            behavior_report.pairs[0]
                .stats
                .left_to_right
                .transferred_event_ids,
            sqlite_report.pairs[0]
                .stats
                .left_to_right
                .transferred_event_ids
        );
        assert_eq!(
            behavior_report.pairs[0]
                .stats
                .right_to_left
                .transferred_event_ids,
            sqlite_report.pairs[0]
                .stats
                .right_to_left
                .transferred_event_ids
        );

        let modeled_tables = ["key_rotations", "key_shared", "key_secrets", "valid_events"];
        let expected_joiner =
            sqlite_behavior_summary(joiner.db_path(), &joiner_peer).expect("sqlite after");
        let behavior_after = behavior_sim
            .node_summaries()
            .get(&(joiner.db_path().to_string(), joiner_peer))
            .cloned()
            .expect("behavior after");
        assert_eq!(
            summary_delta(&behavior_before, &behavior_after, &modeled_tables),
            summary_delta(&sqlite_before, &expected_joiner, &modeled_tables)
        );
    }

    #[test]
    fn behavior_planner_matches_sqlite_planner_for_explicit_message_round() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let creator = VirtualDaemon::new(tmpdir.path().join("creator.db").to_str().unwrap());
        let joiner = VirtualDaemon::new(tmpdir.path().join("joiner.db").to_str().unwrap());

        creator
            .call_ok_value(RpcMethod::CreateWorkspace {
                workspace_name: "sim".into(),
                username: "alice".into(),
                device_name: "laptop".into(),
            })
            .expect("create workspace");
        let invite: CreateInviteResponse = creator
            .call_ok(RpcMethod::CreateInvite {
                public_addr: Some("127.0.0.1:9001".into()),
                public_spki: None,
            })
            .expect("create invite");
        joiner
            .call_ok_value(RpcMethod::AcceptInvite {
                invite: invite.invite_link,
                username: "bob".into(),
                devicename: "phone".into(),
            })
            .expect("accept invite");

        let db_paths = vec![creator.db_path().to_string(), joiner.db_path().to_string()];
        let creator_peer = active_peer_id(&creator);
        let joiner_peer = active_peer_id(&joiner);

        PlannerSimulation::new(db_paths.clone())
            .tick()
            .expect("sqlite bootstrap");
        creator
            .call_ok_value(RpcMethod::Send {
                content: "hello".into(),
                client_op_id: None,
            })
            .expect("send");

        let sqlite_before =
            sqlite_behavior_summary(joiner.db_path(), &joiner_peer).expect("sqlite before");
        let behavior_sim = BehaviorPlannerSimulation::with_explicit_fake_pairs(
            db_paths.clone(),
            [(creator_peer.clone(), joiner_peer.clone())],
            EventProjectionFilter::default(),
        )
        .expect("behavior sim");
        let behavior_before = behavior_sim
            .node_summaries()
            .get(&(joiner.db_path().to_string(), joiner_peer.clone()))
            .cloned()
            .expect("behavior before");

        let sqlite_report = PlannerSimulation::with_explicit_fake_pairs(
            db_paths.clone(),
            [(creator_peer.clone(), joiner_peer.clone())],
        )
        .tick()
        .expect("sqlite round");
        let behavior_report = behavior_sim.tick().expect("behavior round");

        assert_eq!(behavior_report.pairs.len(), sqlite_report.pairs.len());
        assert_eq!(
            behavior_report.pairs[0]
                .stats
                .left_to_right
                .transferred_event_ids,
            sqlite_report.pairs[0]
                .stats
                .left_to_right
                .transferred_event_ids
        );
        assert_eq!(
            behavior_report.pairs[0]
                .stats
                .right_to_left
                .transferred_event_ids,
            sqlite_report.pairs[0]
                .stats
                .right_to_left
                .transferred_event_ids
        );

        let modeled_tables = ["key_secrets", "messages", "valid_events"];
        let expected_joiner =
            sqlite_behavior_summary(joiner.db_path(), &joiner_peer).expect("sqlite after");
        let behavior_after = behavior_sim
            .node_summaries()
            .get(&(joiner.db_path().to_string(), joiner_peer))
            .cloned()
            .expect("behavior after");
        assert_eq!(
            summary_delta(&behavior_before, &behavior_after, &modeled_tables),
            summary_delta(&sqlite_before, &expected_joiner, &modeled_tables)
        );
    }
}
