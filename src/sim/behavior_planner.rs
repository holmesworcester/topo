use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::SocketAddr;

use serde::Serialize;

use super::behavior_pair_sync::BehaviorSimPeerNode;
use super::node_behavior::EventProjectionFilter;
use super::query_snapshot::ImportedPeerState;
use crate::crypto::{event_id_to_base64, EventId};
use crate::runtime::peering::engine::target_dispatch::TargetIngressSource;
use crate::runtime::sync_engine::session::windowing::{
    mark_outbound_task_completed, reset_outbound_window_state, select_outbound_task, SyncTask,
    SyncWindowKind,
};
use crate::sim::pair_sync::{PairSyncDirectionStats, PairSyncSessionStats};

pub type BehaviorPlannerResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BehaviorPlannerConfig {
    pub now_ms: i64,
    pub discovery_disabled: bool,
    pub endpoint_ttl_ms: i64,
}

impl Default for BehaviorPlannerConfig {
    fn default() -> Self {
        Self {
            now_ms: 1_000_000,
            discovery_disabled: false,
            endpoint_ttl_ms: 24 * 60 * 60 * 1000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BehaviorPlannerIntent {
    pub initiator_recorded_by: String,
    pub target_recorded_by: String,
    pub target_transport_peer_id: String,
    pub source: String,
    pub remote: String,
    pub invite_event_id: Option<String>,
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
    fn new(left_db_path: &str, left_recorded_by: &str, right_db_path: &str, right_recorded_by: &str) -> Self {
        let left = PairEndpoint {
            db_path: left_db_path.to_string(),
            recorded_by: left_recorded_by.to_string(),
        };
        let right = PairEndpoint {
            db_path: right_db_path.to_string(),
            recorded_by: right_recorded_by.to_string(),
        };
        if left <= right {
            Self { left, right }
        } else {
            Self { left: right, right: left }
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct BehaviorPlannerRoundReport {
    pub round: usize,
    pub planned_intents: usize,
    pub unique_pairs: usize,
    pub sessions_executed: usize,
    pub transferred_events: usize,
    pub transferred_bytes: u64,
    pub pair_stats: Vec<PairSyncSessionStats>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct BehaviorPlannerReport {
    pub rounds: Vec<BehaviorPlannerRoundReport>,
    pub sessions_executed: usize,
    pub transferred_events: usize,
    pub transferred_bytes: u64,
}

pub struct BehaviorPlannerSimulation {
    peers: Vec<BehaviorSimPeerNode>,
    config: BehaviorPlannerConfig,
    live_peers: BTreeMap<String, BTreeSet<String>>,
}

impl BehaviorPlannerSimulation {
    pub fn from_imported(
        imported: &[ImportedPeerState],
        filter: EventProjectionFilter,
        config: BehaviorPlannerConfig,
    ) -> BehaviorPlannerResult<Self> {
        let mut peers = Vec::with_capacity(imported.len());
        for peer in imported {
            peers.push(BehaviorSimPeerNode::from_imported(peer, filter.clone())?);
        }
        let sim = Self {
            peers,
            config,
            live_peers: BTreeMap::new(),
        };
        sim.reset_planner_state();
        Ok(sim)
    }

    pub fn peers(&self) -> &[BehaviorSimPeerNode] {
        &self.peers
    }

    pub fn tick(&mut self, round: usize) -> BehaviorPlannerResult<BehaviorPlannerRoundReport> {
        let intents = self.plan_intents();
        let mut grouped = BTreeMap::<PairKey, Vec<BehaviorPlannerIntent>>::new();
        for intent in intents {
            let target_idx = self
                .peers
                .iter()
                .position(|peer| peer.recorded_by == intent.target_recorded_by)
                .ok_or_else(|| format!("missing target node {}", intent.target_recorded_by))?;
            let initiator_idx = self
                .peers
                .iter()
                .position(|peer| peer.recorded_by == intent.initiator_recorded_by)
                .ok_or_else(|| format!("missing initiator node {}", intent.initiator_recorded_by))?;
            let key = PairKey::new(
                &self.peers[initiator_idx].db_path,
                &self.peers[initiator_idx].recorded_by,
                &self.peers[target_idx].db_path,
                &self.peers[target_idx].recorded_by,
            );
            grouped.entry(key).or_default().push(intent);
        }

        let mut pair_stats = Vec::new();
        let mut transferred_events = 0usize;
        let mut transferred_bytes = 0u64;

        for intents in grouped.values() {
            if intents.is_empty() {
                continue;
            }
            let left_idx = self
                .peers
                .iter()
                .position(|peer| peer.recorded_by == intents[0].initiator_recorded_by || peer.recorded_by == intents[0].target_recorded_by)
                .ok_or("missing left peer")?;
            let right_idx = self
                .peers
                .iter()
                .enumerate()
                .find(|(idx, peer)| *idx != left_idx && (peer.recorded_by == intents[0].initiator_recorded_by || peer.recorded_by == intents[0].target_recorded_by))
                .map(|(idx, _)| idx)
                .ok_or("missing right peer")?;
            let stats = self.run_pair_session(left_idx, right_idx)?;
            transferred_events += stats.left_to_right.transferred_events + stats.right_to_left.transferred_events;
            transferred_bytes += stats.left_to_right.transferred_bytes + stats.right_to_left.transferred_bytes;
            pair_stats.push(stats);
        }

        Ok(BehaviorPlannerRoundReport {
            round,
            planned_intents: grouped.values().map(Vec::len).sum(),
            unique_pairs: grouped.len(),
            sessions_executed: pair_stats.len(),
            transferred_events,
            transferred_bytes,
            pair_stats,
        })
    }

    pub fn run_until_stable(&mut self, max_rounds: usize) -> BehaviorPlannerResult<BehaviorPlannerReport> {
        let mut report = BehaviorPlannerReport::default();
        for round in 0..max_rounds {
            let round_report = self.tick(round)?;
            report.sessions_executed += round_report.sessions_executed;
            report.transferred_events += round_report.transferred_events;
            report.transferred_bytes += round_report.transferred_bytes;
            let stable = round_report.sessions_executed == 0 || round_report.transferred_events == 0;
            report.rounds.push(round_report);
            if stable {
                break;
            }
        }
        Ok(report)
    }

    fn reset_planner_state(&self) {
        for left in &self.peers {
            for right in &self.peers {
                if left.recorded_by == right.recorded_by {
                    continue;
                }
                reset_outbound_window_state(&left.db_path, &left.recorded_by, &right.recorded_by);
            }
        }
    }

    fn plan_intents(&self) -> Vec<BehaviorPlannerIntent> {
        let mut identities: HashMap<String, Vec<usize>> = HashMap::new();
        for (idx, peer) in self.peers.iter().enumerate() {
            for identity in peer_identity_keys(peer) {
                identities.entry(identity).or_default().push(idx);
            }
        }

        let mut intents = Vec::new();
        let mut seen = BTreeSet::new();
        for initiator in &self.peers {
            for target in initiator
                .behavior
                .current_connect_targets(self.config.now_ms, self.config.discovery_disabled)
            {
                let Some(source) = connect_target_source(&target) else {
                    continue;
                };
                if !initiator
                    .behavior
                    .should_initiate_connect_for_source(self.config.now_ms, &source)
                {
                    continue;
                }
                let Some(matches) = identities.get(&target.transport_peer_id) else {
                    continue;
                };
                for target_idx in matches {
                    let target_peer = &self.peers[*target_idx];
                    if initiator.recorded_by == target_peer.recorded_by {
                        continue;
                    }
                    let key = (
                        initiator.recorded_by.clone(),
                        target_peer.recorded_by.clone(),
                        target.transport_peer_id.clone(),
                        target.source.clone(),
                        target.remote.clone(),
                        target.invite_event_id.clone(),
                    );
                    if seen.insert(key) {
                        intents.push(BehaviorPlannerIntent {
                            initiator_recorded_by: initiator.recorded_by.clone(),
                            target_recorded_by: target_peer.recorded_by.clone(),
                            target_transport_peer_id: target.transport_peer_id.clone(),
                            source: target.source.clone(),
                            remote: target.remote.clone(),
                            invite_event_id: target.invite_event_id.clone(),
                        });
                    }
                }
            }
        }
        intents.sort_by(|left, right| {
            (
                &left.initiator_recorded_by,
                &left.target_recorded_by,
                &left.source,
                &left.remote,
            )
                .cmp(&(
                    &right.initiator_recorded_by,
                    &right.target_recorded_by,
                    &right.source,
                    &right.remote,
                ))
        });
        intents
    }

    fn run_pair_session(&mut self, left_idx: usize, right_idx: usize) -> BehaviorPlannerResult<PairSyncSessionStats> {
        let left = &self.peers[left_idx];
        let right = &self.peers[right_idx];

        self.live_peers
            .entry(left.recorded_by.clone())
            .or_default()
            .insert(right.recorded_by.clone());
        self.live_peers
            .entry(right.recorded_by.clone())
            .or_default()
            .insert(left.recorded_by.clone());

        let left_remote = parse_remote_label(
            &left
                .behavior
                .current_connect_targets(self.config.now_ms, self.config.discovery_disabled)
                .into_iter()
                .find(|target| peer_identity_keys(right).contains(&target.transport_peer_id))
                .map(|target| target.remote)
                .unwrap_or_else(|| "lookup".to_string()),
        );
        let right_remote = parse_remote_label(
            &right
                .behavior
                .current_connect_targets(self.config.now_ms, self.config.discovery_disabled)
                .into_iter()
                .find(|target| peer_identity_keys(left).contains(&target.transport_peer_id))
                .map(|target| target.remote)
                .unwrap_or_else(|| "lookup".to_string()),
        );

        left.behavior.record_successful_session(
            &right.recorded_by,
            &right.behavior.transport_peer_id(),
            left_remote,
            self.config.now_ms,
            self.config.endpoint_ttl_ms,
        );
        right.behavior.record_successful_session(
            &left.recorded_by,
            &left.behavior.transport_peer_id(),
            right_remote,
            self.config.now_ms,
            self.config.endpoint_ttl_ms,
        );

        let left_to_right = self.sync_one_direction(left, right)?;
        let right_to_left = self.sync_one_direction(right, left)?;
        Ok(PairSyncSessionStats {
            left_to_right,
            right_to_left,
        })
    }

    fn sync_one_direction(
        &self,
        source: &BehaviorSimPeerNode,
        dest: &BehaviorSimPeerNode,
    ) -> BehaviorPlannerResult<PairSyncDirectionStats> {
        let live_peers = self
            .live_peers
            .get(&source.recorded_by)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect::<Vec<_>>();
        let task = select_outbound_task(
            &source.db_path,
            &source.recorded_by,
            &dest.recorded_by,
            &live_peers,
            self.config.now_ms,
        );
        let transferred = self.transfer_task(source, dest, task)?;
        mark_outbound_task_completed(&source.db_path, &source.recorded_by, &dest.recorded_by, task);
        Ok(transferred)
    }

    fn transfer_task(
        &self,
        source: &BehaviorSimPeerNode,
        dest: &BehaviorSimPeerNode,
        task: SyncTask,
    ) -> BehaviorPlannerResult<PairSyncDirectionStats> {
        let source_tag = format!("quic_recv:{}@behavior-planner", source.behavior.transport_peer_id());
        let workspace_id = source.behavior.workspace_id();
        let mut transferred_event_ids = Vec::new();
        let mut transferred_bytes = 0u64;

        if let Some(workspace_id) = workspace_id {
            let roots = source.behavior.load_shared_event_index_slice(&workspace_id, task);
            let root_ids = roots.iter().map(|(_, event_id)| *event_id).collect::<Vec<_>>();
            let deps = source.behavior.expand_transitive_shared_deps(&root_ids);
            let mut all_by_id = HashMap::<EventId, i64>::new();
            for (ts, event_id) in roots.into_iter().chain(deps.into_iter()) {
                all_by_id.entry(event_id).or_insert(ts);
            }
            let mut ids = all_by_id.keys().copied().collect::<Vec<_>>();
            ids = prioritize_send_order(&source.behavior, task, &ids);
            let known_dest = dest.behavior.recorded_event_ids();
            let shared = source.behavior.get_shared_batch(&ids);
            let blobs = ids
                .into_iter()
                .filter_map(|event_id| {
                    let event_id_b64 = event_id_to_base64(&event_id);
                    if known_dest.contains(&event_id_b64) {
                        return None;
                    }
                    let blob = shared.get(&event_id)?.clone();
                    transferred_event_ids.push(event_id_b64);
                    transferred_bytes += blob.len() as u64;
                    Some(blob)
                })
                .collect::<Vec<_>>();
            if !blobs.is_empty() {
                let _ = dest.behavior.apply_transferred_batch(&source_tag, blobs)?;
            }
        }

        Ok(PairSyncDirectionStats {
            source_db_path: source.db_path.clone(),
            source_recorded_by: source.recorded_by.clone(),
            dest_db_path: dest.db_path.clone(),
            dest_recorded_by: dest.recorded_by.clone(),
            transferred_events: transferred_event_ids.len(),
            transferred_bytes,
            transferred_key_request_events: 0,
            suppressed_key_request_events: 0,
            transferred_key_shared_events: 0,
            suppressed_key_shared_events: 0,
            transferred_event_ids,
        })
    }
}

fn connect_target_source(target: &crate::sim::query_snapshot::ImportedConnectTarget) -> Option<TargetIngressSource> {
    match target.source.as_str() {
        "bootstrap" => Some(TargetIngressSource::Bootstrap {
            daemon_peer_id: target.transport_peer_id.clone(),
            invite_event_id: target.invite_event_id.clone()?,
        }),
        "observed" | "discovery" => Some(TargetIngressSource::KnownPeer {
            peer_id: target.transport_peer_id.clone(),
        }),
        _ => None,
    }
}

fn parse_remote_label(remote: &str) -> Option<SocketAddr> {
    if remote == "lookup" || remote.starts_with("relay:") {
        return None;
    }
    remote.parse().ok()
}

fn peer_identity_keys(peer: &BehaviorSimPeerNode) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    out.insert(peer.recorded_by.clone());
    if let Some(daemon_peer_id) = &peer.daemon_peer_id {
        out.insert(daemon_peer_id.clone());
    }
    if let Some(local_transport_peer_id) = &peer.local_transport_peer_id {
        out.insert(local_transport_peer_id.clone());
    }
    out.insert(peer.behavior.transport_peer_id());
    out
}

fn dependency_rank(
    event_id: EventId,
    ids_in_batch: &HashSet<EventId>,
    edges: &HashMap<EventId, Vec<EventId>>,
    memo: &mut HashMap<EventId, usize>,
    visiting: &mut HashSet<EventId>,
) -> usize {
    if let Some(rank) = memo.get(&event_id) {
        return *rank;
    }
    if !visiting.insert(event_id) {
        return 0;
    }
    let mut rank = 0usize;
    if let Some(deps) = edges.get(&event_id) {
        for dep_id in deps {
            if !ids_in_batch.contains(dep_id) {
                continue;
            }
            rank = rank.max(1 + dependency_rank(*dep_id, ids_in_batch, edges, memo, visiting));
        }
    }
    visiting.remove(&event_id);
    memo.insert(event_id, rank);
    rank
}

fn prioritize_send_order(
    behavior: &crate::sim::node_behavior::NodeBehaviorEngine,
    task: SyncTask,
    ids: &[EventId],
) -> Vec<EventId> {
    if ids.is_empty() {
        return Vec::new();
    }

    let created_at_by_id = behavior.get_shared_created_at_batch(ids);
    let edges = behavior.get_shared_dep_edges_batch(ids);
    let ids_in_batch: HashSet<EventId> = ids.iter().copied().collect();
    let mut memo = HashMap::new();
    let mut ordered: Vec<EventId> = ids
        .iter()
        .filter(|event_id| created_at_by_id.contains_key(*event_id))
        .copied()
        .collect();
    ordered.sort_by(|left, right| {
        let left_rank = dependency_rank(*left, &ids_in_batch, &edges, &mut memo, &mut HashSet::new());
        let right_rank = dependency_rank(*right, &ids_in_batch, &edges, &mut memo, &mut HashSet::new());
        let left_ts = created_at_by_id.get(left).copied().unwrap_or_default();
        let right_ts = created_at_by_id.get(right).copied().unwrap_or_default();
        left_rank.cmp(&right_rank).then_with(|| match task.window.kind {
            SyncWindowKind::LastDay => right_ts.cmp(&left_ts).then_with(|| right.cmp(left)),
            SyncWindowKind::Full | SyncWindowKind::LastWeek | SyncWindowKind::LastTwelveWeeks => {
                left_ts.cmp(&right_ts).then_with(|| left.cmp(right))
            }
        })
    });
    ordered
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::protocol::RpcMethod;
    use crate::sim::{import_peer_state, run_pair_sync_session, sqlite_behavior_summary, VirtualDaemon};
    use crate::event_modules::workspace::commands::CreateInviteResponse;

    fn active_peer_id(daemon: &VirtualDaemon) -> String {
        daemon
            .call_ok_value(RpcMethod::ActiveTenant)
            .expect("active tenant")["peer_id"]
            .as_str()
            .expect("peer id")
            .to_string()
    }

    #[test]
    fn behavior_planner_sim_matches_sqlite_pair_sync_for_bootstrap_message_flow() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let creator = VirtualDaemon::new(tmpdir.path().join("creator.db").to_str().unwrap());
        let joiner = VirtualDaemon::new(tmpdir.path().join("joiner.db").to_str().unwrap());

        creator
            .call_ok_value(RpcMethod::CreateWorkspace {
                workspace_name: "sim".into(),
                username: "alice".into(),
                device_name: "laptop".into(),
                message_count: 0,
                network_age: None,
            })
            .expect("create workspace");
        creator
            .call_ok_value(RpcMethod::Send {
                content: "hello from planner sim".into(),
                client_op_id: None,
            })
            .expect("send message");
        let invite: CreateInviteResponse = creator
            .call_ok(RpcMethod::CreateInvite {
                public_addr: None,
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

        let creator_peer = active_peer_id(&creator);
        let joiner_peer = active_peer_id(&joiner);
        let imported = vec![
            import_peer_state(creator.db_path(), &creator_peer).expect("import creator"),
            import_peer_state(joiner.db_path(), &joiner_peer).expect("import joiner"),
        ];

        let mut sim = BehaviorPlannerSimulation::from_imported(
            &imported,
            EventProjectionFilter::default(),
            BehaviorPlannerConfig::default(),
        )
        .expect("build planner sim");
        let report = sim.run_until_stable(8).expect("run planner sim");
        assert!(report.transferred_events > 0, "sim must transfer shared events");

        let sqlite_stats = run_pair_sync_session(
            creator.db_path(),
            &creator_peer,
            joiner.db_path(),
            &joiner_peer,
        )
        .expect("sqlite pair sync");
        assert!(sqlite_stats.left_to_right.transferred_events > 0);

        let expected = sqlite_behavior_summary(joiner.db_path(), &joiner_peer).expect("sqlite summary");
        let actual = sim
            .peers()
            .iter()
            .find(|peer| peer.recorded_by == joiner_peer)
            .expect("sim joiner")
            .behavior
            .summary();

        for table in ["messages", "key_shared", "key_secrets", "peers_shared", "valid_events"] {
            assert_eq!(
                actual.tables.get(table).cloned().unwrap_or_default(),
                expected.tables.get(table).cloned().unwrap_or_default(),
                "table mismatch for {table}",
            );
        }
    }

    #[test]
    fn behavior_planner_sim_four_peer_mesh_converges_identity() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let hub = VirtualDaemon::new(tmpdir.path().join("hub.db").to_str().unwrap());
        let source1 = VirtualDaemon::new(tmpdir.path().join("source1.db").to_str().unwrap());
        let source2 = VirtualDaemon::new(tmpdir.path().join("source2.db").to_str().unwrap());
        let source3 = VirtualDaemon::new(tmpdir.path().join("source3.db").to_str().unwrap());

        hub.call_ok_value(RpcMethod::CreateWorkspace {
            workspace_name: "mesh".into(),
            username: "alice".into(),
            device_name: "hub".into(),
            message_count: 0,
            network_age: None,
        })
        .expect("create workspace");
        hub.call_ok_value(RpcMethod::Send {
            content: "mesh head".into(),
            client_op_id: None,
        })
        .expect("send hot message");

        for daemon in [&source1, &source2, &source3] {
            let invite: CreateInviteResponse = hub
                .call_ok(RpcMethod::CreateInvite {
                    public_addr: None,
                    public_spki: None,
                })
                .expect("create invite");
            daemon
                .call_ok_value(RpcMethod::AcceptInvite {
                    invite: invite.invite_link,
                    username: "joiner".into(),
                    devicename: "phone".into(),
                })
                .expect("accept invite");
        }

        let imports = vec![
            import_peer_state(hub.db_path(), &active_peer_id(&hub)).expect("import hub"),
            import_peer_state(source1.db_path(), &active_peer_id(&source1)).expect("import source1"),
            import_peer_state(source2.db_path(), &active_peer_id(&source2)).expect("import source2"),
            import_peer_state(source3.db_path(), &active_peer_id(&source3)).expect("import source3"),
        ];
        let mut sim = BehaviorPlannerSimulation::from_imported(
            &imports,
            EventProjectionFilter::default(),
            BehaviorPlannerConfig::default(),
        )
        .expect("build planner sim");
        let report = sim.run_until_stable(24).expect("run planner sim");
        assert!(report.transferred_events > 0, "mesh sim must transfer identity state");

        for peer in sim.peers() {
            let peer_rows = peer
                .behavior
                .summary()
                .tables
                .get("peers_shared")
                .cloned()
                .unwrap_or_default();
            assert!(peer_rows.len() >= 4, "{} should know all 4 peer identities", peer.recorded_by);
            let targets = peer.behavior.current_connect_targets(BehaviorPlannerConfig::default().now_ms, false);
            let connectable = targets
                .into_iter()
                .filter(|target| target.source == "observed" || target.source == "discovery")
                .map(|target| target.transport_peer_id)
                .collect::<BTreeSet<_>>();
            assert!(connectable.len() >= 3, "{} should have at least three connectable peers", peer.recorded_by);
        }
    }
}
