use std::collections::{BTreeMap, BTreeSet, VecDeque};

use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use serde::Serialize;

use super::hash_graph::{connected_hash_graph_neighbors, synthetic_hash_graph_key};
use super::key_repair::{
    create_encrypted_message_with_key, emit_key_requests_for_peers,
    emit_key_shared_responses_for_peers, seed_deterministic_key_secret, KeyResponsePolicy,
};
use super::planner_runner::PlannerSimulation;
use super::query_snapshot::snapshot_replayed_peer;
use super::virtual_daemon::VirtualDaemon;
use crate::rpc::protocol::RpcMethod;

type SimResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Clone, Serialize)]
pub struct LargeGraphSampleDecryptConfig {
    pub logical_users: usize,
    pub degree: usize,
    pub sample_count: usize,
    pub seed: u64,
    pub response_policy: KeyResponsePolicy,
    pub message_content: String,
}

impl Default for LargeGraphSampleDecryptConfig {
    fn default() -> Self {
        Self {
            logical_users: 100_000,
            degree: 6,
            sample_count: 16,
            seed: 7,
            response_policy: KeyResponsePolicy::BestObservedOnly,
            message_content: "large-graph key repair".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LargeGraphSampleDecryptPeerReport {
    pub logical_peer: usize,
    pub message_distance: u32,
    pub holder_distance: u32,
    pub decrypted: bool,
    pub first_visible_round: Option<u32>,
    pub actual_recorded_by: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LargeGraphSampleDecryptReport {
    pub logical_users: usize,
    pub degree: usize,
    pub seed: u64,
    pub sender: usize,
    pub sample_count: usize,
    pub corridor_peers: usize,
    pub corridor_edges: usize,
    pub max_message_distance: u32,
    pub max_holder_distance: u32,
    pub message_rounds: u32,
    pub request_rounds: u32,
    pub response_rounds: u32,
    pub sampled_peers: Vec<LargeGraphSampleDecryptPeerReport>,
}

#[derive(Debug, Clone)]
struct BfsTree {
    dist: Vec<u32>,
    parent: Vec<Option<usize>>,
}

pub fn run_large_graph_sampled_decrypt_trial(
    config: LargeGraphSampleDecryptConfig,
) -> SimResult<LargeGraphSampleDecryptReport> {
    let sender = 0usize;
    if config.logical_users < 3 {
        return Err("need at least sender + one requester + one spare peer".into());
    }
    if config.sample_count == 0 {
        return Err("sample_count must be > 0".into());
    }

    let keys = (0..config.logical_users)
        .map(|idx| synthetic_hash_graph_key(idx as u64 + 1))
        .collect::<Vec<_>>();
    let adjacency = build_adjacency(&keys, config.degree);
    let sender_tree = bfs_tree(&adjacency, &[sender]).ok_or("sender graph disconnected")?;

    let samples = choose_samples(config.logical_users, config.sample_count, config.seed);
    let (corridor_nodes, corridor_edges) = build_corridor(&samples, &sender_tree, sender);

    let actual = materialize_corridor_peers(&corridor_nodes)?;
    let db_paths = actual
        .values()
        .map(|peer| peer.daemon.db_path().to_string())
        .collect::<Vec<_>>();
    let explicit_pairs = corridor_edges
        .iter()
        .map(|&(left, right)| {
            (
                actual
                    .get(&left)
                    .expect("left actual peer")
                    .recorded_by
                    .clone(),
                actual
                    .get(&right)
                    .expect("right actual peer")
                    .recorded_by
                    .clone(),
            )
        })
        .collect::<Vec<_>>();
    let bootstrap_rounds = corridor_nodes
        .iter()
        .map(|&node| sender_tree.dist[node])
        .max()
        .unwrap_or(0);
    for _ in 0..bootstrap_rounds {
        PlannerSimulation::with_explicit_fake_pairs(db_paths.clone(), explicit_pairs.clone())
            .tick()
            .map_err(|err| format!("bootstrap round: {err}"))?;
    }

    let sender_actual = actual.get(&sender).expect("sender actual peer");
    let key_bytes = [0xAB; 32];
    let sender_key = seed_deterministic_key_secret(
        sender_actual.daemon.db_path(),
        &sender_actual.recorded_by,
        key_bytes,
    )
    .map_err(|err| format!("seed sender key: {err}"))?;

    let _message_event_id = create_encrypted_message_with_key(
        sender_actual.daemon.db_path(),
        &sender_actual.recorded_by,
        &sender_key,
        &config.message_content,
    )
    .map_err(|err| format!("create encrypted message: {err}"))?;

    let max_message_distance = samples
        .iter()
        .map(|&node| sender_tree.dist[node])
        .max()
        .unwrap_or(0);
    let max_holder_distance = samples
        .iter()
        .map(|&node| sender_tree.dist[node])
        .max()
        .unwrap_or(0);

    for _ in 0..max_message_distance {
        PlannerSimulation::with_explicit_fake_pairs(db_paths.clone(), explicit_pairs.clone())
            .tick()
            .map_err(|err| format!("message propagation round: {err}"))?;
    }

    for &sample in &samples {
        let peer = actual.get(&sample).expect("sample actual peer");
        if snapshot_has_message_content(&peer.daemon, &peer.recorded_by, &config.message_content)? {
            return Err(format!("sample {sample} decrypted before repair").into());
        }
    }

    let request_peers = samples
        .iter()
        .map(|sample| {
            let peer = actual.get(sample).expect("sample request peer");
            (peer.daemon.db_path().to_string(), peer.recorded_by.clone())
        })
        .collect::<Vec<_>>();
    let _request_stats = emit_key_requests_for_peers(&request_peers)
        .map_err(|err| format!("emit requests: {err}"))?;
    for _ in 0..max_holder_distance {
        PlannerSimulation::with_explicit_fake_pairs(db_paths.clone(), explicit_pairs.clone())
            .tick()
            .map_err(|err| format!("request propagation round: {err}"))?;
    }

    let response_peers = [sender]
        .into_iter()
        .map(|logical| {
            let peer = actual.get(&logical).expect("response peer");
            (peer.daemon.db_path().to_string(), peer.recorded_by.clone())
        })
        .collect::<Vec<_>>();
    let _response_stats =
        emit_key_shared_responses_for_peers(&response_peers, config.response_policy)
            .map_err(|err| format!("emit responses: {err}"))?;
    let mut sampled_reports = samples
        .iter()
        .map(|&sample| LargeGraphSampleDecryptPeerReport {
            logical_peer: sample,
            message_distance: sender_tree.dist[sample],
            holder_distance: sender_tree.dist[sample],
            decrypted: false,
            first_visible_round: None,
            actual_recorded_by: actual
                .get(&sample)
                .expect("sample actual peer")
                .recorded_by
                .clone(),
        })
        .collect::<Vec<_>>();

    for response_round in 1..=max_holder_distance {
        PlannerSimulation::with_explicit_fake_pairs(db_paths.clone(), explicit_pairs.clone())
            .tick()
            .map_err(|err| format!("response propagation round {response_round}: {err}"))?;
        for report in &mut sampled_reports {
            if report.decrypted {
                continue;
            }
            let peer = actual
                .get(&report.logical_peer)
                .expect("sample actual peer for visibility");
            if snapshot_has_message_content(
                &peer.daemon,
                &peer.recorded_by,
                &config.message_content,
            )? {
                report.decrypted = true;
                report.first_visible_round =
                    Some(max_message_distance + max_holder_distance + response_round);
            }
        }
    }

    if sampled_reports.iter().any(|peer| !peer.decrypted) {
        return Err(format!("not all sampled peers decrypted: {:?}", sampled_reports).into());
    }

    Ok(LargeGraphSampleDecryptReport {
        logical_users: config.logical_users,
        degree: config.degree,
        seed: config.seed,
        sender,
        sample_count: sampled_reports.len(),
        corridor_peers: corridor_nodes.len(),
        corridor_edges: corridor_edges.len(),
        max_message_distance,
        max_holder_distance,
        message_rounds: max_message_distance,
        request_rounds: max_holder_distance,
        response_rounds: max_holder_distance,
        sampled_peers: sampled_reports,
    })
}

fn snapshot_has_message_content(
    daemon: &VirtualDaemon,
    recorded_by: &str,
    content: &str,
) -> SimResult<bool> {
    let snapshot = snapshot_replayed_peer(daemon.db_path(), recorded_by)?;
    let messages = snapshot
        .daemon()
        .call_ok_value(RpcMethod::Messages { limit: 100 })?;
    Ok(messages["messages"]
        .as_array()
        .expect("messages array")
        .iter()
        .any(|message| message["content"].as_str() == Some(content)))
}

fn choose_samples(logical_users: usize, sample_count: usize, seed: u64) -> Vec<usize> {
    let mut candidates = (2..logical_users).collect::<Vec<_>>();
    let mut rng = StdRng::seed_from_u64(seed);
    candidates.shuffle(&mut rng);
    candidates.into_iter().take(sample_count).collect()
}

fn build_adjacency(keys: &[[u8; 32]], degree: usize) -> Vec<Vec<usize>> {
    let neighbors = connected_hash_graph_neighbors(keys, degree);
    let mut adjacency = vec![Vec::new(); keys.len()];
    for node in 0..keys.len() {
        for &other in &neighbors[node] {
            adjacency[node].push(other);
            adjacency[other].push(node);
        }
    }
    for neighbors in &mut adjacency {
        neighbors.sort_unstable();
        neighbors.dedup();
    }
    adjacency
}

fn bfs_tree(adjacency: &[Vec<usize>], sources: &[usize]) -> Option<BfsTree> {
    let users = adjacency.len();
    let mut dist = vec![u32::MAX; users];
    let mut parent = vec![None; users];
    let mut queue = VecDeque::new();

    let mut deduped_sources = sources.to_vec();
    deduped_sources.sort_unstable();
    deduped_sources.dedup();
    for &source in &deduped_sources {
        dist[source] = 0;
        queue.push_back(source);
    }

    while let Some(node) = queue.pop_front() {
        let next_dist = dist[node].saturating_add(1);
        for &neighbor in &adjacency[node] {
            if dist[neighbor] != u32::MAX {
                continue;
            }
            dist[neighbor] = next_dist;
            parent[neighbor] = Some(node);
            queue.push_back(neighbor);
        }
    }

    if dist.iter().any(|distance| *distance == u32::MAX) {
        return None;
    }
    Some(BfsTree { dist, parent })
}

fn build_corridor(
    samples: &[usize],
    sender_tree: &BfsTree,
    sender: usize,
) -> (BTreeSet<usize>, BTreeSet<(usize, usize)>) {
    let mut nodes = BTreeSet::from([sender]);
    let mut edges = BTreeSet::new();

    for &sample in samples {
        insert_path(sample, sender, sender_tree, &mut nodes, &mut edges);
    }

    (nodes, edges)
}

fn insert_path(
    mut node: usize,
    maybe_root: usize,
    tree: &BfsTree,
    nodes: &mut BTreeSet<usize>,
    edges: &mut BTreeSet<(usize, usize)>,
) {
    nodes.insert(node);
    while tree.parent[node].is_some() {
        let parent = tree.parent[node].expect("path parent");
        nodes.insert(parent);
        let edge = if node <= parent {
            (node, parent)
        } else {
            (parent, node)
        };
        edges.insert(edge);
        node = parent;
        if node == maybe_root {
            break;
        }
    }
}

#[derive(Clone)]
struct ActualPeer {
    daemon: VirtualDaemon,
    recorded_by: String,
}

fn materialize_corridor_peers(
    logical_nodes: &BTreeSet<usize>,
) -> SimResult<BTreeMap<usize, ActualPeer>> {
    let tmpdir = tempfile::tempdir()?;
    let base = tmpdir.keep();
    let sender = *logical_nodes
        .first()
        .expect("sender must be present as the first corridor node");

    let sender_db = base.join(format!("{sender:06}.db"));
    let sender_daemon = VirtualDaemon::new(sender_db.to_str().expect("sender db path utf8"));
    let created = sender_daemon.call(RpcMethod::CreateWorkspace {
        workspace_name: "sim".into(),
        username: format!("user{sender}"),
        device_name: "device".into(),
        message_count: 0,
        network_age: None,
        device_chain_length: 0,
    });
    if !created.ok {
        return Err(format!("sender workspace creation failed: {:?}", created.error).into());
    }

    let mut out = BTreeMap::new();
    out.insert(
        sender,
        ActualPeer {
            recorded_by: active_peer_id(&sender_daemon)?,
            daemon: sender_daemon.clone(),
        },
    );

    for &logical in logical_nodes.iter().skip(1) {
        let db_path = base.join(format!("{logical:06}.db"));
        let daemon = VirtualDaemon::new(db_path.to_str().expect("peer db path utf8"));
        let invite = create_invite(
            &sender_daemon,
            &format!("127.0.0.1:{}", 30_000 + (logical % 20_000)),
        )?;
        let accepted = daemon.call(RpcMethod::AcceptInvite {
            invite,
            username: format!("user{logical}"),
            devicename: "device".into(),
        });
        if !accepted.ok {
            return Err(format!("accept invite failed for {logical}: {:?}", accepted.error).into());
        }
        out.insert(
            logical,
            ActualPeer {
                recorded_by: active_peer_id(&daemon)?,
                daemon,
            },
        );
    }

    Ok(out)
}

fn active_peer_id(daemon: &VirtualDaemon) -> SimResult<String> {
    Ok(daemon.call_ok_value(RpcMethod::ActiveTenant)?["peer_id"]
        .as_str()
        .expect("active tenant peer id")
        .to_string())
}

fn create_invite(daemon: &VirtualDaemon, public_addr: &str) -> SimResult<String> {
    Ok(daemon.call_ok_value(RpcMethod::CreateInvite {
        public_addr: Some(public_addr.to_string()),
        public_spki: None,
    })?["invite_link"]
        .as_str()
        .expect("invite link")
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sampled_large_graph_trial_decrypts_random_peers_on_smaller_graph() {
        let report = run_large_graph_sampled_decrypt_trial(LargeGraphSampleDecryptConfig {
            logical_users: 2_048,
            degree: 6,
            sample_count: 6,
            seed: 11,
            response_policy: KeyResponsePolicy::BestObservedOnly,
            message_content: "smaller-graph sampled decrypt".to_string(),
        })
        .expect("sampled decrypt trial");

        assert_eq!(report.sample_count, 6);
        assert!(report.corridor_peers >= 8);
        assert!(report.max_message_distance > 0);
        assert!(report.max_holder_distance > 0);
        assert!(report.sampled_peers.iter().all(|peer| peer.decrypted));
        assert!(report
            .sampled_peers
            .iter()
            .all(|peer| peer.first_visible_round.is_some()));
    }
}
