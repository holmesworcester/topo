use std::collections::VecDeque;
use std::time::Instant;

use serde::Serialize;
use topo::sim::hash_graph::{connected_hash_graph_neighbors, DEFAULT_HASH_GRAPH_DEGREE};

const REQUEST_BYTES: u64 = 160;
const RESPONSE_BYTES: u64 = 170;
const GRAPH_DEGREE: usize = DEFAULT_HASH_GRAPH_DEGREE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TopologyKind {
    Star,
    Graph,
}

impl TopologyKind {
    fn all() -> [Self; 2] {
        [Self::Star, Self::Graph]
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Star => "star",
            Self::Graph => "graph",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct CaseReport {
    users: usize,
    topology: String,
    connected: bool,
    connected_component_size: usize,
    holder_count: usize,
    requester_count: usize,
    avg_request_hops: Option<f64>,
    avg_sender_proactive_hops: Option<f64>,
    max_request_hops: Option<u32>,
    total_request_bytes: Option<u64>,
    total_response_bytes: Option<u64>,
    total_repair_bytes: Option<u64>,
    avg_request_bytes_per_peer: Option<f64>,
    avg_response_bytes_per_peer: Option<f64>,
    avg_total_repair_bytes_per_peer: Option<f64>,
    max_sent_bytes_single_peer: Option<u64>,
    max_received_bytes_single_peer: Option<u64>,
    max_total_bytes_single_peer: Option<u64>,
    proactive_sender_total_bytes: Option<u64>,
    proactive_sender_avg_bytes_per_peer: Option<f64>,
    multiplier_over_sender_proactive: Option<f64>,
    multiplier_over_same_tree_proactive: Option<f64>,
    elapsed_ms: u128,
}

#[derive(Debug, Clone, Serialize)]
struct Report {
    request_bytes: u64,
    response_bytes: u64,
    graph_degree: usize,
    peer_id_model: &'static str,
    cases: Vec<CaseReport>,
}

fn main() {
    let user_counts = [1_000usize, 10_000, 100_000];
    let mut cases = Vec::new();
    for users in user_counts {
        for topology in TopologyKind::all() {
            cases.push(run_case(users, topology));
        }
    }
    let report = Report {
        request_bytes: REQUEST_BYTES,
        response_bytes: RESPONSE_BYTES,
        graph_degree: GRAPH_DEGREE,
        peer_id_model: "deterministic_hashed_u64_small_world_ring",
        cases,
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize topology report")
    );
}

fn run_case(users: usize, topology: TopologyKind) -> CaseReport {
    let started = Instant::now();
    assert!(
        users >= 3,
        "need at least sender + backup holder + requester"
    );

    let sender = 0usize;
    let backup_holder = 1usize;
    let holders = [sender, backup_holder];
    let requester_count = users - holders.len();

    let adjacency = build_adjacency(users, topology);
    let connected_component_size = connected_component_size(&adjacency, sender);
    if connected_component_size != users {
        return CaseReport {
            users,
            topology: topology.as_str().to_string(),
            connected: false,
            connected_component_size,
            holder_count: holders.len(),
            requester_count,
            avg_request_hops: None,
            avg_sender_proactive_hops: None,
            max_request_hops: None,
            total_request_bytes: None,
            total_response_bytes: None,
            total_repair_bytes: None,
            avg_request_bytes_per_peer: None,
            avg_response_bytes_per_peer: None,
            avg_total_repair_bytes_per_peer: None,
            max_sent_bytes_single_peer: None,
            max_received_bytes_single_peer: None,
            max_total_bytes_single_peer: None,
            proactive_sender_total_bytes: None,
            proactive_sender_avg_bytes_per_peer: None,
            multiplier_over_sender_proactive: None,
            multiplier_over_same_tree_proactive: None,
            elapsed_ms: started.elapsed().as_millis(),
        };
    }

    let nearest_holder = bfs_tree(&adjacency, &holders).expect("connected graph");
    let sender_tree = bfs_tree(&adjacency, &[sender]).expect("connected graph");

    let repair_bytes = compute_repair_bytes(users, &holders, &nearest_holder);
    let proactive_sender_total_bytes = (0..users)
        .filter(|node| !holders.contains(node))
        .map(|node| sender_tree.dist[node] as u64 * RESPONSE_BYTES)
        .sum::<u64>();
    let total_request_hops = (0..users)
        .filter(|node| !holders.contains(node))
        .map(|node| nearest_holder.dist[node] as u64)
        .sum::<u64>();
    let total_sender_hops = (0..users)
        .filter(|node| !holders.contains(node))
        .map(|node| sender_tree.dist[node] as u64)
        .sum::<u64>();
    let avg_request_hops = total_request_hops as f64 / requester_count as f64;
    let avg_sender_proactive_hops = total_sender_hops as f64 / requester_count as f64;
    let max_request_hops = (0..users)
        .filter(|node| !holders.contains(node))
        .map(|node| nearest_holder.dist[node])
        .max()
        .unwrap_or(0);

    let total_request_bytes = total_request_hops * REQUEST_BYTES;
    let total_response_bytes = total_request_hops * RESPONSE_BYTES;
    let total_repair_bytes = total_request_bytes + total_response_bytes;
    let max_sent_bytes_single_peer = repair_bytes.sent.iter().copied().max().unwrap_or(0);
    let max_received_bytes_single_peer = repair_bytes.received.iter().copied().max().unwrap_or(0);
    let max_total_bytes_single_peer = repair_bytes
        .sent
        .iter()
        .zip(repair_bytes.received.iter())
        .map(|(sent, received)| sent + received)
        .max()
        .unwrap_or(0);

    CaseReport {
        users,
        topology: topology.as_str().to_string(),
        connected: true,
        connected_component_size,
        holder_count: holders.len(),
        requester_count,
        avg_request_hops: Some(avg_request_hops),
        avg_sender_proactive_hops: Some(avg_sender_proactive_hops),
        max_request_hops: Some(max_request_hops),
        total_request_bytes: Some(total_request_bytes),
        total_response_bytes: Some(total_response_bytes),
        total_repair_bytes: Some(total_repair_bytes),
        avg_request_bytes_per_peer: Some(total_request_bytes as f64 / users as f64),
        avg_response_bytes_per_peer: Some(total_response_bytes as f64 / users as f64),
        avg_total_repair_bytes_per_peer: Some(total_repair_bytes as f64 / users as f64),
        max_sent_bytes_single_peer: Some(max_sent_bytes_single_peer),
        max_received_bytes_single_peer: Some(max_received_bytes_single_peer),
        max_total_bytes_single_peer: Some(max_total_bytes_single_peer),
        proactive_sender_total_bytes: Some(proactive_sender_total_bytes),
        proactive_sender_avg_bytes_per_peer: Some(
            proactive_sender_total_bytes as f64 / users as f64,
        ),
        multiplier_over_sender_proactive: Some(
            total_repair_bytes as f64 / proactive_sender_total_bytes.max(1) as f64,
        ),
        multiplier_over_same_tree_proactive: Some(
            total_repair_bytes as f64 / total_response_bytes.max(1) as f64,
        ),
        elapsed_ms: started.elapsed().as_millis(),
    }
}

fn build_adjacency(users: usize, topology: TopologyKind) -> Vec<Vec<usize>> {
    match topology {
        TopologyKind::Star => build_star_adjacency(users),
        TopologyKind::Graph => build_xor_graph_adjacency(users, GRAPH_DEGREE),
    }
}

fn build_star_adjacency(users: usize) -> Vec<Vec<usize>> {
    let mut adjacency = vec![Vec::new(); users];
    let hub = 0usize;
    for node in 1..users {
        adjacency[hub].push(node);
        adjacency[node].push(hub);
    }
    adjacency
}

fn build_xor_graph_adjacency(users: usize, degree: usize) -> Vec<Vec<usize>> {
    let keys = (0..users)
        .map(|idx| synthetic_hash_key(idx as u64 + 1))
        .collect::<Vec<_>>();
    let neighbors = connected_hash_graph_neighbors(&keys, degree);
    let mut adjacency = vec![Vec::new(); users];
    for node in 0..users {
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

#[derive(Debug, Clone)]
struct BfsTree {
    dist: Vec<u32>,
    parent: Vec<Option<usize>>,
}

fn bfs_tree(adjacency: &[Vec<usize>], sources: &[usize]) -> Option<BfsTree> {
    let users = adjacency.len();
    let mut dist = vec![u32::MAX; users];
    let mut parent = vec![None; users];
    let mut queue = VecDeque::new();

    let mut sorted_sources = sources.to_vec();
    sorted_sources.sort_unstable();
    sorted_sources.dedup();
    for &source in &sorted_sources {
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

#[derive(Debug, Clone)]
struct RepairByteStats {
    sent: Vec<u64>,
    received: Vec<u64>,
}

fn compute_repair_bytes(users: usize, holders: &[usize], tree: &BfsTree) -> RepairByteStats {
    let mut sent = vec![0u64; users];
    let mut received = vec![0u64; users];
    let mut subtree_requesters = vec![0u64; users];
    let mut order = (0..users).collect::<Vec<_>>();
    order.sort_by_key(|node| std::cmp::Reverse(tree.dist[*node]));

    for node in 0..users {
        if !holders.contains(&node) {
            subtree_requesters[node] = 1;
        }
    }

    for node in order {
        if let Some(parent) = tree.parent[node] {
            let requester_count = subtree_requesters[node];
            sent[node] = sent[node].saturating_add(requester_count.saturating_mul(REQUEST_BYTES));
            received[parent] =
                received[parent].saturating_add(requester_count.saturating_mul(REQUEST_BYTES));
            sent[parent] =
                sent[parent].saturating_add(requester_count.saturating_mul(RESPONSE_BYTES));
            received[node] =
                received[node].saturating_add(requester_count.saturating_mul(RESPONSE_BYTES));
            subtree_requesters[parent] =
                subtree_requesters[parent].saturating_add(subtree_requesters[node]);
        }
    }

    RepairByteStats { sent, received }
}

fn connected_component_size(adjacency: &[Vec<usize>], source: usize) -> usize {
    let mut seen = vec![false; adjacency.len()];
    let mut queue = VecDeque::new();
    seen[source] = true;
    queue.push_back(source);
    let mut count = 0usize;
    while let Some(node) = queue.pop_front() {
        count = count.saturating_add(1);
        for &neighbor in &adjacency[node] {
            if seen[neighbor] {
                continue;
            }
            seen[neighbor] = true;
            queue.push_back(neighbor);
        }
    }
    count
}

fn synthetic_hash_key(seed: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut cursor = 0usize;
    let mut value = seed;
    for _ in 0..4 {
        value = splitmix64(value);
        out[cursor..cursor + 8].copy_from_slice(&value.to_be_bytes());
        cursor += 8;
    }
    out
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E3779B97F4A7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}
