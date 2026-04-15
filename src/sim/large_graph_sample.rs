use std::collections::{BTreeMap, BTreeSet, VecDeque};

use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use rusqlite::OptionalExtension;
use serde::Serialize;

use super::hash_graph::{connected_hash_graph_neighbors, synthetic_hash_graph_key};
use super::key_repair::{
    create_encrypted_message_with_key, emit_key_requests_for_peers,
    emit_key_shared_responses_for_peers, seed_deterministic_key_secret, KeyResponsePolicy,
};
use super::planner_runner::PlannerSimulation;
use super::virtual_daemon::VirtualDaemon;
use crate::db::open_connection;
use crate::rpc::protocol::RpcMethod;

type SimResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const RECENT_WINDOW_ROUND_MULTIPLIER: u32 = 4;
const RECENT_WINDOW_ROUND_SLACK: u32 = 4;
const REPAIR_PROPAGATION_PHASES: u32 = 2;

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
    pub repair_transferred_events: usize,
    pub repair_transferred_bytes: u64,
    pub repair_transferred_key_request_events: usize,
    pub repair_transferred_key_shared_events: usize,
    pub distinct_key_request_events: usize,
    pub distinct_key_shared_events: usize,
    pub sampled_peers: Vec<LargeGraphSampleDecryptPeerReport>,
}

#[derive(Debug, Clone, Serialize)]
struct ObservedKeySharedDebug {
    event_id: String,
    recipient_event_id: String,
    unwrap_key_event_id: String,
    signer_event_id: Option<String>,
    signer_valid_locally: bool,
    matching_local_invite_secret_count: i64,
}

#[derive(Debug, Clone, Serialize)]
struct SampleRepairDebugStatus {
    logical_peer: usize,
    has_encrypted_event: bool,
    sender_seen_request_count: i64,
    sender_emitted_response_count: i64,
    recipient_key_shared_count: i64,
    recipient_key_shared_for_key_count: i64,
    recipient_target_key_secret_count: i64,
    recipient_blocked_event_count: i64,
    local_invite_event_id: Option<String>,
    local_invite_secret_event_id: Option<String>,
    local_invite_secret_count: i64,
    observed_key_shared: Vec<ObservedKeySharedDebug>,
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
    let repair_peers = actual
        .values()
        .map(|peer| (peer.daemon.db_path().to_string(), peer.recorded_by.clone()))
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

    let message_event_id = create_encrypted_message_with_key(
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
    let message_round_budget = bounded_recent_window_rounds(max_message_distance);
    let repair_round_budget = bounded_recent_repair_rounds(max_holder_distance);

    let message_event_id_b64 = crate::crypto::event_id_to_base64(&message_event_id);
    let mut message_rounds = 0u32;
    while !samples.iter().all(|sample| {
        let peer = actual
            .get(sample)
            .expect("sample actual peer for message visibility");
        has_event(&peer.daemon, &message_event_id_b64)
    }) {
        PlannerSimulation::with_explicit_fake_pairs(db_paths.clone(), explicit_pairs.clone())
            .tick()
            .map_err(|err| format!("message propagation round {}: {err}", message_rounds + 1))?;
        message_rounds = message_rounds.saturating_add(1);
        if message_rounds > message_round_budget {
            return Err(format!(
                "sampled encrypted event did not reach all peers within bounded rounds: budget={} samples={:?}",
                message_round_budget, samples
            )
            .into());
        }
    }

    for &sample in &samples {
        let peer = actual.get(&sample).expect("sample actual peer");
        if snapshot_has_message_content(&peer.daemon, &config.message_content)? {
            return Err(format!("sample {sample} decrypted before repair").into());
        }
    }

    let response_peers = [sender]
        .into_iter()
        .map(|logical| {
            let peer = actual.get(&logical).expect("response peer");
            (peer.daemon.db_path().to_string(), peer.recorded_by.clone())
        })
        .collect::<Vec<_>>();
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

    let mut repair_rounds = 0u32;
    let mut repair_transferred_events = 0usize;
    let mut repair_transferred_bytes = 0u64;
    let mut repair_transferred_key_request_events = 0usize;
    let mut repair_transferred_key_shared_events = 0usize;
    for repair_round in 1..=repair_round_budget {
        let _request_stats = emit_key_requests_for_peers(&repair_peers)
            .map_err(|err| format!("emit requests before repair round {repair_round}: {err}"))?;
        let _response_stats =
            emit_key_shared_responses_for_peers(&response_peers, config.response_policy).map_err(
                |err| format!("emit responses before repair round {repair_round}: {err}"),
            )?;
        let round_report =
            PlannerSimulation::with_explicit_fake_pairs(db_paths.clone(), explicit_pairs.clone())
                .tick()
                .map_err(|err| format!("repair propagation round {repair_round}: {err}"))?;
        repair_transferred_events =
            repair_transferred_events.saturating_add(round_report.transferred_events);
        repair_transferred_bytes =
            repair_transferred_bytes.saturating_add(round_report.transferred_bytes);
        repair_transferred_key_request_events = repair_transferred_key_request_events
            .saturating_add(
                round_report
                    .pairs
                    .iter()
                    .map(|pair| {
                        pair.stats.left_to_right.transferred_key_request_events
                            + pair.stats.right_to_left.transferred_key_request_events
                    })
                    .sum::<usize>(),
            );
        repair_transferred_key_shared_events = repair_transferred_key_shared_events.saturating_add(
            round_report
                .pairs
                .iter()
                .map(|pair| {
                    pair.stats.left_to_right.transferred_key_shared_events
                        + pair.stats.right_to_left.transferred_key_shared_events
                })
                .sum::<usize>(),
        );
        repair_rounds = repair_round;
        for report in &mut sampled_reports {
            if report.decrypted {
                continue;
            }
            let peer = actual
                .get(&report.logical_peer)
                .expect("sample actual peer for visibility");
            if snapshot_has_message_content(&peer.daemon, &config.message_content)? {
                report.decrypted = true;
                report.first_visible_round = Some(message_rounds + repair_round);
            }
        }
        if sampled_reports.iter().all(|peer| peer.decrypted) {
            break;
        }
    }

    if sampled_reports.iter().any(|peer| !peer.decrypted) {
        let stuck = sampled_reports
            .iter()
            .filter(|peer| !peer.decrypted)
            .map(|peer| {
                sample_repair_debug_status(
                    &actual,
                    sender,
                    peer.logical_peer,
                    &message_event_id_b64,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        return Err(format!(
            "not all sampled peers decrypted: reports={:?} debug={:?}",
            sampled_reports, stuck
        )
        .into());
    }

    let key_event_id_b64 = crate::crypto::event_id_to_base64(&sender_key);
    let distinct_key_request_events =
        distinct_key_request_events_for_blocked_event(&actual, &message_event_id_b64)?;
    let distinct_key_shared_events =
        distinct_key_shared_events_for_key(&actual, &key_event_id_b64)?;

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
        message_rounds,
        request_rounds: repair_rounds,
        response_rounds: repair_rounds,
        repair_transferred_events,
        repair_transferred_bytes,
        repair_transferred_key_request_events,
        repair_transferred_key_shared_events,
        distinct_key_request_events,
        distinct_key_shared_events,
        sampled_peers: sampled_reports,
    })
}

fn bounded_recent_window_rounds(max_distance: u32) -> u32 {
    max_distance
        .saturating_mul(RECENT_WINDOW_ROUND_MULTIPLIER)
        .saturating_add(RECENT_WINDOW_ROUND_SLACK)
}

fn bounded_recent_repair_rounds(max_distance: u32) -> u32 {
    bounded_recent_window_rounds(max_distance).saturating_mul(REPAIR_PROPAGATION_PHASES)
}

fn sample_repair_debug_status(
    actual: &BTreeMap<usize, ActualPeer>,
    sender: usize,
    logical_peer: usize,
    encrypted_event_id_b64: &str,
) -> SimResult<SampleRepairDebugStatus> {
    let peer = actual
        .get(&logical_peer)
        .expect("sample actual peer for debug status");
    let sender_peer = actual
        .get(&sender)
        .expect("sender actual peer for debug status");
    let conn = open_connection(peer.daemon.db_path())?;
    let sender_conn = open_connection(sender_peer.daemon.db_path())?;
    let encrypted_blob: Vec<u8> = conn.query_row(
        "SELECT blob FROM events WHERE event_id = ?1",
        rusqlite::params![encrypted_event_id_b64],
        |row| crate::db::sql_types::get_blob(row, 0),
    )?;
    let target_key_event_id_b64 = match crate::event_modules::parse_event(&encrypted_blob) {
        Ok(parsed) => match parsed {
            crate::event_modules::ParsedEvent::Signed(signed) => {
                match crate::event_modules::parse_event(&signed.payload) {
                    Ok(crate::event_modules::ParsedEvent::Encrypted(enc)) => {
                        crate::crypto::event_id_to_base64(&enc.key_event_id)
                    }
                    _ => return Err("sample encrypted event payload is not encrypted".into()),
                }
            }
            crate::event_modules::ParsedEvent::Encrypted(enc) => {
                crate::crypto::event_id_to_base64(&enc.key_event_id)
            }
            _ => return Err("sample event is not encrypted".into()),
        },
        Err(err) => return Err(format!("parse sample encrypted event: {err}").into()),
    };
    let local_invite_secret_count: i64 = conn.query_row(
        "SELECT COUNT(*)
         FROM invite_secrets
         WHERE recorded_by = ?1",
        rusqlite::params![&peer.recorded_by],
        |row| row.get(0),
    )?;
    let local_invite_material: Option<(String, String)> = conn
        .query_row(
            "SELECT invite_event_id, event_id
             FROM invite_secrets
             WHERE recorded_by = ?1
             ORDER BY created_at ASC, event_id ASC
             LIMIT 1",
            rusqlite::params![&peer.recorded_by],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let local_invite_event_id = local_invite_material
        .as_ref()
        .map(|(invite_event_id, _)| invite_event_id.clone());
    let local_invite_secret_event_id = local_invite_material
        .as_ref()
        .map(|(_, invite_secret_event_id)| invite_secret_event_id.clone());
    let recipient_event_id_b64 = local_invite_event_id.clone().unwrap_or_default();
    let sender_seen_request_count: i64 = sender_conn.query_row(
        "SELECT COUNT(*)
         FROM key_requests
         WHERE recorded_by = ?1
           AND recipient_event_id = ?2",
        rusqlite::params![&sender_peer.recorded_by, &recipient_event_id_b64],
        |row| row.get(0),
    )?;
    let sender_emitted_response_count: i64 = sender_conn.query_row(
        "SELECT COUNT(*)
         FROM key_shared
         WHERE recorded_by = ?1
           AND recipient_event_id = ?2",
        rusqlite::params![&sender_peer.recorded_by, &recipient_event_id_b64],
        |row| row.get(0),
    )?;
    let recipient_key_shared_count: i64 = conn.query_row(
        "SELECT COUNT(*)
         FROM key_shared
         WHERE recorded_by = ?1
           AND recipient_event_id = ?2",
        rusqlite::params![&peer.recorded_by, &recipient_event_id_b64],
        |row| row.get(0),
    )?;
    let recipient_key_shared_for_key_count: i64 = conn.query_row(
        "SELECT COUNT(*)
         FROM key_shared
         WHERE recorded_by = ?1
           AND key_event_id = ?2",
        rusqlite::params![&peer.recorded_by, &target_key_event_id_b64],
        |row| row.get(0),
    )?;
    let recipient_target_key_secret_count: i64 = conn.query_row(
        "SELECT COUNT(*)
         FROM key_secrets
         WHERE recorded_by = ?1
           AND event_id = ?2",
        rusqlite::params![&peer.recorded_by, &target_key_event_id_b64],
        |row| row.get(0),
    )?;
    let recipient_blocked_event_count: i64 = conn.query_row(
        "SELECT COUNT(*)
         FROM blocked_events
         WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![&peer.recorded_by, encrypted_event_id_b64],
        |row| row.get(0),
    )?;
    let mut observed_key_shared_stmt = conn.prepare(
        "SELECT ks.event_id, e.blob
         FROM key_shared ks
         JOIN events e ON e.event_id = ks.event_id
         WHERE ks.recorded_by = ?1
           AND ks.key_event_id = ?2
         ORDER BY ks.event_id ASC",
    )?;
    let observed_key_shared = observed_key_shared_stmt
        .query_map(
            rusqlite::params![&peer.recorded_by, &target_key_event_id_b64],
            |row| {
                Ok((
                    crate::db::sql_types::get_text(row, 0)?,
                    crate::db::sql_types::get_blob(row, 1)?,
                ))
            },
        )?
        .map(|row| {
            let (event_id, blob) = row?;
            let (recipient_event_id, unwrap_key_event_id) =
                match crate::event_modules::parse_event(&blob) {
                    Ok(crate::event_modules::ParsedEvent::Signed(signed)) => {
                        match crate::event_modules::parse_event(&signed.payload) {
                            Ok(crate::event_modules::ParsedEvent::KeyShared(event)) => (
                                crate::crypto::event_id_to_base64(&event.recipient_event_id),
                                crate::crypto::event_id_to_base64(&event.unwrap_key_event_id),
                            ),
                            _ => return Err(rusqlite::Error::QueryReturnedNoRows),
                        }
                    }
                    Ok(crate::event_modules::ParsedEvent::KeyShared(event)) => (
                        crate::crypto::event_id_to_base64(&event.recipient_event_id),
                        crate::crypto::event_id_to_base64(&event.unwrap_key_event_id),
                    ),
                    _ => return Err(rusqlite::Error::QueryReturnedNoRows),
                };
            let signer_event_id = crate::event_modules::signed::outer_signer_event_id(&blob)
                .map(|event_id| crate::crypto::event_id_to_base64(&event_id));
            let signer_valid_locally = signer_event_id
                .as_ref()
                .map(|signer_event_id| {
                    conn.query_row(
                        "SELECT EXISTS(
                             SELECT 1
                             FROM valid_events
                             WHERE peer_id = ?1
                               AND event_id = ?2
                         )",
                        rusqlite::params![&peer.recorded_by, signer_event_id],
                        |row| row.get(0),
                    )
                })
                .transpose()?
                .unwrap_or(false);
            let matching_local_invite_secret_count: i64 = conn.query_row(
                "SELECT COUNT(*)
                 FROM invite_secrets
                 WHERE recorded_by = ?1
                   AND invite_event_id = ?2
                   AND event_id = ?3",
                rusqlite::params![&peer.recorded_by, &recipient_event_id, &unwrap_key_event_id],
                |row| row.get(0),
            )?;
            Ok(ObservedKeySharedDebug {
                event_id,
                recipient_event_id,
                unwrap_key_event_id,
                signer_event_id,
                signer_valid_locally,
                matching_local_invite_secret_count,
            })
        })
        .collect::<Result<Vec<_>, rusqlite::Error>>()?;

    Ok(SampleRepairDebugStatus {
        logical_peer,
        has_encrypted_event: has_event(&peer.daemon, encrypted_event_id_b64),
        sender_seen_request_count,
        sender_emitted_response_count,
        recipient_key_shared_count,
        recipient_key_shared_for_key_count,
        recipient_target_key_secret_count,
        recipient_blocked_event_count,
        local_invite_event_id,
        local_invite_secret_event_id,
        local_invite_secret_count,
        observed_key_shared,
    })
}

fn has_event(daemon: &VirtualDaemon, event_id: &str) -> bool {
    daemon
        .call(RpcMethod::AssertNow {
            predicate: format!("has_event:{event_id} >= 1"),
        })
        .ok
}

fn distinct_key_request_events_for_blocked_event(
    actual: &BTreeMap<usize, ActualPeer>,
    blocked_event_id_b64: &str,
) -> SimResult<usize> {
    let mut seen = BTreeSet::new();
    for peer in actual.values() {
        let conn = open_connection(peer.daemon.db_path())?;
        let mut stmt = conn.prepare(
            "SELECT event_id
             FROM key_requests
             WHERE blocked_event_id = ?1",
        )?;
        let rows = stmt.query_map(rusqlite::params![blocked_event_id_b64], |row| {
            crate::db::sql_types::get_text(row, 0)
        })?;
        for row in rows {
            seen.insert(row?);
        }
    }
    Ok(seen.len())
}

fn distinct_key_shared_events_for_key(
    actual: &BTreeMap<usize, ActualPeer>,
    key_event_id_b64: &str,
) -> SimResult<usize> {
    let mut seen = BTreeSet::new();
    for peer in actual.values() {
        let conn = open_connection(peer.daemon.db_path())?;
        let mut stmt = conn.prepare(
            "SELECT event_id
             FROM key_shared
             WHERE key_event_id = ?1",
        )?;
        let rows = stmt.query_map(rusqlite::params![key_event_id_b64], |row| {
            crate::db::sql_types::get_text(row, 0)
        })?;
        for row in rows {
            seen.insert(row?);
        }
    }
    Ok(seen.len())
}

fn snapshot_has_message_content(daemon: &VirtualDaemon, content: &str) -> SimResult<bool> {
    let messages = daemon.call_ok_value(RpcMethod::Messages { limit: 100 })?;
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
        let invite = create_invite(&sender_daemon)?;
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

fn create_invite(daemon: &VirtualDaemon) -> SimResult<String> {
    Ok(daemon.call_ok_value(RpcMethod::CreateInvite {
        public_addr: None,
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
