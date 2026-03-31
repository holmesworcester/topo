use crate::shared::crypto::event_id_from_hex;

use super::hash_graph::{connected_hash_graph_neighbors, DEFAULT_HASH_GRAPH_DEGREE};
use super::pair_sync::PairSyncIntent;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub enum FakeTopologyPreference {
    Star,
    Graph,
}

impl Default for FakeTopologyPreference {
    fn default() -> Self {
        Self::Graph
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FakeTopologyNode {
    pub(crate) db_path: String,
    pub(crate) recorded_by: String,
}

pub(crate) fn fake_pair_sync_intents(
    nodes: &[FakeTopologyNode],
    topology: FakeTopologyPreference,
    explicit_pairs: Option<&[(String, String)]>,
) -> Vec<PairSyncIntent> {
    if let Some(explicit_pairs) = explicit_pairs {
        return fake_explicit_intents(nodes, explicit_pairs);
    }
    match topology {
        FakeTopologyPreference::Star => fake_star_intents(nodes),
        FakeTopologyPreference::Graph => fake_graph_intents(nodes, DEFAULT_HASH_GRAPH_DEGREE),
    }
}

fn fake_star_intents(nodes: &[FakeTopologyNode]) -> Vec<PairSyncIntent> {
    let Some(hub) = nodes.first() else {
        return Vec::new();
    };
    nodes
        .iter()
        .skip(1)
        .map(|node| fake_intent(node, hub, "fake_star_no_auth"))
        .collect()
}

fn fake_graph_intents(nodes: &[FakeTopologyNode], degree: usize) -> Vec<PairSyncIntent> {
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

fn fake_explicit_intents(
    nodes: &[FakeTopologyNode],
    explicit_pairs: &[(String, String)],
) -> Vec<PairSyncIntent> {
    let by_recorded_by = nodes
        .iter()
        .map(|node| (node.recorded_by.clone(), node))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut out = Vec::new();
    for (left, right) in explicit_pairs {
        let (Some(left_node), Some(right_node)) =
            (by_recorded_by.get(left), by_recorded_by.get(right))
        else {
            continue;
        };
        if left == right {
            continue;
        }
        out.push(fake_intent(left_node, right_node, "fake_explicit_no_auth"));
    }
    out
}

fn fake_intent(
    initiator: &FakeTopologyNode,
    target: &FakeTopologyNode,
    source: &str,
) -> PairSyncIntent {
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

fn fake_graph_key(node: &FakeTopologyNode) -> [u8; 32] {
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

    fn node(peer_hex: &str) -> FakeTopologyNode {
        FakeTopologyNode {
            db_path: format!("/tmp/{peer_hex}.db"),
            recorded_by: peer_hex.to_string(),
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

        let intents = fake_pair_sync_intents(&nodes, FakeTopologyPreference::Graph, None);
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
        let intents = fake_pair_sync_intents(&nodes, FakeTopologyPreference::Star, None);

        assert_eq!(intents.len(), 2);
        assert_eq!(intents[0].initiator_recorded_by, hex_id(1));
        assert_eq!(intents[0].target_recorded_by, hex_id(0));
        assert_eq!(intents[1].initiator_recorded_by, hex_id(2));
        assert_eq!(intents[1].target_recorded_by, hex_id(0));
    }

    #[test]
    fn fake_explicit_pairs_use_exact_requested_edges() {
        let nodes = vec![
            node(&hex_id(0)),
            node(&hex_id(1)),
            node(&hex_id(2)),
            node(&hex_id(3)),
        ];
        let intents = fake_pair_sync_intents(
            &nodes,
            FakeTopologyPreference::Graph,
            Some(&[
                (hex_id(0), hex_id(2)),
                (hex_id(1), hex_id(3)),
                (hex_id(9), hex_id(1)),
            ]),
        );

        assert_eq!(intents.len(), 2);
        assert_eq!(intents[0].initiator_recorded_by, hex_id(0));
        assert_eq!(intents[0].target_recorded_by, hex_id(2));
        assert_eq!(intents[1].initiator_recorded_by, hex_id(1));
        assert_eq!(intents[1].target_recorded_by, hex_id(3));
    }
}
