use serde::Serialize;

use super::scenario::PeerId;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum Topology {
    Star { hub: PeerId },
    Graph { degree: usize },
}

impl Topology {
    pub fn edges(&self, peer_count: usize) -> Vec<(PeerId, PeerId)> {
        let mut edges = Vec::new();
        match self {
            Self::Star { hub } => {
                let hub_idx = hub.0 as usize;
                for idx in 0..peer_count {
                    if idx == hub_idx {
                        continue;
                    }
                    edges.push((*hub, PeerId(idx as u32)));
                }
            }
            Self::Graph { degree } => {
                if peer_count < 2 {
                    return edges;
                }
                let degree = (*degree).max(1).min(peer_count - 1);
                for a in 0..peer_count {
                    for offset in 1..=degree {
                        let b = (a + offset) % peer_count;
                        if a < b {
                            edges.push((PeerId(a as u32), PeerId(b as u32)));
                        }
                    }
                }
            }
        }
        edges
    }

    pub fn neighbors(&self, peer_count: usize, peer: PeerId) -> Vec<PeerId> {
        match self {
            Self::Star { hub } => {
                let peer_idx = peer.0 as usize;
                let hub_idx = hub.0 as usize;
                if peer_idx == hub_idx {
                    (0..peer_count)
                        .filter(|idx| *idx != hub_idx)
                        .map(|idx| PeerId(idx as u32))
                        .collect()
                } else {
                    vec![*hub]
                }
            }
            Self::Graph { degree } => {
                if peer_count < 2 {
                    return Vec::new();
                }
                let degree = (*degree).max(1).min(peer_count - 1);
                let mut out = Vec::new();
                let idx = peer.0 as usize;
                for offset in 1..=degree {
                    out.push(PeerId(((idx + offset) % peer_count) as u32));
                    let other = (idx + peer_count - (offset % peer_count)) % peer_count;
                    if other != idx {
                        out.push(PeerId(other as u32));
                    }
                }
                out.sort_by_key(|p| p.0);
                out.dedup();
                out.retain(|candidate| *candidate != peer);
                out
            }
        }
    }
}
