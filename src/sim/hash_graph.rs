use std::collections::BTreeSet;

pub const DEFAULT_HASH_GRAPH_DEGREE: usize = 6;

pub fn connected_hash_graph_neighbors(keys: &[[u8; 32]], degree: usize) -> Vec<Vec<usize>> {
    let count = keys.len();
    let mut neighbors = vec![Vec::new(); count];
    if count <= 1 {
        return neighbors;
    }

    let degree = degree.max(1).min(count - 1);
    let mut order = (0..count).collect::<Vec<_>>();
    order.sort_by_key(|&idx| keys[idx]);

    let mut ring_pos = vec![0usize; count];
    for (pos, &idx) in order.iter().enumerate() {
        ring_pos[idx] = pos;
    }

    let shortcut_count = degree.saturating_sub(2);

    for idx in 0..count {
        let pos = ring_pos[idx];
        let mut picked = BTreeSet::new();
        picked.insert(order[(pos + count - 1) % count]);
        picked.insert(order[(pos + 1) % count]);
        let mut rng = seed_from_key(keys[idx]);
        let max_distance = (count / 2).max(2);
        let min_log = (2f64).ln();
        let max_log = (max_distance as f64).ln();
        let mut attempts = 0usize;
        while picked.len() < degree && attempts < shortcut_count.saturating_mul(8) {
            rng = splitmix64(rng);
            let unit = (rng as f64) / (u64::MAX as f64);
            let distance = if max_distance <= 2 {
                2usize
            } else {
                (min_log + unit * (max_log - min_log)).exp().round() as usize
            }
            .clamp(2, max_distance);
            rng = splitmix64(rng);
            let forward = (rng & 1) == 0;
            let neighbor_pos = if forward {
                (pos + distance) % count
            } else {
                (pos + count - (distance % count)) % count
            };
            picked.insert(order[neighbor_pos]);
            attempts = attempts.saturating_add(1);
        }
        picked.remove(&idx);
        neighbors[idx] = picked.into_iter().collect();
    }

    neighbors
}

fn seed_from_key(key: [u8; 32]) -> u64 {
    let mut words = [0u64; 4];
    for (idx, chunk) in key.chunks_exact(8).enumerate() {
        words[idx] = u64::from_be_bytes(chunk.try_into().expect("8-byte chunk"));
    }
    words[0] ^ words[1].rotate_left(13) ^ words[2].rotate_left(27) ^ words[3].rotate_left(41)
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E3779B97F4A7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn seq_key(last_byte: u8) -> [u8; 32] {
        let mut key = [0u8; 32];
        key[31] = last_byte;
        key
    }

    #[test]
    fn small_hash_graph_adds_ring_and_fingers() {
        let keys = (0u8..16).map(seq_key).collect::<Vec<_>>();
        let neighbors = connected_hash_graph_neighbors(&keys, 6);
        let node0 = &neighbors[0];
        assert!(node0.contains(&15), "predecessor should be present");
        assert!(node0.contains(&1), "successor should be present");
        assert!(
            node0.len() >= 4,
            "graph should add long-range links beyond ring neighbors"
        );
    }

    #[test]
    fn large_hash_graph_is_connected() {
        let keys = (0u64..4096).map(synthetic_hash_key).collect::<Vec<_>>();
        let neighbors = connected_hash_graph_neighbors(&keys, DEFAULT_HASH_GRAPH_DEGREE);
        let mut seen = vec![false; neighbors.len()];
        let mut queue = VecDeque::from([0usize]);
        seen[0] = true;
        let mut count = 0usize;
        while let Some(node) = queue.pop_front() {
            count += 1;
            for &neighbor in &neighbors[node] {
                if seen[neighbor] {
                    continue;
                }
                seen[neighbor] = true;
                queue.push_back(neighbor);
            }
        }
        assert_eq!(count, neighbors.len());
    }

    fn synthetic_hash_key(seed: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut cursor = 0usize;
        let mut value = seed.wrapping_add(1);
        for _ in 0..4 {
            value = splitmix64(value);
            out[cursor..cursor + 8].copy_from_slice(&value.to_be_bytes());
            cursor += 8;
        }
        out
    }
}
