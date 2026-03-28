use std::collections::BTreeSet;

/// Sparse peer knowledge for simulation.
///
/// This keeps a contiguous prefix plus a sparse tail of out-of-order ids.
/// It is compact for the common "mostly caught up" case and avoids any SQL
/// read-model materialization.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SparseKnowledge {
    contiguous_prefix_exclusive: u32,
    out_of_order_known: BTreeSet<u32>,
}

impl SparseKnowledge {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn known_contiguous_prefix(&self) -> u32 {
        self.contiguous_prefix_exclusive
    }

    pub fn known_count_estimate(&self) -> usize {
        self.contiguous_prefix_exclusive as usize + self.out_of_order_known.len()
    }

    pub fn sparse_tail_count(&self) -> usize {
        self.out_of_order_known.len()
    }

    pub fn knows(&self, event_id: u32) -> bool {
        event_id < self.contiguous_prefix_exclusive || self.out_of_order_known.contains(&event_id)
    }

    pub fn mark_known(&mut self, event_id: u32) -> bool {
        if self.knows(event_id) {
            return false;
        }

        if event_id == self.contiguous_prefix_exclusive {
            self.contiguous_prefix_exclusive = self.contiguous_prefix_exclusive.saturating_add(1);
            while self
                .out_of_order_known
                .remove(&self.contiguous_prefix_exclusive)
            {
                self.contiguous_prefix_exclusive =
                    self.contiguous_prefix_exclusive.saturating_add(1);
            }
            true
        } else {
            self.out_of_order_known.insert(event_id)
        }
    }

    pub fn mark_range_known(&mut self, start: u32, end_exclusive: u32) -> u32 {
        let mut inserted = 0u32;
        for event_id in start..end_exclusive {
            if self.mark_known(event_id) {
                inserted = inserted.saturating_add(1);
            }
        }
        inserted
    }

    pub fn missing_up_to(&self, upper_exclusive: u32) -> Vec<u32> {
        let mut missing = Vec::new();
        for event_id in 0..upper_exclusive {
            if !self.knows(event_id) {
                missing.push(event_id);
            }
        }
        missing
    }

    /// Learn only the donor-known subset of a bounded window.
    ///
    /// This is intentionally window-bounded so the simulator can cheaply model
    /// selective ingest of "hot" events without projecting the full delivered
    /// history at every peer.
    pub fn learn_window_from(&mut self, other: &Self, start: u32, end_exclusive: u32) -> u64 {
        let mut learned = 0u64;
        for event_id in start..end_exclusive {
            if other.knows(event_id) && self.mark_known(event_id) {
                learned = learned.saturating_add(1);
            }
        }
        learned
    }

    /// Merge knowledge from another peer snapshot.
    ///
    /// Returns the count of newly learned event ids. The common case where the
    /// donor has only a larger contiguous prefix is O(tail) instead of O(events).
    pub fn merge_from(&mut self, other: &Self) -> u64 {
        let mut learned = 0u64;

        if other.contiguous_prefix_exclusive > self.contiguous_prefix_exclusive {
            let already_known_in_gap = self
                .out_of_order_known
                .range(self.contiguous_prefix_exclusive..other.contiguous_prefix_exclusive)
                .count() as u64;
            learned = learned.saturating_add(
                (other.contiguous_prefix_exclusive - self.contiguous_prefix_exclusive) as u64
                    - already_known_in_gap,
            );
            self.contiguous_prefix_exclusive = other.contiguous_prefix_exclusive;
            self.out_of_order_known
                .retain(|event_id| *event_id >= self.contiguous_prefix_exclusive);
        }

        for event_id in other
            .out_of_order_known
            .range(self.contiguous_prefix_exclusive..)
        {
            if self.out_of_order_known.insert(*event_id) {
                learned = learned.saturating_add(1);
            }
        }

        while self
            .out_of_order_known
            .remove(&self.contiguous_prefix_exclusive)
        {
            self.contiguous_prefix_exclusive = self.contiguous_prefix_exclusive.saturating_add(1);
        }

        learned
    }
}

/// Exact lower-bound storage for a peer-event knowledge matrix if represented
/// as one bit per `(peer, event)` relation.
pub fn exact_matrix_bytes(peer_count: u64, event_count: u64) -> u64 {
    let bits = (peer_count as u128).saturating_mul(event_count as u128);
    bits.div_ceil(8) as u64
}
