// Copyright (c) 2023 Doug Hoyte
// Copyright (c) 2023 Yuki Kishimoto
// Distributed under the MIT software license

//! Module that contains the various storage implementations.
//!
//! The original vector storage computed fingerprints by linearly scanning the
//! requested range and feeding IDs into an additive accumulator. This backend
//! instead builds a deterministic treap once at `seal()` time and computes
//! arbitrary range fingerprints from Merkle labels over that tree.

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::cmp::Ordering;
use core::convert::TryInto;
use core::ops::Deref;
#[cfg(feature = "std")]
use std::collections::HashMap;
#[cfg(feature = "std")]
use std::sync::OnceLock;

use crate::types::{Accumulator, Bound, Fingerprint, Item};
use crate::{Error, Id, FINGERPRINT_SIZE};

const NULL_NODE: u32 = u32::MAX;

#[cfg(feature = "std")]
type FingerprintCache = HashMap<(u32, u32), Fingerprint>;
#[cfg(not(feature = "std"))]
type FingerprintCache = BTreeMap<(u32, u32), Fingerprint>;

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct MerkleIntervalTree {
    nodes: Vec<MerkleNode>,
    root: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct MerkleNode {
    left: u32,
    right: u32,
    span_lo: u32,
    span_hi: u32,
    item_hash: [u8; 32],
    label: [u8; FINGERPRINT_SIZE],
}

impl Default for MerkleNode {
    fn default() -> Self {
        Self {
            left: NULL_NODE,
            right: NULL_NODE,
            span_lo: 0,
            span_hi: 0,
            item_hash: [0u8; 32],
            label: [0u8; FINGERPRINT_SIZE],
        }
    }
}

impl MerkleIntervalTree {
    fn build(items: &[Item]) -> Result<Self, Error> {
        if items.is_empty() {
            return Ok(Self::default());
        }
        if items.len() > u32::MAX as usize {
            return Err(Error::BadRange);
        }

        let mut nodes = vec![MerkleNode::default(); items.len()];
        let mut ranks = Vec::with_capacity(items.len());
        let mut item_hashes = Vec::with_capacity(items.len());
        for item in items {
            let item_hash = hash_item(item);
            ranks.push(rank_from_hash(&item_hash));
            item_hashes.push(item_hash);
        }

        let mut stack: Vec<u32> = Vec::with_capacity(items.len());
        for idx in 0..items.len() as u32 {
            let mut last = NULL_NODE;
            while let Some(&top) = stack.last() {
                if rank_cmp(top as usize, idx as usize, &ranks, items) == Ordering::Greater {
                    break;
                }
                last = stack.pop().unwrap_or(NULL_NODE);
            }

            nodes[idx as usize].left = last;
            if let Some(&top) = stack.last() {
                nodes[top as usize].right = idx;
            }
            stack.push(idx);
        }

        let root = stack.first().copied().unwrap_or(NULL_NODE);
        let mut postorder = Vec::with_capacity(items.len());
        let mut walk = vec![(root, false)];
        while let Some((node, visited)) = walk.pop() {
            if node == NULL_NODE {
                continue;
            }
            if visited {
                postorder.push(node);
                continue;
            }
            walk.push((node, true));
            let current = nodes[node as usize];
            walk.push((current.right, false));
            walk.push((current.left, false));
        }

        for node in postorder {
            let left = nodes[node as usize].left;
            let right = nodes[node as usize].right;
            let left_lo = if left == NULL_NODE {
                node
            } else {
                nodes[left as usize].span_lo
            };
            let right_hi = if right == NULL_NODE {
                node + 1
            } else {
                nodes[right as usize].span_hi
            };
            let left_label = label_for_child(left, &nodes);
            let right_label = label_for_child(right, &nodes);
            nodes[node as usize].span_lo = left_lo;
            nodes[node as usize].span_hi = right_hi;
            nodes[node as usize].item_hash = item_hashes[node as usize];
            nodes[node as usize].label =
                merkle_label(&left_label, &item_hashes[node as usize], &right_label);
        }

        Ok(Self { nodes, root })
    }

    fn fingerprint(&self, begin: usize, end: usize) -> Result<Fingerprint, Error> {
        let label = self.clamped_label(self.root, begin as u32, end as u32, false, false);
        Ok(Fingerprint::from_bytes(label))
    }

    fn clamped_label(
        &self,
        node: u32,
        begin: u32,
        end: u32,
        skip_least: bool,
        skip_greatest: bool,
    ) -> [u8; FINGERPRINT_SIZE] {
        if node == NULL_NODE {
            return empty_label();
        }

        let current = self.nodes[node as usize];
        if end <= current.span_lo || begin >= current.span_hi {
            return empty_label();
        }
        if begin <= current.span_lo && current.span_hi <= end {
            return current.label;
        }
        if node < begin {
            return self.clamped_label(current.right, begin, end, skip_least, skip_greatest);
        }
        if node >= end {
            return self.clamped_label(current.left, begin, end, skip_least, skip_greatest);
        }

        let left = if skip_least {
            label_for_child(current.left, &self.nodes)
        } else {
            self.clamped_label(current.left, begin, end, false, true)
        };
        let right = if skip_greatest {
            label_for_child(current.right, &self.nodes)
        } else {
            self.clamped_label(current.right, begin, end, true, false)
        };
        merkle_label(&left, &current.item_hash, &right)
    }
}

fn label_for_child(child: u32, nodes: &[MerkleNode]) -> [u8; FINGERPRINT_SIZE] {
    if child == NULL_NODE {
        empty_label()
    } else {
        nodes[child as usize].label
    }
}

fn rank_from_hash(hash: &[u8; 32]) -> u128 {
    u128::from_be_bytes(hash[..16].try_into().expect("hash prefix has fixed length"))
}

fn rank_cmp(left: usize, right: usize, ranks: &[u128], items: &[Item]) -> Ordering {
    ranks[left]
        .cmp(&ranks[right])
        .then_with(|| items[left].cmp(&items[right]))
}

fn hash_item(item: &Item) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"negentropy-item-v1");
    hasher.update(&item.timestamp.to_be_bytes());
    hasher.update(item.id.as_ref());
    *hasher.finalize().as_bytes()
}

fn merkle_label(
    left: &[u8; FINGERPRINT_SIZE],
    item_hash: &[u8; 32],
    right: &[u8; FINGERPRINT_SIZE],
) -> [u8; FINGERPRINT_SIZE] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"negentropy-merkle-node-v1");
    hasher.update(left);
    hasher.update(item_hash);
    hasher.update(right);
    let hash = hasher.finalize();
    let mut out = [0u8; FINGERPRINT_SIZE];
    out.copy_from_slice(&hash.as_bytes()[..FINGERPRINT_SIZE]);
    out
}

fn empty_label() -> [u8; FINGERPRINT_SIZE] {
    #[cfg(feature = "std")]
    {
        static EMPTY_LABEL: OnceLock<[u8; FINGERPRINT_SIZE]> = OnceLock::new();
        return *EMPTY_LABEL.get_or_init(compute_empty_label);
    }
    #[cfg(not(feature = "std"))]
    {
        compute_empty_label()
    }
}

fn compute_empty_label() -> [u8; FINGERPRINT_SIZE] {
    let hash = blake3::hash(b"negentropy-merkle-empty-v1");
    let mut out = [0u8; FINGERPRINT_SIZE];
    out.copy_from_slice(&hash.as_bytes()[..FINGERPRINT_SIZE]);
    out
}

/// Storage
#[derive(Debug)]
pub enum Storage<'a, T: 'a> {
    /// Borrowed
    Borrowed(&'a T),
    /// Owned
    Owned(T),
}

impl<T> Deref for Storage<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Borrowed(b) => b,
            Self::Owned(b) => b,
        }
    }
}

/// NegentropyStorageBase
pub trait NegentropyStorageBase {
    /// Size
    fn size(&self) -> Result<usize, Error>;

    /// Get Item
    fn get_item(&self, i: usize) -> Result<Option<Item>, Error>;

    /// Iterate
    fn iterate(
        &self,
        begin: usize,
        end: usize,
        cb: &mut dyn FnMut(Item, usize) -> Result<bool, Error>,
    ) -> Result<(), Error>;

    /// Find Lower Bound
    fn find_lower_bound(&self, first: usize, last: usize, value: &Bound) -> usize;

    /// Fingerprint
    fn fingerprint(&self, begin: usize, end: usize) -> Result<Fingerprint, Error> {
        let mut out = Accumulator::new();

        self.iterate(begin, end, &mut |item: Item, _| {
            out.add(&item.id)?;
            Ok(true)
        })?;

        out.get_fingerprint((end - begin) as u64)
    }
}

/// Negentropy Storage Vector
#[derive(Debug, Clone, Default)]
pub struct NegentropyStorageVector {
    items: Vec<Item>,
    sealed: bool,
    tree: MerkleIntervalTree,
    fingerprint_cache: RefCell<FingerprintCache>,
}

impl NegentropyStorageVector {
    /// Create new storage
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create new storage with capacity
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            items: Vec::with_capacity(capacity),
            sealed: false,
            tree: MerkleIntervalTree::default(),
            fingerprint_cache: RefCell::new(FingerprintCache::default()),
        }
    }

    /// Insert item
    pub fn insert(&mut self, created_at: u64, id: Id) -> Result<(), Error> {
        if self.sealed {
            return Err(Error::AlreadySealed);
        }

        let elem: Item = Item::with_timestamp_and_id(created_at, id);
        self.items.push(elem);

        Ok(())
    }

    /// Seal
    pub fn seal(&mut self) -> Result<(), Error> {
        if self.sealed {
            return Err(Error::AlreadySealed);
        }
        self.items.sort();
        self.items.dedup();
        self.tree = MerkleIntervalTree::build(&self.items)?;
        self.fingerprint_cache.borrow_mut().clear();
        self.sealed = true;

        Ok(())
    }

    /// Unseal
    pub fn unseal(&mut self) -> Result<(), Error> {
        self.sealed = false;
        self.tree = MerkleIntervalTree::default();
        self.fingerprint_cache.borrow_mut().clear();
        Ok(())
    }

    fn check_sealed(&self) -> Result<(), Error> {
        if !self.sealed {
            return Err(Error::NotSealed);
        }
        Ok(())
    }

    fn check_bounds(&self, begin: usize, end: usize) -> Result<(), Error> {
        if begin > end || end > self.items.len() {
            return Err(Error::BadRange);
        }
        Ok(())
    }
}

impl NegentropyStorageBase for NegentropyStorageVector {
    fn size(&self) -> Result<usize, Error> {
        self.check_sealed()?;
        Ok(self.items.len())
    }

    fn get_item(&self, i: usize) -> Result<Option<Item>, Error> {
        self.check_sealed()?;
        Ok(self.items.get(i).copied())
    }

    fn iterate(
        &self,
        begin: usize,
        end: usize,
        cb: &mut dyn FnMut(Item, usize) -> Result<bool, Error>,
    ) -> Result<(), Error> {
        self.check_sealed()?;
        self.check_bounds(begin, end)?;

        for i in begin..end {
            if !cb(self.items[i], i)? {
                break;
            }
        }

        Ok(())
    }

    fn find_lower_bound(&self, mut first: usize, last: usize, value: &Bound) -> usize {
        let mut count: usize = last - first;

        while count > 0 {
            let mut it: usize = first;
            let step: usize = count / 2;
            it += step;

            if self.items[it] < value.item {
                it += 1;
                first = it;
                count -= step + 1;
            } else {
                count = step;
            }
        }

        first
    }

    fn fingerprint(&self, begin: usize, end: usize) -> Result<Fingerprint, Error> {
        self.check_sealed()?;
        self.check_bounds(begin, end)?;
        let key = (begin as u32, end as u32);
        if let Some(fp) = self.fingerprint_cache.borrow().get(&key).copied() {
            return Ok(fp);
        }
        let fp = self.tree.fingerprint(begin, end)?;
        self.fingerprint_cache.borrow_mut().insert(key, fp);
        Ok(fp)
    }
}

#[cfg(test)]
mod tests {
    use super::NegentropyStorageBase;
    use super::*;

    fn id(byte: u8) -> Id {
        Id::from_byte_array([byte; 32])
    }

    #[test]
    fn same_subset_yields_same_fingerprint_across_different_supersets() {
        let mut left = NegentropyStorageVector::new();
        left.insert(10, id(0x10)).unwrap();
        left.insert(20, id(0x20)).unwrap();
        left.insert(30, id(0x30)).unwrap();
        left.insert(40, id(0x40)).unwrap();
        left.insert(50, id(0x50)).unwrap();
        left.seal().unwrap();

        let mut right = NegentropyStorageVector::new();
        right.insert(5, id(0x05)).unwrap();
        right.insert(20, id(0x20)).unwrap();
        right.insert(30, id(0x30)).unwrap();
        right.insert(40, id(0x40)).unwrap();
        right.insert(60, id(0x60)).unwrap();
        right.seal().unwrap();

        let left_fp = left.fingerprint(1, 4).unwrap().to_bytes();
        let right_fp = right.fingerprint(1, 4).unwrap().to_bytes();
        assert_eq!(left_fp, right_fp);
    }

    #[test]
    fn different_subsets_yield_different_fingerprints() {
        let mut storage = NegentropyStorageVector::new();
        storage.insert(10, id(0x10)).unwrap();
        storage.insert(20, id(0x20)).unwrap();
        storage.insert(30, id(0x30)).unwrap();
        storage.insert(40, id(0x40)).unwrap();
        storage.insert(50, id(0x50)).unwrap();
        storage.seal().unwrap();

        let short = storage.fingerprint(1, 3).unwrap().to_bytes();
        let long = storage.fingerprint(1, 4).unwrap().to_bytes();
        assert_ne!(short, long);
    }
}
