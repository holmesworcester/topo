use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use blake3::Hasher;
use negentropy::{Bound, Fingerprint, Id, Item, NegentropyStorageBase};
use rusqlite::{params, Connection, OptionalExtension, Result as SqliteResult};

use crate::crypto::EventId;
use crate::runtime::sync_engine::session::windowing::SyncWindow;

const EMPTY_LABEL_DOMAIN: &[u8] = b"negentropy-merkle-empty-v1";
const ITEM_HASH_DOMAIN: &[u8] = b"negentropy-item-v1";
const NODE_LABEL_DOMAIN: &[u8] = b"negentropy-merkle-node-v1";
const ID_LEN: usize = 32;
const LABEL_LEN: usize = negentropy::FINGERPRINT_SIZE;
const RANK_LEN: usize = 16;
const PENDING_REBUILD_THRESHOLD: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct NodeKey {
    ts: i64,
    id: [u8; ID_LEN],
}

#[derive(Debug, Clone)]
struct NodeRecord {
    key: NodeKey,
    rank: [u8; RANK_LEN],
    item_hash: [u8; ID_LEN],
    label: [u8; LABEL_LEN],
    subtree_size: usize,
    left: Option<NodeKey>,
    right: Option<NodeKey>,
}

#[derive(Debug, Clone, Copy, Default)]
struct RootRecord {
    root: Option<NodeKey>,
    node_count: usize,
    generation: u64,
    dirty: bool,
}

#[derive(Debug)]
pub struct SharedEventMerkleStorage {
    root: Option<NodeKey>,
    global_begin: usize,
    global_end: usize,
    node_count: usize,
    nodes: HashMap<NodeKey, NodeRecord>,
    items: Vec<Item>,
    fingerprint_cache: RefCell<HashMap<(usize, usize), Fingerprint>>,
}

#[derive(Debug)]
struct WorkspaceIndexTxn<'conn> {
    conn: &'conn Connection,
    workspace_id: String,
    cache: HashMap<NodeKey, Option<NodeRecord>>,
    dirty: HashSet<NodeKey>,
    deleted: HashSet<NodeKey>,
}

impl NodeKey {
    fn to_item(self) -> Item {
        Item::with_timestamp_and_id(self.ts.max(0) as u64, Id::from_byte_array(self.id))
    }
}

impl NodeRecord {
    fn new(ts: i64, id: [u8; ID_LEN]) -> Self {
        let key = NodeKey { ts, id };
        let item_hash = hash_item(ts, &id);
        let mut node = Self {
            key,
            rank: rank_from_hash(&item_hash),
            item_hash,
            label: [0u8; LABEL_LEN],
            subtree_size: 1,
            left: None,
            right: None,
        };
        node.label = merkle_label(&empty_label(), &node.item_hash, &empty_label());
        node
    }
}

impl<'conn> WorkspaceIndexTxn<'conn> {
    fn new(conn: &'conn Connection, workspace_id: &str) -> Self {
        Self {
            conn,
            workspace_id: workspace_id.to_string(),
            cache: HashMap::new(),
            dirty: HashSet::new(),
            deleted: HashSet::new(),
        }
    }

    fn get_node(&mut self, key: NodeKey) -> SqliteResult<Option<NodeRecord>> {
        if let Some(cached) = self.cache.get(&key) {
            return Ok(cached.clone());
        }

        let node = fetch_node_record(self.conn, &self.workspace_id, key)?;
        self.cache.insert(key, node.clone());
        Ok(node)
    }

    fn require_node(&mut self, key: NodeKey) -> SqliteResult<NodeRecord> {
        self.get_node(key)?
            .ok_or(rusqlite::Error::QueryReturnedNoRows)
    }

    fn child_size(&mut self, child: Option<NodeKey>) -> SqliteResult<usize> {
        match child {
            Some(key) => Ok(self.require_node(key)?.subtree_size),
            None => Ok(0),
        }
    }

    fn child_label(&mut self, child: Option<NodeKey>) -> SqliteResult<[u8; LABEL_LEN]> {
        match child {
            Some(key) => Ok(self.require_node(key)?.label),
            None => Ok(empty_label()),
        }
    }

    fn store_node(&mut self, node: NodeRecord) {
        self.deleted.remove(&node.key);
        self.dirty.insert(node.key);
        self.cache.insert(node.key, Some(node));
    }

    fn recompute_node(&mut self, key: NodeKey) -> SqliteResult<NodeRecord> {
        let mut node = self.require_node(key)?;
        let left_label = self.child_label(node.left)?;
        let right_label = self.child_label(node.right)?;
        node.subtree_size = 1 + self.child_size(node.left)? + self.child_size(node.right)?;
        node.label = merkle_label(&left_label, &node.item_hash, &right_label);
        self.store_node(node.clone());
        Ok(node)
    }

    fn priority_cmp(&mut self, left: NodeKey, right: NodeKey) -> SqliteResult<Ordering> {
        let left_node = self.require_node(left)?;
        let right_node = self.require_node(right)?;
        Ok(left_node
            .rank
            .cmp(&right_node.rank)
            .then_with(|| left.cmp(&right)))
    }

    fn rotate_right(&mut self, key: NodeKey) -> SqliteResult<NodeKey> {
        let mut root = self.require_node(key)?;
        let left_key = root.left.expect("rotate_right requires left child");
        let mut left = self.require_node(left_key)?;

        root.left = left.right;
        self.store_node(root.clone());
        self.recompute_node(root.key)?;

        left.right = Some(root.key);
        self.store_node(left.clone());
        self.recompute_node(left.key)?;
        Ok(left.key)
    }

    fn rotate_left(&mut self, key: NodeKey) -> SqliteResult<NodeKey> {
        let mut root = self.require_node(key)?;
        let right_key = root.right.expect("rotate_left requires right child");
        let mut right = self.require_node(right_key)?;

        root.right = right.left;
        self.store_node(root.clone());
        self.recompute_node(root.key)?;

        right.left = Some(root.key);
        self.store_node(right.clone());
        self.recompute_node(right.key)?;
        Ok(right.key)
    }

    fn insert_rec(&mut self, root: Option<NodeKey>, node: NodeRecord) -> SqliteResult<NodeKey> {
        match root {
            None => {
                self.store_node(node.clone());
                Ok(node.key)
            }
            Some(root_key) => {
                let mut root_node = self.require_node(root_key)?;
                match node.key.cmp(&root_key) {
                    Ordering::Equal => Ok(root_key),
                    Ordering::Less => {
                        let inserted = self.insert_rec(root_node.left, node)?;
                        root_node.left = Some(inserted);
                        self.store_node(root_node);
                        if self.priority_cmp(inserted, root_key)? == Ordering::Greater {
                            self.rotate_right(root_key)
                        } else {
                            self.recompute_node(root_key)?;
                            Ok(root_key)
                        }
                    }
                    Ordering::Greater => {
                        let inserted = self.insert_rec(root_node.right, node)?;
                        root_node.right = Some(inserted);
                        self.store_node(root_node);
                        if self.priority_cmp(inserted, root_key)? == Ordering::Greater {
                            self.rotate_left(root_key)
                        } else {
                            self.recompute_node(root_key)?;
                            Ok(root_key)
                        }
                    }
                }
            }
        }
    }

    fn flush(&mut self) -> SqliteResult<()> {
        for key in self.deleted.clone() {
            self.conn.execute(
                "DELETE FROM shared_event_merkle_nodes
                 WHERE workspace_id = ?1 AND ts = ?2 AND id = ?3",
                params![&self.workspace_id, key.ts, key.id.as_slice()],
            )?;
        }
        for key in self.dirty.clone() {
            if let Some(node) = self.cache.get(&key).and_then(|entry| entry.clone()) {
                self.conn.execute(
                    "INSERT INTO shared_event_merkle_nodes
                     (workspace_id, ts, id, rank, item_hash, label, subtree_size,
                      left_ts, left_id, right_ts, right_id)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                     ON CONFLICT(workspace_id, ts, id) DO UPDATE SET
                       rank = excluded.rank,
                       item_hash = excluded.item_hash,
                       label = excluded.label,
                       subtree_size = excluded.subtree_size,
                       left_ts = excluded.left_ts,
                       left_id = excluded.left_id,
                       right_ts = excluded.right_ts,
                       right_id = excluded.right_id",
                    params![
                        &self.workspace_id,
                        node.key.ts,
                        node.key.id.as_slice(),
                        node.rank.as_slice(),
                        node.item_hash.as_slice(),
                        node.label.as_slice(),
                        node.subtree_size as i64,
                        node.left.map(|child| child.ts),
                        node.left.map(|child| child.id.to_vec()),
                        node.right.map(|child| child.ts),
                        node.right.map(|child| child.id.to_vec()),
                    ],
                )?;
            }
        }
        Ok(())
    }
}

impl SharedEventMerkleStorage {
    pub fn load(conn: &Connection, workspace_id: &str, range: SyncWindow) -> Result<Self, String> {
        ensure_workspace_index(conn, workspace_id)
            .map_err(|e| format!("ensure shared_event_merkle index: {e}"))?;
        let root = read_root_record(conn, workspace_id)
            .map_err(|e| format!("read shared_event_merkle root: {e}"))?
            .unwrap_or_default();
        let nodes = load_workspace_nodes(conn, workspace_id)
            .map_err(|e| format!("load shared_event_merkle nodes: {e}"))?;

        let mut storage = Self {
            root: root.root,
            global_begin: 0,
            global_end: 0,
            node_count: root.node_count,
            nodes,
            items: Vec::new(),
            fingerprint_cache: RefCell::new(HashMap::new()),
        };
        let global_begin = match range.ts_min() {
            Some(ts_min) => storage
                .lower_bound_rank(Item::with_timestamp(ts_min.max(0) as u64))
                .map_err(|e| format!("compute shared_event_merkle lower bound: {e}"))?,
            None => 0,
        };
        let global_end = match range.ts_max_exclusive() {
            Some(ts_max) => storage
                .lower_bound_rank(Item::with_timestamp(ts_max.max(0) as u64))
                .map_err(|e| format!("compute shared_event_merkle upper bound: {e}"))?,
            None => root.node_count,
        };
        let mut items = Vec::with_capacity(global_end.saturating_sub(global_begin));
        storage
            .collect_items_in_range(storage.root, global_begin, global_end, 0, &mut items)
            .map_err(|e| format!("materialize shared_event_merkle items: {e}"))?;
        storage.global_begin = global_begin;
        storage.global_end = global_end;
        storage.items = items;
        Ok(storage)
    }

    fn require_node(&self, key: NodeKey) -> SqliteResult<NodeRecord> {
        self.nodes
            .get(&key)
            .cloned()
            .ok_or(rusqlite::Error::QueryReturnedNoRows)
    }

    fn child_size(&self, child: Option<NodeKey>) -> SqliteResult<usize> {
        match child {
            Some(key) => Ok(self.require_node(key)?.subtree_size),
            None => Ok(0),
        }
    }

    fn child_label(&self, child: Option<NodeKey>) -> SqliteResult<[u8; LABEL_LEN]> {
        match child {
            Some(key) => Ok(self.require_node(key)?.label),
            None => Ok(empty_label()),
        }
    }

    fn lower_bound_rank(&self, item: Item) -> SqliteResult<usize> {
        let mut current = self.root;
        let mut prefix = 0usize;
        let mut result = self.node_count;

        while let Some(key) = current {
            let node = self.require_node(key)?;
            let left_size = self.child_size(node.left)?;
            let node_item = key.to_item();
            if node_item < item {
                prefix += left_size + 1;
                current = node.right;
            } else {
                result = prefix + left_size;
                current = node.left;
            }
        }

        Ok(result)
    }

    fn collect_items_in_range(
        &self,
        node: Option<NodeKey>,
        begin: usize,
        end: usize,
        base: usize,
        out: &mut Vec<Item>,
    ) -> SqliteResult<()> {
        let Some(key) = node else {
            return Ok(());
        };
        let current = self.require_node(key)?;
        let left_size = self.child_size(current.left)?;
        let span_lo = base;
        let curr_index = base + left_size;
        let span_hi = base + current.subtree_size;

        if end <= span_lo || begin >= span_hi {
            return Ok(());
        }

        self.collect_items_in_range(current.left, begin, end, span_lo, out)?;
        if begin <= curr_index && curr_index < end {
            out.push(key.to_item());
        }
        self.collect_items_in_range(current.right, begin, end, curr_index + 1, out)
    }

    fn clamped_label(
        &self,
        node: Option<NodeKey>,
        begin: usize,
        end: usize,
        base: usize,
        skip_least: bool,
        skip_greatest: bool,
    ) -> SqliteResult<[u8; LABEL_LEN]> {
        let Some(key) = node else {
            return Ok(empty_label());
        };
        let current = self.require_node(key)?;
        let left_size = self.child_size(current.left)?;
        let span_lo = base;
        let curr_index = base + left_size;
        let span_hi = base + current.subtree_size;

        if end <= span_lo || begin >= span_hi {
            return Ok(empty_label());
        }
        if begin <= span_lo && span_hi <= end {
            return Ok(current.label);
        }
        if curr_index < begin {
            return self.clamped_label(
                current.right,
                begin,
                end,
                curr_index + 1,
                skip_least,
                skip_greatest,
            );
        }
        if curr_index >= end {
            return self.clamped_label(
                current.left,
                begin,
                end,
                span_lo,
                skip_least,
                skip_greatest,
            );
        }

        let left = if skip_least {
            self.child_label(current.left)?
        } else {
            self.clamped_label(current.left, begin, end, span_lo, false, true)?
        };
        let right = if skip_greatest {
            self.child_label(current.right)?
        } else {
            self.clamped_label(current.right, begin, end, curr_index + 1, true, false)?
        };
        Ok(merkle_label(&left, &current.item_hash, &right))
    }

    fn window_size(&self) -> usize {
        self.items.len()
    }
}

impl NegentropyStorageBase for SharedEventMerkleStorage {
    fn size(&self) -> Result<usize, negentropy::Error> {
        Ok(self.window_size())
    }

    fn get_item(&self, i: usize) -> Result<Option<Item>, negentropy::Error> {
        Ok(self.items.get(i).copied())
    }

    fn iterate(
        &self,
        begin: usize,
        end: usize,
        cb: &mut dyn FnMut(Item, usize) -> Result<bool, negentropy::Error>,
    ) -> Result<(), negentropy::Error> {
        if begin > end || end > self.window_size() {
            return Err(negentropy::Error::BadRange);
        }
        for (offset, item) in self.items[begin..end].iter().copied().enumerate() {
            if !cb(item, begin + offset)? {
                break;
            }
        }

        Ok(())
    }

    fn find_lower_bound(&self, first: usize, last: usize, value: &Bound) -> usize {
        if first >= last || last > self.window_size() {
            return first;
        }
        first + self.items[first..last].partition_point(|item| *item < value.item)
    }

    fn fingerprint(&self, begin: usize, end: usize) -> Result<Fingerprint, negentropy::Error> {
        if begin > end || end > self.window_size() {
            return Err(negentropy::Error::BadRange);
        }
        let key = (begin, end);
        if let Some(fp) = self.fingerprint_cache.borrow().get(&key).copied() {
            return Ok(fp);
        }
        let label = self
            .clamped_label(
                self.root,
                self.global_begin + begin,
                self.global_begin + end,
                0,
                false,
                false,
            )
            .map_err(|_| negentropy::Error::BadRange)?;
        let fp = fingerprint_from_bytes(label);
        self.fingerprint_cache.borrow_mut().insert(key, fp);
        Ok(fp)
    }
}

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS shared_event_merkle_nodes (
            workspace_id TEXT NOT NULL,
            ts INTEGER NOT NULL,
            id BLOB NOT NULL,
            rank BLOB NOT NULL,
            item_hash BLOB NOT NULL,
            label BLOB NOT NULL,
            subtree_size INTEGER NOT NULL,
            left_ts INTEGER,
            left_id BLOB,
            right_ts INTEGER,
            right_id BLOB,
            PRIMARY KEY (workspace_id, ts, id)
        ) WITHOUT ROWID;

        CREATE TABLE IF NOT EXISTS shared_event_merkle_roots (
            workspace_id TEXT PRIMARY KEY,
            root_ts INTEGER,
            root_id BLOB,
            node_count INTEGER NOT NULL,
            generation INTEGER NOT NULL,
            dirty INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS shared_event_merkle_pending (
            workspace_id TEXT NOT NULL,
            ts INTEGER NOT NULL,
            id BLOB NOT NULL,
            PRIMARY KEY (workspace_id, ts, id)
        ) WITHOUT ROWID;
        ",
    )?;
    Ok(())
}

pub fn insert_single(
    conn: &Connection,
    workspace_id: &str,
    ts: i64,
    event_id: &EventId,
) -> SqliteResult<()> {
    enqueue_pending_inserts(conn, workspace_id, &[(ts, *event_id)])
}

pub fn apply_batch_inserts(
    conn: &Connection,
    workspace_id: &str,
    items: &[(i64, EventId)],
) -> SqliteResult<()> {
    apply_batch_inserts_internal(conn, workspace_id, items, true)
}

pub fn enqueue_pending_inserts(
    conn: &Connection,
    workspace_id: &str,
    items: &[(i64, EventId)],
) -> SqliteResult<()> {
    if items.is_empty() {
        return Ok(());
    }
    let mut sorted = items.to_vec();
    sorted.sort_unstable_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    let mut stmt = conn.prepare(
        "INSERT OR IGNORE INTO shared_event_merkle_pending (workspace_id, ts, id)
         VALUES (?1, ?2, ?3)",
    )?;
    for (ts, event_id) in sorted {
        stmt.execute(params![workspace_id, ts, event_id.as_slice()])?;
    }
    Ok(())
}

pub fn delete_event_id(conn: &Connection, event_id: &EventId) -> SqliteResult<()> {
    let rows = matching_workspace_rows(conn, event_id)?;
    if rows.is_empty() {
        conn.execute(
            "DELETE FROM shared_event_index WHERE id = ?1",
            params![event_id.as_slice()],
        )?;
        conn.execute(
            "DELETE FROM shared_event_merkle_pending WHERE id = ?1",
            params![event_id.as_slice()],
        )?;
        return Ok(());
    }

    let mut by_workspace: HashMap<String, Vec<NodeKey>> = HashMap::new();
    for (workspace_id, key) in rows {
        by_workspace.entry(workspace_id).or_default().push(key);
    }

    conn.execute(
        "DELETE FROM shared_event_index WHERE id = ?1",
        params![event_id.as_slice()],
    )?;
    conn.execute(
        "DELETE FROM shared_event_merkle_pending WHERE id = ?1",
        params![event_id.as_slice()],
    )?;

    for (workspace_id, _) in by_workspace {
        mark_workspace_dirty(conn, &workspace_id)?;
    }
    Ok(())
}

pub fn ensure_workspace_index(conn: &Connection, workspace_id: &str) -> SqliteResult<()> {
    let root = read_root_record(conn, workspace_id)?;
    let pending_count = pending_insert_count(conn, workspace_id)?;
    match root {
        Some(record) if !record.dirty && pending_count == 0 => Ok(()),
        Some(record) if !record.dirty && pending_count <= PENDING_REBUILD_THRESHOLD => {
            let pending = load_pending_inserts(conn, workspace_id)?;
            apply_batch_inserts_internal(conn, workspace_id, &pending, false)?;
            clear_pending_inserts(conn, workspace_id)
        }
        _ => rebuild_workspace_index(conn, workspace_id),
    }
}

pub fn backfill_missing_workspace_indexes(conn: &Connection) -> SqliteResult<()> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT sei.workspace_id
         FROM shared_event_index sei
         LEFT JOIN shared_event_merkle_roots roots
           ON roots.workspace_id = sei.workspace_id
         WHERE roots.workspace_id IS NULL OR roots.dirty != 0
         ORDER BY sei.workspace_id",
    )?;
    let workspaces = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<SqliteResult<Vec<_>>>()?;
    drop(stmt);

    for workspace_id in workspaces {
        rebuild_workspace_index(conn, &workspace_id)?;
    }
    Ok(())
}

fn rebuild_workspace_index(conn: &Connection, workspace_id: &str) -> SqliteResult<()> {
    let mut stmt = conn.prepare(
        "SELECT ts, id
         FROM shared_event_index
         WHERE workspace_id = ?1
         ORDER BY ts, id",
    )?;
    let mut rows = stmt.query(params![workspace_id])?;

    let mut keys = Vec::new();
    while let Some(row) = rows.next()? {
        let ts: i64 = row.get(0)?;
        let id_blob: Vec<u8> = row.get(1)?;
        if id_blob.len() != ID_LEN {
            continue;
        }
        let mut id = [0u8; ID_LEN];
        id.copy_from_slice(&id_blob);
        keys.push(NodeKey { ts, id });
    }

    conn.execute(
        "DELETE FROM shared_event_merkle_nodes WHERE workspace_id = ?1",
        params![workspace_id],
    )?;

    if keys.is_empty() {
        write_root_record(
            conn,
            workspace_id,
            RootRecord {
                root: None,
                node_count: 0,
                generation: read_root_record(conn, workspace_id)?
                    .unwrap_or_default()
                    .generation
                    .saturating_add(1),
                dirty: false,
            },
        )?;
        clear_pending_inserts(conn, workspace_id)?;
        return Ok(());
    }

    let mut nodes = vec![
        NodeRecord {
            key: NodeKey {
                ts: 0,
                id: [0u8; ID_LEN],
            },
            rank: [0u8; RANK_LEN],
            item_hash: [0u8; ID_LEN],
            label: [0u8; LABEL_LEN],
            subtree_size: 0,
            left: None,
            right: None,
        };
        keys.len()
    ];
    let mut ranks = Vec::with_capacity(keys.len());
    for (index, key) in keys.iter().enumerate() {
        let item_hash = hash_item(key.ts, &key.id);
        let rank = rank_from_hash(&item_hash);
        ranks.push(rank);
        nodes[index] = NodeRecord {
            key: *key,
            rank,
            item_hash,
            label: [0u8; LABEL_LEN],
            subtree_size: 1,
            left: None,
            right: None,
        };
    }

    let mut stack: Vec<usize> = Vec::with_capacity(nodes.len());
    for index in 0..nodes.len() {
        let mut last = None;
        while let Some(&top) = stack.last() {
            if rank_cmp(keys[top], ranks[top], keys[index], ranks[index]) == Ordering::Greater {
                break;
            }
            last = stack.pop();
        }
        nodes[index].left = last.map(|child| keys[child]);
        if let Some(&top) = stack.last() {
            nodes[top].right = Some(keys[index]);
        }
        stack.push(index);
    }

    let root_index = stack.first().copied().expect("non-empty treap has root");
    let mut postorder = Vec::with_capacity(nodes.len());
    let mut walk = vec![(root_index, false)];
    while let Some((index, visited)) = walk.pop() {
        if visited {
            postorder.push(index);
            continue;
        }
        walk.push((index, true));
        if let Some(right) = nodes[index].right {
            let child_index = keys.binary_search(&right).expect("right child key exists");
            walk.push((child_index, false));
        }
        if let Some(left) = nodes[index].left {
            let child_index = keys.binary_search(&left).expect("left child key exists");
            walk.push((child_index, false));
        }
    }

    let by_key: HashMap<NodeKey, usize> = keys
        .iter()
        .copied()
        .enumerate()
        .map(|(index, key)| (key, index))
        .collect();
    for index in postorder {
        let left_label = nodes[index]
            .left
            .and_then(|key| by_key.get(&key).copied())
            .map(|child| nodes[child].label)
            .unwrap_or_else(empty_label);
        let right_label = nodes[index]
            .right
            .and_then(|key| by_key.get(&key).copied())
            .map(|child| nodes[child].label)
            .unwrap_or_else(empty_label);
        let left_size = nodes[index]
            .left
            .and_then(|key| by_key.get(&key).copied())
            .map(|child| nodes[child].subtree_size)
            .unwrap_or(0);
        let right_size = nodes[index]
            .right
            .and_then(|key| by_key.get(&key).copied())
            .map(|child| nodes[child].subtree_size)
            .unwrap_or(0);
        nodes[index].subtree_size = 1 + left_size + right_size;
        nodes[index].label = merkle_label(&left_label, &nodes[index].item_hash, &right_label);
    }

    let mut stmt = conn.prepare(
        "INSERT OR REPLACE INTO shared_event_merkle_nodes
         (workspace_id, ts, id, rank, item_hash, label, subtree_size,
          left_ts, left_id, right_ts, right_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
    )?;
    for node in &nodes {
        stmt.execute(params![
            workspace_id,
            node.key.ts,
            node.key.id.as_slice(),
            node.rank.as_slice(),
            node.item_hash.as_slice(),
            node.label.as_slice(),
            node.subtree_size as i64,
            node.left.map(|child| child.ts),
            node.left.map(|child| child.id.to_vec()),
            node.right.map(|child| child.ts),
            node.right.map(|child| child.id.to_vec()),
        ])?;
    }

    let generation = read_root_record(conn, workspace_id)?
        .unwrap_or_default()
        .generation
        .saturating_add(1);
    write_root_record(
        conn,
        workspace_id,
        RootRecord {
            root: Some(keys[root_index]),
            node_count: nodes.len(),
            generation,
            dirty: false,
        },
    )?;
    clear_pending_inserts(conn, workspace_id)?;
    Ok(())
}

fn apply_batch_inserts_internal(
    conn: &Connection,
    workspace_id: &str,
    items: &[(i64, EventId)],
    ensure_current: bool,
) -> SqliteResult<()> {
    if items.is_empty() {
        return Ok(());
    }
    if ensure_current {
        ensure_workspace_index(conn, workspace_id)?;
    }
    let mut root = read_root_record(conn, workspace_id)?.unwrap_or_default();
    root.dirty = true;
    write_root_record(conn, workspace_id, root)?;
    let mut writer = WorkspaceIndexTxn::new(conn, workspace_id);

    let mut sorted = items.to_vec();
    sorted.sort_unstable_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));

    for (ts, event_id) in sorted {
        let key = NodeKey { ts, id: event_id };
        if fetch_node_record(conn, workspace_id, key)?.is_some() {
            continue;
        }
        let node = NodeRecord::new(ts, event_id);
        root.root = Some(writer.insert_rec(root.root, node)?);
        root.node_count += 1;
    }
    writer.flush()?;
    root.generation = root.generation.saturating_add(1);
    root.dirty = false;
    write_root_record(conn, workspace_id, root)?;
    Ok(())
}

fn pending_insert_count(conn: &Connection, workspace_id: &str) -> SqliteResult<usize> {
    conn.query_row(
        "SELECT COUNT(*)
         FROM shared_event_merkle_pending
         WHERE workspace_id = ?1",
        params![workspace_id],
        |row| row.get::<_, i64>(0),
    )
    .map(|count| count as usize)
}

fn load_pending_inserts(
    conn: &Connection,
    workspace_id: &str,
) -> SqliteResult<Vec<(i64, EventId)>> {
    let mut stmt = conn.prepare(
        "SELECT ts, id
         FROM shared_event_merkle_pending
         WHERE workspace_id = ?1
         ORDER BY ts, id",
    )?;
    let rows = stmt.query_map(params![workspace_id], |row| {
        let ts: i64 = row.get(0)?;
        let id_blob: Vec<u8> = row.get(1)?;
        if id_blob.len() != ID_LEN {
            return Err(rusqlite::Error::InvalidColumnType(
                1,
                "shared_event_merkle_pending.id".into(),
                rusqlite::types::Type::Blob,
            ));
        }
        let mut id = [0u8; ID_LEN];
        id.copy_from_slice(&id_blob);
        Ok((ts, id))
    })?;
    rows.collect()
}

fn clear_pending_inserts(conn: &Connection, workspace_id: &str) -> SqliteResult<()> {
    conn.execute(
        "DELETE FROM shared_event_merkle_pending WHERE workspace_id = ?1",
        params![workspace_id],
    )?;
    Ok(())
}

fn mark_workspace_dirty(conn: &Connection, workspace_id: &str) -> SqliteResult<()> {
    let Some(mut root) = read_root_record(conn, workspace_id)? else {
        return Ok(());
    };
    root.dirty = true;
    write_root_record(conn, workspace_id, root)
}

fn matching_workspace_rows(
    conn: &Connection,
    event_id: &EventId,
) -> SqliteResult<Vec<(String, NodeKey)>> {
    let mut stmt = conn.prepare(
        "SELECT workspace_id, ts, id
         FROM shared_event_index
         WHERE id = ?1",
    )?;
    let rows = stmt.query_map(params![event_id.as_slice()], |row| {
        let workspace_id: String = row.get(0)?;
        let ts: i64 = row.get(1)?;
        let id_blob: Vec<u8> = row.get(2)?;
        let mut id = [0u8; ID_LEN];
        id.copy_from_slice(&id_blob);
        Ok((workspace_id, NodeKey { ts, id }))
    })?;
    rows.collect()
}

fn read_root_record(conn: &Connection, workspace_id: &str) -> SqliteResult<Option<RootRecord>> {
    conn.query_row(
        "SELECT root_ts, root_id, node_count, generation, dirty
         FROM shared_event_merkle_roots
         WHERE workspace_id = ?1",
        params![workspace_id],
        |row| {
            let root_ts: Option<i64> = row.get(0)?;
            let root_id: Option<Vec<u8>> = row.get(1)?;
            let root = match (root_ts, root_id) {
                (Some(ts), Some(id_blob)) if id_blob.len() == ID_LEN => {
                    let mut id = [0u8; ID_LEN];
                    id.copy_from_slice(&id_blob);
                    Some(NodeKey { ts, id })
                }
                _ => None,
            };
            Ok(RootRecord {
                root,
                node_count: row.get::<_, i64>(2)? as usize,
                generation: row.get::<_, i64>(3)? as u64,
                dirty: row.get::<_, i64>(4)? != 0,
            })
        },
    )
    .optional()
}

fn write_root_record(conn: &Connection, workspace_id: &str, root: RootRecord) -> SqliteResult<()> {
    conn.execute(
        "INSERT INTO shared_event_merkle_roots
         (workspace_id, root_ts, root_id, node_count, generation, dirty)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(workspace_id) DO UPDATE SET
           root_ts = excluded.root_ts,
           root_id = excluded.root_id,
           node_count = excluded.node_count,
           generation = excluded.generation,
           dirty = excluded.dirty",
        params![
            workspace_id,
            root.root.map(|key| key.ts),
            root.root.map(|key| key.id.to_vec()),
            root.node_count as i64,
            root.generation as i64,
            if root.dirty { 1 } else { 0 },
        ],
    )?;
    Ok(())
}

fn fetch_node_record(
    conn: &Connection,
    workspace_id: &str,
    key: NodeKey,
) -> SqliteResult<Option<NodeRecord>> {
    conn.query_row(
        "SELECT rank, item_hash, label, subtree_size, left_ts, left_id, right_ts, right_id
         FROM shared_event_merkle_nodes
         WHERE workspace_id = ?1 AND ts = ?2 AND id = ?3",
        params![workspace_id, key.ts, key.id.as_slice()],
        |row| {
            let rank_blob: Vec<u8> = row.get(0)?;
            let item_hash_blob: Vec<u8> = row.get(1)?;
            let label_blob: Vec<u8> = row.get(2)?;
            let left = child_from_parts(row.get(4)?, row.get(5)?)?;
            let right = child_from_parts(row.get(6)?, row.get(7)?)?;

            let mut rank = [0u8; RANK_LEN];
            rank.copy_from_slice(&rank_blob);
            let mut item_hash = [0u8; ID_LEN];
            item_hash.copy_from_slice(&item_hash_blob);
            let mut label = [0u8; LABEL_LEN];
            label.copy_from_slice(&label_blob);

            Ok(NodeRecord {
                key,
                rank,
                item_hash,
                label,
                subtree_size: row.get::<_, i64>(3)? as usize,
                left,
                right,
            })
        },
    )
    .optional()
}

fn load_workspace_nodes(
    conn: &Connection,
    workspace_id: &str,
) -> SqliteResult<HashMap<NodeKey, NodeRecord>> {
    let mut stmt = conn.prepare(
        "SELECT ts, id, rank, item_hash, label, subtree_size, left_ts, left_id, right_ts, right_id
         FROM shared_event_merkle_nodes
         WHERE workspace_id = ?1",
    )?;
    let mut rows = stmt.query(params![workspace_id])?;
    let mut nodes = HashMap::new();
    while let Some(row) = rows.next()? {
        let ts: i64 = row.get(0)?;
        let id_blob: Vec<u8> = row.get(1)?;
        if id_blob.len() != ID_LEN {
            return Err(rusqlite::Error::InvalidColumnType(
                1,
                "shared_event_merkle_nodes.id".into(),
                rusqlite::types::Type::Blob,
            ));
        }
        let mut id = [0u8; ID_LEN];
        id.copy_from_slice(&id_blob);
        let key = NodeKey { ts, id };
        let node = NodeRecord {
            key,
            rank: blob_to_array::<RANK_LEN>(row.get(2)?, "shared_event_merkle_nodes.rank")?,
            item_hash: blob_to_array::<ID_LEN>(row.get(3)?, "shared_event_merkle_nodes.item_hash")?,
            label: blob_to_array::<LABEL_LEN>(row.get(4)?, "shared_event_merkle_nodes.label")?,
            subtree_size: row.get::<_, i64>(5)? as usize,
            left: child_from_parts(row.get(6)?, row.get(7)?)?,
            right: child_from_parts(row.get(8)?, row.get(9)?)?,
        };
        nodes.insert(key, node);
    }
    Ok(nodes)
}

fn child_from_parts(ts: Option<i64>, id_blob: Option<Vec<u8>>) -> SqliteResult<Option<NodeKey>> {
    match (ts, id_blob) {
        (Some(ts), Some(id_blob)) if id_blob.len() == ID_LEN => {
            let mut id = [0u8; ID_LEN];
            id.copy_from_slice(&id_blob);
            Ok(Some(NodeKey { ts, id }))
        }
        (None, None) => Ok(None),
        _ => Err(rusqlite::Error::InvalidColumnType(
            0,
            "shared_event_merkle child".into(),
            rusqlite::types::Type::Blob,
        )),
    }
}

fn blob_to_array<const N: usize>(blob: Vec<u8>, column: &str) -> SqliteResult<[u8; N]> {
    if blob.len() != N {
        return Err(rusqlite::Error::InvalidColumnType(
            0,
            column.into(),
            rusqlite::types::Type::Blob,
        ));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&blob);
    Ok(out)
}

fn hash_item(ts: i64, id: &[u8; ID_LEN]) -> [u8; ID_LEN] {
    let mut hasher = Hasher::new();
    hasher.update(ITEM_HASH_DOMAIN);
    hasher.update(&(ts.max(0) as u64).to_be_bytes());
    hasher.update(id);
    *hasher.finalize().as_bytes()
}

fn rank_from_hash(hash: &[u8; ID_LEN]) -> [u8; RANK_LEN] {
    let mut rank = [0u8; RANK_LEN];
    rank.copy_from_slice(&hash[..RANK_LEN]);
    rank
}

fn rank_cmp(
    left_key: NodeKey,
    left_rank: [u8; RANK_LEN],
    right_key: NodeKey,
    right_rank: [u8; RANK_LEN],
) -> Ordering {
    left_rank
        .cmp(&right_rank)
        .then_with(|| left_key.cmp(&right_key))
}

fn merkle_label(
    left: &[u8; LABEL_LEN],
    item_hash: &[u8; ID_LEN],
    right: &[u8; LABEL_LEN],
) -> [u8; LABEL_LEN] {
    let mut hasher = Hasher::new();
    hasher.update(NODE_LABEL_DOMAIN);
    hasher.update(left);
    hasher.update(item_hash);
    hasher.update(right);
    let hash = hasher.finalize();
    let mut out = [0u8; LABEL_LEN];
    out.copy_from_slice(&hash.as_bytes()[..LABEL_LEN]);
    out
}

fn empty_label() -> [u8; LABEL_LEN] {
    static EMPTY: OnceLock<[u8; LABEL_LEN]> = OnceLock::new();
    *EMPTY.get_or_init(|| {
        let hash = blake3::hash(EMPTY_LABEL_DOMAIN);
        let mut out = [0u8; LABEL_LEN];
        out.copy_from_slice(&hash.as_bytes()[..LABEL_LEN]);
        out
    })
}

fn fingerprint_from_bytes(buf: [u8; LABEL_LEN]) -> Fingerprint {
    Fingerprint::from_bytes(buf)
}

#[cfg(test)]
mod tests {
    use negentropy::NegentropyStorageVector;

    use super::*;
    use crate::db::{
        open_in_memory, schema::create_tables, store::insert_shared_event_index_entry_if_shared,
    };
    use crate::event_modules::ShareScope;

    fn id(byte: u8) -> EventId {
        [byte; 32]
    }

    #[test]
    fn persisted_storage_matches_vector_fingerprints() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        ensure_schema(&conn).unwrap();

        let workspace_id = "ws-a";
        let mut vector = NegentropyStorageVector::new();
        for (ts, event_id) in [
            (10, id(0x10)),
            (20, id(0x20)),
            (30, id(0x30)),
            (40, id(0x40)),
            (50, id(0x50)),
        ] {
            insert_shared_event_index_entry_if_shared(
                &conn,
                ShareScope::Shared,
                ts,
                &event_id,
                workspace_id,
            )
            .unwrap();
            vector
                .insert(ts.max(0) as u64, Id::from_byte_array(event_id))
                .unwrap();
        }
        vector.seal().unwrap();
        let pending_before: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM shared_event_merkle_pending WHERE workspace_id = ?1",
                params![workspace_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pending_before, 5);

        let storage = SharedEventMerkleStorage::load(
            &conn,
            workspace_id,
            SyncWindow {
                kind: crate::runtime::sync_engine::session::windowing::SyncWindowKind::Full,
                ts_min_inclusive_ms: None,
                ts_max_exclusive_ms: None,
            },
        )
        .unwrap();

        assert_eq!(storage.size().unwrap(), vector.size().unwrap());
        assert_eq!(
            storage.fingerprint(1, 4).unwrap().to_bytes(),
            vector.fingerprint(1, 4).unwrap().to_bytes()
        );
        assert_eq!(
            storage.fingerprint(0, 5).unwrap().to_bytes(),
            vector.fingerprint(0, 5).unwrap().to_bytes()
        );
        assert_eq!(storage.get_item(2).unwrap(), vector.get_item(2).unwrap());
        let pending_after: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM shared_event_merkle_pending WHERE workspace_id = ?1",
                params![workspace_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pending_after, 0);
    }

    #[test]
    fn delete_updates_persisted_index() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        ensure_schema(&conn).unwrap();

        let workspace_id = "ws-a";
        for (ts, event_id) in [
            (10, id(0x10)),
            (20, id(0x20)),
            (30, id(0x30)),
            (40, id(0x40)),
        ] {
            insert_shared_event_index_entry_if_shared(
                &conn,
                ShareScope::Shared,
                ts,
                &event_id,
                workspace_id,
            )
            .unwrap();
        }

        delete_event_id(&conn, &id(0x20)).unwrap();

        let storage = SharedEventMerkleStorage::load(
            &conn,
            workspace_id,
            SyncWindow {
                kind: crate::runtime::sync_engine::session::windowing::SyncWindowKind::Full,
                ts_min_inclusive_ms: None,
                ts_max_exclusive_ms: None,
            },
        )
        .unwrap();

        assert_eq!(storage.size().unwrap(), 3);
        assert_eq!(
            storage.get_item(0).unwrap().unwrap().id,
            Id::from_byte_array(id(0x10))
        );
        assert_eq!(
            storage.get_item(1).unwrap().unwrap().id,
            Id::from_byte_array(id(0x30))
        );
    }
}
