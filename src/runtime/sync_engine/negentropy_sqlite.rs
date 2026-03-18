//! SQLite-backed negentropy storage adapter
//!
//! Implements `NegentropyStorageBase` using SQLite queries plus a block index
//! for efficient index-to-item lookups without loading all items into memory.

use negentropy::{Bound, Error as NegError, Id, Item, NegentropyStorageBase};
use rusqlite::Connection;
use std::cell::RefCell;

/// Map SQLite errors to negentropy errors
/// Since negentropy doesn't have a general error variant, we use BadRange
fn sql_err(_e: rusqlite::Error) -> NegError {
    NegError::BadRange
}

/// Block size for neg_blocks index (every Bth item is indexed)
pub const BLOCK_SIZE: usize = 4096;

/// SQLite-backed negentropy storage
///
/// Uses `neg_items` table for sorted (workspace_id, ts, id) pairs and
/// `session_blocks` as a sparse index for O(1) index-to-key lookups.
/// All queries are scoped to a single `workspace_id`.
pub struct NegentropyStorageSqlite<'a> {
    conn: &'a Connection,
    /// Workspace scope for neg_items queries
    workspace_id: String,
    ts_min: Option<i64>,
    ts_max_exclusive: Option<i64>,
    /// Cached size (computed once per sync)
    cached_size: RefCell<Option<usize>>,
    /// Item count at last rebuild — used to skip rebuild when unchanged.
    last_rebuilt_count: RefCell<Option<usize>>,
}

impl<'a> NegentropyStorageSqlite<'a> {
    /// Create a new SQLite storage adapter scoped to the given workspace.
    pub fn new(conn: &'a Connection, workspace_id: &str) -> Self {
        Self::new_with_range(conn, workspace_id, None, None)
    }

    pub fn new_with_range(
        conn: &'a Connection,
        workspace_id: &str,
        ts_min: Option<i64>,
        ts_max_exclusive: Option<i64>,
    ) -> Self {
        Self {
            conn,
            workspace_id: workspace_id.to_string(),
            ts_min,
            ts_max_exclusive,
            cached_size: RefCell::new(None),
            last_rebuilt_count: RefCell::new(None),
        }
    }

    /// Ensure the per-connection TEMP table exists for session block index.
    /// TEMP tables are connection-private — no contention between concurrent sessions.
    fn ensure_session_table(&self) -> Result<(), rusqlite::Error> {
        self.conn.execute_batch(
            "CREATE TEMP TABLE IF NOT EXISTS session_blocks (
                block_idx INTEGER PRIMARY KEY,
                ts INTEGER NOT NULL,
                id BLOB NOT NULL,
                count INTEGER NOT NULL
            )",
        )?;
        Ok(())
    }

    /// Incrementally sync new events from the events table into neg_items.
    /// Uses a rowid watermark stored in neg_meta so only new events are
    /// scanned. Call this before rebuild_blocks to ensure neg_items is fresh.
    pub fn sync_neg_items_from_events(&self) -> Result<usize, rusqlite::Error> {
        use crate::crypto::event_id_from_base64;

        let start = std::time::Instant::now();

        // Read the last synced rowid watermark
        let last_rowid: i64 = self.conn
            .query_row(
                "SELECT COALESCE((SELECT value FROM neg_meta WHERE key = 'last_neg_sync_rowid'), 0)",
                [],
                |row| row.get(0),
            )?;

        // Query new shared events (event_id is base64 text, needs Rust decode)
        let mut stmt = self.conn.prepare(
            "SELECT e.event_id, e.created_at
             FROM events e
             WHERE e.rowid > ?1
               AND e.share_scope = 'shared'"
        )?;

        let mut insert_stmt = self.conn.prepare(
            "INSERT OR IGNORE INTO neg_items (workspace_id, ts, id) VALUES (?1, ?2, ?3)"
        )?;

        let mut inserted = 0usize;
        let mut rows = stmt.query(rusqlite::params![last_rowid])?;
        while let Some(row) = rows.next()? {
            let event_id_b64: String = row.get(0)?;
            let created_at: i64 = row.get(1)?;
            if let Some(event_id) = event_id_from_base64(&event_id_b64) {
                if insert_stmt.execute(rusqlite::params![
                    &self.workspace_id,
                    created_at,
                    event_id.as_slice()
                ]).is_ok() {
                    inserted += 1;
                }
            }
        }

        // Update watermark
        if inserted > 0 {
            self.conn.execute(
                "INSERT OR REPLACE INTO neg_meta (key, value)
                 VALUES ('last_neg_sync_rowid', (SELECT COALESCE(MAX(rowid), 0) FROM events))",
                [],
            )?;
            tracing::info!(
                "sync_neg_items_from_events: {} new items in {}ms",
                inserted,
                start.elapsed().as_millis()
            );
        }

        Ok(inserted)
    }

    /// Rebuild the block index from neg_items into a per-connection TEMP table.
    ///
    /// This is O(N) but streaming and memory-flat.
    /// Call before sync when items have been inserted.
    pub fn rebuild_blocks(&self) -> Result<(), rusqlite::Error> {
        let start = std::time::Instant::now();

        // Quick check: if the item count hasn't changed since the last
        // rebuild, the block index is still valid — skip the O(N) scan.
        let current_count = self.count_items()?;
        if let Some(prev) = *self.last_rebuilt_count.borrow() {
            if current_count == prev {
                *self.cached_size.borrow_mut() = Some(current_count);
                tracing::debug!(
                    "rebuild_blocks: skipped (count unchanged at {})",
                    current_count
                );
                return Ok(());
            }
        }

        self.ensure_session_table()?;

        // Clear existing session blocks
        self.conn.execute("DELETE FROM session_blocks", [])?;

        // Single workspace-scoped scan. The trust anchor is always seeded
        // before any events are stored, so no empty-workspace_id fallback
        // is needed. This uses the (workspace_id, ts, id) primary key
        // directly — no temp B-tree sort.
        let mut stmt = self.conn.prepare(
            "SELECT ts, id
                 FROM neg_items
                 WHERE workspace_id = :workspace_id
                   AND (:ts_min IS NULL OR ts >= :ts_min)
                   AND (:ts_max IS NULL OR ts < :ts_max)
                 ORDER BY ts, id",
        )?;

        let mut insert_stmt = self.conn.prepare(
            "INSERT INTO session_blocks (block_idx, ts, id, count) VALUES (?1, ?2, ?3, ?4)",
        )?;

        let mut row_idx: usize = 0;
        let mut block_idx: usize = 0;

        let mut rows = stmt.query(rusqlite::named_params! {
            ":workspace_id": &self.workspace_id,
            ":ts_min": self.ts_min,
            ":ts_max": self.ts_max_exclusive,
        })?;
        while let Some(row) = rows.next()? {
            if row_idx % BLOCK_SIZE == 0 {
                let ts: i64 = row.get(0)?;
                let id: Vec<u8> = row.get(1)?;
                insert_stmt.execute(rusqlite::params![block_idx as i64, ts, id, row_idx as i64])?;
                block_idx += 1;
            }
            row_idx += 1;
        }

        // Update cached state
        *self.cached_size.borrow_mut() = Some(row_idx);
        *self.last_rebuilt_count.borrow_mut() = Some(row_idx);

        tracing::info!(
            "rebuild_blocks: {} items, {} blocks in {}ms",
            row_idx,
            block_idx,
            start.elapsed().as_millis()
        );

        Ok(())
    }

    /// Cheap item count for the current scope — used to detect whether a
    /// rebuild is needed without scanning all rows.
    fn count_items(&self) -> Result<usize, rusqlite::Error> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*)
             FROM neg_items
             WHERE workspace_id = :workspace_id
               AND (:ts_min IS NULL OR ts >= :ts_min)
               AND (:ts_max IS NULL OR ts < :ts_max)",
            rusqlite::named_params! {
                ":workspace_id": &self.workspace_id,
                ":ts_min": self.ts_min,
                ":ts_max": self.ts_max_exclusive,
            },
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    /// Get the (ts, id) key for a given block index
    fn get_block_start(&self, block_idx: usize) -> Result<Option<(i64, Vec<u8>)>, rusqlite::Error> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT ts, id FROM session_blocks WHERE block_idx = ?")?;

        let result = stmt.query_row([block_idx as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        });

        match result {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Convert (ts, id_blob) to negentropy Item
    fn to_item(ts: i64, id_blob: &[u8]) -> Item {
        let mut id_arr = [0u8; 32];
        let len = id_blob.len().min(32);
        id_arr[..len].copy_from_slice(&id_blob[..len]);
        Item::with_timestamp_and_id(ts as u64, Id::from_byte_array(id_arr))
    }
}

impl NegentropyStorageBase for NegentropyStorageSqlite<'_> {
    fn size(&self) -> Result<usize, NegError> {
        // Return cached size if available
        if let Some(size) = *self.cached_size.borrow() {
            return Ok(size);
        }

        // Otherwise query and cache
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*)
                 FROM neg_items
                 WHERE workspace_id = :workspace_id
                   AND (:ts_min IS NULL OR ts >= :ts_min)
                   AND (:ts_max IS NULL OR ts < :ts_max)",
                rusqlite::named_params! {
                    ":workspace_id": &self.workspace_id,
                    ":ts_min": self.ts_min,
                    ":ts_max": self.ts_max_exclusive,
                },
                |row| row.get(0),
            )
            .map_err(|e| sql_err(e))?;

        let size = count as usize;
        *self.cached_size.borrow_mut() = Some(size);
        Ok(size)
    }

    fn get_item(&self, i: usize) -> Result<Option<Item>, NegError> {
        let block_idx = i / BLOCK_SIZE;
        let offset = i % BLOCK_SIZE;

        // Get block start key
        let (block_ts, block_id) = match self.get_block_start(block_idx).map_err(|e| sql_err(e))? {
            Some(v) => v,
            None => return Ok(None), // Block doesn't exist
        };

        // Fetch item at offset within block
        let mut stmt = self
            .conn
            .prepare(
                "SELECT ts, id
                 FROM neg_items
                 WHERE workspace_id = :workspace_id
                   AND (:ts_min IS NULL OR ts >= :ts_min)
                   AND (:ts_max IS NULL OR ts < :ts_max)
                   AND (ts, id) >= (:block_ts, :block_id)
                 ORDER BY ts, id
                 LIMIT 1 OFFSET :offset",
            )
            .map_err(|e| sql_err(e))?;

        let result = stmt.query_row(
            rusqlite::named_params! {
                ":workspace_id": &self.workspace_id,
                ":ts_min": self.ts_min,
                ":ts_max": self.ts_max_exclusive,
                ":block_ts": block_ts,
                ":block_id": block_id,
                ":offset": offset as i64,
            },
            |row| {
                let ts: i64 = row.get(0)?;
                let id: Vec<u8> = row.get(1)?;
                Ok((ts, id))
            },
        );

        match result {
            Ok((ts, id)) => Ok(Some(Self::to_item(ts, &id))),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(sql_err(e)),
        }
    }

    fn iterate(
        &self,
        begin: usize,
        end: usize,
        cb: &mut dyn FnMut(Item, usize) -> Result<bool, NegError>,
    ) -> Result<(), NegError> {
        if begin >= end {
            return Ok(());
        }

        let count = end - begin;
        let block_idx = begin / BLOCK_SIZE;
        let offset_in_block = begin % BLOCK_SIZE;

        // Get block start key
        let (block_ts, block_id) = match self.get_block_start(block_idx).map_err(|e| sql_err(e))? {
            Some(v) => v,
            None => return Ok(()), // No items
        };

        // Query items starting from begin position
        let mut stmt = self
            .conn
            .prepare(
                "SELECT ts, id
                 FROM neg_items
                 WHERE workspace_id = :workspace_id
                   AND (:ts_min IS NULL OR ts >= :ts_min)
                   AND (:ts_max IS NULL OR ts < :ts_max)
                   AND (ts, id) >= (:block_ts, :block_id)
                 ORDER BY ts, id
                 LIMIT :limit OFFSET :offset",
            )
            .map_err(|e| sql_err(e))?;

        let mut rows = stmt
            .query(rusqlite::named_params! {
                ":workspace_id": &self.workspace_id,
                ":ts_min": self.ts_min,
                ":ts_max": self.ts_max_exclusive,
                ":block_ts": block_ts,
                ":block_id": block_id,
                ":limit": count as i64,
                ":offset": offset_in_block as i64,
            })
            .map_err(|e| sql_err(e))?;

        let mut idx = begin;
        while let Some(row) = rows.next().map_err(|e| sql_err(e))? {
            let ts: i64 = row.get(0).map_err(|e| sql_err(e))?;
            let id: Vec<u8> = row.get(1).map_err(|e| sql_err(e))?;

            let item = Self::to_item(ts, &id);
            if !cb(item, idx)? {
                break;
            }
            idx += 1;
        }

        Ok(())
    }

    fn find_lower_bound(&self, first: usize, last: usize, value: &Bound) -> usize {
        // Handle "infinity" bound - negentropy uses u64::MAX to mean end of items
        if value.item.timestamp >= i64::MAX as u64 {
            return last;
        }

        // Binary search using blocks for efficiency
        let target_ts = value.item.timestamp as i64;
        let target_id = value.item.id.as_bytes();

        // First, find which block contains the lower bound using block index
        let result: Result<usize, rusqlite::Error> = (|| {
            // Find the last block with start key <= target
            let mut stmt = self.conn.prepare_cached(
                "SELECT block_idx, count FROM session_blocks WHERE (ts, id) <= (?, ?) ORDER BY block_idx DESC LIMIT 1"
            )?;

            let (block_idx, block_start_count): (i64, i64) = stmt
                .query_row(rusqlite::params![target_ts, target_id.as_slice()], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .unwrap_or((0, 0));

            // Now scan within that block to find exact position
            let block_start = self
                .get_block_start(block_idx as usize)?
                .unwrap_or((0, vec![0u8; 32]));

            let mut scan_stmt = self.conn.prepare(
                "SELECT ts, id
                 FROM neg_items
                 WHERE workspace_id = :workspace_id
                   AND (:ts_min IS NULL OR ts >= :ts_min)
                   AND (:ts_max IS NULL OR ts < :ts_max)
                   AND (ts, id) >= (:block_ts, :block_id)
                 ORDER BY ts, id
                 LIMIT :limit",
            )?;

            let limit = BLOCK_SIZE + 1; // Scan at most one block plus one
            let mut rows = scan_stmt.query(rusqlite::named_params! {
                ":workspace_id": &self.workspace_id,
                ":ts_min": self.ts_min,
                ":ts_max": self.ts_max_exclusive,
                ":block_ts": block_start.0,
                ":block_id": block_start.1,
                ":limit": limit as i64,
            })?;

            let mut position = block_start_count as usize;
            while let Some(row) = rows.next()? {
                let ts: i64 = row.get(0)?;
                let id: Vec<u8> = row.get(1)?;

                let item = Self::to_item(ts, &id);
                if item >= value.item {
                    break;
                }
                position += 1;
            }

            Ok(position.max(first).min(last))
        })();

        result.unwrap_or(first)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_in_memory, schema::create_tables};

    fn insert_test_items(conn: &Connection, count: usize) {
        let mut stmt = conn
            .prepare("INSERT INTO neg_items (ts, id) VALUES (?, ?)")
            .unwrap();

        for i in 0..count {
            let ts = (i * 1000) as i64; // 1 second apart
            let mut id = [0u8; 32];
            id[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            stmt.execute(rusqlite::params![ts, id.as_slice()]).unwrap();
        }
    }

    #[test]
    fn test_size() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        insert_test_items(&conn, 100);

        let storage = NegentropyStorageSqlite::new(&conn, "");
        assert_eq!(storage.size().unwrap(), 100);
    }

    #[test]
    fn test_rebuild_blocks() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        // Insert more than one block worth
        insert_test_items(&conn, BLOCK_SIZE + 100);

        let storage = NegentropyStorageSqlite::new(&conn, "");
        storage.rebuild_blocks().unwrap();

        // Should have 2 blocks (in session_blocks TEMP table)
        let block_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM session_blocks", [], |row| row.get(0))
            .unwrap();
        assert_eq!(block_count, 2);
    }

    #[test]
    fn test_get_item() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        insert_test_items(&conn, 100);

        let storage = NegentropyStorageSqlite::new(&conn, "");
        storage.rebuild_blocks().unwrap();

        // Get first item
        let item = storage.get_item(0).unwrap().unwrap();
        assert_eq!(item.timestamp, 0);

        // Get item 50
        let item = storage.get_item(50).unwrap().unwrap();
        assert_eq!(item.timestamp, 50000);

        // Get last item
        let item = storage.get_item(99).unwrap().unwrap();
        assert_eq!(item.timestamp, 99000);
    }

    #[test]
    fn test_iterate() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        insert_test_items(&conn, 100);

        let storage = NegentropyStorageSqlite::new(&conn, "");
        storage.rebuild_blocks().unwrap();

        let mut items = Vec::new();
        storage
            .iterate(10, 20, &mut |item, idx| {
                items.push((item.timestamp, idx));
                Ok(true)
            })
            .unwrap();

        assert_eq!(items.len(), 10);
        assert_eq!(items[0], (10000, 10));
        assert_eq!(items[9], (19000, 19));
    }

    #[test]
    fn test_find_lower_bound() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        insert_test_items(&conn, 100);

        let storage = NegentropyStorageSqlite::new(&conn, "");
        storage.rebuild_blocks().unwrap();

        // Find bound for timestamp 50000 (should be index 50)
        let bound = Bound {
            item: Item::with_timestamp(50000),
            id_len: 0,
        };
        let pos = storage.find_lower_bound(0, 100, &bound);
        assert_eq!(pos, 50);
    }

    #[test]
    fn test_cross_block_iteration() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        // Insert items spanning multiple blocks
        insert_test_items(&conn, BLOCK_SIZE * 2 + 100);

        let storage = NegentropyStorageSqlite::new(&conn, "");
        storage.rebuild_blocks().unwrap();

        // Iterate across block boundary
        let start = BLOCK_SIZE - 10;
        let end = BLOCK_SIZE + 10;

        let mut items = Vec::new();
        storage
            .iterate(start, end, &mut |item, idx| {
                items.push((item.timestamp, idx));
                Ok(true)
            })
            .unwrap();

        assert_eq!(items.len(), 20);
    }

    #[test]
    fn test_same_timestamp_items() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        // Insert items with SAME timestamp but different IDs (simulates rapid event generation)
        let mut stmt = conn
            .prepare("INSERT INTO neg_items (ts, id) VALUES (?, ?)")
            .unwrap();

        let ts = 1000i64; // Same timestamp for all
        for i in 0..100 {
            let mut id = [0u8; 32];
            id[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            stmt.execute(rusqlite::params![ts, id.as_slice()]).unwrap();
        }

        let storage = NegentropyStorageSqlite::new(&conn, "");
        storage.rebuild_blocks().unwrap();

        // Verify all items are accessible
        assert_eq!(storage.size().unwrap(), 100);

        // Iterate all items
        let mut count = 0;
        storage
            .iterate(0, 100, &mut |_item, _idx| {
                count += 1;
                Ok(true)
            })
            .unwrap();
        assert_eq!(
            count, 100,
            "Should iterate all 100 items with same timestamp"
        );

        // Test find_lower_bound with items that have same ts but different id
        let mut id50 = [0u8; 32];
        id50[0..8].copy_from_slice(&50u64.to_le_bytes());
        let bound = Bound {
            item: Item::with_timestamp_and_id(1000, Id::from_byte_array(id50)),
            id_len: 32,
        };
        let pos = storage.find_lower_bound(0, 100, &bound);
        assert_eq!(pos, 50, "Should find item 50 at position 50");
    }

    #[test]
    fn test_range_filtered_storage_hot_and_cold() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        insert_test_items(&conn, 10);

        let hot = NegentropyStorageSqlite::new_with_range(&conn, "", Some(5_000), None);
        hot.rebuild_blocks().unwrap();
        assert_eq!(hot.size().unwrap(), 5);
        assert_eq!(hot.get_item(0).unwrap().unwrap().timestamp, 5_000);

        let cold = NegentropyStorageSqlite::new_with_range(&conn, "", None, Some(5_000));
        cold.rebuild_blocks().unwrap();
        assert_eq!(cold.size().unwrap(), 5);
        assert_eq!(cold.get_item(4).unwrap().unwrap().timestamp, 4_000);
    }

    /// Test that compares SQLite storage with in-memory storage
    #[test]
    fn test_compare_with_inmemory() {
        use negentropy::NegentropyStorageVector;

        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        // Insert items with same timestamp pattern as real events
        let mut stmt = conn
            .prepare("INSERT INTO neg_items (ts, id) VALUES (?, ?)")
            .unwrap();

        let mut inmem = NegentropyStorageVector::with_capacity(1000);

        // Use timestamps that cluster (like real rapid event generation)
        for i in 0..1000 {
            let ts = (i / 10) as i64; // 10 items per timestamp
            let mut id = [0u8; 32];
            id[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            stmt.execute(rusqlite::params![ts, id.as_slice()]).unwrap();
            inmem.insert(ts as u64, Id::from_byte_array(id)).unwrap();
        }
        inmem.seal().unwrap();

        let sqlite_storage = NegentropyStorageSqlite::new(&conn, "");
        sqlite_storage.rebuild_blocks().unwrap();

        // Compare sizes
        assert_eq!(sqlite_storage.size().unwrap(), inmem.size().unwrap());

        // Compare all items
        for i in 0..1000 {
            let sqlite_item = sqlite_storage.get_item(i).unwrap().unwrap();
            let inmem_item = inmem.get_item(i).unwrap().unwrap();
            assert_eq!(
                sqlite_item.timestamp, inmem_item.timestamp,
                "Timestamp mismatch at index {}",
                i
            );
            assert_eq!(sqlite_item.id, inmem_item.id, "ID mismatch at index {}", i);
        }
    }
}
