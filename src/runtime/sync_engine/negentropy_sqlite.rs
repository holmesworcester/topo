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
    /// Cached size (computed once per sync)
    cached_size: RefCell<Option<usize>>,
}

impl<'a> NegentropyStorageSqlite<'a> {
    /// Create a new SQLite storage adapter scoped to the given workspace.
    pub fn new(conn: &'a Connection, workspace_id: &str) -> Self {
        Self {
            conn,
            workspace_id: workspace_id.to_string(),
            cached_size: RefCell::new(None),
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

    /// Rebuild the block index from neg_items into a per-connection TEMP table.
    ///
    /// This is O(N) but streaming and memory-flat.
    /// Call before sync when items have been inserted.
    pub fn rebuild_blocks(&self) -> Result<(), rusqlite::Error> {
        let start = std::time::Instant::now();
        self.ensure_session_table()?;

        // Clear existing session blocks
        self.conn.execute("DELETE FROM session_blocks", [])?;

        // Single workspace-scoped scan. The trust anchor is always seeded
        // before any events are stored, so no empty-workspace_id fallback
        // is needed. This uses the (workspace_id, ts, id) primary key
        // directly — no temp B-tree sort.
        let mut stmt = self
            .conn
            .prepare("SELECT ts, id FROM neg_items WHERE workspace_id = ?1 ORDER BY ts, id")?;

        let mut insert_stmt = self.conn.prepare(
            "INSERT INTO session_blocks (block_idx, ts, id, count) VALUES (?1, ?2, ?3, ?4)",
        )?;

        let mut row_idx: usize = 0;
        let mut block_idx: usize = 0;

        let mut rows = stmt.query(rusqlite::params![&self.workspace_id])?;
        while let Some(row) = rows.next()? {
            if row_idx % BLOCK_SIZE == 0 {
                let ts: i64 = row.get(0)?;
                let id: Vec<u8> = row.get(1)?;
                insert_stmt.execute(rusqlite::params![block_idx as i64, ts, id, row_idx as i64])?;
                block_idx += 1;
            }
            row_idx += 1;
        }

        // Update cached size
        *self.cached_size.borrow_mut() = Some(row_idx);

        tracing::info!(
            "rebuild_blocks: {} items, {} blocks in {}ms",
            row_idx,
            block_idx,
            start.elapsed().as_millis()
        );

        Ok(())
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
                "SELECT COUNT(*) FROM neg_items WHERE workspace_id = ?1",
                rusqlite::params![&self.workspace_id],
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
        let mut stmt = self.conn.prepare_cached(
            "SELECT ts, id FROM neg_items WHERE workspace_id = ?1 AND (ts, id) >= (?2, ?3) ORDER BY ts, id LIMIT 1 OFFSET ?4"
        ).map_err(|e| sql_err(e))?;

        let result = stmt.query_row(
            rusqlite::params![&self.workspace_id, block_ts, block_id, offset as i64],
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
        let mut stmt = self.conn.prepare_cached(
            "SELECT ts, id FROM neg_items WHERE workspace_id = ?1 AND (ts, id) >= (?2, ?3) ORDER BY ts, id LIMIT ?4 OFFSET ?5"
        ).map_err(|e| sql_err(e))?;

        let mut rows = stmt
            .query(rusqlite::params![
                &self.workspace_id,
                block_ts,
                block_id,
                count as i64,
                offset_in_block as i64
            ])
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

            let mut scan_stmt = self.conn.prepare_cached(
                "SELECT ts, id FROM neg_items WHERE workspace_id = ?1 AND (ts, id) >= (?2, ?3) ORDER BY ts, id LIMIT ?4"
            )?;

            let limit = BLOCK_SIZE + 1; // Scan at most one block plus one
            let mut rows = scan_stmt.query(rusqlite::params![
                &self.workspace_id,
                block_start.0,
                block_start.1,
                limit as i64
            ])?;

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
