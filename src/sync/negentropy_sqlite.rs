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
/// Uses `neg_items` table for sorted (ts, id) pairs and `neg_blocks`
/// as a sparse index for O(1) index-to-key lookups.
pub struct NegentropyStorageSqlite<'a> {
    conn: &'a Connection,
    /// Cached size (computed once per sync)
    cached_size: RefCell<Option<usize>>,
}

impl<'a> NegentropyStorageSqlite<'a> {
    /// Create a new SQLite storage adapter
    pub fn new(conn: &'a Connection) -> Self {
        Self {
            conn,
            cached_size: RefCell::new(None),
        }
    }

    /// Rebuild the neg_blocks index from neg_items
    ///
    /// This is O(N) but streaming and memory-flat.
    /// Call before sync when items have been inserted.
    pub fn rebuild_blocks(&self) -> Result<(), rusqlite::Error> {
        // Clear existing blocks
        self.conn.execute("DELETE FROM neg_blocks", [])?;

        // Stream through all items and insert every BLOCK_SIZE-th one
        let mut stmt = self.conn.prepare(
            "SELECT ts, id FROM neg_items ORDER BY ts, id"
        )?;

        let mut insert_stmt = self.conn.prepare(
            "INSERT INTO neg_blocks (block_idx, ts, id, count) VALUES (?1, ?2, ?3, ?4)"
        )?;

        let mut row_idx: usize = 0;
        let mut block_idx: usize = 0;

        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            if row_idx % BLOCK_SIZE == 0 {
                let ts: i64 = row.get(0)?;
                let id: Vec<u8> = row.get(1)?;
                insert_stmt.execute(rusqlite::params![
                    block_idx as i64,
                    ts,
                    id,
                    row_idx as i64
                ])?;
                block_idx += 1;
            }
            row_idx += 1;
        }

        // Update cached size
        *self.cached_size.borrow_mut() = Some(row_idx);

        Ok(())
    }

    /// Get the (ts, id) key for a given block index
    fn get_block_start(&self, block_idx: usize) -> Result<Option<(i64, Vec<u8>)>, rusqlite::Error> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT ts, id FROM neg_blocks WHERE block_idx = ?"
        )?;

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
        let count: i64 = self.conn
            .query_row("SELECT COUNT(*) FROM neg_items", [], |row| row.get(0))
            .map_err(|e| sql_err(e))?;

        let size = count as usize;
        *self.cached_size.borrow_mut() = Some(size);
        Ok(size)
    }

    fn get_item(&self, i: usize) -> Result<Option<Item>, NegError> {
        let block_idx = i / BLOCK_SIZE;
        let offset = i % BLOCK_SIZE;

        // Get block start key
        let (block_ts, block_id) = match self.get_block_start(block_idx)
            .map_err(|e| sql_err(e))?
        {
            Some(v) => v,
            None => return Ok(None), // Block doesn't exist
        };

        // Fetch item at offset within block
        let mut stmt = self.conn.prepare_cached(
            "SELECT ts, id FROM neg_items WHERE (ts, id) >= (?, ?) ORDER BY ts, id LIMIT 1 OFFSET ?"
        ).map_err(|e| sql_err(e))?;

        let result = stmt.query_row(
            rusqlite::params![block_ts, block_id, offset as i64],
            |row| {
                let ts: i64 = row.get(0)?;
                let id: Vec<u8> = row.get(1)?;
                Ok((ts, id))
            }
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
        let (block_ts, block_id) = match self.get_block_start(block_idx)
            .map_err(|e| sql_err(e))?
        {
            Some(v) => v,
            None => return Ok(()), // No items
        };

        // Query items starting from begin position
        let mut stmt = self.conn.prepare_cached(
            "SELECT ts, id FROM neg_items WHERE (ts, id) >= (?, ?) ORDER BY ts, id LIMIT ? OFFSET ?"
        ).map_err(|e| sql_err(e))?;

        let mut rows = stmt.query(rusqlite::params![
            block_ts,
            block_id,
            count as i64,
            offset_in_block as i64
        ]).map_err(|e| sql_err(e))?;

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
        // Handle "infinity" bound - negentropy uses u64::MAX to mean "end of all items"
        // Also handle very large timestamps that would overflow when cast to i64
        if value.item.timestamp >= i64::MAX as u64 {
            return last;
        }

        let target_ts = value.item.timestamp as i64;
        let target_id = value.item.id.as_bytes();

        // First, find which block contains the lower bound using block index
        let result: Result<usize, rusqlite::Error> = (|| {
            // Find the last block with start key <= target
            let mut stmt = self.conn.prepare_cached(
                "SELECT block_idx, count FROM neg_blocks WHERE (ts, id) <= (?, ?) ORDER BY block_idx DESC LIMIT 1"
            )?;

            let block_result: Option<(i64, i64)> = stmt.query_row(
                rusqlite::params![target_ts, target_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?))
            ).ok();

            let (block_idx, block_start_count) = match block_result {
                Some((idx, count)) => (idx as usize, count as usize),
                None => {
                    // No block found <= target, so target is before all items
                    // Return first position
                    return Ok(first);
                }
            };

            // Get the block start key
            let block_start = match self.get_block_start(block_idx)? {
                Some(v) => v,
                None => return Ok(first),
            };

            // Scan from block start with bounded limit to avoid full tail scan
            // Limit to remaining items from block_start_count to last
            let scan_limit = (last - block_start_count).min(BLOCK_SIZE * 2) + 1;
            let mut scan_stmt = self.conn.prepare_cached(
                "SELECT ts, id FROM neg_items WHERE (ts, id) >= (?, ?) ORDER BY ts, id LIMIT ?"
            )?;

            let mut rows = scan_stmt.query(rusqlite::params![
                block_start.0,
                block_start.1,
                scan_limit as i64,
            ])?;

            let mut position = block_start_count;
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
        let mut stmt = conn.prepare(
            "INSERT INTO neg_items (ts, id) VALUES (?, ?)"
        ).unwrap();

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

        let storage = NegentropyStorageSqlite::new(&conn);
        assert_eq!(storage.size().unwrap(), 100);
    }

    #[test]
    fn test_rebuild_blocks() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        // Insert more than one block worth
        insert_test_items(&conn, BLOCK_SIZE + 100);

        let storage = NegentropyStorageSqlite::new(&conn);
        storage.rebuild_blocks().unwrap();

        // Should have 2 blocks
        let block_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM neg_blocks", [], |row| row.get(0)
        ).unwrap();
        assert_eq!(block_count, 2);
    }

    #[test]
    fn test_get_item() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        insert_test_items(&conn, 100);

        let storage = NegentropyStorageSqlite::new(&conn);
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

        let storage = NegentropyStorageSqlite::new(&conn);
        storage.rebuild_blocks().unwrap();

        let mut items = Vec::new();
        storage.iterate(10, 20, &mut |item, idx| {
            items.push((item.timestamp, idx));
            Ok(true)
        }).unwrap();

        assert_eq!(items.len(), 10);
        assert_eq!(items[0], (10000, 10));
        assert_eq!(items[9], (19000, 19));
    }

    #[test]
    fn test_find_lower_bound() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        insert_test_items(&conn, 100);

        let storage = NegentropyStorageSqlite::new(&conn);
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

        let storage = NegentropyStorageSqlite::new(&conn);
        storage.rebuild_blocks().unwrap();

        // Iterate across block boundary
        let start = BLOCK_SIZE - 10;
        let end = BLOCK_SIZE + 10;

        let mut items = Vec::new();
        storage.iterate(start, end, &mut |item, idx| {
            items.push((item.timestamp, idx));
            Ok(true)
        }).unwrap();

        assert_eq!(items.len(), 20);
    }

    #[test]
    fn test_same_timestamp_items() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        // Insert items with SAME timestamp but different IDs (simulates rapid event generation)
        let mut stmt = conn.prepare(
            "INSERT INTO neg_items (ts, id) VALUES (?, ?)"
        ).unwrap();

        let ts = 1000i64; // Same timestamp for all
        for i in 0..100 {
            let mut id = [0u8; 32];
            id[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            stmt.execute(rusqlite::params![ts, id.as_slice()]).unwrap();
        }

        let storage = NegentropyStorageSqlite::new(&conn);
        storage.rebuild_blocks().unwrap();

        // Verify all items are accessible
        assert_eq!(storage.size().unwrap(), 100);

        // Iterate all items
        let mut count = 0;
        storage.iterate(0, 100, &mut |_item, _idx| {
            count += 1;
            Ok(true)
        }).unwrap();
        assert_eq!(count, 100, "Should iterate all 100 items with same timestamp");

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
        let mut stmt = conn.prepare(
            "INSERT INTO neg_items (ts, id) VALUES (?, ?)"
        ).unwrap();

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

        let sqlite_storage = NegentropyStorageSqlite::new(&conn);
        sqlite_storage.rebuild_blocks().unwrap();

        // Compare sizes
        assert_eq!(sqlite_storage.size().unwrap(), inmem.size().unwrap());

        // Compare all items
        for i in 0..1000 {
            let sqlite_item = sqlite_storage.get_item(i).unwrap().unwrap();
            let inmem_item = inmem.get_item(i).unwrap().unwrap();
            assert_eq!(
                sqlite_item.timestamp, inmem_item.timestamp,
                "Timestamp mismatch at index {}", i
            );
            assert_eq!(
                sqlite_item.id, inmem_item.id,
                "ID mismatch at index {}", i
            );
        }
    }

    /// Test fingerprint computation - does iterate() return consistent results?
    #[test]
    fn test_fingerprint_iterate_all() {
        use negentropy::NegentropyStorageVector;

        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let mut inmem = NegentropyStorageVector::new();
        let mut stmt = conn.prepare("INSERT INTO neg_items (ts, id) VALUES (?, ?)").unwrap();

        // Storage B pattern
        for i in 0..5000u64 {
            let ts = 1000 + i / 10;
            let mut id = [0u8; 32];
            id[0] = 0x01;
            id[1..9].copy_from_slice(&i.to_le_bytes());
            inmem.insert(ts, Id::from_byte_array(id)).unwrap();
            stmt.execute(rusqlite::params![ts as i64, id.as_slice()]).unwrap();
        }
        drop(stmt);
        inmem.seal().unwrap();

        let sqlite = NegentropyStorageSqlite::new(&conn);
        sqlite.rebuild_blocks().unwrap();

        // Iterate all items and compute a simple "fingerprint" (XOR of all ids)
        let mut inmem_xor = [0u8; 32];
        let mut inmem_count = 0;
        inmem.iterate(0, 5000, &mut |item, _idx| {
            for (i, b) in item.id.as_bytes().iter().enumerate() {
                inmem_xor[i] ^= b;
            }
            inmem_count += 1;
            Ok(true)
        }).unwrap();

        let mut sqlite_xor = [0u8; 32];
        let mut sqlite_count = 0;
        sqlite.iterate(0, 5000, &mut |item, _idx| {
            for (i, b) in item.id.as_bytes().iter().enumerate() {
                sqlite_xor[i] ^= b;
            }
            sqlite_count += 1;
            Ok(true)
        }).unwrap();

        println!("InMem iterate count: {}", inmem_count);
        println!("SQLite iterate count: {}", sqlite_count);
        println!("InMem XOR: {:02x?}", &inmem_xor[0..8]);
        println!("SQLite XOR: {:02x?}", &sqlite_xor[0..8]);

        assert_eq!(inmem_count, sqlite_count, "Iterate count mismatch");
        assert_eq!(inmem_xor, sqlite_xor, "Fingerprint mismatch");
    }

    /// Test which storage has the bug by mixing in-memory and SQLite
    #[test]
    fn test_mixed_storage_reconciliation() {
        use negentropy::{Negentropy, NegentropyStorageVector, Storage};

        // Build all 4 storages
        let mut inmem_a = NegentropyStorageVector::new();
        let mut inmem_b = NegentropyStorageVector::new();

        let conn_a = open_in_memory().unwrap();
        create_tables(&conn_a).unwrap();
        let conn_b = open_in_memory().unwrap();
        create_tables(&conn_b).unwrap();

        let mut stmt_a = conn_a.prepare("INSERT INTO neg_items (ts, id) VALUES (?, ?)").unwrap();
        let mut stmt_b = conn_b.prepare("INSERT INTO neg_items (ts, id) VALUES (?, ?)").unwrap();

        for i in 0..5000u64 {
            let ts_a = i / 10;
            let mut id_a = [0u8; 32];
            id_a[0] = 0x00;
            id_a[1..9].copy_from_slice(&i.to_le_bytes());
            inmem_a.insert(ts_a, Id::from_byte_array(id_a)).unwrap();
            stmt_a.execute(rusqlite::params![ts_a as i64, id_a.as_slice()]).unwrap();

            let ts_b = 1000 + i / 10;
            let mut id_b = [0u8; 32];
            id_b[0] = 0x01;
            id_b[1..9].copy_from_slice(&i.to_le_bytes());
            inmem_b.insert(ts_b, Id::from_byte_array(id_b)).unwrap();
            stmt_b.execute(rusqlite::params![ts_b as i64, id_b.as_slice()]).unwrap();
        }
        drop(stmt_a);
        drop(stmt_b);
        inmem_a.seal().unwrap();
        inmem_b.seal().unwrap();

        let sqlite_a = NegentropyStorageSqlite::new(&conn_a);
        sqlite_a.rebuild_blocks().unwrap();
        let sqlite_b = NegentropyStorageSqlite::new(&conn_b);
        sqlite_b.rebuild_blocks().unwrap();

        // Test 1: InMem A + SQLite B
        {
            let mut neg_a = Negentropy::owned(inmem_a.clone(), 64 * 1024).unwrap();
            let mut neg_b = Negentropy::new(Storage::Borrowed(&sqlite_b), 64 * 1024).unwrap();

            let mut have: Vec<Id> = Vec::new();
            let mut need: Vec<Id> = Vec::new();

            let msg = neg_a.initiate().unwrap();
            let mut response = neg_b.reconcile(&msg).unwrap();
            while !response.is_empty() {
                match neg_a.reconcile_with_ids(&response, &mut have, &mut need).unwrap() {
                    Some(next) => response = neg_b.reconcile(&next).unwrap(),
                    None => break,
                }
            }
            let have: std::collections::HashSet<_> = have.into_iter().collect();
            let need: std::collections::HashSet<_> = need.into_iter().collect();
            println!("InMem_A + SQLite_B: have={}, need={}", have.len(), need.len());
        }

        // Test 2: SQLite A + InMem B
        {
            let mut neg_a = Negentropy::new(Storage::Borrowed(&sqlite_a), 64 * 1024).unwrap();
            let mut neg_b = Negentropy::owned(inmem_b.clone(), 64 * 1024).unwrap();

            let mut have: Vec<Id> = Vec::new();
            let mut need: Vec<Id> = Vec::new();

            let msg = neg_a.initiate().unwrap();
            let mut response = neg_b.reconcile(&msg).unwrap();
            while !response.is_empty() {
                match neg_a.reconcile_with_ids(&response, &mut have, &mut need).unwrap() {
                    Some(next) => response = neg_b.reconcile(&next).unwrap(),
                    None => break,
                }
            }
            let have: std::collections::HashSet<_> = have.into_iter().collect();
            let need: std::collections::HashSet<_> = need.into_iter().collect();
            println!("SQLite_A + InMem_B: have={}, need={}", have.len(), need.len());
        }
    }

    /// Test block boundary operations directly
    #[test]
    fn test_block_boundary_operations() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        // Create storage B pattern
        let mut stmt = conn.prepare("INSERT INTO neg_items (ts, id) VALUES (?, ?)").unwrap();
        for i in 0..5000u64 {
            let ts = (1000 + i / 10) as i64;
            let mut id = [0u8; 32];
            id[0] = 0x01;
            id[1..9].copy_from_slice(&i.to_le_bytes());
            stmt.execute(rusqlite::params![ts, id.as_slice()]).unwrap();
        }
        drop(stmt);

        let storage = NegentropyStorageSqlite::new(&conn);
        storage.rebuild_blocks().unwrap();

        println!("Size: {}", storage.size().unwrap());

        // Check block info
        let block0: (i64, Vec<u8>, i64) = conn.query_row(
            "SELECT ts, id, count FROM neg_blocks WHERE block_idx = 0", [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        ).unwrap();
        println!("Block 0: ts={}, id[0..4]={:02x?}, count={}", block0.0, &block0.1[0..4], block0.2);

        let block1: Option<(i64, Vec<u8>, i64)> = conn.query_row(
            "SELECT ts, id, count FROM neg_blocks WHERE block_idx = 1", [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        ).ok();
        if let Some(b1) = &block1 {
            println!("Block 1: ts={}, id[0..4]={:02x?}, count={}", b1.0, &b1.1[0..4], b1.2);
        } else {
            println!("Block 1: NOT FOUND");
        }

        // Test get_item at block boundary
        let item_4095 = storage.get_item(4095).unwrap().unwrap();
        let item_4096 = storage.get_item(4096).unwrap().unwrap();
        let item_4097 = storage.get_item(4097).unwrap().unwrap();

        println!("Item 4095: ts={}", item_4095.timestamp);
        println!("Item 4096: ts={}", item_4096.timestamp);
        println!("Item 4097: ts={}", item_4097.timestamp);

        // Test iterate across block boundary
        let mut items_boundary: Vec<u64> = Vec::new();
        storage.iterate(4094, 4098, &mut |item, _idx| {
            items_boundary.push(item.timestamp);
            Ok(true)
        }).unwrap();
        println!("Iterate 4094-4098: {:?}", items_boundary);
        assert_eq!(items_boundary.len(), 4, "Should iterate 4 items across boundary");

        // Test find_lower_bound for item at 4096
        let bound_4096 = Bound {
            item: item_4096.clone(),
            id_len: 32,
        };
        let pos = storage.find_lower_bound(0, 5000, &bound_4096);
        println!("find_lower_bound for item 4096: {}", pos);
        assert_eq!(pos, 4096, "Should find position 4096");
    }

    /// Debug test: compare fingerprints from SQLite vs in-memory storage
    #[test]
    fn test_fingerprint_comparison() {
        use negentropy::{Negentropy, NegentropyStorageVector, Storage};

        // Create storage B pattern (timestamps 1000+)
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let mut inmem = NegentropyStorageVector::new();
        let mut stmt = conn.prepare("INSERT INTO neg_items (ts, id) VALUES (?, ?)").unwrap();

        for i in 0..5000u64 {
            let ts = 1000 + i / 10;
            let mut id = [0u8; 32];
            id[0] = 0x01;
            id[1..9].copy_from_slice(&i.to_le_bytes());

            stmt.execute(rusqlite::params![ts as i64, id.as_slice()]).unwrap();
            inmem.insert(ts, Id::from_byte_array(id)).unwrap();
        }
        drop(stmt);
        inmem.seal().unwrap();

        let sqlite_storage = NegentropyStorageSqlite::new(&conn);
        sqlite_storage.rebuild_blocks().unwrap();

        // Compare sizes
        assert_eq!(sqlite_storage.size().unwrap(), inmem.size().unwrap(), "Size mismatch");

        // Compare items at critical positions
        for pos in [0, 1, 4095, 4096, 4097, 4999] {
            let sqlite_item = sqlite_storage.get_item(pos).unwrap().unwrap();
            let inmem_item = inmem.get_item(pos).unwrap().unwrap();

            if sqlite_item.timestamp != inmem_item.timestamp || sqlite_item.id != inmem_item.id {
                println!("MISMATCH at position {}", pos);
                println!("  SQLite: ts={}, id={:02x?}", sqlite_item.timestamp, &sqlite_item.id.as_bytes()[0..8]);
                println!("  InMem:  ts={}, id={:02x?}", inmem_item.timestamp, &inmem_item.id.as_bytes()[0..8]);
                panic!("Item mismatch at position {}", pos);
            }
        }

        // Create negentropy instances and get initial fingerprints
        let mut neg_sqlite = Negentropy::new(Storage::Borrowed(&sqlite_storage), 64 * 1024).unwrap();
        let mut neg_inmem = Negentropy::owned(inmem, 64 * 1024).unwrap();

        let msg_sqlite = neg_sqlite.initiate().unwrap();
        let msg_inmem = neg_inmem.initiate().unwrap();

        // The initial messages should be identical if the storages are equivalent
        if msg_sqlite != msg_inmem {
            println!("Initial messages differ!");
            println!("  SQLite msg len: {}", msg_sqlite.len());
            println!("  InMem msg len:  {}", msg_inmem.len());
            // This might be OK due to different internal state, but let's see
        }

        println!("Test passed - SQLite and in-memory storage produce consistent items");
    }

    /// Test find_lower_bound with offset timestamps (like storage B)
    #[test]
    fn test_find_lower_bound_offset_timestamps() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        // Insert items with timestamps starting at 1000
        let mut stmt = conn.prepare("INSERT INTO neg_items (ts, id) VALUES (?, ?)").unwrap();

        for i in 0..5000u64 {
            let ts = (1000 + i / 10) as i64; // Timestamps 1000-1499
            let mut id = [0u8; 32];
            id[0] = 0x01;
            id[1..9].copy_from_slice(&i.to_le_bytes());
            stmt.execute(rusqlite::params![ts, id.as_slice()]).unwrap();
        }
        drop(stmt);

        let storage = NegentropyStorageSqlite::new(&conn);
        storage.rebuild_blocks().unwrap();

        // Test find_lower_bound for a timestamp BEFORE all items (should return 0)
        let bound_before = Bound {
            item: Item::with_timestamp(500), // Before all items
            id_len: 0,
        };
        let pos = storage.find_lower_bound(0, 5000, &bound_before);
        assert_eq!(pos, 0, "Bound before all items should return 0");

        // Test find_lower_bound for a timestamp AFTER all items (should return 5000)
        let bound_after = Bound {
            item: Item::with_timestamp(2000), // After all items
            id_len: 0,
        };
        let pos = storage.find_lower_bound(0, 5000, &bound_after);
        assert_eq!(pos, 5000, "Bound after all items should return 5000");

        // Test find_lower_bound for timestamp 1000 (first item)
        let bound_first = Bound {
            item: Item::with_timestamp(1000),
            id_len: 0,
        };
        let pos = storage.find_lower_bound(0, 5000, &bound_first);
        assert_eq!(pos, 0, "Bound at first timestamp should return 0");

        // Test find_lower_bound at the block boundary (index 4096)
        // Get the actual item at index 4096 to use as bound
        let item_4096 = storage.get_item(4096).unwrap().unwrap();
        println!("Item at 4096: ts={}, id={:02x?}", item_4096.timestamp, &item_4096.id.as_bytes()[0..8]);

        let bound_4096 = Bound {
            item: item_4096,
            id_len: 32,
        };
        let pos = storage.find_lower_bound(0, 5000, &bound_4096);
        println!("find_lower_bound for item 4096 returned: {}", pos);
        assert_eq!(pos, 4096, "Bound at block boundary should return 4096");
    }

    /// Test find_lower_bound with items from a different storage (simulates reconciliation)
    #[test]
    fn test_find_lower_bound_cross_storage() {
        use negentropy::NegentropyStorageVector;

        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        // Storage B: timestamps 1000+
        let mut stmt = conn.prepare("INSERT INTO neg_items (ts, id) VALUES (?, ?)").unwrap();
        for i in 0..5000u64 {
            let ts = (1000 + i / 10) as i64;
            let mut id = [0u8; 32];
            id[0] = 0x01;
            id[1..9].copy_from_slice(&i.to_le_bytes());
            stmt.execute(rusqlite::params![ts, id.as_slice()]).unwrap();
        }
        drop(stmt);

        let sqlite_b = NegentropyStorageSqlite::new(&conn);
        sqlite_b.rebuild_blocks().unwrap();

        // Storage A: timestamps 0-499 (completely before B)
        let mut inmem_a = NegentropyStorageVector::new();
        for i in 0..5000u64 {
            let ts = i / 10;
            let mut id = [0u8; 32];
            id[0] = 0x00;
            id[1..9].copy_from_slice(&i.to_le_bytes());
            inmem_a.insert(ts, Id::from_byte_array(id)).unwrap();
        }
        inmem_a.seal().unwrap();

        // Test: find_lower_bound in B for various items from A
        // All A items should have lower_bound = 0 (before all B items)
        for test_idx in [0, 100, 2000, 4000, 4095, 4096, 4999] {
            let item_a = inmem_a.get_item(test_idx).unwrap().unwrap();
            let bound = Bound {
                item: item_a.clone(),
                id_len: 32,
            };
            let pos = sqlite_b.find_lower_bound(0, 5000, &bound);

            // A's items have ts 0-499, B's items have ts 1000-1499
            // So all A items should map to position 0 in B (before everything)
            assert_eq!(pos, 0,
                "Item from A at idx {} (ts={}) should have lower_bound 0 in B, got {}",
                test_idx, item_a.timestamp, pos);
        }

        // Test: find_lower_bound in B for items from B itself
        for test_idx in [0, 100, 2000, 4000, 4095, 4096, 4097, 4999] {
            let item_b = sqlite_b.get_item(test_idx).unwrap().unwrap();
            let bound = Bound {
                item: item_b.clone(),
                id_len: 32,
            };
            let pos = sqlite_b.find_lower_bound(0, 5000, &bound);

            if pos != test_idx {
                println!("MISMATCH: find_lower_bound for B's item {} returned {}", test_idx, pos);
                println!("  Item: ts={}, id[0..4]={:02x?}", item_b.timestamp, &item_b.id.as_bytes()[0..4]);
            }
            assert_eq!(pos, test_idx,
                "Item from B at idx {} should have lower_bound {} in B, got {}",
                test_idx, test_idx, pos);
        }

        println!("test_find_lower_bound_cross_storage PASSED");
    }

    /// Test iterate returns same items as get_item across block boundary
    #[test]
    fn test_iterate_vs_get_item_across_boundary() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        // Insert 5000 items with storage B pattern
        let mut stmt = conn.prepare("INSERT INTO neg_items (ts, id) VALUES (?, ?)").unwrap();
        for i in 0..5000u64 {
            let ts = (1000 + i / 10) as i64;
            let mut id = [0u8; 32];
            id[0] = 0x01;
            id[1..9].copy_from_slice(&i.to_le_bytes());
            stmt.execute(rusqlite::params![ts, id.as_slice()]).unwrap();
        }
        drop(stmt);

        let storage = NegentropyStorageSqlite::new(&conn);
        storage.rebuild_blocks().unwrap();

        // Test iterate(4090, 4100) - crosses block boundary at 4096
        let mut iterate_items: Vec<(u64, [u8; 32])> = Vec::new();
        storage.iterate(4090, 4100, &mut |item, idx| {
            let mut id_arr = [0u8; 32];
            id_arr.copy_from_slice(item.id.as_bytes());
            iterate_items.push((item.timestamp, id_arr));
            assert!(idx >= 4090 && idx < 4100, "idx {} out of range", idx);
            Ok(true)
        }).unwrap();

        assert_eq!(iterate_items.len(), 10, "Should get 10 items from iterate");

        // Compare with get_item
        for i in 0..10 {
            let get_item_result = storage.get_item(4090 + i).unwrap().unwrap();
            let (iter_ts, iter_id) = &iterate_items[i];

            if get_item_result.timestamp != *iter_ts {
                println!("MISMATCH at index {}: get_item ts={}, iterate ts={}",
                    4090 + i, get_item_result.timestamp, iter_ts);
            }
            assert_eq!(get_item_result.timestamp, *iter_ts,
                "Timestamp mismatch at index {}", 4090 + i);
            assert_eq!(get_item_result.id.as_bytes(), iter_id,
                "ID mismatch at index {}", 4090 + i);
        }

        // Also test iterate(4096, 4100) - starts exactly at block boundary
        let mut iterate_items2: Vec<(u64, [u8; 32])> = Vec::new();
        storage.iterate(4096, 4100, &mut |item, _idx| {
            let mut id_arr = [0u8; 32];
            id_arr.copy_from_slice(item.id.as_bytes());
            iterate_items2.push((item.timestamp, id_arr));
            Ok(true)
        }).unwrap();

        assert_eq!(iterate_items2.len(), 4, "Should get 4 items");
        for i in 0..4 {
            let get_item_result = storage.get_item(4096 + i).unwrap().unwrap();
            assert_eq!(get_item_result.timestamp, iterate_items2[i].0,
                "Boundary start: ts mismatch at index {}", 4096 + i);
        }

        println!("test_iterate_vs_get_item_across_boundary PASSED");
    }

    /// Test iterate across block boundary with offset timestamps
    #[test]
    fn test_iterate_offset_timestamps() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        // Insert items with timestamps starting at 1000 (like storage B in reconciliation test)
        let mut stmt = conn.prepare("INSERT INTO neg_items (ts, id) VALUES (?, ?)").unwrap();

        for i in 0..5000u64 {
            let ts = (1000 + i / 10) as i64; // Timestamps 1000-1499
            let mut id = [0u8; 32];
            id[0] = 0x01;
            id[1..9].copy_from_slice(&i.to_le_bytes());
            stmt.execute(rusqlite::params![ts, id.as_slice()]).unwrap();
        }
        drop(stmt);

        let storage = NegentropyStorageSqlite::new(&conn);
        storage.rebuild_blocks().unwrap();

        assert_eq!(storage.size().unwrap(), 5000);

        // Test iterate over entire range
        let mut count = 0;
        storage.iterate(0, 5000, &mut |_item, idx| {
            count += 1;
            assert_eq!(idx, count - 1, "Index mismatch");
            Ok(true)
        }).unwrap();

        assert_eq!(count, 5000, "Should iterate all 5000 items");

        // Test iterate across block boundary
        let mut items_across_boundary = Vec::new();
        storage.iterate(4090, 4100, &mut |item, idx| {
            items_across_boundary.push((item.timestamp, idx));
            Ok(true)
        }).unwrap();

        assert_eq!(items_across_boundary.len(), 10, "Should get 10 items across block boundary");
    }

    /// Test SQLite storage reconciliation at various scales
    fn run_reconciliation_test(count: u64) -> (usize, usize, u32) {
        use negentropy::{Negentropy, Storage};

        let conn_a = open_in_memory().unwrap();
        create_tables(&conn_a).unwrap();
        let conn_b = open_in_memory().unwrap();
        create_tables(&conn_b).unwrap();

        // Insert items into each storage with disjoint datasets
        let mut stmt_a = conn_a.prepare("INSERT INTO neg_items (ts, id) VALUES (?, ?)").unwrap();
        let mut stmt_b = conn_b.prepare("INSERT INTO neg_items (ts, id) VALUES (?, ?)").unwrap();

        for i in 0..count {
            let ts_a = i / 100;
            let mut id_a = [0u8; 32];
            id_a[0] = 0x00;
            id_a[1..9].copy_from_slice(&i.to_le_bytes());
            stmt_a.execute(rusqlite::params![ts_a as i64, id_a.as_slice()]).unwrap();

            let ts_b = 100000 + i / 100;
            let mut id_b = [0u8; 32];
            id_b[0] = 0x01;
            id_b[1..9].copy_from_slice(&i.to_le_bytes());
            stmt_b.execute(rusqlite::params![ts_b as i64, id_b.as_slice()]).unwrap();
        }
        drop(stmt_a);
        drop(stmt_b);

        let sqlite_a = NegentropyStorageSqlite::new(&conn_a);
        sqlite_a.rebuild_blocks().unwrap();
        let sqlite_b = NegentropyStorageSqlite::new(&conn_b);
        sqlite_b.rebuild_blocks().unwrap();

        // Run reconciliation
        let mut neg_a = Negentropy::new(Storage::Borrowed(&sqlite_a), 64 * 1024).unwrap();
        let mut neg_b = Negentropy::new(Storage::Borrowed(&sqlite_b), 64 * 1024).unwrap();

        let mut have: Vec<Id> = Vec::new();
        let mut need: Vec<Id> = Vec::new();

        let msg = neg_a.initiate().unwrap();
        let mut response = neg_b.reconcile(&msg).unwrap();
        let mut rounds = 1u32;

        while !response.is_empty() {
            match neg_a.reconcile_with_ids(&response, &mut have, &mut need).unwrap() {
                Some(next) => {
                    response = neg_b.reconcile(&next).unwrap();
                    rounds += 1;
                }
                None => break,
            }
        }

        let have: std::collections::HashSet<_> = have.into_iter().collect();
        let need: std::collections::HashSet<_> = need.into_iter().collect();

        (have.len(), need.len(), rounds)
    }

    #[test]
    #[ignore] // Run with: cargo test --release test_reconciliation_50k -- --ignored --nocapture
    fn test_reconciliation_50k() {
        let (have, need, rounds) = run_reconciliation_test(50_000);
        println!("50k reconciliation: {} rounds, have={}, need={}", rounds, have, need);
        assert_eq!(have, 50_000);
        assert_eq!(need, 50_000);
    }

    #[test]
    #[ignore] // Run with: cargo test --release test_reconciliation_200k -- --ignored --nocapture
    fn test_reconciliation_200k() {
        let start = std::time::Instant::now();
        let (have, need, rounds) = run_reconciliation_test(200_000);
        let elapsed = start.elapsed();
        println!("200k reconciliation: {} rounds, have={}, need={} in {:?}", rounds, have, need, elapsed);
        assert_eq!(have, 200_000);
        assert_eq!(need, 200_000);
    }

    #[test]
    #[ignore] // Run with: cargo test --release test_reconciliation_500k -- --ignored --nocapture
    fn test_reconciliation_500k() {
        let start = std::time::Instant::now();
        let (have, need, rounds) = run_reconciliation_test(500_000);
        let elapsed = start.elapsed();
        println!("500k reconciliation: {} rounds, have={}, need={} in {:?}", rounds, have, need, elapsed);
        assert_eq!(have, 500_000);
        assert_eq!(need, 500_000);
    }

    /// Test negentropy reconciliation with SQLite storage vs in-memory
    /// This simulates the real scenario: two disjoint sets being reconciled
    #[test]
    fn test_reconciliation_sqlite_vs_inmemory() {
        use negentropy::{Negentropy, NegentropyStorageVector, Storage};

        // Create two disjoint datasets (like server and client)
        // Set A: timestamps 0-999, ids starting with 0x00
        // Set B: timestamps 1000-1999, ids starting with 0x01

        // Build in-memory storages
        let mut inmem_a = NegentropyStorageVector::new();
        let mut inmem_b = NegentropyStorageVector::new();

        for i in 0..5000u64 {
            let ts_a = i / 10; // Clustered timestamps
            let mut id_a = [0u8; 32];
            id_a[0] = 0x00;
            id_a[1..9].copy_from_slice(&i.to_le_bytes());
            inmem_a.insert(ts_a, Id::from_byte_array(id_a)).unwrap();

            let ts_b = 1000 + i / 10; // Later timestamps
            let mut id_b = [0u8; 32];
            id_b[0] = 0x01;
            id_b[1..9].copy_from_slice(&i.to_le_bytes());
            inmem_b.insert(ts_b, Id::from_byte_array(id_b)).unwrap();
        }
        inmem_a.seal().unwrap();
        inmem_b.seal().unwrap();

        // Build SQLite storages
        let conn_a = open_in_memory().unwrap();
        create_tables(&conn_a).unwrap();
        let conn_b = open_in_memory().unwrap();
        create_tables(&conn_b).unwrap();

        let mut stmt_a = conn_a.prepare("INSERT INTO neg_items (ts, id) VALUES (?, ?)").unwrap();
        let mut stmt_b = conn_b.prepare("INSERT INTO neg_items (ts, id) VALUES (?, ?)").unwrap();

        for i in 0..5000u64 {
            let ts_a = (i / 10) as i64;
            let mut id_a = [0u8; 32];
            id_a[0] = 0x00;
            id_a[1..9].copy_from_slice(&i.to_le_bytes());
            stmt_a.execute(rusqlite::params![ts_a, id_a.as_slice()]).unwrap();

            let ts_b = (1000 + i / 10) as i64;
            let mut id_b = [0u8; 32];
            id_b[0] = 0x01;
            id_b[1..9].copy_from_slice(&i.to_le_bytes());
            stmt_b.execute(rusqlite::params![ts_b, id_b.as_slice()]).unwrap();
        }
        drop(stmt_a);
        drop(stmt_b);

        let sqlite_a = NegentropyStorageSqlite::new(&conn_a);
        sqlite_a.rebuild_blocks().unwrap();
        let sqlite_b = NegentropyStorageSqlite::new(&conn_b);
        sqlite_b.rebuild_blocks().unwrap();

        // Run reconciliation with in-memory storage
        let mut neg_inmem_a = Negentropy::owned(inmem_a, 64 * 1024).unwrap();
        let mut neg_inmem_b = Negentropy::owned(inmem_b, 64 * 1024).unwrap();

        let mut have_inmem: Vec<Id> = Vec::new();
        let mut need_inmem: Vec<Id> = Vec::new();

        let msg = neg_inmem_a.initiate().unwrap();
        let mut response = neg_inmem_b.reconcile(&msg).unwrap();
        let mut rounds = 1;

        while !response.is_empty() {
            match neg_inmem_a.reconcile_with_ids(&response, &mut have_inmem, &mut need_inmem).unwrap() {
                Some(next) => {
                    response = neg_inmem_b.reconcile(&next).unwrap();
                    rounds += 1;
                }
                None => break,
            }
        }

        // Deduplicate
        let have_inmem: std::collections::HashSet<_> = have_inmem.into_iter().collect();
        let need_inmem: std::collections::HashSet<_> = need_inmem.into_iter().collect();

        println!("In-memory reconciliation: {} rounds, {} have, {} need",
            rounds, have_inmem.len(), need_inmem.len());

        // Run reconciliation with SQLite storage
        let mut neg_sqlite_a = Negentropy::new(Storage::Borrowed(&sqlite_a), 64 * 1024).unwrap();
        let mut neg_sqlite_b = Negentropy::new(Storage::Borrowed(&sqlite_b), 64 * 1024).unwrap();

        let mut have_sqlite: Vec<Id> = Vec::new();
        let mut need_sqlite: Vec<Id> = Vec::new();

        let msg = neg_sqlite_a.initiate().unwrap();
        let mut response = neg_sqlite_b.reconcile(&msg).unwrap();
        rounds = 1;

        println!("SQLite round {}: msg len={}, response len={}", rounds, msg.len(), response.len());

        while !response.is_empty() {
            match neg_sqlite_a.reconcile_with_ids(&response, &mut have_sqlite, &mut need_sqlite).unwrap() {
                Some(next) => {
                    response = neg_sqlite_b.reconcile(&next).unwrap();
                    rounds += 1;
                    println!("SQLite round {}: have={}, need={}, next len={}, response len={}",
                        rounds, have_sqlite.len(), need_sqlite.len(), next.len(), response.len());
                }
                None => {
                    println!("SQLite reconciliation done: have={}, need={}", have_sqlite.len(), need_sqlite.len());
                    break;
                }
            }
        }

        // Deduplicate
        let have_sqlite: std::collections::HashSet<_> = have_sqlite.into_iter().collect();
        let need_sqlite: std::collections::HashSet<_> = need_sqlite.into_iter().collect();

        println!("SQLite reconciliation: {} rounds, {} have (unique), {} need (unique)",
            rounds, have_sqlite.len(), need_sqlite.len());

        // Both should find all 5000 items on each side
        assert_eq!(have_inmem.len(), 5000, "In-memory should find 5000 have");
        assert_eq!(need_inmem.len(), 5000, "In-memory should find 5000 need");
        assert_eq!(have_sqlite.len(), 5000, "SQLite should find 5000 have");

        // Find which items are missing from SQLite need
        let missing: Vec<_> = need_inmem.difference(&need_sqlite).collect();
        if !missing.is_empty() {
            println!("Missing {} items from SQLite need:", missing.len());
            // Show a few examples
            for (i, id) in missing.iter().take(10).enumerate() {
                let ts = id.as_bytes()[1] as u64 | ((id.as_bytes()[2] as u64) << 8);
                println!("  {}: id[0..4]={:02x?}, reconstructed i ~= {}", i, &id.as_bytes()[0..4], ts * 10);
            }

            // Check the range of missing items
            let mut min_i = u64::MAX;
            let mut max_i = 0u64;
            for id in &missing {
                let bytes = id.as_bytes();
                let i = u64::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8]]);
                min_i = min_i.min(i);
                max_i = max_i.max(i);
            }
            println!("Missing items range: i = {} to {}", min_i, max_i);
        }

        assert_eq!(need_sqlite.len(), 5000, "SQLite should find 5000 need");
    }
}
