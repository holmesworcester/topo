//! Negentropy SQLite adapter (low-memory, DB-backed)

use std::cmp::Ordering;

use tracing::{error, info};
use negentropy::{Accumulator, Bound, Fingerprint, Id, Item, NegentropyStorageBase};
use negentropy::NegentropyStorageVector;
use rusqlite::{params, Connection, Error as SqliteError, Result as SqliteResult};
use rusqlite::types::Type;

use crate::crypto::EventId;

pub const NEG_BLOCK_SIZE: usize = 1024;
pub const NEG_REBUILD_MULT: usize = 4;
pub const NEG_MAX_BYTES: usize = 1024 * 1024;

/// Resolve block size (env override `NEG_BLOCK_SIZE`)
pub fn neg_block_size() -> usize {
    std::env::var("NEG_BLOCK_SIZE")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(NEG_BLOCK_SIZE)
}

/// Rebuild threshold based on block size
pub fn neg_rebuild_threshold(block_size: usize) -> usize {
    block_size.saturating_mul(NEG_REBUILD_MULT)
}

/// Resolve negentropy max message size (env override `NEG_MAX_BYTES`)
pub fn neg_max_bytes() -> usize {
    std::env::var("NEG_MAX_BYTES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(NEG_MAX_BYTES)
}

#[derive(Default, Clone)]
struct StorageProfile {
    fingerprint_calls: u64,
    fingerprint_time_ns: u128,
    iterate_calls: u64,
    iterate_time_ns: u128,
    iterate_rows: u64,
    find_calls: u64,
    find_time_ns: u128,
    get_calls: u64,
    get_time_ns: u128,
}

static PROFILE: std::sync::OnceLock<std::sync::Mutex<StorageProfile>> = std::sync::OnceLock::new();

fn profile_enabled() -> bool {
    std::env::var("NEG_PROFILE").is_ok()
}

fn profile() -> &'static std::sync::Mutex<StorageProfile> {
    PROFILE.get_or_init(|| std::sync::Mutex::new(StorageProfile::default()))
}

pub fn reset_negentropy_profile() {
    if !profile_enabled() {
        return;
    }
    if let Ok(mut p) = profile().lock() {
        *p = StorageProfile::default();
    }
}

pub fn log_negentropy_profile(tag: &str) {
    if !profile_enabled() {
        return;
    }
    if let Ok(p) = profile().lock() {
        info!(
            "neg_profile[{}] get_calls={} get_ms={:.3} find_calls={} find_ms={:.3} iterate_calls={} iterate_rows={} iterate_ms={:.3} fp_calls={} fp_ms={:.3}",
            tag,
            p.get_calls,
            (p.get_time_ns as f64) / 1_000_000.0,
            p.find_calls,
            (p.find_time_ns as f64) / 1_000_000.0,
            p.iterate_calls,
            p.iterate_rows,
            (p.iterate_time_ns as f64) / 1_000_000.0,
            p.fingerprint_calls,
            (p.fingerprint_time_ns as f64) / 1_000_000.0
        );
    }
}

/// Convert negentropy Id to our EventId
pub fn neg_id_to_event_id(id: &Id) -> EventId {
    *id.as_bytes()
}

/// Ensure negentropy state row exists and has the expected block size.
fn ensure_negentropy_state(conn: &Connection, block_size: usize) -> SqliteResult<()> {
    conn.execute(
        "INSERT OR IGNORE INTO neg_state (id, max_ts, max_id, item_count, blocks_built_at, needs_rebuild, block_size)\
         VALUES (1, 0, zeroblob(32), 0, 0, 0, ?1)",
        params![block_size as i64],
    )?;

    let existing_block_size: i64 = conn.query_row(
        "SELECT block_size FROM neg_state WHERE id = 1",
        [],
        |row| row.get(0),
    )?;

    if existing_block_size != block_size as i64 {
        conn.execute(
            "UPDATE neg_state SET block_size = ?1, needs_rebuild = 1, blocks_built_at = 0 WHERE id = 1",
            params![block_size as i64],
        )?;
    }

    Ok(())
}

/// Batch inserter for negentropy items with minimal state updates.
pub struct NegentropyBatchInserter<'a> {
    conn: &'a Connection,
    max_ts: u64,
    max_id: [u8; 32],
    needs_rebuild: bool,
    inserted: u64,
}

impl<'a> NegentropyBatchInserter<'a> {
    pub fn new(conn: &'a Connection, block_size: usize) -> SqliteResult<Self> {
        ensure_negentropy_state(conn, block_size)?;

        let (max_ts, max_id): (i64, Vec<u8>) = conn.query_row(
            "SELECT max_ts, max_id FROM neg_state WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;

        let mut max_id_arr = [0u8; 32];
        if max_id.len() == 32 {
            max_id_arr.copy_from_slice(&max_id);
        }

        Ok(Self {
            conn,
            max_ts: max_ts as u64,
            max_id: max_id_arr,
            needs_rebuild: false,
            inserted: 0,
        })
    }

    pub fn insert(&mut self, ts: u64, id: &EventId) -> SqliteResult<()> {
        let rows = self.conn.execute(
            "INSERT OR IGNORE INTO neg_items (ts, id) VALUES (?1, ?2)",
            params![ts as i64, &id[..]],
        )?;

        if rows > 0 {
            self.inserted += rows as u64;

            match ts.cmp(&self.max_ts) {
                Ordering::Greater => {
                    self.max_ts = ts;
                    self.max_id = *id;
                }
                Ordering::Equal => {
                    if id > &self.max_id {
                        self.max_id = *id;
                    } else if id < &self.max_id {
                        self.needs_rebuild = true;
                    }
                }
                Ordering::Less => {
                    self.needs_rebuild = true;
                }
            }
        }

        Ok(())
    }

    pub fn finish(self) -> SqliteResult<()> {
        if self.inserted == 0 && !self.needs_rebuild {
            return Ok(());
        }

        let needs_rebuild = if self.needs_rebuild { 1 } else { 0 };
        self.conn.execute(
            "UPDATE neg_state
             SET max_ts = ?1, max_id = ?2, item_count = item_count + ?3,
                 needs_rebuild = CASE WHEN needs_rebuild = 1 OR ?4 = 1 THEN 1 ELSE 0 END
             WHERE id = 1",
            params![self.max_ts as i64, &self.max_id[..], self.inserted as i64, needs_rebuild],
        )?;

        Ok(())
    }
}

/// Rebuild the negentropy indices from neg_items.
fn rebuild_negentropy_index(conn: &Connection, block_size: usize) -> SqliteResult<()> {
    conn.execute("BEGIN", [])?;
    conn.execute("DELETE FROM neg_blocks", [])?;
    conn.execute("DELETE FROM neg_index", [])?;
    conn.execute("DELETE FROM neg_block_accum", [])?;

    let mut idx: usize = 0;
    let mut block_idx: i64 = 0;
    let mut last_ts: u64 = 0;
    let mut last_id: [u8; 32] = [0u8; 32];
    let mut block_accum = Accumulator::new();
    let mut block_count: u64 = 0;

    {
        let mut stmt = conn.prepare("SELECT ts, id FROM neg_items ORDER BY ts, id")?;
        let mut rows = stmt.query([])?;

        while let Some(row) = rows.next()? {
            let ts: i64 = row.get(0)?;
            let id_blob: Vec<u8> = row.get(1)?;
            let id = Id::from_slice(&id_blob)
                .map_err(|_| SqliteError::InvalidColumnType(1, "id".into(), Type::Blob))?;

            if idx % block_size == 0 {
                if idx > 0 {
                    conn.execute(
                        "INSERT INTO neg_block_accum (block_idx, count, accum) VALUES (?1, ?2, ?3)",
                        params![block_idx - 1, block_count as i64, block_accum_buf(&block_accum)],
                    )?;
                }
                conn.execute(
                    "INSERT INTO neg_blocks (block_idx, ts, id) VALUES (?1, ?2, ?3)",
                    params![block_idx, ts, id.as_bytes()],
                )?;
                block_idx += 1;
                block_accum = Accumulator::new();
                block_count = 0;
            }
            conn.execute(
                "INSERT INTO neg_index (idx, ts, id) VALUES (?1, ?2, ?3)",
                params![idx as i64, ts, id.as_bytes()],
            )?;

            let id_arr = id_to_array(&id_blob)?;
            let _ = block_accum.add(&id_arr);
            block_count += 1;

            idx += 1;
            last_ts = ts as u64;
            last_id = *id.as_bytes();
        }
    }

    if idx > 0 {
        conn.execute(
            "INSERT INTO neg_block_accum (block_idx, count, accum) VALUES (?1, ?2, ?3)",
            params![block_idx - 1, block_count as i64, block_accum_buf(&block_accum)],
        )?;
    }

    conn.execute(
        "UPDATE neg_state
         SET max_ts = ?1, max_id = ?2, item_count = ?3, blocks_built_at = ?3, needs_rebuild = 0
         WHERE id = 1",
        params![last_ts as i64, &last_id[..], idx as i64],
    )?;

    conn.execute("COMMIT", [])?;
    Ok(())
}

/// Ensure negentropy blocks are up-to-date using a delta threshold.
pub fn ensure_negentropy_index(
    conn: &Connection,
    block_size: usize,
    rebuild_threshold: usize,
) -> SqliteResult<()> {
    ensure_negentropy_state(conn, block_size)?;

    let (item_count, blocks_built_at, needs_rebuild): (i64, i64, i64) = conn.query_row(
        "SELECT item_count, blocks_built_at, needs_rebuild FROM neg_state WHERE id = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;

    let block_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM neg_block_accum",
        [],
        |row| row.get(0),
    )?;

    let delta = item_count.saturating_sub(blocks_built_at) as usize;
    let expected_blocks = if item_count == 0 {
        0
    } else {
        ((item_count as usize) + block_size - 1) / block_size
    } as i64;
    let must_rebuild = needs_rebuild != 0
        || (item_count > 0 && block_count == 0)
        || (block_count != expected_blocks)
        || delta >= rebuild_threshold;

    if must_rebuild {
        rebuild_negentropy_index(conn, block_size)?;
    }

    Ok(())
}

/// Build a NegentropyStorageVector from the SQLite index (ts, id).
/// This is a correctness-first fallback when the DB-backed adapter is not used.
pub fn build_negentropy_storage_from_db(
    conn: &Connection,
) -> Result<NegentropyStorageVector, negentropy::Error> {
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM neg_index", [], |row| row.get(0))
        .map_err(map_db_err)?;
    let mut storage = NegentropyStorageVector::with_capacity(count as usize);
    let mut stmt = conn
        .prepare("SELECT ts, id FROM neg_index ORDER BY idx")
        .map_err(map_db_err)?;
    let mut rows = stmt.query([]).map_err(map_db_err)?;
    while let Some(row) = rows.next().map_err(map_db_err)? {
        let ts: i64 = row.get(0).map_err(map_db_err)?;
        let id_blob: Vec<u8> = row.get(1).map_err(map_db_err)?;
        let id = Id::from_slice(&id_blob)?;
        if ts < 0 {
            return Err(negentropy::Error::BadRange);
        }
        storage.insert(ts as u64, id)?;
    }
    storage.seal()?;
    Ok(storage)
}

/// SQLite-backed negentropy storage.
pub struct NegentropyStorageSqlite<'a> {
    conn: &'a Connection,
    size: usize,
    block_size: usize,
}

impl<'a> NegentropyStorageSqlite<'a> {
    pub fn new(conn: &'a Connection, block_size: usize) -> Result<Self, negentropy::Error> {
        ensure_negentropy_state(conn, block_size).map_err(map_db_err)?;
        let stored_block_size: i64 = conn
            .query_row("SELECT block_size FROM neg_state WHERE id = 1", [], |row| row.get(0))
            .map_err(map_db_err)?;
        let size: i64 = conn
            .query_row("SELECT COUNT(*) FROM neg_index", [], |row| row.get(0))
            .map_err(map_db_err)?;

        Ok(Self {
            conn,
            size: size as usize,
            block_size: stored_block_size as usize,
        })
    }

    fn row_to_item(ts: i64, id_blob: Vec<u8>) -> Result<Item, negentropy::Error> {
        if ts < 0 {
            return Err(negentropy::Error::BadRange);
        }
        let id = Id::from_slice(&id_blob)?;
        Ok(Item::with_timestamp_and_id(ts as u64, id))
    }
}

impl NegentropyStorageBase for NegentropyStorageSqlite<'_> {
    fn size(&self) -> Result<usize, negentropy::Error> {
        Ok(self.size)
    }

    fn get_item(&self, i: usize) -> Result<Option<Item>, negentropy::Error> {
        if i >= self.size {
            return Ok(None);
        }
        let start = if profile_enabled() { Some(std::time::Instant::now()) } else { None };
        let row = self.conn.query_row(
            "SELECT ts, id FROM neg_index WHERE idx = ?1",
            params![i as i64],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        );
        if let Some(start) = start {
            if let Ok(mut p) = profile().lock() {
                p.get_calls += 1;
                p.get_time_ns += start.elapsed().as_nanos();
            }
        }

        match row {
            Ok((ts, id_blob)) => Ok(Some(Self::row_to_item(ts, id_blob)?)),
            Err(SqliteError::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(map_db_err(e)),
        }
    }

    fn iterate(
        &self,
        begin: usize,
        end: usize,
        cb: &mut dyn FnMut(Item, usize) -> Result<bool, negentropy::Error>,
    ) -> Result<(), negentropy::Error> {
        if begin > end || end > self.size {
            return Err(negentropy::Error::BadRange);
        }
        if begin == end {
            return Ok(());
        }

        let start = if profile_enabled() { Some(std::time::Instant::now()) } else { None };
        let mut stmt = self.conn
            .prepare(
                "SELECT ts, id FROM neg_index
                 WHERE idx >= ?1 AND idx < ?2
                 ORDER BY idx",
            )
            .map_err(map_db_err)?;

        let mut rows = stmt
            .query(params![begin as i64, end as i64])
            .map_err(map_db_err)?;

        let mut idx = begin;
        let mut rows_seen: u64 = 0;
        while let Some(row) = rows.next().map_err(map_db_err)? {
            let ts: i64 = row.get(0).map_err(map_db_err)?;
            let id_blob: Vec<u8> = row.get(1).map_err(map_db_err)?;
            let item = Self::row_to_item(ts, id_blob)?;
            if !cb(item, idx)? {
                break;
            }
            idx += 1;
            rows_seen += 1;
        }
        if let Some(start) = start {
            if let Ok(mut p) = profile().lock() {
                p.iterate_calls += 1;
                p.iterate_rows += rows_seen;
                p.iterate_time_ns += start.elapsed().as_nanos();
            }
        }

        Ok(())
    }

    fn find_lower_bound(&self, first: usize, last: usize, value: &Bound) -> usize {
        if first >= last || last > self.size {
            return first.min(self.size);
        }

        if value.item.timestamp > i64::MAX as u64 {
            return last;
        }

        let start = if profile_enabled() { Some(std::time::Instant::now()) } else { None };
        let row = self.conn.query_row(
            "SELECT idx FROM neg_index
             WHERE (ts > ?1) OR (ts = ?1 AND id >= ?2)
             ORDER BY ts, id
             LIMIT 1",
            params![value.item.timestamp as i64, value.item.id.as_bytes()],
            |row| row.get::<_, i64>(0),
        );
        if let Some(start) = start {
            if let Ok(mut p) = profile().lock() {
                p.find_calls += 1;
                p.find_time_ns += start.elapsed().as_nanos();
            }
        }

        match row {
            Ok(idx) => {
                let idx = idx as usize;
                if idx < first { first } else if idx > last { last } else { idx }
            }
            Err(SqliteError::QueryReturnedNoRows) => last,
            Err(e) => {
                error!("Negentropy lower_bound query failed: {e}");
                first
            }
        }
    }

    fn fingerprint(&self, begin: usize, end: usize) -> Result<Fingerprint, negentropy::Error> {
        if begin > end || end > self.size {
            return Err(negentropy::Error::BadRange);
        }

        let start = if profile_enabled() { Some(std::time::Instant::now()) } else { None };

        let mut accum = Accumulator::new();
        let mut count: u64 = 0;

        if begin == end {
            let fp = accum.get_fingerprint(0)?;
            if let Some(start) = start {
                if let Ok(mut p) = profile().lock() {
                    p.fingerprint_calls += 1;
                    p.fingerprint_time_ns += start.elapsed().as_nanos();
                }
            }
            return Ok(fp);
        }

        let block_size = self.block_size.max(1);
        let start_block = begin / block_size;
        let end_block = (end - 1) / block_size;

        if start_block == end_block {
            accumulate_range(self.conn, begin, end, &mut accum, &mut count)?;
        } else {
            let left_end = (start_block + 1) * block_size;
            accumulate_range(self.conn, begin, left_end.min(end), &mut accum, &mut count)?;

            if start_block + 1 <= end_block.saturating_sub(1) {
                let mut stmt = self.conn
                    .prepare(
                        "SELECT count, accum FROM neg_block_accum
                         WHERE block_idx >= ?1 AND block_idx <= ?2
                         ORDER BY block_idx",
                    )
                    .map_err(map_db_err)?;
                let mut rows = stmt
                    .query(params![ (start_block + 1) as i64, (end_block - 1) as i64 ])
                    .map_err(map_db_err)?;
                while let Some(row) = rows.next().map_err(map_db_err)? {
                    let cnt: i64 = row.get(0).map_err(map_db_err)?;
                    let accum_blob: Vec<u8> = row.get(1).map_err(map_db_err)?;
                    let accum_arr = id_to_array(&accum_blob).map_err(map_db_err)?;
                    accum.add(&accum_arr)?;
                    if cnt > 0 {
                        count += cnt as u64;
                    }
                }
            }

            let right_start = end_block * block_size;
            accumulate_range(self.conn, right_start, end, &mut accum, &mut count)?;
        }

        let fp = accum.get_fingerprint(count)?;

        if let Some(start) = start {
            if let Ok(mut p) = profile().lock() {
                p.fingerprint_calls += 1;
                p.fingerprint_time_ns += start.elapsed().as_nanos();
            }
        }

        Ok(fp)
    }
}

fn map_db_err(err: SqliteError) -> negentropy::Error {
    error!("Negentropy SQLite error: {err}");
    negentropy::Error::BadRange
}

fn accumulate_range(
    conn: &Connection,
    from: usize,
    to: usize,
    accum: &mut Accumulator,
    count: &mut u64,
) -> Result<(), negentropy::Error> {
    if from >= to {
        return Ok(());
    }
    let mut stmt = conn
        .prepare(
            "SELECT id FROM neg_index
             WHERE idx >= ?1 AND idx < ?2
             ORDER BY idx",
        )
        .map_err(map_db_err)?;
    let mut rows = stmt
        .query(params![from as i64, to as i64])
        .map_err(map_db_err)?;
    while let Some(row) = rows.next().map_err(map_db_err)? {
        let id_blob: Vec<u8> = row.get(0).map_err(map_db_err)?;
        let id_arr = id_to_array(&id_blob).map_err(map_db_err)?;
        accum.add(&id_arr)?;
        *count += 1;
    }
    Ok(())
}

fn id_to_array(blob: &[u8]) -> Result<[u8; 32], SqliteError> {
    if blob.len() != 32 {
        return Err(SqliteError::InvalidColumnType(1, "id".into(), Type::Blob));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(blob);
    Ok(out)
}

fn block_accum_buf(accum: &Accumulator) -> Vec<u8> {
    let bytes = (*accum).to_bytes();
    bytes.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash_event;
    use crate::db::{open_in_memory, schema::create_tables};

    #[test]
    fn test_sqlite_storage_basic() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let mut inserter = NegentropyBatchInserter::new(&conn, 4).unwrap();
        for i in 0..10u64 {
            let blob = format!("blob-{i}").into_bytes();
            let id = hash_event(&blob);
            inserter.insert(1000 + i, &id).unwrap();
        }
        inserter.finish().unwrap();

        ensure_negentropy_index(&conn, 4, 1).unwrap();
        let storage = NegentropyStorageSqlite::new(&conn, 4).unwrap();

        assert_eq!(storage.size().unwrap(), 10);
        let item = storage.get_item(0).unwrap().unwrap();
        assert_eq!(item.timestamp, 1000);
    }

    #[test]
    fn test_sqlite_storage_reconcile_disjoint_sets() {
        use negentropy::Negentropy;
        use negentropy::NegentropyStorageVector;
        use negentropy::NegentropyStorageBase;
        use crate::crypto::hash_event;

        let conn_a = open_in_memory().unwrap();
        let conn_b = open_in_memory().unwrap();
        create_tables(&conn_a).unwrap();
        create_tables(&conn_b).unwrap();

        let mut ins_a = NegentropyBatchInserter::new(&conn_a, 8).unwrap();
        let mut ins_b = NegentropyBatchInserter::new(&conn_b, 8).unwrap();

        for i in 0..100u64 {
            let id_a = hash_event(format!("a-{i}").as_bytes());
            let id_b = hash_event(format!("b-{i}").as_bytes());
            ins_a.insert(1000 + i, &id_a).unwrap();
            ins_b.insert(2000 + i, &id_b).unwrap();
        }
        ins_a.finish().unwrap();
        ins_b.finish().unwrap();

        ensure_negentropy_index(&conn_a, 8, 1).unwrap();
        ensure_negentropy_index(&conn_b, 8, 1).unwrap();

        let storage_a = NegentropyStorageSqlite::new(&conn_a, 8).unwrap();
        let storage_b = NegentropyStorageSqlite::new(&conn_b, 8).unwrap();
        let fp_a = storage_a.fingerprint(0, storage_a.size().unwrap()).unwrap();
        let fp_b = storage_b.fingerprint(0, storage_b.size().unwrap()).unwrap();

        let mut neg_a = Negentropy::borrowed(&storage_a, 64 * 1024).unwrap();
        let mut neg_b = Negentropy::borrowed(&storage_b, 64 * 1024).unwrap();

        let mut have_ids = Vec::new();
        let mut need_ids = Vec::new();

        // Compare with in-memory vector storage to validate correctness.
        let mut vec_a = NegentropyStorageVector::with_capacity(100);
        let mut vec_b = NegentropyStorageVector::with_capacity(100);
        let mut vec_b_items: Vec<Item> = Vec::with_capacity(100);
        let mut vec_a_items: Vec<Item> = Vec::with_capacity(100);
        let mut stmt = conn_a.prepare("SELECT ts, id FROM neg_items ORDER BY ts, id").unwrap();
        let rows = stmt.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))).unwrap();
        for row in rows.flatten() {
            let (ts, id_blob) = row;
            let id = Id::from_slice(&id_blob).unwrap();
            vec_a_items.push(Item::with_timestamp_and_id(ts as u64, id));
            vec_a.insert(ts as u64, id).unwrap();
        }
        let mut stmt = conn_b.prepare("SELECT ts, id FROM neg_items ORDER BY ts, id").unwrap();
        let rows = stmt.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))).unwrap();
        for row in rows.flatten() {
            let (ts, id_blob) = row;
            let id = Id::from_slice(&id_blob).unwrap();
            vec_b_items.push(Item::with_timestamp_and_id(ts as u64, id));
            vec_b.insert(ts as u64, id).unwrap();
        }
        vec_a.seal().unwrap();
        vec_b.seal().unwrap();
        let fp_a_vec = vec_a.fingerprint(0, vec_a.size().unwrap()).unwrap();
        let fp_b_vec = vec_b.fingerprint(0, vec_b.size().unwrap()).unwrap();

        // Exhaustively verify iterate matches expected items for all ranges.
        let size_a = storage_a.size().unwrap();
        for begin in 0..size_a {
            for end in begin..=size_a {
                let mut out: Vec<Item> = Vec::new();
                storage_a.iterate(begin, end, &mut |item, _| {
                    out.push(item);
                    Ok(true)
                }).unwrap();
                let expected = &vec_a_items[begin..end];
                if out != expected {
                    panic!("iterate mismatch at range {}..{}", begin, end);
                }

                let fp_sql = storage_a.fingerprint(begin, end).unwrap();
                let fp_vec = vec_a.fingerprint(begin, end).unwrap();
                if fp_sql.to_bytes() != fp_vec.to_bytes() {
                    panic!("fingerprint mismatch at range {}..{}", begin, end);
                }
            }
        }

        let size_b = storage_b.size().unwrap();
        for begin in 0..size_b {
            for end in begin..=size_b {
                let mut out: Vec<Item> = Vec::new();
                storage_b.iterate(begin, end, &mut |item, _| {
                    out.push(item);
                    Ok(true)
                }).unwrap();
                let expected = &vec_b_items[begin..end];
                if out != expected {
                    panic!("iterate mismatch (b) at range {}..{}", begin, end);
                }

                let fp_sql = storage_b.fingerprint(begin, end).unwrap();
                let fp_vec = vec_b.fingerprint(begin, end).unwrap();
                if fp_sql.to_bytes() != fp_vec.to_bytes() {
                    panic!("fingerprint mismatch (b) at range {}..{}", begin, end);
                }
            }
        }

        // Verify find_lower_bound matches vector behavior for all adjacent bounds.
        for idx in 1..vec_a_items.len() {
            let prev = vec_a_items[idx - 1];
            let curr = vec_a_items[idx];
            let bound = if curr.timestamp != prev.timestamp {
                Bound::with_timestamp(curr.timestamp)
            } else {
                let mut shared = 0usize;
                for i in 0..32 {
                    if prev.id.as_bytes()[i] != curr.id.as_bytes()[i] {
                        break;
                    }
                    shared += 1;
                }
                Bound::with_timestamp_and_id(curr.timestamp, &curr.id.as_bytes()[..shared + 1]).unwrap()
            };
            for first in 0..size_a {
                for last in first..=size_a {
                    let got = storage_a.find_lower_bound(first, last, &bound);
                    let mut expected = first;
                    while expected < last && vec_a_items[expected] < bound.item {
                        expected += 1;
                    }
                    if got != expected {
                        panic!("lower_bound mismatch (a): got {} expected {} for range {}..{}", got, expected, first, last);
                    }
                }
            }
        }
        for idx in 1..vec_b_items.len() {
            let prev = vec_b_items[idx - 1];
            let curr = vec_b_items[idx];
            let bound = if curr.timestamp != prev.timestamp {
                Bound::with_timestamp(curr.timestamp)
            } else {
                let mut shared = 0usize;
                for i in 0..32 {
                    if prev.id.as_bytes()[i] != curr.id.as_bytes()[i] {
                        break;
                    }
                    shared += 1;
                }
                Bound::with_timestamp_and_id(curr.timestamp, &curr.id.as_bytes()[..shared + 1]).unwrap()
            };
            for first in 0..size_b {
                for last in first..=size_b {
                    let got = storage_b.find_lower_bound(first, last, &bound);
                    let mut expected = first;
                    while expected < last && vec_b_items[expected] < bound.item {
                        expected += 1;
                    }
                    if got != expected {
                        panic!("lower_bound mismatch (b): got {} expected {} for range {}..{}", got, expected, first, last);
                    }
                }
            }
        }

        // Bounds derived from storage A should also be handled correctly by storage B.
        for idx in 1..vec_a_items.len() {
            let prev = vec_a_items[idx - 1];
            let curr = vec_a_items[idx];
            let bound = if curr.timestamp != prev.timestamp {
                Bound::with_timestamp(curr.timestamp)
            } else {
                let mut shared = 0usize;
                for i in 0..32 {
                    if prev.id.as_bytes()[i] != curr.id.as_bytes()[i] {
                        break;
                    }
                    shared += 1;
                }
                Bound::with_timestamp_and_id(curr.timestamp, &curr.id.as_bytes()[..shared + 1]).unwrap()
            };
            for first in 0..size_b {
                for last in first..=size_b {
                    let got = storage_b.find_lower_bound(first, last, &bound);
                    let mut expected = first;
                    while expected < last && vec_b_items[expected] < bound.item {
                        expected += 1;
                    }
                    if got != expected {
                        panic!("lower_bound mismatch (b vs a-bound): got {} expected {} for range {}..{}", got, expected, first, last);
                    }
                }
            }
        }

        let mut neg_a_vec = Negentropy::owned(vec_a, 64 * 1024).unwrap();
        let mut neg_b_vec = Negentropy::owned(vec_b, 64 * 1024).unwrap();

        // Compare initial messages and first responses.
        let msg_sql = neg_a.initiate().unwrap();
        let msg_vec = neg_a_vec.initiate().unwrap();
        if msg_sql != msg_vec {
            panic!("initial message mismatch: sql_len {} vec_len {}", msg_sql.len(), msg_vec.len());
        }

        // Inspect how storage_b evaluates the initiator message.
        {
            fn get_bytes<'a>(encoded: &'a mut &[u8], n: usize) -> &'a [u8] {
                let res: &[u8] = &encoded[..n];
                *encoded = encoded.get(n..).unwrap_or_default();
                res
            }

            fn get_byte_array<const N: usize>(encoded: &mut &[u8]) -> [u8; N] {
                let bytes = get_bytes(encoded, N);
                let mut out = [0u8; N];
                out.copy_from_slice(bytes);
                out
            }

            fn decode_var_int(encoded: &mut &[u8]) -> u64 {
                let mut res = 0u64;
                for byte in encoded.iter() {
                    *encoded = &encoded[1..];
                    res = (res << 7) | (*byte as u64 & 0b0111_1111);
                    if (byte & 0b1000_0000) == 0 {
                        break;
                    }
                }
                res
            }

            let mut q: &[u8] = &msg_sql;
            let _ver = get_byte_array::<1>(&mut q);
            let mut last_ts: u64 = 0;
            let mut prev_index: usize = 0;
            let mut matches: usize = 0;
            let mut total: usize = 0;
            while !q.is_empty() {
                // decode bound (timestamp delta + id prefix)
                let ts_delta = decode_var_int(&mut q);
                let mut ts = if ts_delta == 0 { u64::MAX } else { ts_delta - 1 };
                ts = ts.saturating_add(last_ts);
                last_ts = ts;
                let id_len = decode_var_int(&mut q) as usize;
                let id_bytes = get_bytes(&mut q, id_len);
                let mut id = [0u8; 32];
                id[..id_len].copy_from_slice(id_bytes);
                let bound = Bound::with_timestamp_and_id(ts, &id[..id_len]).unwrap_or_else(|_| Bound::with_timestamp(ts));

                let mode = decode_var_int(&mut q);
                let upper = storage_b.find_lower_bound(prev_index, storage_b.size().unwrap(), &bound);
                if mode == 1 {
                    let their_fp = get_byte_array::<16>(&mut q);
                    let our_fp = storage_b.fingerprint(prev_index, upper).unwrap().to_bytes();
                    if our_fp == their_fp {
                        matches += 1;
                    }
                    total += 1;
                } else if mode == 2 {
                    let num_ids = decode_var_int(&mut q) as usize;
                    for _ in 0..num_ids {
                        let _ = get_byte_array::<32>(&mut q);
                    }
                }
                prev_index = upper;
            }
            let _ = (matches, total);
        }

        let resp_sql = neg_b.reconcile(&msg_sql).unwrap();
        let resp_vec = neg_b_vec.reconcile(&msg_vec).unwrap();
        if resp_sql != resp_vec {
            panic!("resp mismatch: sql_len {} vec_len {}", resp_sql.len(), resp_vec.len());
        }
        let mut have_ids_vec = Vec::new();
        let mut need_ids_vec = Vec::new();
        let mut msg = msg_vec;
        let mut last_resp_vec = resp_vec;
        loop {
            match neg_a_vec.reconcile_with_ids(&last_resp_vec, &mut have_ids_vec, &mut need_ids_vec).unwrap() {
                Some(next) => {
                    msg = next;
                    last_resp_vec = neg_b_vec.reconcile(&msg).unwrap();
                }
                None => break,
            }
        }

        assert_eq!(have_ids_vec.len(), 100);
        assert_eq!(need_ids_vec.len(), 100);
        assert_eq!(fp_a.to_bytes(), fp_a_vec.to_bytes());
        assert_eq!(fp_b.to_bytes(), fp_b_vec.to_bytes());

        let mut msg = msg_sql;
        let mut last_resp = resp_sql;
        loop {
            match neg_a.reconcile_with_ids(&last_resp, &mut have_ids, &mut need_ids).unwrap() {
                Some(next) => {
                    msg = next;
                    last_resp = neg_b.reconcile(&msg).unwrap();
                }
                None => break,
            }
        }

        if have_ids.len() != have_ids_vec.len() || need_ids.len() != need_ids_vec.len() {
            use std::collections::HashSet;
            let have_set: HashSet<Id> = have_ids.iter().copied().collect();
            let have_vec_set: HashSet<Id> = have_ids_vec.iter().copied().collect();
            let missing: Vec<Id> = have_vec_set.difference(&have_set).copied().collect();
            panic!("sqlite mismatch: have {} vs {}, need {} vs {}, missing have {:?}",
                have_ids.len(), have_ids_vec.len(), need_ids.len(), need_ids_vec.len(), missing.len());
        }
    }
}
