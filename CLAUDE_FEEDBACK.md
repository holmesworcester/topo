# Feedback on NEGENTROPY_SQLITE_PLAN.md (v3)

## Status: IMPLEMENTED

### Completed Steps

1. ✅ Add `neg_items`, `neg_blocks`, `neg_meta` tables to schema
2. ✅ Modify ingestion to populate `neg_items` (raw 32-byte blob id)
3. ✅ Implement `NegentropyStorageSqlite` with block index (B=4096)
4. ✅ Add two QUIC streams (control + data) via DualConnection
5. ✅ Refactor sync loops with sequential control/data handling
6. ✅ Replace `try_send` with `send().await` on ingest channel (5000 capacity)
7. ⏸️ Decouple projection - DEFERRED (current inline projection works)
8. ✅ Remove blob prefetch, use SQLite-backed negentropy

### Key Changes

- **Memory**: O(1) instead of O(n) for blob storage
- **Backpressure**: `send().await` instead of `try_send` (no dropped events)
- **Streams**: Control (NegOpen/NegMsg/HaveList) and Data (Event) separated
- **Storage**: `NegentropyStorageSqlite` with block index for efficient queries

### Remaining

9. Test at scale (50k, 200k, 500k) - requires QUIC network access

---

## Issue: Race Condition in Negentropy Reconciliation

### Symptoms

Testing at 5k and 10k events per peer shows consistent ~6.25% item loss:

```
5k test:  4688/5000 have_ids found (93.76%) - server ends with 9688/10000
10k test: 9375/10000 have_ids found (93.75%) - server ends with 19375/20000
```

The `have_ids` (items initiator has that responder needs) is consistently undercounted.

### Root Cause Analysis

**Architecture during sync:**
1. Main thread: `NegentropyStorageSqlite` holds reference to `db` connection
2. `batch_writer` (spawn_blocking): Opens separate connection, writes received events to `neg_items`

**The race condition:**
1. Negentropy reconciliation starts with `neg_items` containing 5000 items
2. Block index built for items 0-4999, sorted by (ts, id)
3. During reconciliation, `batch_writer` inserts received events into `neg_items`
4. New items may have timestamps that fall WITHIN the existing range
5. SQLite queries like `SELECT ... WHERE (ts, id) >= ? ORDER BY ts, id OFFSET ?` now return wrong results because the sorted order shifted

**Example:**
- Block 0 starts at (ts=100, id=abc), covers items 0-4095
- Query: `OFFSET 1000` to get item 1000
- New item inserted with ts=150 (between existing items)
- `OFFSET 1000` now returns item 999 (shifted by the insert)
- Items get skipped, reconciliation misses differences

### Why ~6.25% Loss?

The loss correlates with:
- Duration of reconciliation (more time = more inserts = more drift)
- Rate of incoming events during reconciliation
- Not related to block boundaries (consistent percentage, not fixed count)

### Design Choices

#### Option A: Buffer Received Items (Simple)

Don't insert into `neg_items` during reconciliation. Buffer event IDs in memory, insert after reconciliation completes.

```rust
// During sync: collect received items
let mut pending_items: Vec<(i64, EventId)> = Vec::new();

// After reconciliation completes:
for (ts, id) in pending_items {
    insert_neg_item(&db, ts, &id)?;
}
rebuild_blocks(&db)?;
```

**Pros:** Simple, works for current scale
**Cons:** Memory usage scales with received events, doesn't help multi-peer continuous operation

#### Option B: Separate Pending Table

Two tables: `neg_items_stable` (indexed, used for reconciliation) and `neg_items_pending` (receives new items).

```sql
-- During sync: inserts go here
INSERT INTO neg_items_pending (ts, id) VALUES (?, ?);

-- After sync: merge and rebuild
INSERT INTO neg_items_stable SELECT * FROM neg_items_pending;
DELETE FROM neg_items_pending;
-- Then rebuild blocks on neg_items_stable
```

**Pros:** Clear separation, durable storage of pending items
**Cons:** Requires merge step, items from Peer A not available to Peer B until merge

#### Option C: Epoch-Based Versioning

Add epoch column to track when items were added:

```sql
CREATE TABLE neg_items (
    ts INTEGER NOT NULL,
    id BLOB NOT NULL,
    epoch INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ts, id)
);
```

Reconciliation flow:
1. `current_epoch = SELECT MAX(epoch) FROM neg_items`
2. All negentropy queries add `WHERE epoch <= current_epoch`
3. Received items inserted with `epoch = current_epoch + 1`
4. Next sync uses new max epoch automatically

**Pros:** No merge step, items immediately available for next sync, clean semantics
**Cons:** Slightly more complex queries, need to update block index logic

#### Option D: Snapshot Isolation

Use SQLite's `BEGIN IMMEDIATE` or similar to get consistent read view.

**Pros:** No schema changes
**Cons:** SQLite doesn't have true snapshot isolation across connections, WAL mode still shows committed writes

### Recommendation

**For immediate fix:** Option A (buffer in memory) - gets tests passing

**For production/multi-peer:** Option C (epoch-based) - cleanest semantics:
- Each sync operates on consistent snapshot
- Received items immediately durable
- Next sync (any peer) sees all items
- No separate merge step
- Block index can be rebuilt lazily or per-epoch

### Additional Issue Found

The `reconcile_with_ids` accumulates IDs across rounds with duplicates. Fixed by deduplicating after reconciliation:

```rust
let have_set: HashSet<_> = have_ids.iter().cloned().collect();
let need_set: HashSet<_> = need_ids.iter().cloned().collect();
have_ids = have_set.into_iter().collect();
need_ids = need_set.into_iter().collect();
```

This was causing `have_ids.len()` to report 12312 when only 5000 unique items existed.
