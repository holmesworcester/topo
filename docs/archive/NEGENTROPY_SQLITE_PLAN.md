# SQLite Negentropy Adapter and QUIC-First Sync Plan

> **Historical document; file paths and module names may not match the current source tree.**

This document is for another assistant. It describes the simplest reliable path to a SQLite-backed negentropy storage adapter and a QUIC-first send/recv loop that keeps the outgoing stream full without blowing memory. It is intentionally conservative and focused on clarity, correctness, and minimal moving parts.

**Context**
- Project: `poc-7`
- Goal: Efficient QUIC-centric sync, prioritizing outbound throughput while keeping projection responsive.
- Constraints: Low-memory environments (target ~24 MB), no windowing tricks, and keep logic simple.
- Current POC uses `NegentropyStorageVector` and caches all blobs in memory, which does not scale.

---
**Core Decisions**
1. **SQLite-backed negentropy storage**  
   Implement `NegentropyStorageBase` on top of SQLite, not in-memory vectors.
2. **No time-windowing**  
   Full-history reconciliation is always available. No rolling windows or paging strategies that add state management complexity.
3. **Two QUIC streams**  
   Control plane and data plane are separated to prevent large event blobs from blocking negentropy or HaveList messages.
4. **Send-until-blocked**  
   Outbound is driven by a dedicated sender loop that writes until the stream is backpressured.
5. **No blob prefetch**  
   Only IDs are in memory. Blobs are fetched on demand and preferably in batches.
6. **Decouple projection from sync**  
   Network receive feeds a fast ingest path; projection is asynchronous and never blocks receive.
7. **32-byte IDs**  
   Event IDs are already 32-byte Blake2b-256 and align with `negentropy::Id`. No padding required.

---
**SQLite Schema Additions**
Add two tables.

1. `neg_items`  
Stores negentropy items in sorted order by `(ts, id)` and supports efficient range scans.

```
CREATE TABLE IF NOT EXISTS neg_items (
  ts INTEGER NOT NULL,
  id BLOB NOT NULL,
  PRIMARY KEY (ts, id)
) WITHOUT ROWID;
```

2. `neg_blocks`  
Sparse index of every Bth item in `neg_items` to map index -> key quickly.

```
CREATE TABLE IF NOT EXISTS neg_blocks (
  block_idx INTEGER PRIMARY KEY,
  ts INTEGER NOT NULL,
  id BLOB NOT NULL,
  count INTEGER NOT NULL
);
```

**Block size**  
Pick `B = 2048` or `4096`. Larger means fewer blocks, smaller index, and slightly more scanning per lookup. Keep it simple: start with 4096.

---
**Ingestion Path Changes**
Every time an event is stored and marked shareable, also insert into `neg_items`.

Minimal changes:
- Extract `created_at_ms` once during ingest and store it in `neg_items`.
- Insert `id` as raw 32-byte blob, not base64, to avoid extra conversions.
- Add an `incoming_queue` row for projection; projection consumes this asynchronously.

Example flow:
1. Store blob in `store`
2. Insert ID into `shareable_events`
3. Insert `(ts, id)` into `neg_items`

Pitfall: do not rely on re-reading blobs later to extract timestamps. This is slow and forces large memory or repeated IO. Store timestamp once.

---
**NegentropyStorageSqlite Adapter**
Implement `NegentropyStorageBase` using SQLite queries plus `neg_blocks`.

**Data types**
- `Item` is `{ timestamp: u64, id: [u8; 32] }`
- SQLite stores `ts` as `INTEGER` and `id` as `BLOB`.

**Implementation details**
1. `size()`  
   `SELECT COUNT(*) FROM neg_items`
   Cache the result per sync run.

2. `get_item(i)`  
   - `block = i / B`
   - `offset = i % B`
   - Fetch block start key:
     `SELECT ts, id FROM neg_blocks WHERE block_idx = ?`
   - Fetch item:
     `SELECT ts, id FROM neg_items WHERE (ts, id) >= (?, ?) ORDER BY ts, id LIMIT 1 OFFSET ?`
   - Offset is bounded by `B`, so the query is cheap.

3. `iterate(begin, end)`  
   - Fetch start key using block table.
   - `LIMIT (end - begin)` in one query.
   - Call callback for each row.

4. `find_lower_bound(bound)`  
   - Find the last block with start key <= bound:
     `SELECT block_idx, ts, id FROM neg_blocks WHERE (ts, id) <= (?, ?) ORDER BY block_idx DESC LIMIT 1`
   - Scan within that block:
     `SELECT ts, id FROM neg_items WHERE (ts,id) >= (block_ts, block_id) ORDER BY ts,id LIMIT B`
   - Return `block_idx * B + offset_of_first_ge_bound`.

Pitfall: if `neg_blocks` is missing or stale, `find_lower_bound` will be wrong. Rebuild it before sync or when delta exceeds a threshold.

---
**Rebuilding `neg_blocks`**
Keep it simple and safe, but avoid rebuilding every sync.

Recommended:
- Track `item_count`, `blocks_built_at`, and `needs_rebuild` in a `neg_meta` table.
- On ingest:
  - If `(ts,id)` >= current max, it is append-only; update `item_count` and max.
  - If out-of-order insert, set `needs_rebuild = 1`.
- On sync start:
  - If `needs_rebuild = 1`, **rebuild before running negentropy** (no OFFSET fallback).
  - Else if append-only and `(item_count - blocks_built_at) >= B`, rebuild.
  - Else do nothing.

Simplest acceptable variant:
- Skip incremental extend. Rebuild only in the two cases above.
- No OFFSET fallback. Correctness requires `neg_blocks` to be valid before negentropy.

Rebuild is O(N) but streaming and memory-flat. It avoids complex incremental logic.

Pitfall: do not attempt per-insert updates to `neg_blocks` beyond the append-only case.

---
**QUIC Loop Refactor**
Objective: keep outbound full while preserving control responsiveness.

1. **Open two bidirectional streams**  
   - Control stream for `NegOpen`, `NegMsg`, `HaveList`
   - Data stream for `Event` blobs

2. **Dedicated sender loops**  
   - Control sender drains control queue first.
   - Data sender loops `send()` until it hits backpressure or queue is empty.

3. **Dedicated receiver loop**  
   - Reads both streams concurrently.
   - Enqueues events into a bounded **ingest** channel.
   - Uses `send().await` on ingest channel to apply backpressure at the ingest stage, not projection.

4. **No fixed-size batches**  
   - Batching is only at the DB layer.
   - Network sends are continuous until blocked.
5. **Send during reconciliation**  
   Start sending as soon as IDs are known. Do not wait for reconciliation to finish.

Pitfall: if control and data share one stream, large event writes can delay negotiation. Use two streams.

---
**Projection Priority**
Sync is priority. Projection must not block network receive.

Recommended:
- **Ingest worker** does fast writes (`store`, `shareable`, `neg_items`) and inserts into `incoming_queue`.
- **Projection worker** consumes `incoming_queue` asynchronously in batches.
- Receiver backpressures only on the ingest channel, not on projection speed.

Pitfall: do not block receiver on projection queue. Keep projection fully decoupled.

---
**Memory Budget (24 MB Target)**
To keep memory under ~24 MB:
- Remove full `blob_cache`.
- Keep only small ID lists in memory.
- Reduce SQLite cache size to ~2 MB to 8 MB depending on device.
- Bound channels to a few thousand items, not 100k.
- Use streaming DB reads and writes.

Pitfall: with full blob prefetch and large channels, memory explodes regardless of negentropy changes.

---
**Minimal Code Touch List**
Files likely to change:
- `db/schema.rs`  
  Add `neg_items`, `neg_blocks` tables.
- `main.rs`  
  Replace prefetch logic. Add two streams. Add dedicated send/recv loops. Remove `try_send`.
- (adapter removed; negentropy integration lives in `sync/negentropy_sqlite.rs`)  
  Replace vector loading with `NegentropyStorageSqlite`.
- New file: `sync/negentropy_sqlite.rs`  
  Implement the storage adapter.

Keep the changes scoped. Avoid refactoring unrelated code during this pass.

---
**Testing Plan**
1. Unit tests for `NegentropyStorageSqlite`
   - Insert known items into `neg_items`.
   - Build `neg_blocks`.
   - Validate `get_item`, `iterate`, and `find_lower_bound`.
2. Integration test
   - Run negentropy reconcile with SQLite storage and verify `have_ids`/`need_ids` correctness.
3. Stress test
   - 50k to 200k events, measure memory with `time -v` or OS tools outside sandbox.

Pitfall: do not rely on the existing demo in sandbox for QUIC testing. UDP sockets are blocked.

---
**Potential Simplifications to Keep**
- Keep `ENVELOPE_SIZE` fixed to avoid variable framing complexity.
- Keep `HaveList` as vector of IDs.
- Keep `batch_writer` structure but remove dependency simulation when moving toward production.

---
**Things to Avoid**
- Time-windowed reconciliation.
- Full in-memory blob caches.
- Channel drops via `try_send`.
- Single-stream control/data.
- Incremental `neg_blocks` maintenance until the baseline is stable.

---
**Acceptance Criteria**
The path is correct if:
- Negentropy reconciliation works on full history with no in-memory vector of items.
- Memory does not scale linearly with event count beyond small constants.
- Outbound stream stays busy when data is available.
- Control messages are not delayed by blob transfers.
 - Network receive does not block on projection workload.
