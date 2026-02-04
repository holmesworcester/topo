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
