# Performance Analysis: Sync Scaling & Memory

> **Status: Active** — Scaling analysis and architecture guidance for memory-constrained targets.

Benchmarked on master (`78cdf82`), 2026-02-07.

## Benchmark Results

### Normal Mode

| Size | Events/s | Wall Time | Peak RSS (2 peers) |
|------|----------|-----------|---------------------|
| 50k | 15,315 | 3.3s | 83 MiB |
| 100k | 12,201 | 8.2s | 136 MiB |
| 200k | 10,332 | 19.4s | 219 MiB |
| 500k | 6,180 | 80.9s | 253 MiB |

### LOW_MEM_IOS=1

| Size | Events/s | Wall Time | Peak RSS (2 peers) |
|------|----------|-----------|---------------------|
| 50k | 14,363 | 3.5s | 24 MiB |
| 100k | 12,938 | 7.7s | 33 MiB |
| 200k | 11,190 | 17.9s | 50 MiB |
| 500k | 7,282 | 68.7s | 87 MiB |

All tests are one-way sync (generate on alice, sync to empty bob).

### Observations

- **LOW_MEM_IOS is faster at scale**: 500k went from 80.9s to 68.7s. The smaller SQLite cache (1 MiB vs 64 MiB) causes less memory pressure at large dataset sizes.
- **Throughput degrades ~2.4x from 50k to 500k** in both modes, suggesting negentropy reconciliation cost grows with set size.
- **Memory savings are dramatic**: 253 MiB to 87 MiB at 500k (2.9x reduction). At 50k: 83 to 24 MiB (3.5x).
- **No correctness issues** at any scale in either mode.

## Memory Breakdown (LOW_MEM_IOS, 500k, per peer)

The test harness runs two peers in one process. The 87 MiB total means roughly 40-44 MiB per peer, plus ~8 MiB shared baseline (Rust runtime, tokio, QUIC/TLS, SQLite library code).

### SQLite table sizes on disk (per peer)

| Table | Rows | Est. size |
|-------|------|-----------|
| `events` | 500k | ~65 MB (event_id TEXT + type + blob + timestamps) |
| `neg_items` | 500k | ~20 MB (WITHOUT ROWID, tightly packed) |
| `recorded_events` | 500k | ~40 MB |
| `messages` (projection) | 500k | ~60 MB |
| **Total** | | **~185 MB** |

### Why RSS grows despite cache_size = 1 MiB

Even with `PRAGMA cache_size = -1024`, SQLite's RSS grows with database size because:

1. **WAL frames**: `wal_autocheckpoint = 1000` means up to 1000 dirty pages (~4 MB) accumulate before auto-checkpoint.
2. **Page cache pressure**: SQLite must load pages into its cache to execute queries. With a 1 MiB cache, pages are evicted quickly, but during batch operations many pages are touched and briefly resident.
3. **Temp allocations**: `ORDER BY`, `INSERT OR IGNORE` conflict resolution, and index maintenance all create transient allocations.
4. **`rebuild_blocks()` full scan**: Streams through all 500k neg_items. Memory-flat in application code, but forces SQLite to page through the entire table.
5. **Negentropy reconciliation state**: The `Negentropy` struct (64 KiB frame size) accumulates fingerprints proportional to the number of differing items.

### In-flight buffers (small)

| Buffer | Size |
|--------|------|
| SQLite cache | 1 MiB |
| Transport send/recv buffers | 512 KiB each |
| Ingest channel (1000 items x ~100B) | ~100 KB |
| Write batch cap (500 items) | ~50 KB |

These are negligible. The dominant cost is SQLite's page working set.

## Can a single peer reach <24 MiB at 500k?

**No, not without fundamental architectural changes.**

24 MiB for 500k events means ~48 bytes of resident memory per event. That's less than the event blob itself (~100 bytes). The core problem: SQLite's RSS footprint grows with database size regardless of cache settings, because sync operations must touch a meaningful fraction of all pages.

### Incremental improvements (stay within current architecture)

| Change | Estimated saving | Tradeoff |
|--------|-----------------|----------|
| Reduce `wal_autocheckpoint` to 100 | ~3 MB WAL | Hurts write throughput |
| Explicit `PRAGMA wal_checkpoint(TRUNCATE)` after batch writes | Reclaims WAL space | Adds latency between batches |
| Defer projection during sync (project lazily on read) | ~30 MB less table data | Read latency increases |
| Smaller `rebuild_blocks()` — incremental block updates | Avoids full scan spike | Implementation complexity |

These might get a single peer to ~25-30 MiB at 500k. Not below 24.

### Architectural changes (would make a real difference)

1. **Separate blob store from index**: Store event blobs in a flat append-only file. Keep only the index (event_id, offset, length) in SQLite. This dramatically reduces SQLite's page working set since the bulk of the data (blobs) never touches SQLite pages.

2. **mmap the blob file**: Let the OS manage memory pressure. RSS stays low because the OS can evict clean mmap pages under pressure. On iOS (`LOW_MEM_IOS`), use `read()` instead of mmap.

3. **Streaming negentropy without full rebuild**: Maintain the block index incrementally on insert rather than rebuilding from scratch before each sync. Avoids the full-table scan of neg_items.

4. **Columnar projection storage**: Instead of duplicating event data into projection tables (messages, reactions, etc.), store projections as lightweight pointers back to the blob store. Roughly halves total SQLite data.

### Target architecture for <24 MiB at 500k

```
SQLite (~5 MB):     event index, neg_items, neg_blocks, metadata
Blob file (~50 MB): append-only, mmap'd, OS-managed pages
RSS budget:         ~8 MB baseline + ~5 MB SQLite cache + ~5 MB hot pages + ~6 MB buffers = ~24 MB
```

This is achievable but represents a significant refactor of the storage layer.
