# Performance Benchmarks

## Test Environment
- SQLite on disk (WAL mode, NORMAL sync)
- QUIC over localhost loopback
- 50,000 events per peer (100,000 total)
- 512-byte envelopes (~51 MB per direction)

## Running Performance Tests

```bash
# Run full perf test suite
cargo test --release perf_ -- --nocapture --ignored

# Run specific test
cargo test --release perf_sync_50k -- --nocapture --ignored
```

## Sync Performance (50k events/peer)

| Phase | Time |
|-------|------|
| Event generation | ~1.4s per 50k |
| Prefetch to memory | ~260ms per side |
| Negentropy reconciliation | ~630ms (51 rounds) |
| Event transfer + projection | varies (see below) |

## Projection Dependency Read Modes

Each event projection reads 10 dependencies (real messages from the database).
This simulates looking up parent messages, thread roots, mentioned users, etc.

| Mode | Transfer Time | vs Baseline | Description |
|------|---------------|-------------|-------------|
| NO_DEPS | 1.32s | baseline | No dependency reads |
| NAIVE | 2.70s | +105% | Individual query per dependency |
| BATCHED | 1.91s | +44% | Single IN (...) query per batch |

**BATCHED is 42% faster than NAIVE** with real dependency data.

### Why BATCHED is faster

With real data to fetch:
1. Single IN query avoids SQLite statement preparation overhead per read
2. Fewer round trips through the query planner
3. Better cache locality for index lookups

## Throughput

| Metric | Value |
|--------|-------|
| Events synced | 100,000 (50k each direction) |
| Data transferred | ~102 MB total |
| Sync time (no deps) | ~2s |
| Effective throughput | ~50 MB/s |

## Scaling

| Events/peer | Reconciliation Rounds | Transfer Time |
|-------------|----------------------|---------------|
| 500 | 2 | <100ms |
| 1,000 | 3 | ~30ms |
| 50,000 | 51 | ~1.3s |

## Key Optimizations

1. **Prefetching**: Load all blobs into HashMap before sync starts
2. **Channel + spawn_blocking**: Async network I/O, sync SQLite writes in separate thread
3. **Batch transactions**: BEGIN/COMMIT around 1000-event batches
4. **Batched dependency reads**: Single IN query for all deps per batch (42% faster)
5. **Interleaved send/recv**: Drain receives before sending to avoid QUIC flow control deadlock
6. **Inline projection**: Project in same transaction as store (atomic, <100ms latency)

## Environment Variables

```bash
NO_DEPS=1    # Skip dependency reads (baseline)
NAIVE_DEPS=1 # Use individual queries per dependency (slower)
# default    # Use batched IN query (faster)
```

## Simulated Dual-Stream (SQLite-backed, no prefetch)

All numbers below are from the in-process simulator (no sockets) with constrained
latency/bandwidth. These runs include projection + ingest, but **exclude DB generation**
by using `--no-generate` and prebuilt databases.

### How to Run (sync-only)

```bash
# Generate DBs once (separate process)
cargo run --release -- generate --db sim_server.db --count 100000 --channel aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
cargo run --release -- generate --db sim_client.db --count 100000 --channel bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

# Run sync-only (no generation)
cargo run --release -- sim --events 100000 --timeout 120 --latency-ms 10 --bandwidth-kib 50000 --no-generate
```

### Release Perf Observations (sync-only)

| Events/peer | Rounds | Combined Throughput | Peak RSS (VmHWM) |
|-------------|--------|---------------------|------------------|
| 10,000 | ~11 | ~5.5 MiB/s | ~48–50 MiB |
| 100,000 | ~99 | ~5.2 MiB/s | ~270–280 MiB |

Notes:
- Throughput is **data stream only** (event blobs).
- `VmHWM` is peak RSS for the entire run (sync phase only, generation excluded).
- These numbers are on `--release`; debug builds are significantly slower.

## 24 MB Target (iOS NSE) — Memory Control Levers

If we need to run within ~24 MB, the biggest wins are **SQLite cache/buffers** and
**queue sizes**. None of these require dropping projection or correctness.

Recommended adjustments:

- Reduce SQLite cache per connection (`PRAGMA cache_size`), e.g. `-1024` (1 MiB).
- Minimize number of open connections (one read snapshot + one writer).
- Use small bounded channels (ingest queue of 500–1000).
- Keep `have/need` chunked and spill to DB (already done).
- Avoid large in-memory prefetch or blob caches (already done).
- Consider `PRAGMA temp_store=FILE` for large temp operations.
- Set `PRAGMA mmap_size=0` to avoid extra mapped memory.
- Use `PRAGMA wal_autocheckpoint` and `PRAGMA journal_size_limit` to keep WAL small.

Measurement guidance:
- For sync-only memory, **exclude generation** using `--no-generate`.
- On iOS, use `task_info` (resident size) instead of `/proc/self/status` (Linux only).

### Low-Mem Profile (implemented)

Set `LOW_MEM=1` to enable:
- SQLite cache ~1 MiB per connection
- `temp_store=FILE`, `mmap_size=0`
- Smaller WAL/journal limits
- Ingest channel capacity reduced to 1000

Example:
```bash
LOW_MEM=1 cargo run --release -- sim --events 10000 --timeout 60 --latency-ms 1 --bandwidth-kib 50000 --no-generate
```

#### Low-Mem Result (10k/peer, 50,000 KiB/s cap)

```
LOW_MEM=1 cargo run --release -- sim --events 10000 --timeout 120 --latency-ms 1 --bandwidth-kib 50000 --no-generate
```

Results:
- Combined throughput: **~15.7 MiB/s**
- Peak RSS (VmHWM): **~19.4 MiB**

#### Low-Mem Result (10k/peer, effectively unconstrained)

```
LOW_MEM=1 cargo run --release -- sim --events 10000 --timeout 60 --latency-ms 1 --bandwidth-kib 1000000 --no-generate
```

Results:
- Combined throughput: **~13.5 MiB/s**
- Peak RSS (VmHWM): **~20.6 MiB**
