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
