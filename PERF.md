# Performance Benchmarks

## Test Environment
- SQLite on disk (WAL mode, NORMAL sync)
- In-process sim transport (no real QUIC sockets)
- 512-byte envelopes
- Linux x86_64, release build

## Running Performance Tests

```bash
# Run all perf tests
cargo test --release --test perf_test -- --nocapture

# Run a specific test
cargo test --release --test perf_test perf_sync_50k -- --nocapture
```

## Results (2026-02-06)

### 50k one-way sync

One peer generates 50k events, syncs to an empty peer.

| Metric | Value |
|--------|-------|
| Event generation | 0.33s |
| Sync wall time | 1.22s |
| Events/s | 40,831 |
| Throughput | 19.94 MiB/s |
| Peak RSS | 71.1 MiB |

### 10k bidirectional sync

Each peer generates 5k events, syncs both directions.

| Metric | Value |
|--------|-------|
| Event generation | 0.07s |
| Sync wall time | 0.20s |
| Events/s | 49,137 |
| Throughput | 23.99 MiB/s |
| Peak RSS | 26.2 MiB |

### 10k continuous sync (inject while syncing)

Sync starts with empty peers, then 5k events injected on each side
in 100-event batches while sync is running.

| Metric | Value |
|--------|-------|
| Inject time | 0.11s |
| Total wall time | 1.53s |
| Events/s | 6,551 |
| Throughput | 3.20 MiB/s |
| Peak RSS | 27.6 MiB |

## Key Design Points

1. **No blob prefetch**: blobs fetched on demand, not cached in memory
2. **Channel + spawn_blocking**: async network I/O, sync SQLite writes in separate thread
3. **Batch transactions**: BEGIN/COMMIT around event batches
4. **Interleaved send/recv**: drain receives before sending to avoid flow control deadlock
5. **Inline projection**: project in same transaction as store

## Environment Variables

```bash
LOW_MEM=1  # Reduce SQLite cache, smaller channels (target ~24 MiB RSS)
```

## 24 MiB Target (iOS NSE) — Memory Control Levers

`LOW_MEM=1` enables:
- SQLite cache ~1 MiB per connection
- `temp_store=FILE`, `mmap_size=0`
- Smaller WAL/journal limits
- Ingest channel capacity reduced to 1000

Additional tuning options:
- `PRAGMA cache_size = -1024` (1 MiB)
- Minimize open connections (one read snapshot + one writer)
- `PRAGMA wal_autocheckpoint` and `PRAGMA journal_size_limit` to keep WAL small

## CLI Tools for Manual Testing

```bash
# Generate test messages
cargo run --release -- generate --count 50000 --db test.db

# Run sync between two terminals
cargo run --release -- sync --bind 127.0.0.1:4433 --db server.db
cargo run --release -- sync --bind 127.0.0.1:4434 --connect 127.0.0.1:4433 --db client.db

# Check status
cargo run --release -- status --db server.db
```
