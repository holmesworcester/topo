# Performance Benchmarks

> **Status: Active** — Current benchmark results and testing guide.

## Test Environment
- SQLite on disk (WAL mode, NORMAL sync)
- In-process sim transport (no real QUIC sockets)
- 512-byte envelopes
- Linux x86_64, release build

## Running Performance Tests

```bash
# Core sync benchmarks
cargo test --release --test perf_test -- --nocapture
cargo test --release --test perf_test -- --nocapture --include-ignored

# File attachment throughput
cargo test --release --test file_throughput -- --nocapture --include-ignored

# Sync graph (chain + catchup) — requires --test-threads=1
cargo test --release --test sync_graph_test -- --nocapture --test-threads=1
cargo test --release --test sync_graph_test -- --nocapture --include-ignored --test-threads=1

# Low-memory budget tests
cargo test --release --test low_mem_test -- --nocapture
```

## Results (2026-02-26)

### Core Sync (`perf_test.rs`)

#### 10k bidirectional sync

Each peer generates 5k events, syncs both directions.

| Metric | Value |
|--------|-------|
| Event generation | 0.92s |
| Sync wall time | 1.22s |
| Events transferred | 6,199 |
| Events/s | 5,099 |
| Throughput | 0.49 MiB/s |
| Peak RSS | 317.6 MiB |

#### 50k one-way sync

One peer generates 50k events, syncs to an empty peer.

| Metric | Value |
|--------|-------|
| Event generation | 5.47s |
| Sync wall time | 1.42s |
| Events transferred | 2,598 |
| Events/s | 1,835 |
| Throughput | 0.18 MiB/s |
| Peak RSS | 444.4 MiB |

#### 100k one-way sync

| Metric | Value |
|--------|-------|
| Event generation | 10.64s |
| Sync wall time | 17.40s |
| Events transferred | 76,523 |
| Events/s | 4,398 |
| Throughput | 0.42 MiB/s |
| Peak RSS | 877.2 MiB |

#### 200k one-way sync

| Metric | Value |
|--------|-------|
| Event generation | 23.34s |
| Sync wall time | 17.76s |
| Events transferred | 36,673 |
| Events/s | 2,065 |
| Throughput | 0.20 MiB/s |
| Peak RSS | 1,241.3 MiB |

#### 500k one-way sync

Timed out (>20 min). Convergence not reached within budget.

#### 10k continuous sync (inject while syncing)

Sync starts with empty peers, then 5k events injected on each side
in 100-event batches while sync is running.

| Metric | Value |
|--------|-------|
| Inject time | 0.73s |
| Total wall time | 6.40s |
| Events/s | 1,562 |
| Throughput | 0.15 MiB/s |
| Peak RSS | 448.3 MiB |

### File Attachment Throughput (`file_throughput.rs`)

Measures encode + store + project throughput for file slices (256 KiB ciphertext per slice).
Single-threaded, no sync — pure local write path.

| Size | Slices | Wall time | Throughput | Slices/s |
|------|--------|-----------|------------|----------|
| 256 KiB | 1 | 0.003s | 83.7 MB/s | 335 |
| 10 MB | 40 | 0.057s | 175.1 MB/s | 701 |
| 100 MB | 400 | 0.531s | 188.4 MB/s | 754 |
| 1 GB | 4,096 | 5.167s | 198.2 MB/s | 793 |

### Sync Graph (`sync_graph_test.rs`)

Multi-peer topology benchmarks. All require `--test-threads=1`.

#### 10-hop chain: 10 peers, 10k events

Events injected at P0, propagate through P0↔P1↔...↔P9.

| Metric | Value |
|--------|-------|
| Tail converge | 7,127 ms |
| All converge | 7,136 ms |
| Events/s (tail) | 1,403 |
| Hop latency P50 | 1,021 ms |
| Hop latency P95 | 6,329 ms |
| Peak RSS | 1,363.3 MiB |

#### 10-hop chain: 10 peers, 50k events

| Metric | Value |
|--------|-------|
| Tail converge | 3,668 ms |
| All converge | 3,672 ms |
| Events/s (tail) | 13,631 |
| Hop latency P50 | 2,929 ms |
| Hop latency P95 | 7,777 ms |
| Peak RSS | 1,755.3 MiB |

#### Multi-source catchup: 4 sources, 100k events

Sink connects to all sources as initiator using coordinated round-based assignment.
Each source contributes at least one unique marker, proving all sources participated.

| Metric | Value |
|--------|-------|
| Catchup wall | 6,083 ms |
| Events/s | 16,439 |
| MB/s | 1.64 |
| Contributing sources | 4/4 |
| Sink store | 22,949 |
| Peak RSS | 689.4 MiB |

#### Multi-source catchup: 8 sources, 100k events

| Metric | Value |
|--------|-------|
| Catchup wall | 9,604 ms |
| Events/s | 10,412 |
| MB/s | 1.04 |
| Contributing sources | 8/8 |
| Sink store | 14,908 |
| Peak RSS | 1,370.3 MiB |

### Low-Memory Budget (`low_mem_test.rs`)

Verifies sync stays within iOS NSE memory budget (24 MiB per instance, 48 MiB process).
`LOW_MEM_IOS=1` enabled. Pass/fail only — no throughput metrics.

- **10k smoke**: PASS (2 peers, 5k each)
- **1M soak** (`#[ignore]`): long-running hardening test

## Key Design Points

1. **No blob prefetch**: blobs fetched on demand, not cached in memory
2. **Channel + spawn_blocking**: async network I/O, sync SQLite writes in separate thread
3. **Batch transactions**: BEGIN/COMMIT around event batches
4. **Interleaved send/recv**: drain receives before sending to avoid flow control deadlock
5. **Inline projection**: project in same transaction as store
6. **Coordinated download**: sink-driven round-based assignment avoids redundant transfers from overlapping sources

## Environment Variables

```bash
LOW_MEM_IOS=1  # iOS NSE low-memory mode (target <=24 MiB RSS)
```

## 24 MiB Target (iOS NSE) — Memory Control Levers

`LOW_MEM_IOS=1` enables:
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
cargo run --release -- create-invite --db server.db --bootstrap 127.0.0.1:4433
# then on client:
cargo run --release -- accept-invite --db client.db --invite quiet://invite/...
cargo run --release -- sync --bind 127.0.0.1:4434 --db client.db

# Check status
cargo run --release -- status --db server.db
```
