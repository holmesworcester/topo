# Performance Benchmarks

> **Status: Active** — Current benchmark results and testing guide.

## Test Environment
- SQLite on disk (WAL mode, NORMAL sync)
- QUIC transport (localhost, certificate-pinned)
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

## Results (2026-02-27)

### Core Sync (`perf_test.rs`)

#### 10k bidirectional sync

Each peer generates 5k events, syncs both directions.

| Metric | Value |
|--------|-------|
| Event generation | 0.82s |
| Sync wall time | 1.02s |
| Messages synced | 10,000 |
| Msgs/s | 9,783 |
| Peak RSS | 134.8 MiB |

#### 50k one-way sync

One peer generates 50k events, syncs to an empty peer.

| Metric | Value |
|--------|-------|
| Event generation | 4.65s |
| Sync wall time | 6.73s |
| Messages synced | 50,000 |
| Msgs/s | 7,431 |
| Peak RSS | 230.4 MiB |

#### 500k one-way sync

One peer generates 500k events, syncs to an empty peer.
Single session, 62 negentropy rounds (256 KB frame size).

| Metric | Value |
|--------|-------|
| Event generation | 47s |
| Sync wall time | 116s |
| Messages synced | 500,000 |
| Msgs/s | 4,300 |
| Peak RSS | 488.5 MiB |

Throughput profile (receiver-side message count):

| Phase | Events | Time | Msgs/s |
|-------|--------|------|--------|
| 0-250k | 250,000 | 31s | 8,065 |
| 250k-400k | 150,000 | 49s | 3,061 |
| 400k-500k | 100,000 | 36s | 2,778 |

Tail-phase slowdown is gated by receiver-side batch_writer throughput
(SQLite insert rate degrades as tables grow).

#### 10k continuous sync (inject while syncing)

Sync starts with empty peers, then 5k events injected on each side
in 100-event batches while sync is running.

| Metric | Value |
|--------|-------|
| Inject time | 0.57s |
| Total wall time | 3.60s |
| Events/s | 2,775 |
| Throughput | 0.26 MiB/s |
| Peak RSS | 176.3 MiB |

### Negentropy Frame Size Tuning

Per-round reconciliation cost scales super-linearly with frame size.
256 KB is the sweet spot: larger frames reduce round count but each
round takes disproportionately longer.

| Frame Size | Rounds | Reconcile | Wall Time | Msgs/s |
|------------|--------|-----------|-----------|--------|
| 64 KB | 245 | 295s | 303s | 1,648 |
| 128 KB | 123 | 152s | 162s | 3,087 |
| **256 KB** | **62** | **131s** | **141s** | **3,555** |
| 512 KB | 31 | 105s | 117s | 4,267 |
| 1 MB | 16 | 543s | killed | - |

512 KB is ~10% faster on 500k but regresses 50k by ~7%.
1 MB is catastrophic: 34s/round due to super-linear fingerprint cost.

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

Events injected at P0, propagate through P0-P1-...-P9.

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
2. **Reconciliation worker thread**: neg.reconcile() runs on a dedicated OS thread so egress drain continues during 100-400ms reconciliation calls
3. **Immediate egress deletion**: sent items are deleted (not marked) to keep the egress table small during bulk transfers
4. **Batch transactions**: BEGIN/COMMIT around event batches
5. **Streaming pull dispatch**: HaveList frames sent during reconciliation rounds, not deferred until reconciliation completes
6. **Inline projection**: project in same transaction as store
7. **Coordinated download**: sink-driven round-based assignment avoids redundant transfers from overlapping sources

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
