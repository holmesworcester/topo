# Performance Benchmarks

> **Status: Active** — Current benchmark results and testing guide.

## Test Environment
- SQLite on disk (WAL mode, NORMAL sync)
- QUIC transport (localhost) with SPKI fingerprint allowlist enforcement (`PinnedCertVerifier` + `AllowedPeers`)
- Message benchmarks use current message wire size: 1,194 bytes/event (`MESSAGE_WIRE_SIZE`, includes fixed 1,024-byte content slot)
- Linux x86_64, release build

## Running Performance Tests

```bash
# Preferred: strict serial runner (prevents cross-test interference)
# Also auto-updates this doc's "Auto-Generated Latest Serial Run" section.
scripts/run_perf_serial.sh core
scripts/run_perf_serial.sh full

# Optional: run serial perf suite without writing docs/PERF.md
WRITE_PERF_MD=0 scripts/run_perf_serial.sh core
WRITE_PERF_MD=0 scripts/run_perf_serial.sh full

# Core sync benchmarks
cargo test --release --test perf_test -- --nocapture
cargo test --release --test perf_test -- --nocapture --include-ignored

# File attachment throughput
cargo test --release --test file_throughput -- --nocapture --include-ignored

# Topo-sort cascade benchmark
cargo test --release --test topo_cascade_test topo_cascade_10k -- --nocapture --test-threads=1
cargo test --release --test topo_cascade_test -- --nocapture --include-ignored --test-threads=1

# Sync graph (chain + catchup) — requires --test-threads=1
cargo test --release --test sync_graph_test -- --nocapture --test-threads=1
cargo test --release --test sync_graph_test -- --nocapture --include-ignored --test-threads=1

# Low-memory budget tests
cargo test --release --test low_mem_test -- --nocapture
```

## Results (2026-02-27)

### Core Sync (`perf_test.rs`)

Throughput conversion used below:
- `MiB/s = Msgs/s * 1194 / 1024 / 1024`

#### 10k bidirectional sync

Each peer generates 5k events, syncs both directions.

| Metric | Value |
|--------|-------|
| Event generation | 0.82s |
| Sync wall time | 1.02s |
| Messages synced | 10,000 |
| Msgs/s | 9,783 |
| MiB/s | 11.14 |
| Peak RSS | 134.8 MiB |

#### 50k one-way sync

One peer generates 50k events, syncs to an empty peer.

| Metric | Value |
|--------|-------|
| Event generation | 4.65s | 
| Sync wall time | 6.73s |
| Messages synced | 50,000 |
| Msgs/s | 7,431 |
| MiB/s | 8.46 |
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
| MiB/s | 4.90 |
| Peak RSS | 488.5 MiB |

Throughput profile (receiver-side message count):

| Phase | Events | Time | Msgs/s | MiB/s |
|-------|--------|------|--------|-------|
| 0-250k | 250,000 | 31s | 8,065 | 9.18 |
| 250k-400k | 150,000 | 49s | 3,061 | 3.49 |
| 400k-500k | 100,000 | 36s | 2,778 | 3.16 |

Tail-phase slowdown is gated by receiver-side batch_writer throughput
(SQLite insert rate degrades as tables grow).

Investigation order (profiling-first):
1. Profile first (CPU + SQLite + WAL timing) on the 250k->500k tail to confirm dominant stall source before tuning.
2. If commit cost dominates, bound writer batches by page/byte budget (not only count) so commit latency stays flatter at high cardinality.
3. If WAL pressure appears in profile, tune checkpoint policy (`wal_autocheckpoint`, explicit passive checkpoints between large rounds) and re-measure.
4. Re-verify projection table indexes against dominant write/read paths for high-cardinality tails (`messages`, `recorded_events`, `valid_events`).

#### 10k continuous sync (inject while syncing)

Sync starts with empty peers, then 5k events injected on each side
in 100-event batches while sync is running.

| Metric | Value |
|--------|-------|
| Inject time | 0.57s |
| Total wall time | 3.60s |
| Events/s | 2,775 |
| Throughput (MiB/s) | 3.16 |
| Peak RSS | 176.3 MiB |

### Negentropy Frame Size Tuning

Per-round reconciliation cost scales super-linearly with frame size.
256 KB is the sweet spot: larger frames reduce round count but each
round takes disproportionately longer.

| Frame Size | Rounds | Reconcile | Wall Time | Msgs/s | MiB/s |
|------------|--------|-----------|-----------|--------|-------|
| 64 KB | 245 | 295s | 303s | 1,648 | 1.88 |
| 128 KB | 123 | 152s | 162s | 3,087 | 3.52 |
| **256 KB** | **62** | **131s** | **141s** | **3,555** | **4.05** |
| 512 KB | 31 | 105s | 117s | 4,267 | 4.86 |
| 1 MB | 16 | 543s | killed | - | - |

512 KB is ~10% faster on 500k but regresses 50k by ~7%.
1 MB is catastrophic: 34s/round due to super-linear fingerprint cost.

### File Attachment Throughput (`file_throughput.rs`)

Measures encode + store + project throughput for file slices (256 KiB ciphertext per slice).
Single-threaded, no sync — pure local write path.

| Size | Slices | Wall time | Throughput (MB/s) | Throughput (MiB/s) | Slices/s |
|------|--------|-----------|-------------------|--------------------|----------|
| 256 KiB | 1 | 0.003s | 83.7 | 79.82 | 335 |
| 10 MB | 40 | 0.057s | 175.1 | 166.99 | 701 |
| 100 MB | 400 | 0.531s | 188.4 | 179.67 | 754 |
| 1 GB | 4,096 | 5.167s | 198.2 | 189.02 | 793 |

### Topo Cascade (`topo_cascade_test.rs`)

Worst-case projector cascade benchmark using `bench_dep` events:
each event depends on up to 10 prior events, inserted in reverse order to maximize block/unblock depth.

#### 10k cascade (`topo_cascade_10k`, 2026-03-01)

| Metric | Value |
|--------|-------|
| Setup | 0.071s |
| Blocking phase | 2.216s |
| Cascade phase | 1.442s |
| Cascade rate | 6,930 events/s |
| Total | 3.729s |
| Peak RSS | 59.2 MiB |

### Sync Graph (`sync_graph_test.rs`)

Multi-peer topology benchmarks. All require `--test-threads=1`.

#### 10-hop chain: 10 peers, 10k events

Events injected at P0, propagate through P0-P1-...-P9.

| Metric | Value |
|--------|-------|
| Tail converge | 7,127 ms |
| All converge | 7,136 ms |
| Events/s (tail) | 1,403 |
| MiB/s (tail, message-wire equivalent) | 1.60 |
| Hop latency P50 | 1,021 ms |
| Hop latency P95 | 6,329 ms |
| Peak RSS | 1,363.3 MiB |

#### 10-hop chain: 10 peers, 50k events

| Metric | Value |
|--------|-------|
| Tail converge | 3,668 ms |  
| All converge | 3,672 ms |
| Events/s (tail) | 13,631 |
| MiB/s (tail, message-wire equivalent) | 15.52 |
| Hop latency P50 | 2,929 ms |
| Hop latency P95 | 7,777 ms |
| Peak RSS | 1,755.3 MiB |

Why this appears much faster than 10k:
1. Chain timing now uses full store-count convergence per peer; no sampled marker events.
2. Fixed setup/connection costs are amortized more at 50k, so apparent throughput improves with larger batches.
3. Treat chain results as topology behavior (hop-delay + memory) rather than canonical bulk-throughput numbers.

#### Multi-source catchup: 4 sources, 100k events

Sink connects to all sources as initiator using coordinated round-based assignment.
All sources are pre-seeded with the same dataset; sink success requires exact ID-set equality with the union of source stores.
Ingest attribution is recorded in `recorded_events.source` as
`quic_recv:<peer_id>@<ip:port>` for sink-side per-source accounting.

| Metric | Value |
|--------|-------|
| Catchup wall | 6,083 ms |
| Events/s | 16,439 |
| MB/s | 1.64 |
| MiB/s (same estimator) | 1.56 |
| Sink store | 100,000 |
| Peak RSS | 689.4 MiB |

#### Multi-source catchup: 8 sources, 100k events

| Metric | Value |
|--------|-------|
| Catchup wall | 9,604 ms |
| Events/s | 10,412 |
| MB/s | 1.04 |
| MiB/s (same estimator) | 0.99 |
| Sink store | 100,000 |
| Peak RSS | 1,370.3 MiB |

### Multi-Source Large-File Catchup Harness (Implemented)

Files dominate transfer volume, so we now keep a dedicated large-file catchup harness in `sync_graph_test.rs`:
1. Seed source `S0` with signed `message_attachment + file_slice` events.
2. Clone that exact dataset to all non-sink sources.
3. Run sink-driven multi-source catchup.
4. Assert sink `file_slice` event-id set exactly equals the seeded set.
5. Attribute each received file slice by source from `recorded_events.source` (`quic_recv:<peer_id>@<ip:port>`).
6. Assert each source contributes a substantial slice share, not just `>0`:
   at least `min_fair_share_fraction * (total_slices / source_count)`; current smoke config uses `10%` of fair share.

Run:
`cargo test --release --test sync_graph_test catchup_large_file_4x_1024_slices -- --ignored --nocapture --test-threads=1`

### Low-Memory Budget (`low_mem_test.rs`)

`low_mem_test.rs` is an in-process sanity suite (both peers in one process).
Authoritative budget gating uses `scripts/run_lowmem_regimen.sh`, which runs
two separate daemon processes and enforces per-daemon peak RSS (VmHWM) against
the 24 MiB target.

- **Regimen smoke (10k total, 5k/peer)**: currently fails 24 MiB per-daemon target (~30-38 MiB peaks)
- **Regimen soak (100k one-way)**: currently fails 24 MiB per-daemon target (~39 MiB sender, ~85 MiB receiver)
- **Standard command**: `scripts/run_lowmem_regimen.sh soak`

On low-memory catchup strategy:
1. Current path already keeps memory bounded mostly by connection/cache/channel limits; larger history should increase wall time more than RSS.
2. There is no unavoidable SQLite memory floor proportional to total historical rows; practical floor is per-connection overhead + active query working set + WAL pressure.
3. For stronger guarantees, the next protocol step is segmented catchup (time-window or bounded-range rounds) so old history is replayed in deterministic chunks.

### Auto-Generated Latest Serial Run

This section is updated by `scripts/run_perf_serial.sh` when `WRITE_PERF_MD=1`.

<!-- PERF_AUTO_RESULTS_START -->
_Not generated yet. Run `scripts/run_perf_serial.sh core`._
<!-- PERF_AUTO_RESULTS_END -->

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
LOW_MEM_IOS_SOAK_EVENTS=1000000  # optional: override soak event count
LOW_MEM_IOS_SOAK_BUDGET_MIB=24   # optional: override soak RSS budget
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
