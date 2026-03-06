# Performance Benchmarks

> **Status: Active** — Current benchmark results and testing guide.

## Test Environment
- OS: Linux 6.17.0-8-generic x86_64
- CPU: AMD RYZEN AI MAX+ 395 w/ Radeon 8060S (16 cores / 32 threads, 64 MiB L3)
- RAM: 122 GiB system memory
- Build: Rust `--release` profile
- Storage/DB: SQLite on disk (WAL mode, `synchronous=NORMAL`)

## Running Performance Tests

```bash
# Preferred: strict serial runner (prevents cross-test interference)
# Also auto-updates this doc's "Auto-Generated Latest Serial Run" section.
scripts/run_perf_serial.sh core
scripts/run_perf_serial.sh lowmem
scripts/run_perf_serial.sh full

# Optional: run serial perf suite without writing docs/PERF.md
WRITE_PERF_MD=0 scripts/run_perf_serial.sh core
WRITE_PERF_MD=0 scripts/run_perf_serial.sh lowmem
WRITE_PERF_MD=0 scripts/run_perf_serial.sh full

# Optional lowmem matrix overrides
# (defaults shown)
PERF_LOWMEM_BASELINE_SMALL=50000 \
PERF_LOWMEM_BASELINE_LARGE=1000000 \
PERF_LOWMEM_DELTA_TARGET=10000 \
PERF_LOWMEM_DELTA_BRACKET=50000 \
PERF_LOWMEM_FILE_BASELINE=50000 \
PERF_LOWMEM_FILE_COUNT=20 \
PERF_LOWMEM_FILE_SIZE_MIB=1 \
PERF_LOWMEM_CGROUP_ENFORCE=1 \
PERF_LOWMEM_CGROUP_LIMIT_KB=22528 \
scripts/run_perf_serial.sh lowmem

# Optional lowmem proof-of-concept overrides
# (24MB iOS target, 22MB enforced Linux receiver cap)
PERF_LOWMEM_BUDGET_KB=24576 \
PERF_LOWMEM_CGROUP_ENFORCE=1 \
PERF_LOWMEM_CGROUP_LIMIT_KB=22528 \
PERF_LOWMEM_POC_ENABLE=1 \
PERF_LOWMEM_RUN_LARGE_TARGET=1 \
PERF_LOWMEM_RUN_SMALL_BRACKET=1 \
PERF_LOWMEM_POC_MSG_BASELINE=1000000 \
PERF_LOWMEM_POC_MSG_DELTA=10000 \
PERF_LOWMEM_POC_REALISM_FILE_BASELINE=500000 \
PERF_LOWMEM_POC_REALISM_FILE_COUNT=100 \
PERF_LOWMEM_POC_FILE_COUNT=10000 \
PERF_LOWMEM_POC_FILE_SIZE_MIB=1 \
scripts/run_perf_serial.sh lowmem

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

# Low-memory RSS-sampling tests (ignored by default)
cargo test --release --test low_mem_test -- --ignored --nocapture --test-threads=1

# Dedicated lowmem proxy delta harness (direct, Linux-only)
# Requires /proc/<pid>/{status,smaps}; cgroup-enforced mode also requires cgroup v2.
scripts/run_lowmem_proxy.sh delta10k
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

Exchanged negentropy (sync protocol) control messages have a max fame size. Per-round reconciliation cost scales super-linearly with this frame size.
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

Quick note: coordinated sink-driven catchup over pre-seeded identical source datasets with sink-side per-source ingest attribution (`recorded_events.source`).

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

### Multi-Source Large-File Catchup

Validates sink exact `file_slice` convergence and per-source fairness floor in multi-source file catchup using `recorded_events.source` attribution.

Latest large-file multi-source snapshot (2026-03-04, Linux, `--ignored --nocapture --test-threads=1`):

| Test | Result | Catchup wall | Events/s | MB/s | Peak RSS |
|---|---|---:|---:|---:|---:|
| `catchup_large_file_4x_400_slices` | PASS | `416 ms` | `962` | `240.5` | `1111.0 MiB` |
| `catchup_large_file_4x_1024_slices` | PASS | `630 ms` | `1625` | `406.6` | `1111.0 MiB` |
| `catchup_large_file_8x_1024_slices` | PASS | `833 ms` | `1229` | `307.5` | `1363.4 MiB` |

Run:
`cargo +stable test --release --test sync_graph_test catchup_large_file_ -- --ignored --nocapture --test-threads=1`

### Low-Memory Coverage

Linux-only constrained-runtime gate for iOS background Notification Service Extension (NSE) targets (`24 MiB` iOS target, `22 MiB` enforced Linux receiver cap to account for iOS overhead). Detailed methodology is in `docs/DESIGN.md`.

Latest cgroup-enforced snapshot (2026-03-03):

| Scenario | Result | Receiver Peak (`MAX_BOB_TOTAL_KB`) | 24 MiB Gate | 22 MiB cgroup |
|---|---:|---:|---:|---:|
| Message realism: `500,000 + 10,000` | `10,000/10,000` msgs synced | `18,764` KB | PASS | PASS (`CGROUP_OOM_KILL=0`) |
| File realism: `500,000 + 100 x 1MiB` | `400/400` slices synced | `14,088` KB | PASS | PASS (`CGROUP_OOM_KILL=0`) |

Receiver peak stayed flat across sampled baselines; transfer size and ingest backpressure (`wanted` watermark + DB-backed `need_queue`) dominated memory shape.

Non-lowmem regression spot checks (2026-03-03):
1. `cargo +stable test --release --test perf_test perf_sync_10k -- --nocapture --test-threads=1` passed (`Msgs/s: 12315`).
2. `cargo +stable test --release --test sync_graph_test catchup_large_file_4x_400_slices -- --ignored --nocapture --test-threads=1` passed (`Catchup wall: 2250 ms`, all 400 slices attributed).

### Auto-Generated Latest Serial Run

This section is updated by `scripts/run_perf_serial.sh` when `WRITE_PERF_MD=1`.

<!-- PERF_AUTO_RESULTS_START -->
_Refreshed from `WRITE_PERF_MD=0 scripts/run_perf_serial.sh lowmem` output on 2026-03-03 (auto-write mode was flaky in this sandbox due intermittent daemon auto-start `os error 1`)._

### Lowmem Delta (50000+10000 messages)

```bash
env LOWMEM_PROXY_BASE_EVENTS=50000 LOWMEM_PROXY_DELTA_EVENTS=10000 LOWMEM_PROXY_BUDGET_KB=24576 LOWMEM_PROXY_CGROUP_ENFORCE=1 LOWMEM_PROXY_CGROUP_LIMIT_KB=22528 scripts/run_lowmem_proxy.sh delta10k
```

```text
RUN_DIR=/home/holmes/poc-7-lowmem-gordian/target/lowmem-proxy/delta-3414689_1772561432
SCENARIO=large_delta
DELTA_KIND=messages
BASE_EVENTS=50000
DELTA_EVENTS=10000
DELTA_MESSAGES_OBSERVED=10000
MAX_BOB_TOTAL_KB=18964
PASS_UNDER_24MB=1
CGROUP_ENFORCED=1
CGROUP_LIMIT_KB=22528
CGROUP_OOM_KILL=0
MAX_INIT_NEED_QUEUE=9987
```

### Lowmem Delta Files (50000+20x1MiB)

```bash
env LOWMEM_PROXY_BASE_EVENTS=50000 LOWMEM_PROXY_DELTA_FILES=20 LOWMEM_PROXY_DELTA_FILE_MIB=1 LOWMEM_PROXY_BUDGET_KB=24576 LOWMEM_PROXY_CGROUP_ENFORCE=1 LOWMEM_PROXY_CGROUP_LIMIT_KB=22528 scripts/run_lowmem_proxy.sh deltafiles
```

```text
RUN_DIR=/home/holmes/poc-7-lowmem-gordian/target/lowmem-proxy/delta-3417912_1772561466
SCENARIO=large_delta
DELTA_KIND=files
BASE_EVENTS=50000
DELTA_FILES=20
DELTA_FILE_SLICES_EXPECTED=80
DELTA_FILE_SLICES_OBSERVED=80
MAX_BOB_TOTAL_KB=14348
PASS_UNDER_24MB=1
CGROUP_ENFORCED=1
CGROUP_LIMIT_KB=22528
CGROUP_OOM_KILL=0
```

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
cargo run --release -- sync --bind 127.0.0.1:4433 --db topo.db
cargo run --release -- invite --db topo.db --bootstrap 127.0.0.1:4433
# then on client:
cargo run --release -- accept-invite --db client.db --invite topo://invite/...
cargo run --release -- sync --bind 127.0.0.1:4434 --db client.db

# Check status
cargo run --release -- status --db topo.db
```
