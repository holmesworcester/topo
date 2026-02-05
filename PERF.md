# Performance Benchmarks

## What This Measures
- End-to-end sync in the simulator: negentropy reconciliation + event transfer + projection.
- SQLite on disk with WAL + NORMAL sync.
- Envelope size ~512 bytes.
- Two peers in a single process (sim mode), with a constrained link model.

## How To Run

```bash
# Simulated sync (latency + bandwidth model)
cargo run --release -- sim --events 100000 --timeout 200 --latency-ms 50 --bandwidth-kib 6250

# Low-memory profile (optional)
LOW_MEM=1 cargo run --release -- sim --events 100000 --timeout 200 --latency-ms 50 --bandwidth-kib 6250
```

## Recent Results (Sim, 50ms RTT, 6250 KiB/s)

| Events/peer | Rounds | Throughput (MB/s) | Elapsed | Max RSS |
|-------------|--------|-------------------|---------|---------|
| 10,000 | 4 | 7.40 | 1.41s | 23.51 MB |
| 100,000 | 8 | 7.93 | 13.12s | 40.89 MB |
| 200,000 | 15 | 5.32 | 39.10s | 48.68 MB |
| 300,000 | 21 | 4.65 | 67.07s | 53.55 MB |
| 500,000 | 34 | 3.71 | 140.02s | 63.02 MB |

Notes:
- RSS is for **both peers combined** (single process). Per-peer RSS is roughly half.
- Throughput includes reconciliation time.
- 200k/300k/500k numbers above are with `LOW_MEM=1` unless stated otherwise.

## Baseline vs LOW_MEM (Sim, 50ms RTT, 6250 KiB/s)

| Events/peer | LOW_MEM | Throughput (MB/s) | Max RSS |
|-------------|---------|-------------------|---------|
| 200,000 | 0 | 5.88 | 86.05 MB |
| 200,000 | 1 | 5.32 | 48.68 MB |
| 500,000 | 0 | 3.74 | 107.87 MB |
| 500,000 | 1 | 3.71 | 63.02 MB |

## Projection Tradeoff
- Decoupled projection improves sync throughput versus inline projection, especially at higher event counts.
- The tradeoff is higher RSS: the projection worker and queue add memory overhead.
- If memory is tighter than throughput, consider inline projection or reducing queue sizes.

## Memory Notes (24MB Target)
- The biggest memory consumer is the in-flight event queue.
- The sim runs both peers in one process, so RSS is roughly doubled.
- Use `LOW_MEM=1` to shrink queue caps and SQLite cache; tune `EVENT_CHAN_CAP` if needed.

## Realism and Gaps
This sim is great for relative comparisons but is **not** a real QUIC network:
- No kernel network stack, no UDP/IP overhead, no real QUIC congestion control.
- No packet loss, jitter, reordering, or path changes.
- Single process means shared caches and no OS scheduling contention.
- SQLite is local and warm; no disk contention or fsync spikes.
- Crypto cost is not representative of production TLS + signature verification.

To make it more realistic:
1. **Run real QUIC**: use the QUIC demo with two processes.
2. **Add loss/jitter**: `tc netem` or container network shaping.
3. **Separate hosts**: run peers on different machines or VMs.
4. **Cold cache**: drop OS caches between runs; measure fsync-heavy settings.
5. **CPU contention**: pin CPUs, add background load.
6. **Real payloads**: use realistic event sizes and dependency graphs.

## Environment Variables

```bash
NO_DEPS=1    # Skip dependency reads (baseline)
NAIVE_DEPS=1 # Use individual queries per dependency (slower)
# default    # Use batched IN query (faster)

# Negentropy tuning
NEG_MAX_BYTES=1048576 # Max negentropy frame size (default 1 MiB)
NEG_BLOCK_SIZE=1024   # Negentropy block size (default 1024 items)

# Memory/queue tuning (LOW_MEM is optional)
LOW_MEM=1            # Enable low-memory presets for queues and SQLite cache
EVENT_CHAN_CAP=4096  # Max in-flight event blobs (default 4096)
DB_CACHE_KIB=1024    # SQLite cache size (KiB, default 4096 or 1024 in LOW_MEM)
IO_CTRL_CAP=256      # Control channel cap (default 1024 or 256 in LOW_MEM)
IO_DATA_CAP=1024     # Data channel cap (default 8192 or 1024 in LOW_MEM)
IO_IN_CAP=1024       # Inbound channel cap (default 8192 or 1024 in LOW_MEM)
DATA_BATCH_BYTES=16384 # Data send batch bytes (default 65536 or 16384 in LOW_MEM)
```
