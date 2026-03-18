# Throughput Roadmap: 5K → 20K events/s

## Current State (March 2026)

| Benchmark | msgs/s | Notes |
|---|---|---|
| Continuous 10k (forward-on-have) | ~5,000 | Live hint path, no negentropy |
| Preloaded 10k (negentropy + ingest) | ~5,000 | Discovery + transfer + ingest |
| Bidirectional 10k (create + sync) | ~4,400 | Includes source-side creation |
| 50k one-way | ~2,100 | Degrades at scale (negentropy O(N)) |

## Where Time Goes (10k events, 2.0s wall)

| Phase | Est. time | % | Notes |
|---|---|---|---|
| ed25519 sig verification | ~650ms | 32% | 10k × 65µs, per-event |
| Persist: events INSERT | ~200ms | 10% | 10k rows, 1 multi-row INSERT per chunk |
| Persist: neg_items INSERT | ~150ms | 8% | 10k rows, shared events only |
| Persist: recorded_events INSERT | ~150ms | 8% | 10k rows, per-tenant scoped |
| Persist: project_queue INSERT | ~200ms | 10% | 10k rows, 3 NOT EXISTS subqueries each |
| Projection: context load + dispatch + write | ~350ms | 17% | Per-event autocommit |
| Negentropy reconciliation | ~200ms | 10% | rebuild_blocks + protocol rounds |
| QUIC transfer + framing | ~100ms | 5% | ~400 bytes × 10k = 4MB on localhost |

## Network Ceiling (small ~400-byte messages)

| Link | Network ceiling | CPU-bound until |
|---|---|---|
| Localhost | 12M msgs/s | Always CPU-bound |
| LAN 1Gbps | 2M msgs/s | Always CPU-bound |
| WAN 100Mbps | 25K msgs/s | ~25K msgs/s |
| WAN 50Mbps | 12.5K msgs/s | ~12.5K msgs/s |
| Mobile 10Mbps | 2.5K msgs/s | Already network-bound at ~2.5K |

For small events, the system is CPU/DB-bound on all but mobile links.

---

## Tier 1: Eliminate Per-Event DB Work (5K → 10K)

These changes reduce the number of SQLite B-tree operations per event.

### 1a. Consolidate recorded_events into events table

**Impact**: eliminates 10K INSERTs per batch (one full table's worth)
**Effort**: Medium-high (20+ read sites to migrate)

Add `recorded_by`, `recorded_at`, `source` columns to the `events` table.
The "already local" check becomes `SELECT 1 FROM events WHERE event_id = ?`.
All 20+ read sites in service.rs, assert.rs, file_slice, workspace, etc.
need to join on `events` instead of `recorded_events`.

### 1b. Eliminate project_queue from hot path

**Impact**: eliminates 10K INSERTs with 3 NOT EXISTS subqueries each
**Effort**: Done (on `codex/batch-projection-tuning` branch)

Pass event IDs directly from persist output to `project_batch` in
post-commit effects. Queue still used for startup recovery and fanout.

### 1c. Defer neg_items to incremental rebuild

**Impact**: eliminates 10K INSERTs from persist, replaces with 1 bulk INSERT...SELECT before negentropy
**Effort**: Medium (lock contention with neg worker needs careful design)

Track last-synced rowid in neg_meta. Before each negentropy round, bulk-insert
new events from the events table. The cost moves from the hot ingest path
to the observer loop (which runs every few seconds, not per event).

Challenge: the neg worker runs on a separate connection. The bulk INSERT
must happen on the writer connection (which holds the write lock) or
before the neg worker takes its snapshot.

---

## Tier 2: Reduce Per-Event CPU Work (10K → 15K)

### 2a. Hash-chain signature batching (merkle chain)

**Impact**: reduces 10K sig verifications to ~2-5 (one per device per sync round)
**Effort**: Medium (protocol change — add prev_message_ref field)

Each message includes a 32-byte hash of the sender's previous message.
During sync, verify only the chain tip's signature, then walk the hash
chain backwards. Each link is authenticated by the hash above it.

- BLAKE2b hash check: ~1µs per event (vs 65µs for ed25519)
- For 10k messages from 2 devices: 2 sig verifies + 10k hash checks
- Saves ~640ms (from 650ms to 10ms)

Requires wire format change (new field in message events).

### 2b. Skip cascade for dependency-free types

**Impact**: eliminates ~10K no-op cascade queries
**Effort**: Low

Messages have no dependents. The cascade check (`SELECT ... FROM
blocked_event_deps WHERE blocker_event_id = ?`) always returns empty.
Skip it entirely for event types with no possible dependents (messages,
reactions, file_slices).

### 2c. Cache signer key resolution

**Impact**: eliminates ~10K blob reads for signer keys
**Effort**: Low (already done in batch projection — key lookup is batched)

In the per-event path, cache the signer public key after first resolution.
All messages from the same peer use the same key.

### 2d. Skip subscription check when no subscriptions active

**Impact**: eliminates ~10K queries when no subscriptions exist
**Effort**: Low

Check a cached flag "any active subscriptions?" before the per-event
subscription hook. If none, skip entirely.

---

## Tier 3: Parallelism (15K → 20K+)

### 3a. Parallel signature verification (rayon)

**Impact**: divides sig verify time by core count
**Effort**: Low (already prototyped on `codex/batch-projection-refactor`)

The map phase of the batch pipeline (parse + verify + build context +
dispatch projector) is pure — no DB access. Use `rayon::par_iter` for
batches > 50 events. On 8 cores: 650ms → ~80ms.

Only useful AFTER the hash-chain optimization makes sig verify rare,
OR if hash chains aren't implemented.

### 3b. Concurrent persist + project on separate threads

**Impact**: hides projection latency behind persist
**Effort**: Medium

Persist thread: writes events to DB, passes event IDs to project thread.
Project thread: reads blobs (already in page cache), projects, writes results.
Both use the same DB but different transactions.

Challenge: SQLite single-writer means they can't both write simultaneously.
Would need to batch and alternate, or use WAL mode's concurrent-reader
capability to let the project thread read while persist writes.

---

## Tier 4: Architecture Changes (20K+)

### 4a. Memory-first event staging

Buffer received events in memory. Project from in-memory blobs (no DB
read-back). Flush to SQLite in large batches on a timer or threshold.
Crash loses unflushed events but sync will re-request them.

### 4b. Workspace-scoped event deduplication

Replace per-tenant `recorded_events` with workspace-scoped dedup.
"Any event recorded by one tenant in a workspace will be recorded by
every tenant in the same workspace." This means the dedup check is
just "does this event_id exist in events?" — no per-tenant scoping needed.

### 4c. LSM or append-only storage for events

The events table is append-only (INSERT OR IGNORE, never UPDATE/DELETE
during normal operation). A log-structured storage engine (RocksDB,
sled, or custom WAL-only append) would eliminate B-tree rebalancing
overhead entirely. Reads are rare (only during projection and data-plane
drain). Writes dominate.

---

## Priority Sequence

1. **Skip cascade for dep-free types** (Tier 2b) — low effort, immediate win
2. **Cache signer keys** (Tier 2c) — low effort
3. **Skip empty subscriptions** (Tier 2d) — low effort
4. **Eliminate project_queue** (Tier 1b) — done
5. **Hash-chain sig batching** (Tier 2a) — medium effort, biggest single win
6. **Consolidate recorded_events** (Tier 1a) — medium-high effort, reduces write amplification
7. **Defer neg_items** (Tier 1c) — medium effort
8. **Parallel sig verify** (Tier 3a) — low effort, only matters after hash chains
