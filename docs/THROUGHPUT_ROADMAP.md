# Sync Performance Roadmap

## Goal

Make download and sync times invisible to the user (<1s perceived latency)
when catching up and connected to a fast node, regardless of workspace size.

This means: when a user opens the app after being offline, the most recent
messages and files should appear immediately. History fills in behind the
scenes. The user should never see "syncing..." for more than a moment.

## Current State (March 2026)

| Benchmark | msgs/s | Notes |
|---|---|---|
| Continuous 10k (forward-on-have) | ~5,000 | Live hint path, no negentropy |
| Preloaded 10k (negentropy + ingest) | ~5,000 | Discovery + transfer + ingest |
| Bidirectional 10k (create + sync) | ~4,400 | Includes source-side creation |
| 50k one-way | ~2,100 | Degrades at scale (negentropy O(N)) |

## Where Time Goes (10k events, 2.0s wall)

| Phase | Est. time | % |
|---|---|---|
| ed25519 sig verification | ~650ms | 32% |
| Persist: events INSERT | ~200ms | 10% |
| Persist: neg_items INSERT | ~150ms | 8% |
| Persist: recorded_events INSERT | ~150ms | 8% |
| Persist: project_queue INSERT | ~200ms | 10% |
| Projection: context + dispatch + write | ~350ms | 17% |
| Negentropy reconciliation | ~200ms | 10% |
| QUIC transfer + framing | ~100ms | 5% |

## Network Ceiling (small ~400-byte messages)

| Link | Network ceiling |
|---|---|
| Localhost | 12M msgs/s |
| LAN 1Gbps | 2M msgs/s |
| WAN 100Mbps | 25K msgs/s |
| WAN 50Mbps | 12.5K msgs/s |
| Mobile 10Mbps | 2.5K msgs/s |

For small events, the system is CPU/DB-bound on all non-mobile links.

---

## Architecture: Decouple Download from Projection

The core design change that enables everything below: **download is just
blob storage (fast, I/O bound); projection is indexing + verification
(slow, CPU bound). Let them run at different speeds with a cursor between
them.**

### Fast blob persist (download-speed path)

Persist downloaded event blobs as fast as possible. Don't index them —
no neg_items, no recorded_events, no project_queue INSERT. Just:

```sql
INSERT OR IGNORE INTO events (event_id, blob, share_scope, created_at, inserted_at)
VALUES (?, ?, ?, ?, ?)
```

One INSERT per event, no subqueries, no constraint checks beyond the PK.
This makes downloads network-bound (not CPU-bound) on any reasonable link.

### Background projection cursor

A background job walks unprojected events via a cursor:

```sql
SELECT event_id, blob FROM events
WHERE projected_at IS NULL
ORDER BY priority_score DESC
LIMIT ?
```

The cursor processes events in priority order (see below), running
projection, indexing, and sig verification at its own pace. The UI
queries projected state, which fills in progressively.

### Priority-driven projection order

Not all events are equal. Project in this order:

1. **Subscription-matching events** — events visible in the current UI
   view (matches an active query/subscription). These appear instantly.
2. **Newest events** — sort by `created_at DESC` so recent messages
   show before old history.
3. **Dependency-unblocking events** — if projection of event B is
   blocked waiting for event A, boost A's priority so B can proceed.
4. **Everything else** — old history, bulk backfill.

This way the user sees the latest messages in <1s even while 100k old
events are still being projected in the background.

### Priority-driven download order

Mirror the projection priority in the download scheduler:

- `wanted_events.priority_ts` already sorts by `created_at DESC`
  (newest first) within priority lanes.
- When projection blocks on a missing dep, boost that dep's priority
  in `wanted_events` so it gets requested sooner.
- The planner already respects priority ordering — just needs the
  priority values set correctly.

This ensures we download what the user needs first, not just whatever
negentropy discovered first.

---

## Optimizations: Ranked by Impact

### Tier 1: Eliminate Per-Event DB Work (5K → 10K)

#### 1a. Blob-only persist (skip indexing on the hot path)

**Impact**: reduces persist from ~4 INSERTs/event to 1 INSERT/event
**Effort**: Medium

Persist only the events table row during download. A background cursor
handles neg_items, recorded_events, and projection. Downloads become
network-bound.

#### 1b. Consolidate recorded_events into events table

**Impact**: eliminates one full table's INSERTs from the hot path
**Effort**: Medium-high (20+ read sites to migrate)

Add `recorded_by`, `recorded_at`, `source` columns to the `events`
table. The "already local" check becomes `SELECT 1 FROM events WHERE
event_id = ?`. All read sites in service.rs, assert.rs, file_slice,
workspace, etc. need migration.

#### 1c. Eliminate project_queue from hot path

**Impact**: eliminates per-event INSERT with 3 NOT EXISTS subqueries
**Effort**: Done (on `codex/batch-projection-tuning` branch)

Pass event IDs directly from persist output to `project_batch` in
post-commit effects. Queue still used for startup recovery and fanout.

#### 1d. Defer neg_items to incremental rebuild

**Impact**: eliminates per-event neg_items INSERT from persist
**Effort**: Medium

Track last-synced rowid in `neg_meta`. Before each negentropy round,
bulk-insert new events. Cost moves from the hot ingest path to the
observer loop (runs every few seconds).

### Tier 2: Reduce Per-Event CPU Work (10K → 15K)

#### 2a. Hash-chain signature batching (merkle chain per device)

**Impact**: reduces 10K sig verifications to ~2-5 (one per device per sync)
**Effort**: Medium (protocol/wire format change)

Each message includes a 32-byte `prev_message_ref` (hash of sender's
previous message blob). During catchup sync:

1. Sort received messages by signer, find the chain tips (newest)
2. Verify ed25519 signature on chain tips only (~2-5 verifies)
3. Walk each chain backwards, verifying hash links (~1µs each vs 65µs)
4. If hash chain is unbroken, all messages in the chain are authenticated

For 10k messages from 2 devices: 2 sig verifies + 10k hash checks.
Saves ~640ms (from 650ms to ~12ms).

Safe because: if the tip signature is valid and the hash chain is
unbroken, every message was created by the same signer. An attacker
can't splice in a fake message without breaking the hash link above it.

#### 2b. Skip cascade for dependency-free types

**Impact**: eliminates ~10K no-op cascade queries
**Effort**: Low

Messages, reactions, and file_slices have no dependents. The cascade
check (`SELECT FROM blocked_event_deps WHERE blocker_event_id = ?`)
always returns empty for these types. Skip it entirely based on
event type metadata.

#### 2c. Cache signer key resolution

**Impact**: eliminates ~10K blob reads for signer keys
**Effort**: Low (already done in batch projection pipeline)

All messages from the same peer use the same signer key. Cache it
after first resolution. The batch projection pipeline already does
this via `gather_signer_keys`.

#### 2d. Skip subscription check when no subscriptions active

**Impact**: eliminates ~10K queries when no subscriptions exist
**Effort**: Low

Check a cached flag before the per-event subscription hook. If no
active subscriptions, skip entirely.

### Tier 3: Parallelism (15K → 20K+)

#### 3a. Parallel signature verification (rayon)

**Impact**: divides sig verify time by core count
**Effort**: Low (already prototyped on `codex/batch-projection-refactor`)

The map phase of the batch projection pipeline is pure — no DB access.
Use `rayon::par_iter` for batches > 50 events. On 8 cores: 650ms → ~80ms.

Most useful before hash-chain optimization is implemented. After hash
chains, sig verify is already fast enough that parallelism adds little.

#### 3b. Parallel projection of independent events

**Impact**: utilize multiple cores for projection
**Effort**: High

Messages are independent (no cross-event deps). Their projection could
run on multiple threads with a shared SQLite writer collecting results.
Requires careful transaction design.

### Tier 4: Perceived Performance (any throughput → <1s UX)

These don't increase raw throughput but make sync feel instant.

#### 4a. Subscription-aware projection priority

**Impact**: events visible in the current UI view project first
**Effort**: Low

When the projection cursor picks events to process, check against
active subscriptions first. If a message matches what the user is
looking at, project it before processing old history.

**Privacy note**: this only affects local projection order, not
download order. Download order stays the same (newest first), so
no information about UI state leaks to peers.

#### 4b. Newest-first download scheduling

**Impact**: recent messages download before old history
**Effort**: Already implemented

`wanted_events.priority_ts` sorts by `created_at DESC`. The planner
requests newest events first. Combined with forward-on-have for
truly live events, this means:
- Live: forward-on-have delivers in <100ms
- Recent (last hour): downloaded first via priority scheduling
- History: fills in behind the scenes

#### 4c. Dependency-boost in download priority

**Impact**: unblocks projection chains faster
**Effort**: Low

When projection blocks on a missing dep, boost that dep's `priority_ts`
in `wanted_events` to `MAX_PRIORITY`. The planner requests it next.
This prevents identity chain stalls during bootstrap.

#### 4d. Progressive UI rendering

**Impact**: show partial results while sync is ongoing
**Effort**: UI-layer change

The UI queries projected state, which fills in progressively. Show
a count of "N more messages loading..." while the projection cursor
catches up. No spinner, no blocking — just progressive rendering.

### Tier 5: Architecture Changes (20K+)

#### 5a. Memory-first event staging

Buffer received events in memory (Vec). Project from in-memory blobs
(no DB read-back). Flush to SQLite in large batches on a timer.
Crash loses unflushed events but sync re-requests them.

#### 5b. Workspace-scoped event deduplication

Replace per-tenant `recorded_events` with workspace-scoped dedup.
All tenants in a workspace see the same shared events. The dedup
check becomes `SELECT 1 FROM events WHERE event_id = ?` — no
per-tenant scoping needed for shared events.

#### 5c. LSM or append-only storage for events

The events table is append-only. A log-structured engine (RocksDB,
sled, or custom WAL-append) would eliminate B-tree rebalancing.
Reads are rare (only during projection and data-plane drain).
Writes dominate.

---

## Priority Sequence

For the <1s perceived latency goal, the order is:

1. **Blob-only persist + background cursor** (1a) — makes downloads
   network-bound, decouples download from projection
2. **Newest-first download** (4b) — already implemented
3. **Subscription-aware projection** (4a) — low effort, instant UX win
4. **Dependency-boost** (4c) — low effort, fixes bootstrap stalls
5. **Skip cascade for dep-free types** (2b) — low effort, speeds projection
6. **Hash-chain sig batching** (2a) — medium effort, biggest CPU win
7. **Consolidate recorded_events** (1b) — medium effort, reduces writes
8. **Progressive UI rendering** (4d) — UI-layer, makes everything feel fast

The first 4 items give the user <1s perceived latency for recent messages
even during a large catchup sync, without changing raw throughput at all.
The remaining items increase raw throughput for the background projection.

---

## Already Implemented

- Batch projection pipeline (gather/map/reduce/apply) — `codex/batch-projection-refactor`
- Project queue bypass — `codex/batch-projection-tuning`
- Multi-row INSERT for persist phase — `codex/batch-projection-tuning`
- Batched recorded_events check in observe_many_for_peer
- Cached rebuild_blocks (count-based skip)
- Forward-on-have live hint bus (sub-second live delivery)
- Larger batch sizes (write_batch_cap 5000, drain 1000)
- Credit watermarks tuned for file slices (2 MiB high, 512 KiB low)
- Bidirectional DiscoveryHints with real byte sizes
- Vendored negentropy with reconcile_with_diff
- Configurable timeline recording (TOPO_EVENT_TIMELINE env var)
- WAL checkpoint deferral on writer
- AUTOINCREMENT removed from recorded_events
- temp_store=MEMORY for non-low-mem mode
- Preloaded sync benchmark for isolated measurement
