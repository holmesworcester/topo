# Sync Performance Ideas

## Goal

Make sync invisible to the user (<1s perceived latency for recent content)
when catching up on a fast connection, regardless of workspace size.

## Current State (March 2026)

| Benchmark | msgs/s |
|---|---|
| Continuous 10k (forward-on-have) | ~5,000 |
| Preloaded 10k (negentropy + ingest) | ~5,000 |
| Bidirectional 10k (create + sync) | ~4,400 |
| 50k one-way | ~2,100 |

For small messages (~400 bytes), the system is CPU/DB-bound on all
non-mobile links. Network is never the bottleneck for messages.

## Where Time Goes (10k events, 2.0s wall)

| Phase | % |
|---|---|
| ed25519 sig verification (10k × 65µs) | 32% |
| Persist: 4 INSERTs per event across 4 tables | 36% |
| Projection: context load + dispatch + write ops | 17% |
| Negentropy reconciliation | 10% |
| QUIC transfer | 5% |

## Things We Tried (not yet merged)

These are on the `codex/batch-projection-tuning` and
`codex/batch-projection-refactor` branches. Results were modest —
the bottleneck is fundamental to the per-event SQLite write model.

| Change | Result |
|---|---|
| Batch projection pipeline (gather/map/reduce/apply) | Neutral — batching reads doesn't help when per-event writes dominate |
| Multi-row INSERT for persist phase | Neutral — prepared statements inside a transaction are already near-optimal |
| Project queue bypass (direct projection, skip enqueue) | Neutral — saves the enqueue INSERT but projection still does the same writes |
| Parallel sig verify via rayon | Neutral — batch sizes too small to amortize thread pool overhead |
| Larger batch sizes (write_batch_cap 5000, drain 1000, channel 10k) | +17% on continuous (5.3K), neutral on bidirectional, worse on 50k (memory) |
| WAL checkpoint deferral on writer | Neutral |
| synchronous=OFF | Neutral — confirms fsync is not the bottleneck |
| temp_store=MEMORY | Neutral |
| AUTOINCREMENT removal from recorded_events | Neutral |

**Key learning**: SQLite prepared statements inside a transaction are
already ~2µs per execute. Multi-row INSERT, batching, and parallelism
don't help because the overhead is in B-tree operations, not statement
setup. The only way forward is **fewer writes per event**.

---

## Known Bugs That Affect Perceived Latency

### Send-idle stall (1s+ pauses with queued work)

Documented in `docs/planning/PERF_HYPOTHESES_2026-03-12.md`. Overlapping
live sessions cause 1.0-1.1s `SendIdle` gaps where the sync handler has
events queued for transfer but isn't sending them. This alone can blow
the entire <1s latency budget even if throughput is high. Must be
investigated and fixed — no amount of throughput optimization helps if
the protocol stalls for a full second between bursts.

---

## Corrections From Code Review

These were identified by tracing the actual code paths:

- **`priority_ts` is set to discovery time (now), not event `created_at`**
  (`wanted.rs:195`). Newest-first download doesn't actually work yet.
  The wire `DiscoveryHint` doesn't carry `created_at_ms` (`protocol.rs:25`),
  so the scheduler has no way to sort by event age.

- **Messages DO have dependents.** Reactions and files depend on messages
  (`event_modules/mod.rs:177`). Cascade skip should only apply to true
  leaf types (reactions, file_slices), not messages.

- **Hot ingest bypasses project_queue** (on the tuning branch) and calls
  `project_batch()` directly after commit. Projection priority (Idea 3)
  needs to be implemented in that direct path, not just in project_queue.

- **Blob re-read on hot ingest.** `run_persist_phase()` already has blob
  bytes in memory, but `project_batch()` re-reads them from the events
  table. Carrying blobs through `PersistPhaseOutput` avoids this re-read.

- **Incremental neg_items rebuild is not multi-workspace safe.** The
  current helper stamps every event with one `workspace_id`, which
  breaks on a shared DB hosting multiple workspaces.

---

## Ideas for <1s Perceived Latency

### Idea 1: Memory-first processing — only store what earns it

Don't write event blobs to SQLite until they're projected or part of a
dependency chain we care about. Events live in memory until they prove
useful.

Flow:
1. Receive blob from QUIC → `HashMap<EventId, Vec<u8>>` in memory
2. Parse, verify sig, check deps — all from memory, no DB
3. **If it projects successfully** → write blob + projection results
   to SQLite in one transaction. The event earns its storage.
4. **If it blocks on a dep we already have stored** → write to SQLite
   (it's part of a chain we're building)
5. **If it blocks on a dep we DON'T have** → keep in memory, boost
   that dep's download priority
6. **Memory pressure** → flush oldest to SQLite as fallback
7. **Crash** → lose in-memory events, re-request on next sync

This means messages (95% of events) go: QUIC → memory → parse → project
→ 1 SQLite transaction (blob + projection tables + valid_events). Down
from 4 separate INSERTs across 4 tables in the current model.

Identity chain events get stored as they unblock each other. Orphan
events (deps not downloaded yet) cost zero SQLite until their deps arrive.

`wanted_events` and `wanted_sources` can also be in-memory. Losing them
on crash is fine — negentropy rediscovers everything in the next round.

**Risks** (from Codex review):
- Invasive: projection assumes blobs live in `events` before processing.
  Signer resolution reads signer blobs from `events JOIN valid_events`.
  Egress serves blobs from `events`. All need an in-memory overlay.
- Low-memory mode: caps `shared_ingest_cap` to 2 and enforces 24 MiB
  per-instance limits. An in-memory orphan pool can break this.
- Crash recovery: `project_queue` and `pending_shared_fanouts` rely on
  durable recovery boundaries. Memory-first needs a clear rule for which
  blocked/fanout states still become durable.
- Demand suppression: `recorded_events` check in `wanted.rs:105` assumes
  events are in the DB. In-memory events need an overlay for this check.

### Idea 2: Hash-chain signature batching

Each message includes a 32-byte `prev_message_ref` (hash of sender's
previous message blob). During catchup:

1. Sort received messages by signer, find chain tips (newest)
2. Verify ed25519 on tips only (~2-5 verifies total)
3. Walk chain backwards verifying hash links (~1µs each vs 65µs)

For 10k messages from 2 devices: 2 sig verifies + 10k hash checks.
Saves ~640ms of the current 650ms sig verify cost.

Requires wire format change (new field in message events).

**Design concerns** (from Codex review):
- Chain scope: per signer or per signer+workspace? A global chain per
  signer creates cross-workspace coupling with encrypted events.
- What to hash: outer encrypted event ID or inner signed bytes? Outer
  fits sync, inner fits signature semantics.
- Fork handling: concurrent sends from same signer create ambiguous tips.
  Need fork rejection or deterministic branch choice.
- Mixed-mode: legacy events, key rotations, and gaps force fallback to
  ordinary ed25519 verification. Win is on contiguous new history only.
- Scope: message-only batching leaves reactions, deletions, files on the
  old path. A generic `prev_signed_event_ref` is cleaner but bigger.
- This is an authenticity optimization, not a freshness proof.

### Idea 3: Project newest and blocking events first

The projection cursor processes events in priority order:

1. **Subscription-matching** — events visible in the current UI view
2. **Newest** — `created_at DESC` so recent messages appear first
3. **Dependency-unblocking** — events that unblock something we've
   already tried to project
4. **Everything else** — old history fills in behind the scenes

**Prerequisite**: the hot-ingest direct projection path (post-commit
`project_batch()`) needs to honor this priority order, not just the
queue-based path.

### Idea 4: Download what matters first

**Prerequisite**: add `created_at_ms` to the `DiscoveryHint` wire format
(`protocol.rs:25`). Currently hints don't carry timestamps, so
`wanted_sources.priority_ts` is set to discovery time (now), not event
creation time. Without this, newest-first scheduling doesn't work.

With `created_at_ms` in hints:
- Store it in `wanted_sources.priority_ts` during `observe_many_for_peer`
- The planner already sorts `priority_ts DESC` — newest events get
  requested first automatically
- When projection blocks on a missing dep, boost that dep's priority

### Idea 5: Newest-first negentropy discovery

The hot/cold window split is currently disabled (all rounds are Full).
With forward-on-have handling live events and the download scheduler
handling priority, negentropy just needs to discover everything — the
scheduler decides what to request first. So this is already handled
by idea 4 without changing negentropy.

### Idea 6: Subscription-aware projection priority

When the projection cursor picks events, check against active
subscriptions first. Project matching events before old history.

**Privacy**: this only affects local projection order, not download
order. No information about UI state leaks to peers.

### Idea 7: Consolidate recorded_events into events table

Add `recorded_by`, `recorded_at`, `source` columns to `events`.
Eliminates one full table's INSERTs from the hot path. The "already
local" check becomes `SELECT 1 FROM events WHERE event_id = ?`.

100+ references to `recorded_events` across the codebase need migration.
Medium-high effort but reduces write amplification permanently.

### Idea 8: Defer neg_items to incremental rebuild

Track last-synced rowid in `neg_meta`. Before each negentropy round,
bulk-insert new events from the events table. Moves the cost from the
hot ingest path to the observer loop.

**Caveat**: must handle multi-workspace DBs correctly. The current
prototype stamps every event with one `workspace_id`, which is not
safe for shared DBs hosting multiple workspaces.

### Idea 9: Skip cascade for true leaf types only

~~Messages, reactions, and file_slices have no dependents.~~

**Correction**: messages DO have dependents (reactions, files). Cascade
skip should only apply to true leaf types: reactions, file_slices.
These types are never referenced as a dependency by any other type.

### Idea 10: Skip subscription check when none active

Cache a flag for "any active subscriptions?" — skip the per-event
subscription hook when there are none. Subscription filtering currently
only exists for messages (`subscriptions/engine.rs:122`), so this is
a small win but easy.

### Idea 11: Progressive UI rendering

Show partial projected state while sync is ongoing. "N more messages
loading..." instead of a spinner. The UI queries projected state which
fills in progressively.

### Idea 12: Avoid blob re-read on hot ingest

`run_persist_phase()` already has blob bytes in memory from the ingest
channel. `project_batch()` then re-reads them from the events table.
Carry blobs through `PersistPhaseOutput` to project from memory.
Cheap localized optimization, no architectural change.

### Idea 13: Fix the send-idle stall

The 1s+ SendIdle gaps documented in `PERF_HYPOTHESES_2026-03-12.md`
are a protocol-level bug where overlapping sessions cause the sync
handler to stall with events queued but not sending. This is a
blocking bug for <1s perceived latency regardless of throughput.

---

## What Would Ship First (2-week push)

Based on code review feedback, the highest-impact items for perceived
latency that don't require architectural changes:

1. **Add `created_at_ms` to DiscoveryHint wire format** → enables real
   newest-first download scheduling (Idea 4 prerequisite)
2. **Fix the send-idle stall** (Idea 13) → removes 1s+ pauses
3. **Progressive UI rendering** (Idea 11) → makes sync feel instant
4. **Low-risk trims**: skip empty subscriptions (Idea 10), avoid blob
   re-read (Idea 12), skip cascade for leaf types only (Idea 9)

Defer for later: memory-first processing (Idea 1), hash-chain batching
(Idea 2), recorded_events consolidation (Idea 7).

---

## What's Already Merged (on master)

- Forward-on-have live hint bus (sub-second live delivery)
- Bidirectional ExactDiffHints with real byte sizes (vendored negentropy)
- Credit watermarks tuned for file slices (2 MiB high, 512 KiB low)
- Configurable timeline recording (`TOPO_EVENT_TIMELINE` env var)
- Batched recorded_events check in observe_many_for_peer
- Cached rebuild_blocks (count-based skip)

## What's on Branches (not merged)

- `codex/batch-projection-tuning`: batch projection architecture,
  multi-row INSERT, project queue bypass, larger batch sizes,
  preloaded sync benchmark
- `codex/batch-projection-refactor`: full gather/map/reduce/apply
  pipeline, parallel rayon map, project_batch_from_blobs
