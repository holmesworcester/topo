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

### Idea 2: Hash-chain signature batching

Each message includes a 32-byte `prev_message_ref` (hash of sender's
previous message blob). During catchup:

1. Sort received messages by signer, find chain tips (newest)
2. Verify ed25519 on tips only (~2-5 verifies total)
3. Walk chain backwards verifying hash links (~1µs each vs 65µs)

For 10k messages from 2 devices: 2 sig verifies + 10k hash checks.
Saves ~640ms of the current 650ms sig verify cost.

Requires wire format change (new field in message events). Safe because
an unbroken hash chain from a verified tip authenticates the entire chain.

### Idea 3: Project newest and blocking events first

The projection cursor processes events in priority order:

1. **Subscription-matching** — events visible in the current UI view
2. **Newest** — `created_at DESC` so recent messages appear first
3. **Dependency-unblocking** — events that unblock something we've
   already tried to project
4. **Everything else** — old history fills in behind the scenes

The user sees the latest messages in <1s even during a 100k event
catchup. History appears progressively.

### Idea 4: Download what matters first

Mirror projection priority in the download scheduler:

- `wanted_events.priority_ts` already sorts `created_at DESC` (newest first)
- When projection blocks on a missing dep, boost that dep to MAX_PRIORITY
- Prefer downloading events that are either newest or unblock stored events

This means the download order matches what the user needs, not just
what negentropy discovered.

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

20+ read sites across the codebase need migration. Medium-high effort
but reduces write amplification permanently.

### Idea 8: Defer neg_items to incremental rebuild

Track last-synced rowid in `neg_meta`. Before each negentropy round,
bulk-insert new events from the events table. Moves the cost from the
hot ingest path to the observer loop.

### Idea 9: Skip cascade for dependency-free types

Messages, reactions, and file_slices have no dependents. The cascade
check always returns empty. Skip it based on event type metadata.

### Idea 10: Skip subscription check when none active

Cache a flag for "any active subscriptions?" — skip the per-event
subscription hook when there are none.

### Idea 11: Progressive UI rendering

Show partial projected state while sync is ongoing. "N more messages
loading..." instead of a spinner. The UI queries projected state which
fills in progressively.

---

## What's Already Merged (on master)

- Forward-on-have live hint bus (sub-second live delivery)
- Bidirectional DiscoveryHints with real byte sizes (vendored negentropy)
- Credit watermarks tuned for file slices (2 MiB high, 512 KiB low)
- Batch projection architecture (gather/map/reduce/apply) — on branch, not merged
- Configurable timeline recording (`TOPO_EVENT_TIMELINE` env var)
- Batched recorded_events check in observe_many_for_peer
- Cached rebuild_blocks (count-based skip)
