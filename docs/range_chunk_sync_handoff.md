# Range-Chunk Sync Handoff

## Scope

This handoff is for a new implementation branch and worktree:

- Worktree: `/home/holmes/poc-7/.codex-worktrees/range-chunk-sync-design`
- Branch: `codex/range-chunk-sync-design`

Do not continue this work on `/home/holmes/poc-7` `master`.

## Important Starting-State Caveat

This worktree was created from committed branch state at:

- commit: `f2186ff`

That means this worktree is effectively off the current committed `master` tip, not off the large uncommitted tiered-window prototype in:

- `/home/holmes/poc-7/.codex-worktrees/tiered-hot-window-sync`

That other worktree contains:

- the recent tiered-window prototype
- the `daemon_tiered_window_perf_test.rs` benchmark
- current `parallel hour/day/week/month/full` experiments
- recent 10k / 50k / 200k perf artifacts

So the intended workflow for the next assistant is:

1. Implement from this clean branch/worktree.
2. Use the tiered prototype worktree as a read-only reference.
3. Recreate or port only the parts that prove useful.

## Mission

Replace the current ID-heavy hot sync path with a range-chunk downloader that still preserves:

- the strong recent-message projection behavior from parallel windowed discovery
- explicit high-priority blocker fetching by event id
- good bulk throughput and stable multi-peer behavior

The design target is:

- discovery remains windowed and newest-biased
- dense history/root fetches move by range chunks rather than explicit event ids
- sparse blockers/deps remain explicit `RequestIds` and are always higher priority
- multi-peer catchup divides range work explicitly across peers and steals stalled chunks
- single-peer join converges toward "almost just send me everything" in window order

## Why This Direction

The recent prototype in `/home/holmes/poc-7/.codex-worktrees/tiered-hot-window-sync` established two important facts:

1. Windowed discovery order matters a lot.
2. Explicit per-event request overhead is still a major limiter once windows get dense.

Measured prototype results on `parallel` nested windows:

- `50k`, `cable`:
  - hour `0.35s`
  - day `0.40s`
  - week `0.60s`
  - month `1.55s`
  - full `65.13s`
- `200k`, `cable`:
  - hour `0.35s`
  - day `0.40s`
  - week `1.05s`
  - month `7.87s`
  - full `812.90s`

Artifacts:

- `/home/holmes/poc-7/.codex-worktrees/tiered-hot-window-sync/target/perf-results/daemon_tiered_window_perf_test.parallel_50000_cable.summary`
- `/home/holmes/poc-7/.codex-worktrees/tiered-hot-window-sync/target/perf-results/daemon_tiered_window_perf_test.parallel_200000_cable.summary`

The recent-window behavior is already strong. Full catchup still scales poorly. The most plausible next gain is:

- keep the same discovery order
- stop insisting on ID-by-ID fetch for dense windows

## Design Principles

### Preserve

- Parallel repeated windowed negentropy:
  - last hour
  - last day
  - last week
  - last month
  - full
- Explicit blocker/dependency requests by event id.
- Receiver-side planning.
- Multi-peer duplicate suppression.

### Add

- Range metadata from discovery/reconciliation.
- Range-chunk requests for dense windows.
- Chunk ownership and work stealing across peers.
- Bounded chunk hedging only after progress failure.

### Do Not Do

- Do not replace blocker/dependency requests with range fetches.
- Do not make the source guess hidden deps for encrypted content.
- Do not regress the recent-message projection wins from parallel window rounds.

## Correct Mental Model

The intended end state is one unified scheduler with two fetch primitives:

1. `RequestRangeChunk`
   - for dense history/root windows
2. `RequestIds`
   - for sparse blockers and leftovers

Priority order should be:

1. blocker ids
2. hot-window range chunks
3. colder-window range chunks
4. sparse leftovers / full cleanup

That is a unified planner, not an ad hoc hybrid.

## Proposed Protocol Shape

### Discovery / range metadata

Extend the current windowed reconciliation path so that it can expose interval metadata without requiring full ID expansion first.

Minimum useful metadata for a missing interval:

- `ts_min_inclusive_ms`
- `ts_max_exclusive_ms`
- `event_count`
- `encoded_size_bytes`
- `priority_lane`
- optional:
  - `newest_ts_ms`
  - `oldest_ts_ms`
  - `fingerprint`
  - `estimated_item_density`

This can come from:

- explicit new frames layered on top of current negentropy usage, or
- a local range-analysis pass driven by current windowed storage

The key requirement is that the receiver learns enough to segment and lease work by bytes rather than only by explicit event ids.

### Range request

Introduce a new request primitive with explicit bounding:

```text
RequestRangeChunk {
  lane,
  ts_min_inclusive_ms,
  ts_max_exclusive_ms,
  cursor,
  max_bytes,
  max_items
}
```

Responder behavior:

- stream events newest-first within the requested interval
- stop at `max_bytes` or `max_items`
- return a continuation cursor or "done"

Associated completion frame:

```text
RangeChunkEnd {
  next_cursor,
  bytes_sent,
  events_sent,
  done
}
```

### Blockers

Keep `RequestIds` for:

- direct blockers
- deps discovered during projection
- sparse leftovers where chunk fetch is no longer efficient

These should always outrank range-chunk work.

## Ordered Space and Chunk Model

Use one global ordering:

- `created_at DESC`
- tie-break `event_id DESC`

Range chunks should be contiguous in that ordering. Do not use raw SQLite byte offsets.

Why:

- newest-first delivery stays natural
- scrolling to an arbitrary historical point stays natural
- chunk ownership and stealing are easier to reason about

## Multi-Peer Strategy

Do not assign whole windows to peers. Assign contiguous chunks.

### Ownership

- each chunk has exactly one owner peer initially
- ownership is a receiver-side lease
- leases are in-memory and bounded

### Initial assignment

Pick owner peer by:

- known possession of the range
- current inflight bytes
- recent service rate
- recent chunk completion latency
- current queue depth

### Stealing

Idle peers should steal only when:

- they are below a unique-work watermark
- some other peer owns chunks that are not progressing enough

Steal policy:

- oldest unstarted chunk first, or
- hottest outstanding chunk first

### Hedging

At most one backup hedge per chunk.

Do not duplicate chunks eagerly.

Hedging should be triggered by:

- lack of owner progress, or
- explicit idle-peer steal path

not just by lease age alone.

## Single-Peer Behavior

For a single fresh peer with no data:

- discovery should very quickly identify the newest hour/day/week/month/full windows
- the receiver should immediately start chunk requests in that order
- the source should quickly converge to streaming chunk responses almost continuously
- blockers should still cut in ahead of chunk work

This should feel close to:

- "send me the newest stuff now"
- then "keep pouring history in window order"

without abandoning correctness or dep handling.

## Scrollback / Arbitrary Historical Window

The same machinery should support:

- "show me the previous `N` messages before timestamp `T`"
- "show me the previous `N` messages before event `E`"
- "show me all messages in `[A, B)`"

That means the range-chunk machinery should not be hard-coded to only the newest suffix windows.

The time-window rounds are just the default hot-window schedule, not the only valid ranges.

## Encrypted Events

Assume the source may not know inner deps.

Therefore:

- range discovery and chunk delivery can use only:
  - type
  - timestamp
  - outer metadata
- explicit blocker chasing still happens receiver-side after projection/decrypt reveals deps

This is why explicit blocker requests must remain a first-class primitive.

## Suggested Phased Implementation

### Phase 1: Port the tiered benchmark and preserve the existing recent-message win

Bring over or recreate the current tiered benchmark from the prototype worktree:

- `tests/daemon_tiered_window_perf_test.rs`

Re-establish the current baseline on this clean branch before adding range fetch.

### Phase 2: Introduce range metadata without changing fetch yet

Add enough instrumentation/metadata so the receiver can reason about:

- dense empty intervals
- estimated encoded bytes per interval
- chunk boundaries in ordered time space

This phase should still use existing `RequestIds`.

### Phase 3: Add single-peer range-chunk fetch

Implement:

- `RequestRangeChunk`
- responder-side newest-first chunk serving
- continuation cursor
- range-chunk ingest path

Keep blockers on explicit IDs and verify they preempt chunk work.

### Phase 4: Add multi-peer chunk leases and stealing

Implement:

- per-chunk owner lease
- idle-peer stealing
- bounded hedge

Prove duplication stays low.

### Phase 5: Sparse fallback

When a chunk becomes sparse, mixed, or nearly satisfied:

- degrade to exact `RequestIds`

Do not overfit the chunk path to the last sparse tail.

## Files Likely Relevant

Current branch:

- `src/runtime/sync_engine/session/initiator.rs`
- `src/runtime/sync_engine/session/responder.rs`
- `src/runtime/sync_engine/session/control_plane.rs`
- `src/runtime/sync_engine/session/coordinator.rs`
- `src/runtime/sync_engine/session/connection_scope.rs`
- `src/runtime/sync_engine/session/windowing.rs`
- `src/runtime/sync_engine/session/data_plane.rs`
- `src/shared/protocol.rs`
- `src/state/db/wanted.rs`
- `src/state/projection/apply/stages.rs`
- `tests/sync_graph_test.rs`
- `tests/daemon_perf_test.rs`

Reference-only prototype worktree:

- `/home/holmes/poc-7/.codex-worktrees/tiered-hot-window-sync/src/runtime/sync_engine/session/windowing.rs`
- `/home/holmes/poc-7/.codex-worktrees/tiered-hot-window-sync/src/runtime/sync_engine/session/control_plane.rs`
- `/home/holmes/poc-7/.codex-worktrees/tiered-hot-window-sync/src/state/db/wanted.rs`
- `/home/holmes/poc-7/.codex-worktrees/tiered-hot-window-sync/src/state/projection/apply/stages.rs`
- `/home/holmes/poc-7/.codex-worktrees/tiered-hot-window-sync/src/state/projection/create.rs`
- `/home/holmes/poc-7/.codex-worktrees/tiered-hot-window-sync/tests/daemon_tiered_window_perf_test.rs`

## Success Criteria

### SC1: Preserve recent-message performance benefits

The new implementation must preserve the recent-window advantage already demonstrated by the tiered prototype.

Proof:

- Recreate `daemon_tiered_window_perf_test.rs` or equivalent.
- Run at least:
  - `50k`, `cable`
  - `200k`, `cable`
- Show that:
  - hour/day/week remain close to current prototype levels
  - month does not regress materially

### SC2: Improve dense-window/full-history throughput relative to ID-only tiered fetch

The new implementation must improve or at least materially simplify the dense-history transfer path.

Proof:

- Compare against the current prototype baselines:
  - `parallel 50k cable`
  - `parallel 200k cable`
- Show at least one of:
  - lower full-history wall time
  - lower sender/request overhead with comparable wall time
  - lower control-plane volume with comparable wall time

### SC3: Blockers stay explicit and hot

A missing dep discovered during projection must still be fetchable immediately by id and must preempt chunk work.

Proof:

- Add focused unit/contract coverage for:
  - blocker discovered during chunk-driven ingest
  - blocker request outranks range chunk request
  - encrypted wrapper path where deps become visible only after decrypt

### SC4: Multi-peer duplication stays bounded

Range work must not recreate the old duplicate spray problem.

Proof:

- Extend the existing multi-peer catchup metrics tests.
- Add or preserve duplication gates for:
  - `2x10k`
  - `4x10k`
  - `8x10k`
- Target:
  - duplication ratio `<= 1.6x`
  - or a justified revised threshold backed by measurements

### SC5: Arbitrary historical window is supported

The system must be able to prioritize and display a non-latest historical slice.

Proof:

- Add an end-to-end test that requests a historical window by timestamp or anchor event.
- Show that:
  - the previous `N` messages in that window become projected quickly
  - their blockers are also resolved
  - bulk catchup does not starve that historical hot window

## Required Tests / Checks

At minimum, the next assistant should leave behind:

### Unit / contract tests

- protocol roundtrip tests for new range frames
- range cursor / chunk boundary tests
- coordinator lease / steal / hedge tests
- blocker-vs-range priority tests
- sparse-fallback tests

### End-to-end tests

- single-peer tiered hot-window perf
- historical-window hot fetch perf
- multi-peer duplication and catchup metrics

### Performance checks

- `50k` `cable`
- `50k` `fast-mobile`
- `200k` `cable`

Report:

- hour/day/week/month projected times
- full catchup wall time
- duplication ratio for multi-peer
- newest/historical hot-window projected times

## End-to-End Validation Required Before Calling This Done

The task is not done until the following are demonstrated on this branch/worktree:

1. A fresh single-peer join can display the most recent hot windows quickly in window order.
2. A historical anchored window can be prioritized and displayed quickly without waiting for bulk catchup.
3. Full catchup remains stable and does not materially regress under cable/mobile shaping.
4. Multi-peer catchup uses chunk ownership/stealing without unacceptable duplication.
5. Explicit blockers still preempt range chunks and unblock projection quickly.

## Recommended First Move

The first concrete move should be:

1. Port the tiered benchmark and the encrypted-wrapper timestamp fix from the prototype worktree.
2. Re-establish the current `parallel` baseline on this clean branch.
3. Only then add range metadata and chunk fetch.

That keeps the work grounded in a known-good recent-message baseline instead of restarting from abstractions.
