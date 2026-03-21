# Range-Owned Sync + Dependency Fast Lane Execution Plan

Date: 2026-03-21
Branch: `codex/dependency-ingest-fastlane`
Worktree: `/home/holmes/poc-7/.codex-worktrees/dependency-ingest-fastlane`

## Objective

Replace the current "discovery + durable wanted truth + per-event request-credit"
hot path with a simpler split:

1. bulk catchup is range-owned, append-only, and optimized for time-to-durable,
2. dependency repair is immediate, direct, and optimized for unblock latency,
3. the runtime coordinator is a small owner of connections, ranges, and command
   dispatch rather than the owner of per-event balancing state.

Primary outcome:

1. recent data reaches durable storage with less SQLite work on the wire path,
2. dependency replies project immediately instead of waiting behind large
   foreground batches,
3. multi-source balancing moves up to range assignment rather than living in
   the event request loop,
4. the dependency path stays minimal and only grows extra state when tests
   prove it is required,
5. the implementation optimizes for human readability and minimal lines of
   code, not just raw mechanism count.

## Design Summary

### Bulk path

1. A sync engine owns one explicit time range.
2. The first implementation uses the fixed priority ladder:
   - `hour`
   - `day`
   - `week`
   - `month`
   - `year`
   - `all`
3. This ladder is a bootstrap policy only. The long-term design keeps ranges
   arbitrary and coordinator-chosen.
4. It receives:
   - authenticated connection,
   - range bounds,
   - local IDs for that range,
   - output file path and memory limits.
5. It runs negentropy for that range in memory.
6. Both sides stream all missing blobs full-duplex as fast as QUIC and local
   buffering permit.
7. The receiver writes framed blobs to an append-only file.
8. On explicit completion or idle timeout, the file is finalized and handed to
   the ingest pipeline.
9. If a connection breaks mid-range, the session must not get stuck waiting to
   finish the range. Whatever was already durably appended remains useful data.
10. The target design does not use durable `wanted` rows for bulk catchup.
    Bulk progress is driven by coordinator-assigned ranges only.

### Dependency path

1. Missing deps discovered by projection stay represented as missing deps.
2. Dependency fetch exists to accelerate:
   - `project newest`
   - `project all in range`
   when blocked events prevent those goals from completing.
3. The runtime sends targeted dependency fetch requests directly to the origin
   peer of the blocking event whenever that source is known.
4. Blocked-event metadata therefore needs the source metadata of the blocking
   event available at ingest/projection time.
5. The simplest first design is to record source peer and observed remote
   address once in the append-only file metadata/header for the session, then
   stamp persisted events with the same source tag used by the normal
   connection ingest path.
6. Dependency replies are persisted immediately and projected immediately
   through the normal canonical ingest + `project_one` path.
7. If several dependency replies are already buffered together, the ingest side
   may opportunistically drain a tiny no-wait batch (`max 8-16`) but must not
   intentionally sleep to build a batch.

### Transport shape

1. There is exactly one QUIC connection per peer.
2. Dependency traffic uses two long-lived streams:
   - `dep_ctrl`: dependency request/control messages in both directions
   - `dep_data`: dependency response blobs in both directions
3. Range traffic is one semantic work lane per active range session.
4. A `RangeSession` runs in two strict phases:
   - reconcile/control
   - data transfer
5. The implementation may use separate control and data streams internally for
   a `RangeSession`, but that is an internal transport detail, not a top-level
   runtime abstraction.

### Anti-complexity rule

1. Do not add a dedicated dependency single-flight map up front.
2. First prove with tests whether duplicate dependency requests are a real
   problem in practice.
3. Only add an explicit single-flight map if the proof tests show repeated
   duplicate dependency requests that matter to correctness or latency.

### Tracking model

1. The coordinator must track completion in two dimensions:
   - `durable_complete`
   - `projection_complete`
2. These are logical states, not a requirement to add new stored state
   objects or counters.
3. Event-level durable/projected status should be derived from existing
   canonical and projection tables.
4. Range-level proofs should come from timestamped observations in tests and
   simple queries over existing tables, not from new persisted counters.
5. A range may become durably complete before it becomes projection complete.
6. Dependency fetch exists to reduce the gap between durable and projected
   completeness for blocked events.

### Readability rule

1. Prefer the simplest readable implementation over the most generalized one.
2. Prefer fewer moving parts and fewer lines of code when the behavior stays
   clear and testable.
3. Avoid rebuilding mechanisms already provided adequately by the transport,
   filesystem, or upstream `negentropy` library.
4. Public vocabulary should stay minimal:
   - `Range`
   - `RangeSession`
   - `DependencyFetch`
   - `ReceiveLog`
   - `durable`
   - `projected`

### Negentropy rule

1. Optimize for using the vendored/upstream `negentropy` library as provided to
   the maximum practical extent.
2. The target design should explicitly revisit whether SQLite-backed negentropy
   storage is still needed at all once range sync is append-only and
   coordinator-chunked.
3. If range-local ID sets fit comfortably in memory for the chosen initial
   range ladder, prefer in-memory negentropy state over bespoke SQLite-backed
   negentropy storage.

## Scope

In scope:

1. `src/runtime/sync_engine/*`
2. `src/runtime/peering/engine/supervisor.rs`
3. `src/runtime/transport/*` as needed for lane/session shape
4. `src/state/pipeline/*`
5. `src/state/projection/apply/*`
6. tests covering sync contract, blocked dependency repair, and multi-source
   range behavior
7. docs describing the new runtime story
8. startup recovery for partial append-only files

Out of scope:

1. event schema changes
2. projector semantic rule changes
3. transport trust model redesign
4. TLA mapping changes unless a later implementation slice actually changes a
   modeled runtime guard

## Non-Negotiable Requirements

### R1. Bulk sync is range-owned, not event-owned

1. Bulk catchup work units are explicit time ranges, not open-ended per-event
   request rows.
2. Range assignment across peers is the balancing mechanism.
3. Newer ranges must remain higher priority than older ranges.
4. The initial range ladder is `hour/day/week/month/year/all`.
5. Durable `wanted` rows are not part of the target bulk design.

### R2. Bulk receive path is append-only and durable-first

1. Bulk transfer writes blobs directly to an append-only file.
2. Bulk transfer does not interleave the network hot path with per-event
   projector/database work.
3. The finalized file is the handoff boundary into ingest.
4. Partial files are not discarded on startup; the runtime ingests them and
   deletes them after successful ingest.
5. The ingester must be able to parse to EOF and ignore a truncated tail frame.

### R3. Dependency replies are latency-first

1. Dependency replies must not wait behind large bulk ingest batches.
2. Dependency replies persist and project immediately via the normal canonical
   path.
3. Opportunistic reply batching is allowed only as a no-wait drain of what is
   already buffered now, capped at a small batch size.

### R4. Extra dependency coordination is evidence-gated

1. A dedicated dependency single-flight map is allowed only if tests prove it
   is needed in practice.
2. If proof tests do not show a practical duplicate-request problem, keep the
   simpler model with no explicit single-flight map.

### R5. One peer connection, multiple streams

1. There is exactly one authenticated QUIC connection per `(tenant, peer)`.
2. Dependency traffic uses two long-lived streams:
   - `dep_ctrl`
   - `dep_data`
3. Each active `RangeSession` is one semantic work lane with strict
   control-then-data phases.
4. Do not multiply peer connections just to emulate priority.

### R6. Runtime coordinator stays small

1. The coordinator owns:
   - connection lifecycle,
   - range scheduling,
   - stream and range priority,
   - ingest/command dispatch.
2. The coordinator does not own per-event balancing logic for bulk catchup.

### R7. Completion tracking must be explicit

1. The runtime tracks `durable_complete` and `projection_complete` separately.
2. Tests and runtime reasoning must not collapse those two notions into one.
3. This does not require adding new per-event or per-range state structs or
   stored counters.

### R8. Human-readable implementation is a first-class optimization target

1. The first implementation slice should minimize total mechanism count and
   lines of code.
2. Readability and local reasoning are primary design constraints, not
   afterthoughts.

### R9. Prefer stock negentropy over bespoke storage machinery

1. Reuse the `negentropy` library as directly as practical.
2. Do not keep SQLite-backed negentropy storage unless the range size and
   memory evidence show it is still necessary.

## Implementation Phases

### Phase 0: Baseline and proof-first investigation

1. Record current tests and perf evidence for:
   - blocked dependency repair,
   - recent-message visibility,
   - multi-source catchup,
   - low-memory behavior.
2. Add proof tests for the dependency path before introducing new runtime state:
   - repeated blockers on the same missing dep,
   - dependency replies arriving in bursts,
   - dependency replies arriving interleaved with bulk traffic.
3. Decide from those tests whether an explicit dependency single-flight map is
   actually required.
4. Measure whether the initial `hour/day/week/month/year/all` ladder is small
   enough to keep negentropy state in memory without SQLite-backed storage.

### Phase 1: Range engine contract

1. Define an explicit range-engine boundary:
   - input: connection, range, local IDs, output path, limits,
   - output: finalized append-only file + stats + completion reason.
2. Make range sync fully synchronous within the engine boundary.
3. Allow multiple engines in parallel across peers or across non-overlapping
   ranges for one peer.
4. Start with the fixed range ladder:
   - `hour`
   - `day`
   - `week`
   - `month`
   - `year`
   - `all`
5. Keep the engine contract general enough that the coordinator can later
   choose arbitrary chunks.
6. Treat a range as one semantic work lane even if its internal transport uses
   a control phase and a data phase.

### Phase 2: Append-only transfer format and finalize handoff

1. Define one on-disk append-only `ReceiveLog` format for received blobs.
2. Include session-level source metadata in the file header or equivalent
   metadata block:
   - source peer id
   - observed remote address
   - range identity
3. Add explicit completion semantics:
   - normal completion marker,
   - idle-timeout finalize,
   - partial/interrupted session result.
4. Ensure the file is ingestible after restart without hidden in-memory state.
5. The ingester reads valid frames until EOF and ignores a truncated or invalid
   tail frame.
6. On startup, ingest all leftover log files found on disk, then delete
   them after successful ingest.
7. If a session times out or disconnects after appending useful data, finalize
   what exists instead of waiting for perfect completion.

### Phase 3: Dependency fast lane

1. Add a direct dependency fetch command path from projection blocking to the
   runtime coordinator.
2. Route dependency replies to immediate canonical persist + immediate
   projection.
3. Allow only no-wait opportunistic reply micro-batching (`max 8-16`) if
   several replies are already buffered together.
4. Do not add a sleep or timer to build a dependency batch.
5. Treat dependency fetch as a follow-on optimization after the append-only
   range receiver and "time to project all in range" baseline are working.

### Phase 4: Coordinator collapse

1. Replace sink-side per-event multi-source balancing with range assignment.
2. Keep the coordinator as the owner of:
   - peer connections,
   - active range sessions,
   - dependency stream dispatch,
   - ingest-file execution.
3. Keep explicit priority:
   - `dep_ctrl` highest
   - `dep_data` above range work
   - newer ranges above older ranges

### Phase 5: Ingest pipeline split

1. Support two scheduling modes over one canonical ingest core:
   - `ingest_event_log(file)` for bulk range files,
   - `ingest_one(blob)` or equivalent immediate path for dependency replies.
2. Both paths must converge through the same canonical persist and projection
   rules.
3. Bulk path may batch aggressively.
4. Dependency path must optimize for unblock latency.

### Phase 6: Evidence and doc updates

1. Update `docs/DESIGN.md` after the code lands.
2. Add an evidence doc mapping each success criterion to code and test proof.

## Strict Success Criteria (SCs)

### SC1. Bulk sync work is range-owned

1. The implementation exposes an explicit range-engine API or equivalent owner
   boundary.
2. Multi-source balancing for bulk catchup is expressed as range assignment,
   not per-event request scheduling.
3. The first implementation uses the `hour/day/week/month/year/all` ladder.
4. The implementation does not depend on durable `wanted` rows for bulk.

Proof checks:

1. grep/file proof showing a range-engine owner and range scheduler
2. tests showing newer ranges are scheduled ahead of older ranges

End-to-end validation:

1. one sink pulling the same history from multiple peers must show distinct
   range assignment and successful full ingest

### SC2. Bulk receive is append-only and decoupled from projection

1. Bulk receive writes directly to an append-only file.
2. Projection happens only after file finalize handoff.
3. The network hot path no longer interleaves per-event projection work for the
   bulk path.
4. Startup recovery ingests partial files rather than discarding them.
5. The ingester tolerates a truncated tail frame and still ingests prior valid
   records.

Proof checks:

1. file-level proof of append-only writer + finalize handoff
2. tests for normal completion and idle-timeout finalize
3. tests for startup ingest of partial files
4. tests for tolerant EOF/tail parsing

End-to-end validation:

1. interrupt a bulk session mid-transfer, restart, and prove the finalized file
   or startup-ingested partial file still converges correctly

### SC3. Dependency replies project immediately

1. Dependency replies enter canonical storage immediately.
2. Dependency replies trigger immediate projection and cascade.
3. Dependency replies do not sit behind large bulk foreground batches.
4. This path is justified as an optimization for `project newest` and `project
   all in range` when blocked events exist.

Proof checks:

1. tests showing a blocked event unblocks as soon as its dependency reply
   arrives
2. tests showing a concurrent bulk transfer does not delay dependency unblock
   beyond the immediate ingest step

End-to-end validation:

1. create a blocker chain where an event is blocked, fetch its missing dep over
   the dependency lane, and prove the event becomes valid without waiting for
   bulk ingest drain completion

### SC4. Dependency single-flight is evidence-gated

1. There is an explicit proof test for repeated blocker demand on one missing
   dep.
2. If that test passes with existing state, no new single-flight map is added.
3. If that test fails, the implementation adds the smallest explicit
   single-flight map needed to make it pass.

Proof checks:

1. the proof test itself
2. file-level proof showing either:
   - no new single-flight map exists because the test passed, or
   - a minimal single-flight map exists because the test failed first

End-to-end validation:

1. multiple blocked events waiting on the same missing dep must not cause
   repeated dependency requests beyond the accepted single-flight policy

### SC5. Dependency burst ingest uses tiny no-wait micro-batching only

1. If multiple dependency replies are already buffered, the ingest path may
   drain a tiny batch (`max 8-16`).
2. There is no intentional sleep/timer to build that batch.
3. Bulk ingest batching and dependency micro-batching remain separate policies.

Proof checks:

1. file-level proof of reply batch cap
2. grep proof that no dependency ingest wait/sleep is introduced
3. unit/integration test for a dependency reply burst

End-to-end validation:

1. a burst of dependency replies should unblock a chain quickly while keeping
   per-reply latency low

### SC6. Runtime coordinator is structurally simpler

1. The runtime has explicit owners for:
   - connector,
   - range scheduler,
   - dependency stream dispatch,
   - ingest executor.
2. The coordinator does not retain the old per-event credit-balancing role for
   the bulk path.

Proof checks:

1. file-level proof of the new owner split
2. grep proof that old bulk-balancing hot-path logic is removed or retired from
   runtime use

End-to-end validation:

1. runtime startup with active peers should show:
   - connections established,
   - range engines scheduled,
   - dependency commands dispatched when blockers appear

### SC7. Durable and projected completeness are tracked separately

1. The runtime exposes `durable_complete` and `projection_complete` separately.
2. Tests prove a range can be durably complete before it is projection
   complete.
3. This proof comes from queries over existing tables/timestamps, not from new
   stored counters.

Proof checks:

1. file-level proof that no new counter/state machinery was introduced just for
   this distinction
2. tests for durable/projection split using existing tables and timestamps

End-to-end validation:

1. ingest a range containing blocked events and prove the range reaches durable
   completion before dependency repair finishes projection completion

### SC8. The implementation favors readability and direct upstream use

1. The first implementation slice is small and direct.
2. The implementation does not retain SQLite-backed negentropy storage unless
   evidence proves it is still required.

Proof checks:

1. file-level proof of direct `negentropy` usage
2. evidence section explicitly deciding whether SQLite-backed negentropy
   storage remains

End-to-end validation:

1. the code path for the first slice is explainable top-down in a small number
   of modules without cross-cutting hidden ownership

## Required Tests and Checks

The implementation is not complete unless these checks exist and pass.

### Proof-first dependency checks

1. A test where two or more blocked events depend on the same missing event and
   only one dependency request is emitted unless explicit evidence proves extra
   single-flight state is needed.
2. A test where dependency replies arrive while a bulk range ingest is active
   and the blocked event unblocks immediately.
3. A test where multiple dependency replies arrive together and are drained as
   a tiny no-wait burst instead of a large batch.

### Bulk range checks

1. Range-engine unit tests for:
   - explicit range bounds,
   - initial `hour/day/week/month/year/all` ladder,
   - full-duplex diff transfer,
   - completion marker,
   - idle-timeout finalize.
2. Multi-source tests proving range assignment across peers.
3. Low-memory tests proving small ranges can be selected without requiring the
   full-history range.
4. Startup-recovery tests proving partial append-only files are ingested and
   deleted on startup.

### Coordinator checks

1. Runtime tests proving `dep_ctrl` outranks all other work.
2. Runtime tests proving `dep_data` is not blocked by range session work.
2. Runtime tests proving newer ranges outrank older ranges.
3. Duplicate-connection/idempotency tests remain green.
4. Tests proving `durable_complete != projection_complete` is observable from
   existing tables/timestamps.

## Required End-to-End Validation

At least these end-to-end validations must be run:

1. Recent-message catchup:
   - one peer creates recent events,
   - sink prioritizes the hot range,
   - events become durable before older history completes.
   - if some events block on missing deps, dependency fetch improves projection
     completion rather than durable completion.
2. Dependency unblock:
   - sink receives an event blocked on a missing dep,
   - runtime issues a dependency fetch,
   - dep reply arrives and is projected immediately,
   - the blocked event becomes valid without waiting for bulk ingest.
3. Multi-source history:
   - history is split into range segments across peers,
   - all range files ingest successfully,
   - final projected state converges.
4. Low-memory constrained run:
   - only smaller ranges are scheduled,
   - dependency fetches still work,
   - no unbounded in-memory buffer is required.
5. Partial-file restart:
   - connection breaks mid-range,
   - startup ingests the partial file,
   - future rounds continue filling the same logical range later.

## Suggested Verification Commands

These commands are the minimum expected proof surface once implementation
starts. Adjust exact test names as code lands, but preserve the proof intent.

```bash
cargo check

bash scripts/check_boundary_imports.sh

# Dependency proof tests
cargo test -q --test sync_contract_tests dependency
cargo test -q --test topo_cascade_test

# Multi-source / range behavior
cargo test -q --test sync_graph_test
cargo test -q --test low_mem_test

# Runtime / realism
cargo test -q --test cheat_proof_realism_test -- --test-threads=1
cargo +stable test --release --test daemon_perf_test perf_sync_10k -- --nocapture --exact --test-threads=1
```

Interpretation requirements:

1. Dependency tests must prove immediate unblock behavior.
2. Multi-source tests must prove range scheduling rather than per-event bulk
   balancing.
3. Realism/perf tests must show no regression to startup or durable catchup
   liveness.
4. Evidence must explicitly state whether SQLite-backed negentropy storage was
   removed or retained and why.

## Required Evidence Artifact

Create after implementation:

- `docs/planning/RANGE_SYNC_DEPENDENCY_FASTLANE_EVIDENCE.md`

The evidence file must map SC1-SC6 to:

1. file-level proof,
2. grep output proof,
3. targeted test proof,
4. end-to-end validation proof.

## Working Rules

1. Work only in `/home/holmes/poc-7/.codex-worktrees/dependency-ingest-fastlane`.
2. Keep the first implementation slice as small as possible:
   - prove whether dependency single-flight is actually needed,
   - add tiny reply micro-batching only without an intentional wait,
   - avoid reintroducing the old per-event planner under new names.
3. First implementation priority order:
   - append-only range receiver,
   - durable/projection completion tracking,
   - time-to-project-all-in-range baseline,
   - dependency fetch optimization later.
3. Rebase on latest `master` before final review:
   - `git fetch origin`
   - `git rebase origin/master`
4. Do not mark the work complete until SC1-SC8 have explicit PASS evidence.
