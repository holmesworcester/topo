# Hot/Cold Sync + Leased Egress Execution Plan

Date: 2026-03-11
Branch: `codex/hot-cold-sync-plan`
Worktree: `/tmp/poc-7-hot-cold-sync`
Status: implemented; correctness verification complete; performance follow-up still required

Review follow-up:
`docs/planning/CREATE_PATH_ATOMICITY_FOLLOWUP.md` captures the proposed
create-side simplification discussed after implementation review. It is a
follow-up design note, not a description of the current branch behavior.

## Objective

Preserve the current sync and bootstrap behavior while removing duplicate
wire sends under concurrent sessions and keeping live messages responsive
during large transfers.

The implementation target is intentionally small:

1. Keep the current repeated-session runtime model.
2. Make the peer-scoped egress queue safe for multiple concurrent sessions.
3. Push newly-created shared events directly into peer egress queues so an
   active session can send them without waiting for a fresh full reconcile.
4. Split reconciliation into `hot` and `cold` timestamp windows so we do not
   repeatedly drill through the entire historical match set at live-message
   cadence.
5. Prevent `file_slice` bursts from monopolizing ingest/projection visibility
   by giving bulk its own lower-priority lane while preserving arrival order
   inside the foreground lane.

## Scope

In scope:

- `src/state/db/egress_queue.rs`
- `src/state/db/project_queue.rs`
- `src/state/db/store.rs`
- `src/state/projection/create.rs`
- `src/runtime/sync_engine/session/{initiator.rs,responder.rs,data_plane.rs,logging.rs,windowing.rs}`
- `src/state/pipeline/{mod.rs,phases.rs}`
- `src/shared/tuning.rs`
- targeted test additions in `tests/` and unit tests near the changed modules

Out of scope:

- collapsing all duplicate authenticated connections to one canonical transport slot
- changing multi-source ownership math
- replacing the current repeated-session transport shape with a long-lived actor

## Non-Negotiable Requirements

### R1. Concurrent sessions must not duplicate event sends

If two sessions for the same peer are active at once, they may both discover
the same delta, but the runtime must send each event blob at most once from a
given side.

### R2. Live messages must remain responsive during large transfers

While a large file is still downloading, newly-created chat messages must be
able to reach the peer before the transfer completes.

### R3. Low-memory shape must stay peer-scoped

Any new coordination state must stay O(peers). Large backlog state continues to
live in SQLite queues.

### R4. Existing sync semantics stay intact

The same protocol still supports:

1. ongoing sync
2. both sides initiating
3. efficient download
4. balanced multi-source sink behavior

## Implementation Plan

### Phase 1. Regression tests first

Add fast tests that cover:

1. leased egress claim behavior and priority ordering
2. hot/cold window envelope parsing and filtered negentropy storage
3. live message arrival during an in-progress file transfer
4. the double-send regression at the runtime level

### Phase 2. Leased + priority egress queue

Change the egress queue from single-consumer FIFO to peer-scoped
multi-consumer leasing:

1. queue rows carry `lease_owner`, `lease_until`, `priority_lane`, `priority_ts`
2. `claim_batch` atomically leases only currently unleased rows
3. `mark_sent` only deletes rows owned by the claiming session
4. session cleanup releases only that session's leases; it does not wipe the
   peer queue
5. claim ordering is by lane, then recency, then row id

### Phase 3. Direct enqueue for locally-created shared events

When a local shared event is created:

1. store/project it as today
2. enqueue it directly to all known remote peer egress queues for that tenant
3. rely on queue dedupe so later negentropy discovery does not duplicate rows

This is the path that keeps live messages moving during an active large sync.

### Phase 4. Hot/cold reconciliation windows

Add a lightweight session envelope on top of the first negentropy message:

1. first outbound session is `full`
2. later hot sessions use `ts >= cutoff`
3. periodic cold sessions use `ts < cutoff`

The storage adapter is range-filtered from the same `shared_event_index` table. The
runtime schedules hot sessions frequently and cold sessions less frequently.

### Phase 5. Projection and ingest fairness for bulk slices

Protect user-visible progress during large file sync without introducing a
second event universe:

1. batch-writer ingest partitions foreground before bulk
2. slice-heavy batches use a much smaller write cap
3. `project_queue` claims foreground before bulk
4. foreground preserves arrival order; no recency reordering within that lane

## Hard Success Criteria

### SC1. Double-send regression is fixed

Proof:

1. a runtime integration test shows duplication stays below the regression threshold
2. queue unit tests prove concurrent claims do not return the same row twice

### SC2. Live messages arrive while a file is still incomplete

Proof:

1. a CLI test starts a large file transfer
2. a later message arrives before the file finishes
3. the assertion confirms the file was still in progress when the message became visible

### SC3. New local shared events bypass full reconcile latency

Proof:

1. a unit/integration test shows local create writes peer egress rows directly
2. runtime behavior demonstrates those rows are drained by active sessions

### SC4. Hot/cold windows are real, not just documented

Proof:

1. unit tests for range-filtered negentropy storage pass
2. protocol/logging tests can decode the windowed session envelope

### SC5. `file_slice` bulk cannot monopolize visibility

Proof:

1. a CLI test observes a large file still in progress
2. a later message becomes visible before file completion
3. queue/unit coverage proves projection keeps foreground ahead of bulk without reordering foreground arrival

### SC6. Existing behavior remains intact

Proof:

1. sync contract tests pass
2. representative CLI and graph sync tests pass
3. low-memory tests covering sync continue to pass

## Required Verification Commands

Executed verification:

```bash
cargo test -q --lib state::db::project_queue
cargo test -q --lib state::pipeline
cargo test -q --lib runtime::sync_engine::session::windowing
cargo test -q --test scenario_tests queue -- --nocapture
cargo test -q --test double_send_test -- --nocapture --test-threads=1
cargo test -q --test cli_test test_cli_live_message_during_large_file_sync -- --nocapture --test-threads=1
cargo test -q --test sync_contract_tests
cargo test -q --test cli_test
cargo test -q
```

## End-to-End Validation

End-to-end validation is not complete until:

1. the double-send regression test passes
2. the live-message-during-file-transfer test passes
3. the broader sync regression suites listed above pass

## Evidence

- SC1: `tests/double_send_test.rs` now reproduces the old failure mode against the daemon runtime and passes at `1.00x` duplication after leased egress was added. `egress_queue` unit coverage proves concurrent claims do not return the same row twice.
- SC2: `tests/cli_test.rs::test_cli_live_message_during_large_file_sync` proves a message becomes visible on Bob while the file is still incomplete.
- SC3: `egress_queue` unit coverage plus `projection/create.rs` direct enqueue path prove newly-created shared events enter peer egress queues immediately.
- SC4: `windowing.rs` and range-storage tests cover the `Full`/`Hot`/`Cold` envelope and range-filtered storage.
- SC5: `project_queue` and pipeline unit tests cover foreground-vs-bulk ordering; the CLI file-sync test provides end-to-end confirmation that bulk slices do not monopolize visibility.
- SC6: `sync_contract_tests`, targeted CLI regressions, the full CLI suite, and the full `cargo test -q` suite pass on this branch.

## Performance Status

Release checks rerun on this branch after the final correctness fixes:

```text
perf_sync_10k:
  current = 3.69s, 2709 msgs/s, 43.0 MiB
  PERF.md = 2.37s, 4211 msgs/s, 70.4 MiB

perf_continuous_10k:
  current = 2.26s, 4432 msgs/s, 36.7 MiB
  PERF.md = 1.85s, 5412 msgs/s, 66.6 MiB

file_throughput_test:
  100 MB  current = 108.9 MB/s   PERF.md = 204.6 MB/s
  10 MB   current = 106.2 MB/s   PERF.md = 206.0 MB/s
  1 GB    current = 78.9 MB/s    PERF.md = 205.0 MB/s
  0.2 MB  current = 157.2 MB/s   PERF.md = 185.6 MB/s
```

Current sync-graph spot checks, compared to the earlier branch-local release run:

```text
catchup_dead_peer_dropout:
  current = 2660 ms
  earlier branch run = 2401 ms

catchup_non_uniform_sources:
  current = 231 ms
  earlier branch run = 229 ms

ten_hop_chain_10k:
  current = 25865 ms
  earlier branch run = 34281 ms
```

Interpretation:

1. correctness is green,
2. memory is lower on the daemon perf tests,
3. warm-sync throughput and file-slice throughput are still below the `docs/PERF.md` baseline,
4. multi-source/catchup does not show a clear broad regression from the earlier branch-local run, but `catchup_dead_peer_dropout` is slightly slower and there is no `PERF.md` baseline for that family.

## Follow-Up TODO

Before calling this work performance-complete:

1. recover the `docs/PERF.md` warm-sync and file-throughput baselines, with special attention to local-create durable queue overhead,
2. add maintained multi-source/catchup baselines to `docs/PERF.md` so those paths can be regression-checked explicitly,
3. keep converting remaining bespoke CLI polling sites to shared eventual-assert helpers where it improves clarity without hiding races.

## Final Step

1. Commit the completed work on this same worktree branch before handoff or review.
