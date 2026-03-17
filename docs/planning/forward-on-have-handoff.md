# Forward-On-Have Handoff

## Mission

Continue the `forward-on-have` work from a clean summary, without needing the chat transcript.

The goal is to validate and, if needed, improve a real `forward-on-have` design based on:

- `IdHint`-style hot discovery using existing `NeedList` frames
- `forward-on-have`, not `forward-on-hint`
- pull-only blob transfer
- periodic negentropy as repair/cold-tail sync, not as the primary low-latency path

The active implementation work is in the master-based worktree:

- Worktree: `/home/holmes/poc-7/.worktrees/forward-on-have-master`
- Branch: `codex/forward-on-have-master`

Do not continue in the main worktree at `/home/holmes/poc-7`.

## Scope

This session did four things:

1. Replaced the earlier polling prototype with a real post-commit live-hint bus.
2. Ensured local create and received-store paths both publish hints on first durable `recorded_events` insert.
3. Added focused correctness coverage for the missing workspace seed replay case.
4. Added and fixed stage-level latency instrumentation in the perf test to explain where the large observed latency is accumulating.

## Implemented State

### Live hint bus

New file:

- `src/state/live_hints.rs`

Behavior:

- tenant-scoped in-memory broadcaster keyed by `(db_path, tenant_id)`
- payload: `event_id` plus optional `source_peer_id`
- sessions subscribe once per tenant/DB
- publish happens only after durable commit

### Session integration

Relevant files:

- `src/runtime/sync_engine/session/control_plane.rs`
- `src/runtime/sync_engine/session/initiator.rs`
- `src/runtime/sync_engine/session/responder.rs`
- `src/runtime/sync_engine/session/mod.rs`

Behavior:

- `P7_FORWARD_ON_HAVE=1` enables live-hint forwarding
- sessions drain live hints and send `NeedList` immediately on the control stream
- hints from the same remote peer are not echoed back to that peer
- hint receipt still goes through durable `wanted` / `wanted_sources`
- there is no direct “request immediately no matter what” bypass

### Stored-event publication coverage

Production publication sites currently wired:

- ingest persist path: `src/state/pipeline/phases.rs`
- post-commit publish: `src/state/pipeline/mod.rs`
- same-workspace sibling fanout: `src/state/pipeline/effects.rs`
- local create path: `src/state/projection/create.rs`
- deterministic emit path: `src/state/projection/emit.rs`
- sibling fanout helpers: `src/state/shared_workspace_fanout.rs`
- workspace seed replay path: `src/event_modules/workspace/commands.rs`

Important helper:

- `src/state/db/store.rs`
  - `insert_recorded_event_checked(...) -> SqliteResult<bool>`
  - first durable insert is the source of truth for “new to this tenant”

### Latency instrumentation

Relevant file:

- `tests/multi_peer_delivery_latency_perf_test.rs`

Added/fixed:

- auto-enable `TOPO_EVENT_TIMELINE=1` when stage output is requested
- stage summary and stage CSV generation
- per-event timestamps for:
  - `created_to_need_sent_ms`
  - `need_transit_ms`
  - `need_recv_to_wanted_ms`
  - `wanted_to_credit_ms`
  - `credit_to_request_selected_ms`
  - `wanted_to_request_selected_ms`
  - `selected_to_request_sent_ms`
  - `request_transit_ms`
  - `request_recv_to_response_sent_ms`
  - `response_transit_ms`
  - `response_recv_to_persisted_ms`
  - `persisted_to_projected_ms`
- CSV writer fixed to avoid the prior format-string compile break

## Success Criteria

### SC1: Real `forward-on-have` is implemented, not polling

Definition:

- No scan/poll loop over `recorded_events` for hint propagation.
- Hint publication happens from real post-commit durable insert points.

Proof:

- Inspect `src/state/live_hints.rs`
- Inspect session subscribers in:
  - `src/runtime/sync_engine/session/initiator.rs`
  - `src/runtime/sync_engine/session/responder.rs`
- Confirm there is no remaining poll-based `forward_on_have` publisher

### SC2: All shared stored events publish hints on first durable tenant-local record

Definition:

- Locally created shared events and remotely received shared events receive the same treatment.
- Hints are emitted only for first durable `recorded_events` insertion for that tenant.
- Old/duplicate durable records do not regossip.

Proof:

- Inspect the production publication sites listed above
- Confirm `insert_recorded_event_checked(...)` gates “first seen by this tenant”
- Confirm workspace seed replay uses the same rule

### SC3: Hint receipt remains discovery-only and dedup-safe

Definition:

- Receiving a hint populates durable `wanted` state and candidate sources.
- It does not bypass the existing request scheduler or create a duplicate-prone fast lane.

Proof:

- Inspect `src/runtime/sync_engine/session/control_plane.rs`
- Inspect `observe_event_ids_for_peer(...)` and `refill_wanted_requests(...)`

### SC4: Focused correctness tests pass

Definition:

- The missing workspace seed replay case is covered.
- The live forward-on-have path works with slow negentropy repair.

Required checks:

```bash
cargo test --lib join_workspace_seed_replay_emits_live_hints_for_existing_shared_events -- --nocapture
cargo test --test download_timeline_test forward_on_have_hints_fresh_events_with_slow_negentropy_repair -- --nocapture --test-threads=1
```

### SC5: Latency harness compiles and emits per-event stage timing

Definition:

- The perf test compiles.
- It emits `.summary`, `.csv`, and `.stages.csv` files in `target/perf-results`.

Required checks:

```bash
cargo test --test multi_peer_delivery_latency_perf_test --no-run
env TOPO_PERF_PRELOAD_MESSAGES=5000 \
    TOPO_PERF_MESSAGES_PER_SEC=2 \
    TOPO_PERF_LIVE_SECONDS=15 \
    TOPO_PERF_PROGRESS_WINDOWS=6 \
    TOPO_PERF_STAGE_BREAKDOWN=1 \
    P7_FORWARD_ON_HAVE=1 \
    P7_DISCOVERY_ROUND_GAP_MS=5000 \
    cargo test --release --test multi_peer_delivery_latency_perf_test \
    perf_two_peer_delivery_latency_over_time \
    -- --ignored --nocapture --test-threads=1
```

### SC6: The dominant source of the large latency is explained with evidence

Definition:

- The handoff agent must be able to point to a measured stage, not a guess.
- The explanation must identify whether the delay is in:
  - hint publication
  - hint receipt/control-path servicing
  - wanted/request scheduling
  - data transfer
  - persist/project

Required evidence:

- stage summary from the perf test
- stage CSV timing pattern
- if needed, a traced run that correlates session/negentropy behavior with the stage results

## Current Validation Status

These checks passed in this session from the master-based worktree:

```bash
cargo fmt
cargo test --test multi_peer_delivery_latency_perf_test --no-run
cargo test --lib join_workspace_seed_replay_emits_live_hints_for_existing_shared_events -- --nocapture
cargo test --test download_timeline_test forward_on_have_hints_fresh_events_with_slow_negentropy_repair -- --nocapture --test-threads=1
```

## Current Profiling Findings

### Main benchmark result

Command used:

```bash
env TOPO_PERF_PRELOAD_MESSAGES=5000 \
    TOPO_PERF_MESSAGES_PER_SEC=2 \
    TOPO_PERF_LIVE_SECONDS=15 \
    TOPO_PERF_PROGRESS_WINDOWS=6 \
    TOPO_PERF_STAGE_BREAKDOWN=1 \
    P7_FORWARD_ON_HAVE=1 \
    P7_DISCOVERY_ROUND_GAP_MS=5000 \
    cargo test --release --test multi_peer_delivery_latency_perf_test \
    perf_two_peer_delivery_latency_over_time \
    -- --ignored --nocapture --test-threads=1
```

Observed summary:

- avg: `~7293 ms`
- p50: `~7541 ms`
- p95: `~14045 ms`
- worst: `~14545 ms`

### Stage breakdown

The hot path itself is fast:

- `create_to_need_sent_ms`: ~2 to 4 ms
- `need_recv_to_wanted_ms`: ~0 ms
- `wanted_to_request_selected_ms`: ~0 ms
- `request_transit_ms`: single-digit ms
- `request_recv_to_response_sent_ms`: ~0 to 1 ms
- `response_transit_ms`: low single-digit ms
- `response_recv_to_persisted_ms`: low single-digit ms
- `persisted_to_projected_ms`: low single-digit ms

The dominant delay is:

- `need_transit_ms`: avg `~7276 ms`, worst `~14520 ms`

Interpretation:

- source publishes and sends hints quickly
- sink handles the hint immediately once it receives it
- the large latency is almost entirely before `NeedList` receipt on the sink side

### Per-event stage CSV pattern

Observed from `target/perf-results/two-peer-pre5000-m2-s15-w6.stages.csv`:

- source `origin_need_list_sent_at` spans the full live-send window
- sink `sink_need_list_received_at` is clustered into a very tight burst near the end
- total latency tracks message creation time almost perfectly

This means the benchmark behaves like:

- hints are sent continuously during the run
- the sink does not surface them until much later
- once surfaced, request/response/persist/project complete quickly

### Traced run finding

A traced run with the same workload showed:

- the connection/session is live
- the initial full round can complete quickly
- there is still heavy control-path activity during the large catchup state
- live `NeedList` processing is consistent with being delayed behind same-session control traffic

Important caution:

- Slowing `P7_DISCOVERY_ROUND_GAP_MS` from `5000` to `60000` did **not** materially improve the benchmark result in this workload.
- That means the issue is **not explained solely by periodic hot rounds**.
- The stronger current hypothesis is:
  - live hints are being delayed behind existing control-stream backlog from the large preload/catchup state on the same long-lived session

## Open Questions

These are the next questions another agent should answer with measurements, not guesswork:

1. Does the bad latency disappear with `TOPO_PERF_PRELOAD_MESSAGES=0` or a much smaller preload?
2. Are live `NeedList` frames queued behind preload-related control traffic on the same QUIC control stream?
3. Is there still residual catchup control chatter after preload message counts have converged?
4. Would a separate prioritized hint stream, or hint/control prioritization, eliminate the delay without changing the pull-only data model?
5. Is the benchmark’s “preload converged” point still leaving a large ordered control backlog in flight?

## Recommended Next Steps

1. Run the same perf test with `TOPO_PERF_PRELOAD_MESSAGES=0`.
2. Run again with a small preload like `100` or `500`.
3. Compare stage summaries and `sink_need_list_received_at` clustering across those runs.
4. If low-preload runs are healthy, focus on control-stream contention during heavy catchup, not on the hint publication path.
5. Consider a design experiment:
   - separate hint stream
   - control-frame prioritization
   - or stricter suppression/coalescing of catchup-related control chatter

## End-to-End Validation Checklist

Before calling the mission complete, another agent should be able to show all of the following:

```bash
# correctness
cargo test --lib join_workspace_seed_replay_emits_live_hints_for_existing_shared_events -- --nocapture
cargo test --test download_timeline_test forward_on_have_hints_fresh_events_with_slow_negentropy_repair -- --nocapture --test-threads=1

# perf harness compiles
cargo test --test multi_peer_delivery_latency_perf_test --no-run

# stage timing reproduction
env TOPO_PERF_PRELOAD_MESSAGES=5000 \
    TOPO_PERF_MESSAGES_PER_SEC=2 \
    TOPO_PERF_LIVE_SECONDS=15 \
    TOPO_PERF_PROGRESS_WINDOWS=6 \
    TOPO_PERF_STAGE_BREAKDOWN=1 \
    P7_FORWARD_ON_HAVE=1 \
    P7_DISCOVERY_ROUND_GAP_MS=5000 \
    cargo test --release --test multi_peer_delivery_latency_perf_test \
    perf_two_peer_delivery_latency_over_time \
    -- --ignored --nocapture --test-threads=1

# control experiment
env TOPO_PERF_PRELOAD_MESSAGES=0 \
    TOPO_PERF_MESSAGES_PER_SEC=2 \
    TOPO_PERF_LIVE_SECONDS=15 \
    TOPO_PERF_PROGRESS_WINDOWS=6 \
    TOPO_PERF_STAGE_BREAKDOWN=1 \
    P7_FORWARD_ON_HAVE=1 \
    P7_DISCOVERY_ROUND_GAP_MS=5000 \
    cargo test --release --test multi_peer_delivery_latency_perf_test \
    perf_two_peer_delivery_latency_over_time \
    -- --ignored --nocapture --test-threads=1
```

## Notes For The Next Agent

- The prior polling prototype is obsolete; do not revive it.
- Avoid CLI-driven tests unless they are required; focused Rust tests were sufficient for the correctness gap found here.
- The local environment has shown repeated sandbox startup failures with:
  - `bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted`
- If you can avoid shell calls, do so. If not, operate from the worktree above and keep validation tightly targeted.
