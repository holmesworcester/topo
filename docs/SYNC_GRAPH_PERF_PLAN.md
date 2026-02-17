# Sync Graph Performance Plan

> **Status: Active** — Performance measurement and improvement plan for graph-topology sync.

## Goal
Measure and improve sync behavior in graph-like topologies, with focus on:
1. propagation across a peer chain (hop-by-hop spread),
2. catchup speed from multiple sources (8 peers feeding one lagging peer).

This plan answers:
1. Is current behavior efficient?
2. What should we expect today?
3. What changes most improve efficiency?

## Minimal-complexity strategy
1. Keep the current protocol and queues intact.
2. Add only small control knobs first (cadence + source caps).
3. Prefer in-memory heuristics before new durable coordination tables.
4. Only add heavier coordination logic if measured data shows clear need.

## Current constraints to account for
1. `sync` CLI is invite/discovery-driven (no manual outbound connect flag).
2. `accept_loop` handles one accepted connection at a time in a long inner loop, so inbound concurrency is effectively serialized.
3. Negentropy sessions run continuously per live connection with short inter-session delay; there is no configurable sync cadence policy yet.

Implication:
1. chain tests are valid now (seed addresses via invite/bootstrap),
2. true 8-source parallel catchup is not valid until accept/connect concurrency is refactored.

## Metrics to collect (minimum required)
1. `catchup_wall_ms`: time from test start until target convergence.
2. `events_per_sec_effective`: unique new events at sink / wall time.
3. `hop_latency_p95_ms` (chain only): P95 first-seen delay by hop.
4. `duplicate_ingress_ratio`: received event frames / unique inserted events.
5. `cpu_pct` + RSS at sink.

Optional if easy:
1. `negentropy_rounds_per_session`.
2. queue peaks (`egress_queue`, `project_queue`).

Primary sources:
1. existing DB tables (`recorded_events`, `events`, queue tables),
2. existing sync logs/stats,
3. small helper counters in test harness.

## Test family A: Chain propagation

### Topology
Use a line graph: `P0 <-> P1 <-> P2 ... <-> Pn`.

Recommended sizes:
1. `n=4` (5 peers) smoke.
2. `n=9` (10 peers) primary.
3. `n=19` (20 peers) stress.

Realism tiers:
1. A0 (minimal): separate processes + localhost links.
2. A1 (realistic): Linux namespaces + `tc netem` (RTT/jitter/loss).

### Workload
1. Inject burst at `P0` (for example 10k events).
2. Optionally inject background writes at interior peers (5-20% of main rate).
3. Sample fixed event IDs and track `recorded_at` at every hop.

### What we expect (current code)
1. Propagation delay grows roughly with hop count.
2. If sessions are frequent, data spread is smooth but control overhead is high.
3. With larger chains, repeated full-ish reconciliation drives extra negentropy CPU work at each hop.

### Frequency/cadence experiment (minimal set)
Evaluate three practical modes:
1. current behavior baseline,
2. heartbeat-only periodic sync (for example every 1s or 2s),
3. triggered nudge on new shared event (debounce 100-200ms) + heartbeat fallback (for example 5s).

Expected:
1. heartbeat-only gives simple predictable load but higher hop latency,
2. triggered+heartbeat gives much lower hop latency with manageable control overhead,
3. this hybrid should be the default "reasonable perf with low complexity" mode.

### Efficiency tweaks for chain propagation
1. Add event-triggered sync nudge when new shared events are recorded.
2. Add debounce/coalescing window (for example 100-200ms).
3. Keep slow heartbeat safety net (for example 5s).
4. Expose two knobs only: `SYNC_TRIGGER_DEBOUNCE_MS`, `SYNC_HEARTBEAT_MS`.

## Test family B: Multi-source catchup (8 sources)

### Scenario
Peers `S1..S8` are up-to-date and hold overlapping data.
Lagging peer `L` was offline and must catch up.

### Minimal benchmark plan

#### Phase B0 (baseline on current architecture)
Run with current serialized accept behavior to quantify limit:
1. start `L` in listen mode,
2. have `S1..S8` connect to `L`,
3. trigger catchup and measure.

Expected:
1. throughput near single-source baseline (or worse),
2. little to no speedup from 8 sources,
3. connection churn/queue contention may increase overhead.

#### Phase B1 (minimal concurrency refactor)
Required refactor before claiming real multi-source behavior:
1. make accept path per-connection concurrent (spawn task per accepted conn),
2. keep implementation simple by capping active source sessions at sink (for example `MAX_ACTIVE_SOURCES=3`).

Then rerun with offered sources `1, 2, 4, 8` while active sources remain capped.

### What we expect after concurrency support
1. Sublinear speedup, not 8x, because sink-side DB write/projection becomes bottleneck.
2. Likely useful range: ~1.5-3x over single-source before saturation.
3. More than 3-4 active sources usually hurts due to duplicate ingress + DB contention.

### Efficiency tweaks for multi-source catchup (minimal first)
1. Cap active source sessions at sink (`2` or `3`).
2. Use sticky source preference with simple failover (don't rotate every cycle).
3. Add short in-memory request cooldown map (`event_id -> last_requested_at`) to reduce duplicate requests across concurrent sources.
4. Tune batch sizes only after measuring sink DB saturation.
5. Defer heavier coordination (`want lease` tables, complex schedulers) unless duplicates remain high.

## Concrete benchmark matrix

### Chain matrix
1. peers: 5, 10
2. events: 10k, 50k
3. link profile: localhost baseline, then netem RTT 25ms + loss 1%
4. sync policy: baseline / heartbeat-only / triggered+heartbeat

### Multi-source matrix
1. source count: 1, 2, 4, 8
2. unique backlog at sink: 50k, 200k, 1M
3. overlap ratio across sources: 100%, 50%
4. sink mode: normal vs low-mem
5. active source cap: 1, 2, 3

## Pass/fail targets
1. Chain: triggered+heartbeat policy must materially reduce P95 hop latency vs periodic 1s baseline.
2. Catchup: with active-source cap tuning, effective throughput should reach at least 1.5x single-source.
3. Duplicate ingress ratio should stay below 1.5x under tuned multi-source policy.
4. No correctness regressions: event-set equality and projection invariants still pass.

## Suggested implementation order
1. Add benchmark harness for chain and B0 multi-source baseline (no architecture changes).
2. Add cadence controls (heartbeat + triggered nudge) and rerun chain matrix.
3. Refactor accept/connect concurrency for true multi-source.
4. Add active-source cap + sticky source selection + in-memory request cooldown.
5. Tune batch sizes and low-mem behavior.
6. Only if needed, consider heavier request coordination.

## Harness notes
1. Put runnable benchmarks in `tests/` plus a small orchestration helper for N-peer topologies.
2. Use existing `assert_eventually` style checks for convergence gates.
3. Persist raw CSV/JSON results for trend analysis and regressions.

## Recommendation summary
1. Treat negentropy cadence policy as first-class: this is the dominant lever for chain propagation latency.
2. Add event-triggered sync (debounced) plus heartbeat.
3. Do not expect efficient 8-source catchup until connection concurrency is fixed.
4. After concurrency, start with capped active sources and simple duplicate cooldown before adding complex schedulers.
