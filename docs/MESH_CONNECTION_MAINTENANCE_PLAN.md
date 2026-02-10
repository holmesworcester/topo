# Mesh Connection Maintenance Plan

## 1. Problem statement

Current hole-punch work gives us:
1. endpoint observations,
2. introductions,
3. direct-connect attempts,
4. sync sessions over existing links.

What is still missing as a first-class mechanism:
1. a target connection count per peer,
2. periodic edge add/drop to keep an overlay graph healthy,
3. objective graph health metrics over time.

So yes: today we have path-establishment primitives, but not a full graph-maintenance policy.

## 2. Goals

1. Keep each peer near a target active degree `K`.
2. Build/maintain a connected sparse mesh without centralized coordinator.
3. Keep connections alive with lightweight heartbeat traffic.
4. Recover quickly from churn (peer restarts, NAT mapping expiry, packet loss).
5. Make behavior measurable with graph-level metrics.

## 3. Non-goals (v1)

1. No global optimal topology computation.
2. No strong guarantees on minimal diameter under adversarial churn.
3. No advanced routing strategy; this is overlay maintenance only.
4. No TURN-style relay redesign in this phase.

## 4. Simplest useful algorithm (v1)

The simplest mechanism that reliably yields a graph is:
1. target-degree maintenance with hysteresis,
2. random peer selection from a candidate set,
3. periodic pruning when over target.

This is essentially a lightweight partial-view overlay.

### 4.1 State per peer

1. `active_connections`: currently connected peers + metadata.
2. `candidate_peers`: peers known via:
   - transport bindings,
   - endpoint observations,
   - intros,
   - optional peer exchange in heartbeat messages (v2).
3. `dial_backoff`: per-peer retry backoff state.

### 4.2 Parameters

1. `K_target`: desired steady-state active connections (example: 6-8).
2. `K_low`: reconnect threshold (example: `K_target - 1`).
3. `K_high`: prune threshold (example: `K_target + 2`).
4. `min_conn_age_ms`: do not drop very new links (anti-thrash).
5. `heartbeat_interval_ms`: periodic keepalive (example: 5-15s).
6. `dial_budget_per_tick`: cap new outbound attempts per tick.
7. `job_tick_ms`: maintenance cadence (example: 1000-2000ms).

### 4.3 Periodic connection-maintenance job

On each tick:

```text
observe active_degree = |active_connections|

if active_degree < K_low:
  need = K_target - active_degree
  choose up to min(need, dial_budget_per_tick) candidates:
    - not currently connected
    - not in dial backoff
    - currently trusted
    - freshest endpoint observation first, then random among top-N fresh
  attempt connect (hole-punch/direct path as available)
  on success -> add active connection
  on failure -> update dial backoff

if active_degree > K_high:
  drop_count = active_degree - K_target
  score each active connection for pruning:
    - protect links younger than min_conn_age_ms
    - prefer dropping highest-latency and oldest-idle links
    - keep at least one "recently useful" link if possible
  close lowest-score links until drop_count reached

for each active connection:
  send heartbeat if due
  mark unhealthy if heartbeat timeout exceeded
```

### 4.4 Why this is the right v1

1. Very small implementation surface.
2. Gives explicit control over graph sparsity (`K_target`).
3. Handles both under-connected and over-connected states.
4. Works independently of how candidates are discovered (intro can remain separate).

## 5. Job organization (cron-like runtime)

Introduce an explicit local scheduler with named jobs and fixed cadence.

### 5.1 Proposed jobs

1. `connection_maintenance_job` (1-2s tick)
   - enforce `K_target` via add/drop logic.
2. `heartbeat_job` (5-15s per link)
   - send lightweight keepalive frame over active links.
3. `intro_job` (existing intro worker; optional)
   - discover and suggest new candidates/paths.
4. `endpoint_cleanup_job` (existing TTL purge)
   - cleanup stale endpoint observations.
5. `metrics_snapshot_job` (10-30s)
   - emit local graph/sync health metrics.

### 5.2 Scheduler shape

1. Single runtime-local scheduler loop.
2. Job descriptors:
   - `name`,
   - `interval_ms`,
   - `next_run_at`,
   - `run()` callback.
3. Jitter each interval slightly to avoid lockstep spikes across peers.
4. Job failures should be logged and isolated (no scheduler crash).

## 6. Data model additions (minimal)

Add operational tables (not canonical events):

1. `active_connections_state`
   - `recorded_by`,
   - `peer_id`,
   - `connected_at`,
   - `last_heartbeat_at`,
   - `last_heartbeat_rtt_ms`,
   - `last_sync_at`,
   - `last_error`.

2. `connection_attempts`
   - `recorded_by`,
   - `peer_id`,
   - `attempted_at`,
   - `result` (`success|timeout|tls_reject|unreachable|other`),
   - `reason`.

3. `connection_job_metrics`
   - periodic snapshots:
   - `active_degree`,
   - `candidate_count`,
   - `connect_attempts`,
   - `connect_successes`,
   - `drops`.

## 7. 100-peer test plan (heartbeat + tiny data sync)

### 7.1 Test objective

With 100 peers and heartbeat traffic:
1. maintain stable target degree,
2. keep one large connected component,
3. preserve sync readiness (small payload propagation still works),
4. avoid runaway reconnect thrash.

### 7.2 Workload profile

1. Each peer emits heartbeat events/frames only (or tiny "I'm alive" data event every 30-60s).
2. Very low payload volume; focus is connection continuity and graph shape.
3. Small random churn:
   - periodic peer restarts,
   - temporary connectivity loss,
   - endpoint expiry.

### 7.3 Test environments (realism tiers)

1. Tier A (fast CI sanity, reduced realism)
   - single host, local namespaces/ports, no heavy NAT complexity.
   - use for correctness and regressions.

2. Tier B (high realism on one machine)
   - Linux netns with multiple NAT namespaces (mixed behaviors),
   - nftables rules,
   - `tc netem` latency/jitter/loss,
   - constrained bandwidth on subsets of links.

3. Tier C (max realism)
   - distributed VMs across regions/providers,
   - real internet paths + real home/CGN NAT where possible,
   - injected restarts and network impairments.

For "maximally realistic" validation, Tier C is the target signal; Tier B is a strong preflight.

### 7.4 Suggested 100-peer topology for realism

1. 10 introducer-capable/public peers.
2. 90 edge peers split behind NAT groups:
   - mostly EIM+ADF style,
   - minority difficult NAT profile (to measure graceful degradation).
3. Connection target example:
   - edge peers `K_target = 6`,
   - introducer/public peers `K_target = 10-12`.

## 8. How to analyze whether the test is working

Collect periodic graph snapshots from all peers and compute:

1. Degree distribution:
   - mean, p50, p95, stddev vs `K_target`.
2. Connectivity:
   - largest connected component ratio (goal near 1.0).
3. Path quality proxy:
   - sampled shortest-path estimates across random peer pairs.
4. Churn health:
   - connect success rate,
   - reconnect time after drop,
   - drop/add rate (thrash indicator).
5. Keepalive health:
   - heartbeat RTT distribution,
   - timeout rate.
6. Sync readiness:
   - time for tiny event to reach 95% of peers.

### 8.1 Practical pass criteria (initial)

1. `>= 95%` peers in largest component after warmup.
2. Mean degree within `K_target +/- 1`.
3. Reconnect median `< 10s` after induced drop.
4. Heartbeat timeout rate `< 2%` steady-state (environment dependent).
5. Tiny event reaches `>= 95%` peers within bounded window (set by network profile).

## 9. Implementation phases

1. Phase 1: Add scheduler skeleton and `connection_maintenance_job`.
2. Phase 2: Add heartbeat frame and active connection state tracking.
3. Phase 3: Add pruning policy and anti-thrash safeguards.
4. Phase 4: Add metrics snapshots + aggregator script for graph KPIs.
5. Phase 5: Add 100-peer harness (Tier A first, Tier B next).
6. Phase 6: Run long soak tests and tune `K_target`, backoff, pruning.

## 10. Recommended algorithm evolution

After v1 is stable, evolve toward:
1. peer-sampling exchange (Cyclon-style passive view),
2. active/passive view separation (HyParView-style),
3. adaptive degree by observed reliability/latency.

But v1 should be shipped first: target-degree maintenance with random candidate selection and hysteresis.

## 11. Concrete next steps

1. Add scheduler module with job registry and jittered intervals.
2. Implement `connection_maintenance_job` using current trust + endpoint tables.
3. Add heartbeat message/frame and per-connection freshness tracking.
4. Build a `tools/mesh_test_100/` harness to spawn peers and aggregate metrics.
5. Add a `tools/mesh_test_100/analyze.py` report producing:
   - component size over time,
   - degree histogram,
   - reconnect latency CDF,
   - heartbeat RTT/timeout trends.
