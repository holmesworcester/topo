# Realistic Network Perf Investigation Handoff

## Mission

Diagnose why the new realistic-network daemon/CLI perf harness is both:

1. Much slower than expected on the `cable` profile.
2. Timing out or stalling on lower-bandwidth profiles like `dsl`.

The specific questions from the user are:

- Why does roughly 10 MB of replicated data take on the order of 100 seconds instead of a few seconds?
- Is the realistic-network harness failing to saturate the QUIC connection?
- Is negentropy or sync control logic taking far too long?
- Why do low-end profiles fail asymmetrically?

## Constraints

- Work in the dedicated worktree:
  - `/home/holmes/poc-7/.codex-worktrees/realistic-cli-perf-network-master`
- Do not do implementation work in the main worktree at `/home/holmes/poc-7`.
- Do not undermine or revert master's download changes or transport auth simplifications.
- The user is frustrated by repeated sandbox-escape prompts.
  - Prefer source inspection and preserved-artifact analysis first.
  - If an actual daemon/CLI run is indispensable, batch it and keep it targeted.
- Black-box daemon/CLI perf runs do not work inside the current sandbox because the wrapper fails before the test code starts with:
  - `bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted`

## Current Branch State

- Branch/worktree:
  - `codex/realistic-cli-perf-network-master`
  - `/home/holmes/poc-7/.codex-worktrees/realistic-cli-perf-network-master`
- Main repo `/home/holmes/poc-7` was already fast-forwarded earlier to include the readiness fix commit:
  - `0f1500e Fix realistic network perf readiness on master`
- There are additional local, uncommitted investigation changes in this worktree:
  - `tests/perf_network_shaper/mod.rs`
  - `tests/daemon_perf_harness/mod.rs`
  - `tests/daemon_realistic_network_perf_test.rs`

These local changes add instrumentation and a smaller ignored profile test.

## Files Most Relevant To This Investigation

- `tests/perf_network_shaper/mod.rs`
- `tests/daemon_perf_harness/mod.rs`
- `tests/daemon_realistic_network_perf_test.rs`
- `src/runtime/sync_engine/session/mod.rs`
- `src/runtime/sync_engine/session/initiator.rs`
- `src/runtime/sync_engine/session/responder.rs`
- `src/runtime/sync_engine/session/control_plane.rs`
- `src/runtime/sync_engine/session/data_plane.rs`
- `src/runtime/sync_engine/session/logging.rs`
- `src/shared/tuning.rs`
- `tests/cli_harness/mod.rs`

## What Has Already Been Proven

### 1. Direct daemon sync is fast

This command passed:

```bash
env PERF_KEEP_TMPDIR=1 cargo +stable test --release --test daemon_perf_test perf_sync_10k -- --nocapture --test-threads=1
```

Observed output:

- `Wall time: 2.25s`
- `Messages: 10000`
- `Msgs/s: 4437`
- preserved artifacts: `/tmp/.tmpWVFoTn`

This means the basic daemon/CLI sync path is not inherently a 100-second operation.

### 2. Realistic `cable` sync is slow, and the time is not in local message generation

A targeted `cable` run completed with the new instrumentation.

Observed summary:

- `Wall time: 105.91s`
- `Generate: 1.30s`
- `Sync wait: 104.61s`
- `Messages: 10000`
- `Msgs/s: 94`
- preserved artifacts: `/tmp/.tmpbocUjF`

This rules out local message generation as the cause of the slowdown.

### 3. The shaper is not saturating the configured 35 Mbps link

The same `cable` run logged:

- left->right:
  - `bytes_sent=7523384` (`7.17 MiB`)
  - `active_secs=108.492`
  - `effective_mbps=0.55`
- right->left:
  - `bytes_sent=7460589` (`7.11 MiB`)
  - `active_secs=108.518`
  - `effective_mbps=0.55`

The configured profile was `35.0 Mbps/dir`, `24 ms RTT`, `+/- 2 ms jitter`, `0.20% loss`.

This is the strongest current fact:

- The link is not the bottleneck.
- The session is application-limited or protocol-limited.
- The shaper is mostly idle.

### 4. Low-end profile failure is not driven by packet loss

`dsl` failed under the 300 second budget both:

- with normal configured loss
- with `PERF_REALISTIC_NETWORK_LOSS_PERCENT=0.0`

So the lower-profile failure is not explained by packet loss alone.

### 5. Low-end failure is asymmetric

In a preserved `dsl` timeout, Alice reached the expected final count while Bob lagged far behind.

Representative pattern observed:

- expected total: `10004`
- Alice actual: about `10004`
- Bob actual: about `6359`

That means:

- Alice received essentially all of Bob's messages.
- Bob did not receive all of Alice's messages.

So the failure is not "everything is just uniformly slow." It is directionally skewed.

### 6. The main realistic run does not currently leave useful finalized `sync_runs` counters unless sync logging is enabled

In `/tmp/.tmpbocUjF`:

- `events` count was `10020` on both sides.
- `sync_runs` only showed:
  - one tiny finalized warm-up run
  - one main run left as `in_progress` with zero counters

This means:

- the long runtime is not explained by finalized `sync_runs.bytes_sent` counters
- a future reproduction should enable sync logging if you want per-frame evidence

## Important Source-Level Clues

### Likely suspect: repeated discovery rounds plus a fixed 100 ms inter-round gap

In `src/runtime/sync_engine/session/mod.rs`:

- `DISCOVERY_ROUND_GAP: Duration = Duration::from_millis(100);`

If the realistic path is causing the session to split work across many discovery rounds, this fixed 100 ms gap can easily add tens of seconds.

### Request credit is probably not the first-order bottleneck

In `src/shared/tuning.rs`:

- `request_credit_high_watermark()` defaults to `512`
- `request_credit_low_watermark()` defaults to `128`

At `35 Mbps` and `24 ms RTT`, the bandwidth-delay product is on the order of 100 KB, so 512 small messages in flight should be more than enough if the data plane is healthy.

### Data send quantum is probably not the first-order bottleneck

In `src/shared/tuning.rs`:

- `egress_send_quantum_bytes()` defaults to `1 MiB`

That is also comfortably above the `cable` bandwidth-delay product.

### There is at least one metrics bug

In `src/runtime/sync_engine/session/data_plane.rs`, `events_received` is incremented twice for each incoming event.

That is almost certainly a stats-accounting bug, but it does not currently look like the root cause of the 100-second runtime.

## Instrumentation Already Added Locally

### `tests/perf_network_shaper/mod.rs`

Added per-direction shaper stats:

- packets sent
- bytes sent
- packets dropped
- bytes dropped
- active send duration
- effective Mbps

Controlled by:

- `PERF_REALISTIC_NETWORK_SHAPER_STATS=1`

### `tests/daemon_perf_harness/mod.rs`

`PerfMeasurement` now separates:

- `generate_secs`
- `sync_wait_secs`
- `wall_secs`

This was critical in proving the slowdown is not local message generation.

### `tests/daemon_realistic_network_perf_test.rs`

Added a smaller ignored benchmark:

- `perf_sync_2k_realistic_profiles`

This exists because `10k` is too large to be the first profiling workload for `dsl`, `slow-mobile`, and similar profiles.

## Preserved Artifacts

### Realistic cable run

- `/tmp/.tmpbocUjF`
- currently contains:
  - `alice.db`
  - `bob.db`

Useful known queries:

```sql
select count(*) from events;
select run_id,direction,role,rounds,events_sent,events_received,bytes_sent,bytes_received,outcome,coalesce(error,'') from sync_runs order by run_id desc limit 20;
select frame_type,count(*),sum(msg_len) from sync_run_events where run_id=2 group by frame_type order by count(*) desc;
```

Current result from that preserved run:

- `events = 10020` on both sides
- main run was still `in_progress`
- no useful `sync_run_events` were present for the main run because sync logging was not enabled

### Direct 10k baseline

- `/tmp/.tmpWVFoTn`

## Highest-Value Next Hypotheses To Test

### H1. The realistic slowdown is dominated by many discovery rounds, and the fixed 100 ms `DISCOVERY_ROUND_GAP` is adding most of the time

Why this is plausible:

- shaper only achieved `0.55 Mbps` on a `35 Mbps` link
- local generation took only `1.30s`
- direct benchmark is `2.25s`
- a fixed `100 ms` per round becomes massive if the work fragments into many rounds

How to test:

1. Run a small realistic benchmark with sync logging enabled:

```bash
env \
  PERF_REALISTIC_NETWORK_PROFILES=cable \
  PERF_REALISTIC_NETWORK_REPEATS=1 \
  PERF_KEEP_TMPDIR=1 \
  PERF_DAEMON_LOGS=1 \
  PERF_ENABLE_SYNC_LOG=1 \
  SYNC_SEND_IDLE_LOG=1 \
  RUST_LOG=info \
  cargo +stable test --release --test daemon_realistic_network_perf_test perf_sync_2k_realistic_profiles -- --ignored --nocapture --test-threads=1
```

2. Count evidence of repeated discovery rounds in:
   - daemon stdout logs
   - `sync_run_events`
3. Temporarily patch `DISCOVERY_ROUND_GAP` downward or make it env-configurable, then rerun the same small `cable` case.

Pass condition:

- if runtime drops dramatically, the inter-round gap is a real root cause

### H2. The session is spending most of its time idle on the control plane rather than moving data

Why this is plausible:

- `effective_mbps=0.55`
- main sync time is in `sync_wait`
- data volume is modest

How to test:

1. Use the same small logged `cable` run as above.
2. Inspect:
   - `Requested more wanted IDs from peer ...`
   - `Reconciliation complete: ...`
   - `SendIdle`
3. Determine whether the idle state is mostly:
   - `waiting_on_control`
   - `between_rounds`
   - `queued_not_sending`

Pass condition:

- a single idle mode clearly dominates long gaps in the run

### H3. The lower-bandwidth failure is caused by asymmetric control/data pacing rather than simple bandwidth shortage

Why this is plausible:

- the `dsl` failure was asymmetric
- removing packet loss did not fix it

How to test:

1. After the `cable` root cause is clearer, run:

```bash
env \
  PERF_REALISTIC_NETWORK_PROFILES=dsl \
  PERF_REALISTIC_NETWORK_REPEATS=1 \
  PERF_KEEP_TMPDIR=1 \
  PERF_DAEMON_LOGS=1 \
  PERF_ENABLE_SYNC_LOG=1 \
  SYNC_SEND_IDLE_LOG=1 \
  RUST_LOG=info \
  cargo +stable test --release --test daemon_realistic_network_perf_test perf_sync_2k_realistic_profiles -- --ignored --nocapture --test-threads=1
```

2. Compare Alice vs Bob:
   - message counts
   - idle states
   - request issuance
   - discovery round counts

Pass condition:

- you can explain why one direction completes while the other lags

## Success Criteria

### SC1. Quantify the gap correctly

You must show, with measurements from the same codebase, that:

- direct daemon/CLI sync is fast
- realistic `cable` sync is much slower
- the realistic slowdown is in `sync_wait`, not local generation

Proof:

- include concrete outputs from:
  - direct `perf_sync_10k`
  - realistic `perf_sync_2k_realistic_profiles` or `perf_sync_10k_realistic_profiles`

### SC2. Determine whether the realistic run is link-limited or application-limited

You must prove whether the realistic session saturates the shaped link.

Proof:

- use shaper stats from `PERF_REALISTIC_NETWORK_SHAPER_STATS=1`
- compare effective Mbps to configured Mbps

Pass condition:

- a clear conclusion such as:
  - "the session is not saturating QUIC; the shaper is mostly idle"
  - or the opposite, if new evidence shows saturation

### SC3. Identify the concrete pacing mechanism

You must isolate what is causing the idle time.

Acceptable root causes include:

- repeated discovery rounds plus `DISCOVERY_ROUND_GAP`
- control-plane request refill pacing
- response-credit starvation
- some other specific mechanism backed by logs and measurements

Proof:

- daemon logs and/or `sync_run_events`
- relevant code references
- a small reproducer run showing the behavior

### SC4. Explain the asymmetric lower-profile failure

You must determine why lower-bandwidth profiles like `dsl` stall asymmetrically.

Proof:

- small `dsl` realistic run with logging
- preserved message counts and sync evidence from both sides

### SC5. Leave the repo in a safe state

Whether or not you land a fix, do not regress the current baseline.

Proof checks:

```bash
cargo +stable test --release --test perf_network_transport_test -- --nocapture --test-threads=1
cargo +stable test --release --test daemon_perf_test perf_sync_10k -- --nocapture --test-threads=1
cargo +stable test --release --test daemon_realistic_network_perf_test --no-run
```

If you change sync behavior, also rerun a small realistic benchmark to prove the change improves the suspected root cause.

## End-to-End Validation Expectations

Do not stop at a code-level theory. Finish with one of these two outcomes:

### Outcome A: Root cause fixed

Required evidence:

- small realistic `cable` run is materially faster than before
- shaper effective Mbps rises or idle time drops for the identified reason
- small realistic `dsl` run no longer shows the prior asymmetric stall, or its failure mode is materially improved and understood
- baseline direct benchmark still passes

### Outcome B: Root cause conclusively identified but not fixed

Required evidence:

- one concise report with:
  - the bottleneck mechanism
  - the affected code path
  - the evidence from logs/metrics
  - the exact next patch that should fix or test it

This is only acceptable if the evidence is strong enough that the remaining work is mechanical.

## Recommended Working Order

1. Use preserved artifacts and source inspection first.
2. Run the smallest logged `cable` reproduction needed to see round/idle behavior.
3. Decide whether the main culprit is:
   - discovery-round fragmentation
   - control-plane pacing
   - response-credit starvation
4. Patch the smallest plausible lever and rerun small `cable`.
5. Once `cable` is explained, rerun small `dsl`.
6. Only then consider broader profile tuning or larger runs.

## Notes For The Next Agent

- The previous agent already proved the important negative:
  - this is not a raw bandwidth problem on the `cable` profile
  - it is almost certainly a protocol/application pacing problem
- The previous agent also already proved:
  - local message generation is not the issue
  - packet loss is not the primary cause of the `dsl` timeout
- The next useful run is not another blind 10k matrix.
  - It is a small, heavily logged `cable` reproduction.
