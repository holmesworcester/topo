# `test_zero_loss_stress` Investigation + Fix Plan

## Branch + Worktree

- Branch: `exec/zero-loss-stress-investigation`
- Worktree: `/home/holmes/poc-7-zero-loss-stress-investigation`
- Base: `master`

## Why This Exists

`tests/scenario_test.rs:test_zero_loss_stress` is flaky and can fail with:

- `alice has too many unique events: 40`

Observed repro command:

```bash
cargo test --test scenario_test test_zero_loss_stress -- --nocapture
```

Observed output included:

- `zero-loss stress: 9976 events in 1.67s ...`
- then failure on unique-event difference assertion.

## Test Anatomy (Current)

Relevant code: `tests/scenario_test.rs:238`

Current flow:

1. Create two peers (`alice`, `bob`), each with 5,000 local messages.
2. Snapshot each peer’s full event ID set (`store_ids`) before sync.
3. Pick 50 random sample event IDs from each peer (`sample_event_ids` uses `ORDER BY RANDOM()`).
4. Run `sync_until_converged(...)` with convergence condition:
   - all 50 alice samples visible on bob, and
   - all 50 bob samples visible on alice.
5. Immediately compute full set differences and assert each side has `<= 2` unique events.

Key helper behavior:

- `sync_until_converged` (`src/testutil.rs:1661`) stops as soon as closure returns true.
- It does **not** enforce “full-set convergence” or “quiescence”.

## Most Likely Failure Mode

The convergence check is sample-based and can pass while transfer is still in progress.

Because only 50 random IDs are checked out of ~5,000+, the check can pass even if dozens of events are still missing. Then the test immediately performs full-set equality checks and fails.

This is highly consistent with observed failures and metrics.

## Important Context: Is This “Real Packet Loss”?

This test runs over local loopback endpoints (`127.0.0.1`) via `start_peers_pinned` in `src/testutil.rs:1447`, with no explicit netem/loss injection in this path.

So first priority is to distinguish:

1. **Premature test convergence** (most likely), vs
2. **Real protocol/data-loss bug**.

## Investigation Steps

## 1) Reproduce Flake Rate

Run multiple iterations:

```bash
cd /home/holmes/poc-7-zero-loss-stress-investigation
for i in $(seq 1 20); do
  echo "=== run $i ==="
  RUST_TEST_THREADS=1 cargo test --test scenario_test test_zero_loss_stress -- --nocapture || break
done
```

Capture at least one failure with metrics output.

## 2) Add Temporary Diagnostic Probe (Do Not Keep in Final Commit)

In `test_zero_loss_stress`, right before current unique-diff assertions:

1. Poll every 200ms for up to 10s.
2. Recompute `alice_only.len()` / `bob_only.len()` each poll.
3. Log progression.
4. If counts shrink to `<= 2` within probe window, this proves the failure is a race (not true loss).

Optional extra diagnostics during probe:

- `alice.store_count()` and `bob.store_count()`
- pending queue counts from DB (`egress_queue`, `project_queue`) if available

## 3) Decide Path

- If probe shows diffs naturally drain to `<= 2`: implement **test convergence fix**.
- If diffs remain high and stable after probe window: investigate protocol/session correctness.

## Fix Plan A (Expected): Harden Test Convergence

Goal: keep test strict while eliminating false negatives.

Recommended change:

1. Keep current fast sample-based check as phase 1 (quick “sync started and mostly converged” gate).
2. Add phase 2 full-set quiescence gate before final assertions:
   - require `alice_only.len() <= 2` and `bob_only.len() <= 2`
   - require condition to hold for N consecutive polls (e.g., 5 polls at 200ms) to avoid transient wobble.
3. Only then run final assertions.

Notes:

- This preserves strict zero-loss intent.
- It avoids passing purely on sparse random samples.
- It tests the actual invariant being asserted.

## Fix Plan B (Only If Needed): Protocol-Level Loss Investigation

If true loss is confirmed after quiescence wait:

1. Instrument session stats in `sync/session/initiator.rs` and `sync/session/responder.rs`:
   - events sent/received per session
   - done/data_done/done_ack state transitions
2. Validate that DoneAck is never emitted before responder has fully drained inbound data.
3. Validate that initiator waits for inbound data drain after DoneAck (already present, but confirm no early exit path).
4. Add a deterministic regression test in `tests/replication_contract_tests/` modeling the failure mode (not only scenario-level).

## Acceptance Criteria

Required:

1. `test_zero_loss_stress` passes in repeated local runs:
   - at least 20 consecutive runs.
2. No relaxation of core invariant:
   - final full-set diff must still be `<= 2` each side.
3. Keep `ScenarioHarness` usage and replay invariant checks intact.
4. Full test and boundary sanity:
   - `cargo check`
   - `bash scripts/check_boundary_imports.sh`
   - `cargo test --test scenario_test test_zero_loss_stress -- --nocapture`

Recommended additional confidence:

```bash
cargo test --test scenario_test -q
```

## Commit Strategy

1. `test: add temporary diagnostics for zero-loss stress flake` (optional, can be squashed/drop)
2. `test: harden zero-loss stress convergence to full-set quiescence`
3. `cleanup: remove temporary diagnostics, keep stable assertions`

