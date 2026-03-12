# Perf Hypotheses: 2026-03-12

This note records the first round of perf hypotheses tested on top of
`2b139ff` / `314ea53`.

## Goal

Recover some of the normal-path throughput lost on the hot/cold sync branch
without reintroducing duplicate sends or weakening correctness.

## Control

Historical branch-local numbers before this investigation:

- `perf_sync_10k`: `3.69s`, `2709 msgs/s`
- `perf_continuous_10k`: `2.26s`, `4432 msgs/s`
- `file_throughput_test`:
  - `100 MB`: `108.9 MB/s`
  - `10 MB`: `106.2 MB/s`
  - `1 GB`: `78.9 MB/s`
  - `0.2 MB`: `157.2 MB/s`

Current reruns on 2026-03-12 using
`cargo +stable test --release --test daemon_perf_test perf_sync_10k -- --nocapture --test-threads=1`
did not reproduce those older branch-local numbers. Repeated clean reruns on
the reverted runtime timed out at roughly `7.3k-7.5k / 10k` delivered after
`120s`.

That means there is now a benchmark-stability problem or a real warm-sync
liveness regression on the committed branch itself. Treat the results below as
"what this branch did today", not as definitive replacement baselines for
`docs/PERF.md`.

## Hypothesis 1: egress micro-batching is the main throughput bottleneck

Reasoning:

- non-lowmem `egress_claim_count()` is only `8`
- non-lowmem `bulk_egress_claim_count()` is `1`
- `drain_egress_to_data_stream()` only claims one batch per loop

Tested variants:

- `egress_claim_count = 128`, `bulk_egress_claim_count = 16`
- `egress_claim_count = 32`, `bulk_egress_claim_count = 4`

Results:

- `128/16`: `perf_sync_10k` timed out at `7826 / 10002`
- `32/4`: `perf_sync_10k` timed out at `7234 / 10002`

What this exposed:

- `egress.count_pending()` excludes rows leased by the current session.
- That makes the session shutdown logic believe egress is empty while it still
  owns unsent leased rows.

Follow-up test:

- Added a temporary `count_available_or_owned()` backlog metric and used it for
  session completion checks.
- That improved the failed `32/4` run to `8187 / 10002`, but still timed out.

Conclusion:

- Larger send quanta are still the most plausible throughput win.
- But they are not currently safe.
- Before re-testing this seriously, session completion needs a correct notion of
  "my outstanding leased work", and send/lease cleanup on partial send failure
  likely needs tightening too.

## Hypothesis 2: local-create direct first-hop enqueue is hurting warm-sync perf

Reasoning:

- successful local shared create does direct peer egress enqueue in addition to
  the normal fanout/reconciliation path
- this adds DB work on every local message
- conceptually it only helps the first hop and can hide weak hot-sync cadence

Test:

- removed the direct local-create enqueue shortcut from `create.rs`

Result:

- `perf_sync_10k` timed out at `5818 / 10002`

Conclusion:

- On the current branch, that shortcut is carrying real liveness, not just
  masking a tiny latency issue.
- It should not be removed until hot-session re-entry / dirty handling is
  strong enough to propagate fresh events promptly without it.

## Hypothesis 3: duplicate pending-fanout persistence on local create is hot-path churn

Reasoning:

- local create persists a `pending_shared_fanouts` row during store
- successful immediate fanout persists the same row again with `INSERT OR IGNORE`
  and then deletes it on success

Test:

- skipped the redundant persist when local create had already stored the pending
  fanout row

Result:

- could not isolate a trustworthy throughput delta because the release warm-sync
  benchmark was already timing out on the reverted runtime during the same
  investigation window

Conclusion:

- This is still a plausible small hot-path win.
- Re-test only after the release `perf_sync_10k` control is trustworthy again.

## What Seems Most Likely

1. The branch still pays too much per-message overhead in the normal path.
2. The first place to recover perf is still egress batching, but only after
   fixing completion/lease accounting.
3. The direct first-hop enqueue is not presently optional.
4. Small local-create churn reductions may help, but they are secondary to the
   egress/session-control issue.

## Next Useful Work

1. Reproduce `perf_sync_10k` on the committed branch with preserved temp DBs and
   daemon logs so the `~7.4k / 10k` stall can be inspected directly.
2. Fix session completion semantics for leased rows before retrying larger
   egress quanta.
3. Re-test the duplicate-fanout-write reduction once the warm-sync benchmark is
   stable again.
