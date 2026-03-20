# Range-Chunk Sync: Start Here

## What This Is

This is the short execution brief for the next assistant working on range-chunk sync.

Use this worktree only:

- Worktree: `/home/holmes/poc-7/.codex-worktrees/range-chunk-sync-design`
- Branch: `codex/range-chunk-sync-design`

Read the full design doc for protocol detail:

- `/home/holmes/poc-7/.codex-worktrees/range-chunk-sync-design/docs/range_chunk_sync_handoff.md`

Reference-only prototype worktree:

- `/home/holmes/poc-7/.codex-worktrees/tiered-hot-window-sync`

## First Moves

1. Port or recreate the tiered benchmark from the prototype worktree:
   - `/home/holmes/poc-7/.codex-worktrees/tiered-hot-window-sync/tests/daemon_tiered_window_perf_test.rs`
2. Port the encrypted-wrapper timestamp fix if it is still missing:
   - `/home/holmes/poc-7/.codex-worktrees/tiered-hot-window-sync/src/state/projection/create.rs`
3. Re-establish the existing `parallel` hot-window baseline on this clean branch before adding range-chunk transport.
4. Only after that, add:
   - range metadata
   - `RequestRangeChunk`
   - chunk ownership / stealing
   - bounded hedge

## Core Non-Negotiables

- Preserve parallel repeated windowed discovery:
  - hour
  - day
  - week
  - month
  - full
- Keep explicit blocker/dependency `RequestIds`.
- Blockers must stay higher priority than range-chunk work.
- Multi-peer range work must be owner-based and stealable, not eager-duplicate.

## Success Matrix

## Single-Source: Cable

### SC-SS-C1: 50k cable recent windows stay fast

Target at `50k`, `cable`, `parallel`:

- hour `<= 0.50s`
- day `<= 0.60s`
- week `<= 0.90s`
- month `<= 2.00s`

These are deliberately a little looser than the prototype results:

- prototype baseline:
  - hour `0.35s`
  - day `0.40s`
  - week `0.60s`
  - month `1.55s`

Proof:

- run the tiered benchmark on `50k`, `cable`, `parallel`
- compare to:
  - `/home/holmes/poc-7/.codex-worktrees/tiered-hot-window-sync/target/perf-results/daemon_tiered_window_perf_test.parallel_50000_cable.summary`

### SC-SS-C2: 50k cable full catchup is at least stable, ideally better

Target at `50k`, `cable`, `parallel`:

- full catchup wall `<= 70s` minimum bar
- full catchup wall `<= 65.13s` stretch goal

Reason:

- current prototype baseline is `65.13s`
- range-chunk work should eventually improve this, not regress it

Proof:

- same `50k`, `cable`, `parallel` run as above

### SC-SS-C3: 200k cable keeps recent windows fast

Target at `200k`, `cable`, `parallel`:

- hour `<= 0.50s`
- day `<= 0.60s`
- week `<= 1.50s`
- month `<= 9.00s`

Prototype baseline:

- hour `0.35s`
- day `0.40s`
- week `1.05s`
- month `7.87s`

Proof:

- run the tiered benchmark on `200k`, `cable`, `parallel`
- compare to:
  - `/home/holmes/poc-7/.codex-worktrees/tiered-hot-window-sync/target/perf-results/daemon_tiered_window_perf_test.parallel_200000_cable.summary`

### SC-SS-C4: 200k cable full catchup improves materially

Target at `200k`, `cable`, `parallel`:

- full catchup wall `< 750s` minimum bar
- full catchup wall `< 700s` stretch goal

Reason:

- prototype baseline is `812.90s`
- this is the clearest place where range-chunk transport should win

## Single-Source: Mobile

### SC-SS-M1: 50k mobile recent windows remain usable

Target at `50k`, `mobile`, `parallel`:

- hour `<= 0.70s`
- day `<= 1.00s`
- week `<= 2.20s`
- month `<= 5.50s`

Prototype baseline:

- hour `0.50s`
- day `0.85s`
- week `1.80s`
- month `4.41s`

Proof:

- run the tiered benchmark on `50k`, `mobile`, `parallel`
- compare to:
  - `/home/holmes/poc-7/.codex-worktrees/tiered-hot-window-sync/target/perf-results/daemon_tiered_window_perf_test.parallel_50000_mobile.summary`

### SC-SS-M2: 50k mobile full catchup does not regress materially

Target at `50k`, `mobile`, `parallel`:

- full catchup wall `<= 450s` minimum bar
- full catchup wall `<= 427.87s` stretch goal

## Multi-Source

### SC-MS-1: duplication stays bounded

Target for `2x10k`, `4x10k`, and `8x10k`:

- duplication ratio `<= 1.60x`

Proof:

- extend or recreate the multi-source metrics test
- report duplication ratio for:
  - `2x10k`
  - `4x10k`
  - `8x10k`

### SC-MS-2: no source-idle starvation

Target:

- at `8x10k`, no long-lived state where most peers are idle while one peer owns most hot work
- chunk ownership should spread across peers and idle peers should steal stalled work

Proof:

- add per-peer chunk assignment / completion counters
- validate in test output that multiple peers actually serve meaningful work at `8x10k`

### SC-MS-3: hot-window projection still scales in multi-source mode

Target for `2x10k`, `4x10k`, `8x10k` under `cable`:

- most-recent hot window does not get slower as peer count increases by more than `2x` from the `2x` case

This is intentionally looser than a perfect scaling target, but strict enough to reject obviously broken peer assignment.

Proof:

- add a hot-window projected metric to the multi-source test
- compare `2x`, `4x`, `8x`

### SC-MS-4: full multi-source catchup remains stable

Target:

- `2x10k`, `4x10k`, and `8x10k` all complete under `cable`
- `2x10k` and `4x10k` also complete under `mobile`
- no duplication-driven explosion

Proof:

- run the multi-source end-to-end benchmark matrix
- record:
  - full catchup wall
  - duplication ratio
  - per-peer chunk completion counters

## Historical Window Requirement

### SC-HW-1: arbitrary historical slice works

Target:

- given a timestamp or anchor event, the previous `N` messages in that region can be made hot
- their blockers are fetched aggressively
- bulk catchup does not starve them

Proof:

- add a historical-window perf test:
  - choose an anchor well away from the newest tail
  - request previous `100` messages
  - measure time until all `100` are projected

## Tests / Checks That Must Exist

At minimum:

- protocol roundtrip tests for new range-chunk frames
- chunk cursor / continuation tests
- owner lease / steal / hedge coordinator tests
- blocker-preempts-range tests
- single-source tiered perf tests
- historical-window perf test
- multi-source duplication / hot-window / full-catchup metrics tests

## End-to-End Validation Required

Do not call the task done until all of the following are demonstrated:

1. `50k cable parallel` meets the single-source recent-window and full-catchup bars.
2. `50k mobile parallel` meets the mobile usability bars.
3. `200k cable parallel` keeps recent windows fast and improves full catchup materially.
4. `2x10k`, `4x10k`, and `8x10k` meet the multi-source duplication bound.
5. A historical window of previous `100` messages can be projected quickly without waiting for full catchup.

## Suggested Benchmark Commands

Recreate or adapt the prototype benchmark and then run at least:

```bash
TOPO_TIERED_SYNC_TOTAL_MESSAGES=50000 TOPO_JOIN_CATCHUP_NETWORK_PROFILE=cable cargo test --release --test daemon_tiered_window_perf_test perf_tiered_window_50k_parallel -- --ignored --exact --nocapture --test-threads=1

TOPO_TIERED_SYNC_TOTAL_MESSAGES=50000 TOPO_JOIN_CATCHUP_NETWORK_PROFILE=mobile cargo test --release --test daemon_tiered_window_perf_test perf_tiered_window_50k_parallel -- --ignored --exact --nocapture --test-threads=1

TOPO_TIERED_SYNC_TOTAL_MESSAGES=200000 TOPO_JOIN_CATCHUP_NETWORK_PROFILE=cable cargo test --release --test daemon_tiered_window_perf_test perf_tiered_window_50k_parallel -- --ignored --exact --nocapture --test-threads=1
```

And the multi-source metrics/gates once ported or recreated.
