# Perf comparison: dep-facts-pilot vs. master

Date: 2026-04-22
Branch: `dep-facts-pilot` at `f4be0bb6`
Baseline: `master` at `cf05cb5e`
Hardware: same runner, release profile, single `cargo test` per run.

## Results

| Scenario | master (`cf05cb5e`) | dep-facts-pilot (`f4be0bb6`) | Δ |
|---|---|---|---|
| **10k bidirectional** — msgs/s | 3,797 | 3,796 | −0.03% (noise) |
| **10k bidirectional** — wall | 2.63s | 2.63s | flat |
| **10k bidirectional** — peak RSS | 156.5 MiB | 150.3 MiB | **−4.0%** |
| **50k one-way** — msgs/s | 1,495 | 1,505 | **+0.7%** |
| **50k one-way** — wall | 33.45s | 33.22s | −0.7% |
| **50k one-way** — peak RSS | 379.1 MiB | 353.3 MiB | **−6.8%** |

Test invocations:

```
cargo test --release --test perf_test perf_sync_10k -- --ignored --nocapture
cargo test --release --test perf_test perf_sync_50k -- --ignored --nocapture
```

## Reading

**Throughput flat within noise.** The full branch — DepFacts/GuardFacts
migration for 15 projectors, admin-as-dep wire-format bump, LocalKeySecret
refactor, WriteCapability threading across the apply pipeline, the
canonical KeyShared security theorem wired to runtime via
`debug_assert_eq!` at Valid finalization — does not move msgs/s.

The `debug_assert_eq!` in `decide_key_shared` is gated behind
`cfg(debug_assertions)` so release builds don't pay the cost. Release
perf stays flat.

**Memory improvement: 4–7% RSS reduction.** Plausible contributors:

- `RetryBlockedEncryptedByKey` retirement — no more bespoke scan of
  `blocked_events` to re-project encrypted rows when a key arrives.
  Standard cascade handles it now.
- `key_secrets` ambient writes consolidated — where KeyShared /
  KeyRotation / KeyHistory used to directly `INSERT OR IGNORE` into
  `key_secrets` + emit a retry signal, they now emit one deterministic
  KeySecret blob. The KeySecret projector writes `key_secrets` once.
- `access_control.rs` retirement — ~390 lines of abstract-model Verus
  proofs removed; the test-time `topo-verus-proofs` footprint shrinks.

No per-cause attribution was measured; the aggregate number is what's
above.

## Baseline hygiene

- Ten pre-existing test failures on `dep-facts-pilot` match the same
  ten on `master` — no functional regressions from the migration.
- Verus: 355 verified / 0 errors on `dep-facts-pilot` (down from 371
  on branch HEAD before `access_control.rs` retirement; the 16-proof
  drop is the intentionally-removed wrong-target proofs).
- All four mirror/coverage/fake-proof lints PASS on both branches.

## Scenarios not re-measured this turn

- `perf_continuous_10k` (inject while syncing).
- Larger scales (`perf_sync_100k`, `perf_sync_200k` exist in
  `tests/perf_test.rs`).
- `daemon_perf_test.rs`, `daemon_tiered_window_perf_test.rs`,
  `multi_peer_delivery_latency_perf_test.rs`.

Run any of those if you want a broader comparison.
