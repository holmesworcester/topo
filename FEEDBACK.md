# Merge Readiness: master

- Status: `NOT READY`
- Head: `b9fd42993c00`
- Ahead/behind vs `origin/master`: `ahead 3`, `behind 0`

## Verified
- `cargo test --test cli_test -q` ✅
- `cargo test --test two_process_test -q` ✅

## Blockers
1. Known perf blocker still open: `perf_continuous_10k` has been failing in prior runs and was not re-cleared in this pass.
2. Tenant routing safety issue remains: `accept_loop_with_ingest` still has first-tenant fallback when peer-to-tenant resolution misses.

## Required before merge
1. Make `perf_continuous_10k` green (or explicitly quarantine with justification).
2. Replace fallback routing with hard reject + telemetry.
