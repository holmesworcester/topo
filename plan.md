# Plan: Phase 6 Large Trust-Set + Low-Memory Hardening

## Objective
Meet Phase 6 goals for low-memory trust lookup and large identity-set coverage.

Key targets:
1. Avoid full in-memory trust-keyset loading in low-memory mode.
2. Add explicit large trust-set test coverage (`>= 100_000` trust keys).
3. Preserve deterministic transport allow/deny behavior.

## Current Risk Areas
1. Startup paths may still materialize full allowlists for checks/logging.
2. Large trust sets are not explicitly covered by low-memory tests.
3. Potential memory spikes from unbounded caching patterns.

## Scope
- Trust lookup path and memory behavior under `LOW_MEM_IOS` / `LOW_MEM`.
- Targeted tests/bench coverage for large trust sets.

## Out of Scope
- Phase 7 trust-source policy redesign (separate worktree).
- Event-backed TLS authority migration (separate worktree).

## Implementation Plan
1. Audit runtime trust checks for full-set materialization and replace with indexed SQL checks where possible.
2. Ensure handshake-time allow/deny path uses SQL indexed lookup with bounded cache only.
3. Add bounded hot cache (size-limited, eviction tested) if needed for performance.
4. Add large trust-set test fixture:
   - seed `transport_keys` with at least `100_000` rows for one tenant,
   - validate allow/deny correctness and bounded memory behavior.
5. Add/extend low-memory tests in `tests/low_mem_test.rs`:
   - include large trust-set scenario,
   - assert budget ceiling using existing RSS measurement approach.
6. Verify queue and sync behavior remain stable under low-memory constraints.

## Files To Touch (Expected)
1. `src/db/transport_trust.rs`
2. `src/service.rs` and/or `src/main.rs` (startup checks)
3. `tests/low_mem_test.rs`
4. optional helper updates in `src/testutil.rs`

## Test Plan
1. `cargo test --test low_mem_test -- --nocapture`
2. `cargo test --test scenario_test test_transport_key_replay_invariants -- --nocapture`
3. Add targeted large trust-set test command (new test) and run it explicitly.
4. If added, run perf-style targeted trust lookup benchmark in debug notes.

## Acceptance Criteria
1. Low-memory path does not require loading full trust set into memory.
2. Large trust-set test exists and passes.
3. Memory budget behavior is enforced/observable in low-memory mode.
4. No trust correctness regressions.

## Mistakes To Avoid
1. Building full allowlists just to test emptiness.
2. Unbounded in-memory caches that defeat low-memory mode.
3. Bench-only validation without a deterministic test assertion.
