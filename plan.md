# Plan: Phase 7 Transport Trust Retrofit (Remove CLI/File Authority)

## Objective
Move transport allow/deny authority fully to SQL projected trust state in steady state.

Steady-state trust source:
- `transport_keys`
- `invite_bootstrap_trust`
- `pending_invite_bootstrap_trust`

CLI pins and filesystem artifacts can exist as diagnostics/bootstrap helpers, but not as runtime policy authority.

## Current Risk Areas
1. `svc_sync` runtime verifier path still unions CLI pins with SQL trust.
2. Startup checks may still rely on full in-memory allowlist materialization.
3. Behavior drift risk between `src/main.rs` and `src/service.rs`.

## Scope
- Runtime verifier path and sync startup behavior only.
- Trust-source query APIs and tests.
- CLI semantics for bootstrap helper mode.

## Out of Scope
- Event-backed TLS credential materialization (separate worktree).
- TLA transport-credential extension (separate worktree).

## Implementation Plan
1. Add explicit trust-source policy in runtime (`sql_only` default in production path).
2. Refactor `svc_sync` / daemon sync startup to derive allow decisions from SQL-only path.
3. Keep CLI pin support only as explicit helper mode:
   - either import into SQL bootstrap rows,
   - or restricted diagnostic mode that is not default and clearly labeled.
4. Ensure dynamic verifier closure checks SQL trust rows directly per handshake decision.
5. Remove/replace code paths that build policy authority from CLI pin union by default.
6. Add/update tests to prove:
   - SQL-trusted peer accepted,
   - SQL-untrusted peer rejected,
   - CLI-only pin does not silently grant production trust.

## Files To Touch (Expected)
1. `src/service.rs`
2. `src/main.rs`
3. `src/db/transport_trust.rs`
4. tests that cover sync/bootstrap trust behavior (`tests/rpc_test.rs`, `tests/holepunch_test.rs`, `tests/scenario_test.rs` as needed)

## Test Plan
1. `cargo test --test holepunch_test -- --nocapture`
2. `cargo test --test scenario_test test_transport_key_replay_invariants -- --nocapture`
3. `cargo test --test rpc_test -- --nocapture`
4. Targeted unit tests in `src/db/transport_trust.rs`

## Acceptance Criteria
1. Production runtime trust authority is SQL-projected state only.
2. CLI pins are no longer implicit verifier authority.
3. Existing bootstrap/invite flow remains functional.
4. Tests explicitly lock this behavior to prevent regression.

## Mistakes To Avoid
1. Breaking invite bootstrap by removing helper path without replacement.
2. Leaving one codepath (`main` or `service`) on old semantics.
3. Loading huge trust sets into memory unnecessarily in low-memory mode.
