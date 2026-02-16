# CLI Bootstrap Test Realism: Execution And Handoff Plan

Date: 2026-02-16
Owner branch: `plan/cli-bootstrap-test-realism`
Worktree: `/home/holmes/poc-7-cli-bootstrap-realism-plan`
Base commit: `47e2982` (`origin/master` at branch creation)

## Objective

Remove direct SQL trust seeding from CLI bootstrap tests and make invite/bootstrap CLI tests use production command/API flows only.

Primary TODO target:

1. `P1: Stop direct SQL trust seeding in CLI invite-bootstrap test`

## Current Fake Surface

In `tests/cli_test.rs`:

1. `seed_invite_bootstrap_trust(...)` inserts trust rows directly.
2. `seed_pending_invite_bootstrap_trust(...)` inserts trust rows directly.
3. `test_cli_sync_bootstrap_from_accepted_invite_data` depends on those direct DB writes.

## Primary Files

1. `tests/cli_test.rs`
2. `src/main.rs` and/or `src/service.rs` (if missing non-interactive invite flow commands)
3. (optional) new CLI integration test file if a cleaner split is needed

## Constraints

1. No direct DB trust-row seeding in functional CLI bootstrap tests.
2. Pinning-policy tests may still use `--pin-peer` where pinning itself is under test.
3. Functional bootstrap tests must run as separate process invocations.

## Phase Plan

## Phase 0: Baseline Verification

Required commands:

1. `cargo test --test cli_test -q`
2. `cargo test --test interactive_test -q`

## Phase 1: Enable Production Invite Bootstrap Path For CLI Tests

Tasks:

1. Decide and implement one production-safe path for tests:
   - add non-interactive CLI commands for invite create/accept, or
   - route tests through an existing production command surface that performs invite create/accept.
2. Ensure acceptance path performs real bootstrap sync/trust materialization through runtime logic, not raw SQL inserts.

Verification:

1. New or updated CLI integration test proves invite create -> accept -> sync works without DB seeding.
2. `cargo test --test cli_test -q`

## Phase 2: Remove Direct SQL Seeding Helpers

Tasks:

1. Delete/retire seeding helpers from `tests/cli_test.rs`.
2. Rewrite `test_cli_sync_bootstrap_from_accepted_invite_data` to use production flow.
3. Keep pinning-policy tests intact and clearly separated from bootstrap realism tests.

Verification:

1. `rg -n "seed_invite_bootstrap_trust|seed_pending_invite_bootstrap_trust|record_invite_bootstrap_trust|record_pending_invite_bootstrap_trust" tests/cli_test.rs` returns no functional-test usage.
2. `cargo test --test cli_test -q`

## Phase 3: Regression Gate

Required commands:

1. `cargo test --test cli_test -q`
2. `cargo test --test rpc_test -q`
3. `cargo test --test scenario_test -q`
4. `cargo test -q`

## Acceptance Checklist

1. CLI bootstrap tests do not write trust rows directly.
2. Invite/bootstrap sync path is tested via production command/API flows.
3. Pinning-policy tests remain explicit and isolated.
4. Regression gate passes.
