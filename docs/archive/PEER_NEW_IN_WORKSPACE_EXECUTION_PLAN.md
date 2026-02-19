# Peer::new_in_workspace Realism: Execution And Handoff Plan

> **Historical plan; completed. Retained for reference.**

Date: 2026-02-16
Owner branch: `plan/peer-new-in-workspace-realism`
Worktree: `/home/holmes/poc-7-peer-new-workspace-plan`
Base commit: `47e2982` (`origin/master` at branch creation)

## Objective

Remove prerequisite-event copying from `Peer::new_in_workspace` and replace it with a realistic production-style join/bootstrap flow.

Primary TODO target:

1. `P1: Replace prerequisite event copy in Peer::new_in_workspace`

## Current Fake Surface

In `src/testutil.rs::Peer::new_in_workspace`:

1. Directly copies events with `insert_event(...)`.
2. Directly inserts `recorded_events` rows.
3. Directly inserts `neg_items` via `insert_neg_item_if_shared(...)`.
4. Then calls `accept_user_invite(...)`.

This bypasses real sync/bootstrap behavior.

## Primary Files

1. `src/testutil.rs`
2. tests relying on `Peer::new_in_workspace` (notably `tests/holepunch_test.rs` and scenario flows)

## Constraints

1. No direct event/recorded/neg insertion shortcut in `new_in_workspace`.
2. Test helper must remain deterministic enough for CI.
3. Keep helper API ergonomics stable for existing tests where possible.

## Phase Plan

## Phase 0: Baseline Verification

Required commands:

1. `cargo test --test scenario_test -q`
2. `cargo test --test holepunch_test -q`

## Phase 1: Characterization Tests

Tasks:

1. Add/strengthen tests around `new_in_workspace` behavior expectations:
   - join succeeds,
   - resulting identity chain valid,
   - no hidden direct-copy side effects expected by callers.
2. Capture current invariants before refactor.

Verification:

1. `cargo test --test scenario_test -q`

## Phase 2: Replace Copy Shortcut With Realistic Bootstrap Path

Tasks:

1. Implement realistic prerequisite acquisition path for `new_in_workspace`, using production flow primitives (invite + sync/bootstrap semantics) rather than DB row injection.
2. Remove direct calls to:
   - `insert_event(...)`,
   - `insert_recorded_event(...)` (for prerequisite copy),
   - `insert_neg_item_if_shared(...)`.
3. Keep `new_in_workspace` API stable unless a deliberate test migration is approved.

Verification:

1. `rg -n "insert_event\(|insert_neg_item_if_shared\(|insert_recorded_event\(" src/testutil.rs` no longer shows prerequisite-copy usage in `new_in_workspace`.
2. `cargo test --test holepunch_test -q`
3. `cargo test --test scenario_test -q`

## Phase 3: Regression Gate

Required commands:

1. `cargo test --test holepunch_test -q`
2. `cargo test --test scenario_test -q`
3. `cargo test --test cli_test -q`
4. `cargo test -q`

## Acceptance Checklist

1. `Peer::new_in_workspace` no longer copies prerequisite events via direct DB insertion.
2. Join path uses realistic production-style bootstrap/sync behavior.
3. Downstream tests depending on helper still pass.
4. Regression gate passes.
