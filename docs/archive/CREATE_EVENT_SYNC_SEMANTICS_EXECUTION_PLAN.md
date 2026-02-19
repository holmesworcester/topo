# create_event_sync Semantics Investigation: Execution And Handoff Plan

> **Historical plan; completed. Retained for reference.**

Date: 2026-02-16
Owner branch: `plan/create-event-sync-semantics`
Worktree: `/home/holmes/poc-7-create-event-sync-plan`
Base commit: `47e2982` (`origin/master` at branch creation)

## Objective

Investigate and decide the `create_event_sync` contract before implementation changes.

Primary TODO target:

1. `P1: Investigate and decide create_event_sync service semantics before implementation changes`

## Decision To Make

Whether `create_event_sync` should:

1. return success only for `Valid` terminal outcomes, or
2. continue allowing wrapped/translated `Blocked` outcomes as success-like behavior in some service paths.

## Scope

Investigation + decision artifact first.
No implementation refactor until decision approval.

## Primary Files

1. `src/projection/create.rs`
2. `src/service.rs`
3. `src/main.rs`
4. call sites in tests and orchestration code
5. `docs/PLAN.md` and `TODO.md` for contract alignment

## Phase Plan

## Phase 0: Baseline Verification

Required commands:

1. `cargo test --test cli_test -q`
2. `cargo test --test scenario_test -q`

## Phase 1: Call-Site And Behavior Inventory

Tasks:

1. Enumerate all `create_event_sync` and wrapper call sites.
2. For each call site, document expected behavior when projection returns:
   - `Valid`,
   - `Block`,
   - `Reject`.
3. Identify any service/main wrappers that convert `Block` into success-like outcomes.

Verification:

1. Produce an investigation note in this worktree (e.g., `docs/CREATE_EVENT_SYNC_SEMANTICS_FINDINGS.md`) with evidence and references.

## Phase 2: Option Matrix

Tasks:

1. Define at least two explicit options:
   - Option A: strict success-only-on-valid contract.
   - Option B: preserve current behavior with explicit wrapper semantics.
2. For each option, document:
   - API impact,
   - caller impact,
   - test impact,
   - migration/cutover steps (POC-style, no compatibility scaffolding),
   - risk and rollback strategy.

Verification:

1. Reviewable matrix exists with concrete code references.

## Phase 3: Approval Gate (No Code Changes Yet)

Tasks:

1. Present recommendation + rationale.
2. Wait for explicit approval on selected option.
3. Only after approval, create an implementation plan/branch for semantic change.

Verification:

1. No semantic code changes before approval.
2. `git diff` in this branch should contain investigation docs only.

## Phase 4: Post-Approval Implementation (Deferred)

Execution in a follow-on branch should include:

1. chosen contract implementation,
2. updated tests for valid/block/reject behavior,
3. docs alignment in PLAN/design mapping,
4. full regression gate:
   - `cargo test --test cli_test -q`
   - `cargo test --test scenario_test -q`
   - `cargo test --test interactive_test -q`
   - `cargo test -q`

## Acceptance Checklist

1. Investigation artifact completed with call-site inventory and option matrix.
2. Explicit decision recorded before code changes.
3. Follow-on implementation (separate branch) can proceed with clear contract target.
