# Event Pipeline Phase Boundary + Command-Driven Side Effects: Execution Plan

Date: 2026-02-24
Branch: `exec/event-pipeline-phase-boundary-no-cheat-plan`
Status: active plan

## Goal

Make `event_pipeline` boundaries explicit and enforceable so a reader can answer three questions instantly:

1. What is transactional ingest persistence?
2. What is post-commit intent planning?
3. What performs side effects?

Target property: phase 1 persists, phase 2 plans commands, phase 3 executes commands via an adapter boundary.

## Why This Refactor

1. `batch_writer` is still the semantic center of ingest/projection flow; clarity here multiplies across peering, sync, and replay reasoning.
2. Current code improved naming (`PersistPhaseOutput`, `PostCommitCommand`) but still allows boundary drift because planner/orchestrator/effects live together.
3. We want tests that are realistic and hard to fake: command planning should be verifiable without hidden DB writes.

## Current Baseline (master as of 2026-02-24)

In `src/event_pipeline.rs`:

1. Phase intent is present in comments and helper names.
2. Post-commit actions are command-shaped (`PostCommitCommand`).
3. `batch_writer` still coordinates intake, transaction retries, persistence, command build, and command execution in one function.
4. Side-effect calls (`project_one`, `post_drain_hooks`, wanted removal) are still directly reachable from the same module body.

## Target Architecture

Preferred module layout:

1. `src/event_pipeline/mod.rs`
   - `batch_writer` orchestration only.
   - High-level phase sequence and error policy only.
2. `src/event_pipeline/phases.rs`
   - `PersistPhaseOutput`, `PostCommitCommand`, and phase data models.
3. `src/event_pipeline/planner.rs`
   - Pure command planning from `PersistPhaseOutput`.
   - Deterministic ordering rules.
4. `src/event_pipeline/effects.rs`
   - Side-effect executor contract + SQLite implementation.
   - Only place that can call projection/hook/wanted effects.
5. `src/event_pipeline/drain.rs`
   - `drain_project_queue` helper (shared startup recovery path).

If implementer keeps a single-file layout, equivalent boundaries are acceptable, but the same ownership rules and no-cheat checks still apply.

## Ownership Contract

1. **Persist phase** owns SQL writes for ingest rows + queue enqueue inside transaction.
2. **Planner phase** owns transformation from persisted output -> post-commit command list.
3. **Effects phase** owns side effects (wanted removal, queue drain projection, health logging, post-drain hooks).
4. `batch_writer` owns phase sequencing and retry policy only.

## Non-Goals

1. No event schema changes.
2. No sync protocol behavior changes.
3. No dual-path compatibility layer: remove old direct side-effect path in the same PR.

## Implementation Steps

### Step 1: Structural split

1. Move phase models and planner out of `batch_writer` body.
2. Introduce explicit phase entrypoints:
   - `run_persist_phase(...) -> PersistPhaseOutput`
   - `plan_post_commit_commands(&PersistPhaseOutput, batch_size) -> Vec<PostCommitCommand>`
   - `run_post_commit_effects(...)`
3. Keep `batch_writer` as a short sequence:
   - receive batch
   - begin/retry transaction
   - run persist phase
   - commit
   - plan post-commit commands
   - run effects

### Step 2: Introduce side-effect adapter boundary

1. Define a small executor contract in `event_pipeline/effects.rs` (trait or function-table).
2. Provide production SQLite executor implementation.
3. `batch_writer` must call only the executor boundary for post-commit side effects.

### Step 3: Enforce boundary with checks

Add `scripts/check_boundary_imports.sh` rules for event pipeline boundaries:

1. Fail if `project_one(` is called outside approved files (`effects.rs` and optional `drain.rs`).
2. Fail if `post_drain_hooks(` is called outside `effects.rs`.
3. Fail if `wanted.remove(` is called outside `effects.rs`.
4. Fail if planner imports `rusqlite` or `crate::db`.
5. Fail if `batch_writer` directly calls side-effect functions instead of executor boundary.

### Step 4: Add no-cheat tests

Required tests:

1. Planner purity tests:
   - deterministic command order for same inputs;
   - no commands when nothing persisted;
   - command set exactly matches persisted event IDs + tenant set.
2. Orchestrator phase-order tests with fake executor:
   - commit failure does not call effects;
   - commit success calls effects exactly once with planned command list.
3. Effects integration tests (SQLite-backed):
   - command execution performs expected side effects;
   - one command failure logs/warns but does not skip unrelated commands (if current policy is best-effort).
4. Boundary-script test:
   - `bash scripts/check_boundary_imports.sh` must fail when a temporary violation is introduced (record this manually in PR notes).

### Step 5: Docs alignment

Update docs so diagrams and prose match new boundary:

1. `docs/CURRENT_RUNTIME_DIAGRAM.md`: render `batch_writer` as 3 explicit internal phases.
2. `docs/DESIGN.md`: add concise ownership statement for persist/planner/effects.
3. `docs/PLAN.md`: update implementation notes and validation commands for this boundary.

## No-Cheat Gates (must all pass)

Run and include outputs in PR summary:

1. `cargo check`
2. `cargo test -q event_pipeline` (or exact new test modules)
3. `cargo test --test sync_graph_test -q`
4. `cargo test --test cli_test -q`
5. `bash scripts/check_boundary_imports.sh`
6. `rg -n "project_one\(|post_drain_hooks\(|wanted\.remove\(" src/event_pipeline`
   - output must only reference allowed files per this plan.
7. `rg -n "use rusqlite|crate::db" src/event_pipeline/planner.rs`
   - output must be empty.

## Acceptance Criteria

All are required:

1. `batch_writer` is orchestration-thin and phase sequence is obvious at a glance.
2. Planner is pure and deterministic.
3. Side effects are reachable only through the effect executor boundary.
4. Boundary script contains explicit event-pipeline checks and fails on violations.
5. Required tests pass and are reported in PR with command outputs.
6. Runtime diagrams/docs describe the same boundaries implemented in code.

## Reviewer Checklist

1. Can you locate persist/planner/effects code in under 30 seconds?
2. Does `batch_writer` avoid direct side-effect calls?
3. Do grep checks prove boundary constraints, not just style?
4. Do tests prove phase order and commit-gating behavior?
5. Do docs/diagram match the code path exactly?

