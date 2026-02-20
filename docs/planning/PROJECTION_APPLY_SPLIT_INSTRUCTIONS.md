# Projection Apply Split Instructions

## Goal
Split `src/projection/apply.rs` into smaller modules without changing projection behavior, queue semantics, or test outcomes.

Current baseline:
- `src/projection/apply.rs` is ~5.7k lines.
- Runtime logic is concentrated in the first ~900 lines.
- The remaining ~4.8k lines are `#[cfg(test)]` helpers/tests.

## Non-Goals
1. No protocol/schema behavior changes.
2. No projector policy changes.
3. No trust/identity semantics changes.
4. No test deletions.

## Hard Constraints
1. Keep public API stable: `projection::apply::project_one(...)` remains the canonical entrypoint.
2. Keep encrypted wrapper path behavior unchanged (`projection::encrypted` still delegates into shared dep/signer/projection stages).
3. Keep deterministic ordering and rejection/block reasons unchanged unless a test explicitly needs string updates.
4. Prefer mechanical moves before any cleanup/refactor.

## Target Module Shape
Create a directory module:
- `src/projection/apply/mod.rs` (public facade + exports)
- `src/projection/apply/context.rs`
  - `build_context_snapshot`
  - signer/author consistency helper(s)
- `src/projection/apply/write_exec.rs`
  - `execute_write_ops`
  - `execute_emit_commands`
- `src/projection/apply/dispatch.rs`
  - `dispatch_pure_projector`
- `src/projection/apply/stages.rs`
  - `check_dep_types`
  - `check_deps_and_block`
  - `record_rejection`
  - `apply_projection`
  - `run_dep_and_projection_stages`
- `src/projection/apply/project_one.rs`
  - `project_one_step`
  - `project_one` (public re-export from `mod.rs`)
- `src/projection/apply/cascade.rs`
  - `cascade_unblocked`
  - `cascade_unblocked_inner`
- `src/projection/apply/tests/` (test split in phase 2)

Note:
- Keep function visibility minimal (`pub(crate)` only where cross-module use requires it).
- Keep names unchanged initially to minimize churn.

## Execution Plan

### Phase 1: Runtime split (no behavior changes)
1. Move `apply.rs` to `apply/mod.rs` intact first, compile, and run projection tests.
2. Extract `context.rs` and wire imports.
3. Extract `write_exec.rs` and wire imports.
4. Extract `dispatch.rs` and wire imports.
5. Extract `stages.rs` and wire imports.
6. Extract `project_one.rs` and `cascade.rs`; keep `project_one` export path unchanged.
7. Ensure `src/projection/encrypted.rs` continues importing `run_dep_and_projection_stages` from `super::apply`.

Phase-1 verification command:
- `cargo test projection::apply -- --nocapture`

### Phase 2: Test split (still no behavior changes)
1. Move `#[cfg(test)] mod tests` out of `apply/mod.rs` into:
   - `src/projection/apply/tests/mod.rs`
   - optional helper subfiles (`identity.rs`, `encrypted.rs`, `deletion.rs`, `file_slice.rs`, etc.).
2. Keep helper function names and fixtures intact during move.
3. Keep any order-sensitive tests deterministic (avoid hidden global mutable state changes during split).

Phase-2 verification commands:
- `cargo test projection::apply -- --nocapture`
- `cargo test projection::encrypted -- --nocapture`

### Phase 3: Optional cleanup (only after parity)
1. Deduplicate repeated test setup helpers.
2. Reduce oversized `use` lists.
3. Add brief file-level comments describing responsibility boundaries.

## Known Couplings To Preserve
1. `src/projection/encrypted.rs` depends on `run_dep_and_projection_stages`.
2. `src/event_pipeline.rs`, `src/projection/create.rs`, `src/service.rs`, and `src/testutil.rs` depend on `project_one`.
3. Cascade path must keep existing blocked-edge cleanup behavior (`blocked_event_deps` orphan cleanup after header removal).
4. Guard-retry behavior (`RetryWorkspaceEvent`, `RetryFileSliceGuards`) must remain command-driven.

## Acceptance Criteria
1. `src/projection/apply.rs` is replaced by a module directory split with clear responsibilities.
2. `projection::apply::project_one` remains stable for all callers.
3. Projection behavior is unchanged (tests passing without semantic diffs).
4. No new DB writes/reads are introduced outside existing logic.
5. No tests are removed; failures only allowed if directly caused by naming/path mechanical changes and then fixed in-branch.

## Suggested Commit Sequence
1. `refactor(projection): convert apply.rs to module scaffold`
2. `refactor(projection): split apply runtime stages into submodules`
3. `test(projection): move apply tests into apply/tests module`
4. `chore(projection): small cleanup after parity`

## Safety Checklist Before Merge
1. Run formatting and compile:
   - `cargo fmt`
   - `cargo test projection::apply`
2. Spot-check high-risk paths:
   - encrypted inner projection path
   - workspace guard retry path
   - file-slice guard retry + dep-unblock interactions
3. Confirm no public callsite changes were required outside `projection::apply` exports.
