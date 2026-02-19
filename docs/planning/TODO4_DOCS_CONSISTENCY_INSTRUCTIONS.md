# TODO 4 Instructions: Docs Vocabulary and Path Consistency

Date: 2026-02-19
Branch: `exec/todo4-docs-consistency-instructions`
Worktree: `/home/holmes/poc-7-todo4-docs-consistency`

## Goal

Make active docs reflect the current codebase vocabulary and paths:

1. `peering`
2. `sync`
3. `protocol`
4. `event_modules`
5. `event_pipeline`
6. `projection/apply`

## Required start step

1. `git fetch origin`
2. `git rebase origin/master`

## Scope

1. Update active docs only (`docs/*.md`, `docs/planning/*.md` that are still active references).
2. Archived docs may keep historical names, but should be clearly marked as historical.
3. No code changes in this branch.

## Current inconsistencies to fix

Examples currently present:

1. old paths like `src/sync/protocol.rs` still referenced in active docs.
2. legacy terms (`network`, `replication`, `event_runtime`, `events`) appear in active planning docs as if current.
3. some docs reference removed files (`src/projection/pipeline.rs`).

## Required work

### A) Audit and classify docs

1. Build a list of active docs that should be accurate for implementation.
2. Build a list of historical docs that can remain legacy but must be marked clearly.

### B) Update active docs to current names/paths

1. Replace stale module names with current ones.
2. Replace stale file paths with current file paths.
3. Keep terminology consistent with `TODO.md` target vocabulary.

### C) Add a docs hygiene check section

1. Add a short section in `docs/PLAN.md` (or `docs/INDEX.md` if present) defining canonical module vocabulary.
2. Add a maintenance note: archived docs may be historically inaccurate and should not be used as implementation source of truth.

### D) Mark historical docs explicitly

1. For non-active docs that still mention old module names, add a top note like:
   - "Historical plan; names may not match current tree."
2. Prefer moving stale planning docs under `docs/archive/` when appropriate.

## Mandatory searches before commit

Run and resolve hits in active docs:

1. `rg -n "src/network|src/replication|src/event_runtime|src/events|src/sync/protocol\\.rs|src/projection/pipeline\\.rs" docs`
2. `rg -n "crate::replication|crate::network|crate::events" docs`

## Quality gate

1. `cargo check` (sanity check, even though this is docs-only)

## Done criteria

1. Active docs use current vocabulary and file paths consistently.
2. Historical docs are clearly marked as historical and not mistaken for active implementation guidance.
3. The grep checks above are clean for active docs.
