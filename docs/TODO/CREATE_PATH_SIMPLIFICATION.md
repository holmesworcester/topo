# Create Path Simplification TODO

Date: 2026-03-12
Branch: `codex/hot-cold-sync-plan`
Worktree: `/tmp/poc-7-hot-cold-sync`

## Why this exists

The branch now has the right create-side atomicity model:

1. strict synchronous create commits canonical store plus the first projection
   attempt atomically,
2. blocked synchronous create returns only after blocked rows are durable,
3. local create no longer relies on origin `project_queue` rows or create-side
   pending fanout rows for crash safety,
4. rare bootstrap-context flows use an explicit
   `store_*_then_project(...)` pattern.

What remains is mostly API and documentation cleanup so the merge story is
small and unambiguous.

## Target model

Prefer only two real create modes in product code:

1. `create_*_synchronous(...)`
   - default path
   - returns `Ok(event_id)` only after projection succeeds
2. `store_*_then_project(...)`
   - rare path for event-id-dependent context such as invite bootstrap trust
   - stores, writes the extra context, and projects in the same transaction

`event_id_or_blocked(...)` and `create_*_staged(...)` should be treated as
bootstrap/test conveniences layered on top of those two modes, not as a third
storage model.

## Remaining cleanup

1. Replace product call sites that open-code `event_id_or_blocked(create_*_synchronous(...))`
   with narrower bootstrap-local helpers where that improves readability.
2. Keep staged helpers out of ordinary user-facing command paths.
3. Remove stale documentation that still describes local-create crash recovery
   in terms of create-side origin `project_queue` rows.
4. Revisit the local direct-to-egress enqueue shortcut separately from create
   atomicity; it is a sync-latency concern, not a create-correctness one.

## Merge checklist

1. `create.rs` tests prove no create-side origin recovery rows remain.
2. bootstrap invite creation proves the explicit `store -> context -> project`
   path works.
3. docs (`PLAN.md`, `DESIGN.md`, planning notes) describe the same two-mode
   create model.
4. staged helpers are clearly scoped to bootstrap/test flows.
