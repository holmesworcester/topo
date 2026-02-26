# Event-Module-Owned Schema Execution Plan (Epoch-Only, No Migrations)

Branch: `exec/event-module-owned-migrations-plan`  
Worktree: `/home/holmes/poc-7-event-module-owned-migrations-plan`

## Worktree Rule

Do all work only in `/home/holmes/poc-7-event-module-owned-migrations-plan`.  
Do not execute this plan in any other worktree.

## Goal

Make schema ownership local to the code that owns behavior:

1. Event module read-model tables are owned by their event modules.
2. Queue/infra tables are owned by their queue/infra modules.
3. DB bootstrap is epoch-based only (no migration runner in scope for this POC).
4. Layer boundary leaks are removed (`state/db` must not depend on `runtime/transport`).

## Why This Exists

Current issues:

1. Central DDL ownership is scattered/ambiguous (`schema.rs` + `migrations.rs`).
2. Event concerns and queue concerns are not fully colocated with their modules.
3. `state/db` has boundary leaks to transport runtime helpers (for example `removal_watch.rs` importing transport cert/SPKI helpers; similar leak pattern in related DB modules).

This hurts locality, readability, and diagram clarity.

## Scope

In scope:

- Remove migration-runner dependency from bootstrap path (POC epoch model only).
- Move table DDL into owning modules (`event_modules/*`, `state/db/project_queue.rs`, `state/db/egress_queue.rs`, etc.).
- Keep one central bootstrap orchestrator that calls module-owned `ensure_schema` in deterministic order.
- Keep/strengthen `schema_epoch` gating.
- Remove `state/db -> runtime/transport` boundary leaks, including `removal_watch` and related modules.

Out of scope:

- Backward compatibility for legacy DB snapshots.
- Wire/protocol redesign.
- Runtime behavior redesign unrelated to schema ownership/boundaries.

## Target Architecture

### 1) Epoch-only bootstrap contract

Create/use a single bootstrap entrypoint (name as needed):

- `ensure_schema_epoch(conn)`
- `ensure_all_schema(conn)`

`ensure_all_schema` calls owner modules in fixed order and is idempotent.

No `schema_migrations` table, no versioned migration runner in active path.

### 2) Owner-local DDL

Each owner module exports `ensure_schema(conn)`:

- Event modules own their projection/read tables.
- Queue modules own queue tables.
- Infra DB modules own infra tables.

Central bootstrap orchestrates; owners define SQL.

### 3) Identity rebinding locality

`finalize_identity` table targets must be registry-driven or owner-specified metadata, not hardcoded monolith lists.

### 4) Boundary hardening (`removal_watch` and related)

`state/db` modules must not import runtime transport code.

Required cleanup:

- Remove `state/db/removal_watch.rs -> runtime/transport/*` dependency.
- Remove equivalent dependency pattern from related DB modules (for example `transport_trust.rs` if present).
- Move shared SPKI/crypto derivation helpers to a neutral shared layer (e.g. `src/shared/crypto/*`) and depend on that from both sides.

## Ownership Boundary

Queue/infra examples (owned under `state/db`):

- `project_queue` (in `project_queue.rs`)
- `egress_queue` (in `egress_queue.rs`)
- `wanted_events` (in `wanted.rs`)
- pipeline/infra tables (`events`, `valid_events`, etc.)

Event-module examples (owned under `event_modules/*`):

- `messages`, `reactions`, `deleted_messages`, `deletion_intents`
- `workspaces`, `users`, `peers_shared`, `admins`, invites, secret-sharing tables
- attachment/read-model tables owned by attachment module(s)

Exact ownership must be explicit in code.

## Implementation Sequence

1. Rebase this branch on latest `master`.
2. Introduce/finalize epoch-only bootstrap orchestration API.
3. Remove `run_migrations` from active bootstrap path.
4. Move queue table DDL into queue owner modules.
5. Move event table DDL into event-module owners.
6. Replace hardcoded identity-rebind table lists with owner metadata/registry.
7. Remove `state/db` boundary leaks to runtime transport:
   - `removal_watch`
   - related modules with same dependency pattern.
8. Delete/retire obsolete migration-runner code and tests that no longer apply.
9. Add/adjust tests and static checks.
10. Update `docs/DESIGN.md` and `docs/PLAN.md` with the epoch-only + owner-local pattern.

## Strict Success Criteria (SC)

1. Active bootstrap path is epoch-only; no migration runner required.
2. `schema_migrations` is not required for startup/operation.
3. Queue table DDL lives in queue modules (`project_queue`, `egress_queue`, etc.).
4. Event projection/read-model DDL lives in owning event modules.
5. `finalize_identity` does not depend on a hardcoded monolithic table-name list.
6. `state/db/removal_watch.rs` has no dependency on runtime transport modules.
7. Related DB boundary leaks (same pattern) are removed.
8. Shared crypto/SPKI helper location is neutral and reused from both sides.
9. `cargo check` passes.
10. Relevant tests pass (schema/bootstrap, identity finalization, removal-watch/trust boundary behavior).

## No-Cheat Validation

Add explicit checks/tests:

1. Guard check: fail if `run_migrations`/`schema_migrations` is required in active bootstrap path.
2. Guard check: fail if `src/state/db/*` imports `src/runtime/transport/*`.
3. Test that each owner `ensure_schema` is idempotent and called by central bootstrap.
4. Integration test:
   - bootstrap fresh DB
   - run key event flows (workspace/message/reaction)
   - run identity finalization
   - assert owner tables exist and rebinding works
5. Regression test for removal watch/trust behavior after boundary helper relocation.

## Completion Workflow

1. Rebase branch on latest `master` before finalizing.
2. Run checks/tests and record evidence.
3. Get Codex CLI review and address all findings.
4. Re-run checks/tests.
5. Commit on this worktree branch with a clear message.
6. Report completion with evidence summary.
