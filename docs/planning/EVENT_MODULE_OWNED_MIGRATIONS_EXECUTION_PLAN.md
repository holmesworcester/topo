# Event-Module-Owned Migrations Execution Plan

Branch: `exec/event-module-owned-migrations-plan`  
Worktree: `/home/holmes/poc-7-event-module-owned-migrations-plan`

## Worktree Rule

Do all work only in `/home/holmes/poc-7-event-module-owned-migrations-plan`.  
Do not execute this plan in any other worktree.

## Goal

Make event modules own their SQL read-model schema/migrations locally so adding or evolving a module table does not require editing one central migration monolith.

## Why This Exists

Today we have two central-locality bottlenecks:

1. `src/state/db/migrations.rs` contains most table DDL for all modules.
2. `src/state/db/mod.rs` has hardcoded projection-table lists (for identity rebinding).

This scatters event concerns away from their module code and forces unrelated central edits.

## Scope

In scope:

- Introduce a module-owned migration contract.
- Move module table migrations from central `migrations.rs` into module-local files.
- Replace hardcoded projection table lists in `src/state/db/mod.rs` with module-owned registration/metadata.
- Keep infra/system tables under `state/db` ownership.

Out of scope:

- No event wire/protocol redesign.
- No behavior changes to invite/sync/runtime flow.
- No backwards-compat promise for legacy developer DB snapshots (POC stance). Fresh DB behavior + tests are the source of truth.

## Target Architecture

### 1) Migration contract (shared)

Create a shared contract in `src/state/db` (name as needed), e.g.:

- `ModuleMigration { module, version, name, sql }`
- `ModuleSchemaSpec { module, migrations, identity_rebind_targets }`
- `IdentityRebindTarget { table, column }`

### 2) Module-local schema ownership

Each event module that owns projection/read tables gets a local schema file, e.g.:

- `src/event_modules/message/schema.rs`
- `src/event_modules/reaction/schema.rs`
- `src/event_modules/workspace/schema.rs`
- etc.

Each module exports its own `ModuleSchemaSpec` with:

- module-owned migrations
- module-owned identity rebinding targets (`recorded_by` tables, etc.)

### 3) Central runner becomes orchestrator only

`src/state/db/migrations.rs` should:

- own infra/system migrations only
- run module migrations from module registry in deterministic order
- no longer carry module table SQL bodies

### 4) `db/mod.rs` locality fix

`src/state/db/mod.rs` should stop hardcoding projection table names for identity rebinding.  
It should iterate module-provided `identity_rebind_targets` from the same schema registry.

## Ownership Boundary

Infra/system tables remain in `state/db` migration ownership (examples):

- `events`, `valid_events`, `rejected_events`, `blocked_event_deps`, `blocked_events`
- `project_queue`, `egress_queue`, `ingress_queue`, `recorded_events`, `store`
- `schema_migrations` (or equivalent migration state tables)

Event-module-owned tables move to module schema ownership (examples):

- `messages`, `reactions`, `deleted_messages`, `deletion_intents`
- `workspaces`, `users`, `peers_shared`, `admins`, `user_invites`, `device_invites`, `invite_accepted`
- `secret_keys`, `secret_shared`, `transport_keys`, `peer_transport_bindings`
- `message_attachments`, `file_slices`, `local_signer_material`, etc.

Exact final mapping should be explicit in code via module schema specs.

## Implementation Sequence

1. Rebase this branch on latest `master`.
2. Add migration contract types and module-schema registry plumbing.
3. Add module-local `schema.rs` files and migrate SQL from central file module-by-module.
4. Update migration runner to execute module schema specs.
5. Replace hardcoded projection table list in `src/state/db/mod.rs` with registry-driven identity rebinding targets.
6. Remove moved SQL from central `migrations.rs`.
7. Add tests for migration locality and registry-driven identity rebinding.
8. Update docs (`docs/DESIGN.md`, `docs/PLAN.md`) with the new ownership pattern.

## Strict Success Criteria (SC)

1. Module table DDL is defined in module-local schema files, not central monolith.
2. `src/state/db/migrations.rs` no longer contains module-table SQL (infra only).
3. `src/state/db/mod.rs` no longer hardcodes module projection table names for identity rebinding.
4. Module registry drives both:
   - module migration execution
   - identity rebinding target iteration
5. `cargo check` passes.
6. `cargo test` passes for migration/identity-related coverage and existing runtime/CLI smoke coverage used in this repo.
7. `docs/DESIGN.md` and `docs/PLAN.md` document:
   - where new table migrations go
   - how to register module schema
   - how identity rebinding ownership works

## No-Cheat Validation

Add explicit checks/tests so locality regressions are hard to hide:

1. A test that fails if module table DDL appears in `src/state/db/migrations.rs`.
2. A test that fails if `finalize_identity` depends on a hardcoded table-name list.
3. A test that validates module migration registry order is deterministic and idempotent.
4. A focused integration test:
   - create workspace
   - send message/react
   - run identity finalization path
   - verify module-owned tables were migrated/rebound correctly.

## Completion Workflow

1. Rebase this branch on latest `master` before finalizing.
2. Run required checks/tests.
3. Get review feedback (Codex CLI review) and address all findings.
4. Re-run checks/tests.
5. Commit on this worktree branch with a clear message.
6. Report completion with evidence summary.

