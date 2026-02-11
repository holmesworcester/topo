# Stream 3: DB Surface and Schema Pruning

## Goal

Remove unused DB modules and legacy schema artifacts that are no longer part of the active runtime path.

## Scope

1. Delete unused DB wrapper modules.
2. Remove unused table creation from baseline schema.
3. Keep active runtime tables untouched.

## Owned Files

1. `src/db/mod.rs`
2. `src/db/schema.rs`
3. `src/db/outgoing.rs`
4. `src/db/shareable.rs`
5. `src/db/tenant.rs`

## Non-Goals

1. No queue architecture redesign for active `project_queue` / `egress_queue`.
2. No event-type protocol changes.
3. No test trust changes.

## Work Items

1. Confirm no runtime callers for:
   - `OutgoingQueue`
   - `Shareable`
   - `TenantDb`
2. Remove unused modules and exports.
3. Prune dead tables from `create_tables`:
   - `store`
   - `shareable_events`
   - `wanted_events`
   - `outgoing_queue`
   - `incoming_queue`
   if they are confirmed unused by active runtime.
4. Update schema tests to assert only active table set.
5. If table removal is not backward-compatible for existing DBs, explicitly bump prototype epoch and fail fast on old DBs.

## Acceptance Criteria

1. Removed modules are not referenced anywhere in `src/` or `tests/`.
2. `create_tables` creates only active runtime/storage tables.
3. Schema tests pass after pruning.
4. `cargo check --all-targets` passes.

## Validation Commands

```bash
rg -n "\bOutgoingQueue\b|\bShareable\b|\bTenantDb\b" src tests
cargo test db::schema::tests -- --nocapture
cargo check --all-targets
```

## Risks

1. Hidden dependence on tables from ad hoc scripts.
2. Breaking old local DBs in developer environments.

## Mitigations

1. Keep explicit prototype-epoch incompatibility messaging.
2. Document DB recreation requirement in release notes/README snippet if epoch changes.

