# Option 5 Execution Instructions: Service Locality Into Event Modules

Date: 2026-02-19
Branch: `exec/event-locality-opt5-service-event-locality`
Worktree: `/home/holmes/poc-7-event-locality-opt5`

## Goal

Make `src/service.rs` thin by moving event-specific command/query logic into event modules.

Secondary goal: establish and apply a module split rule so large event modules are organized as:

1. `commands`
2. `queries`
3. `projector`
4. wire/parse/encode/meta

## Required starting step

Before implementation, rebase on latest `master`:

1. `git fetch origin`
2. `git rebase origin/master`

Resolve conflicts in favor of current `master` behavior first, then re-apply locality changes.

## What this option is and is not

This option is:

1. locality refactor
2. ownership cleanup
3. service-thinning

This option is not:

1. transport/runtime redesign
2. wire format redesign
3. projection behavior change

POC policy: backwards compatibility with old internal layouts is not required. Prefer direct, clear ownership.

## Current problem

`src/service.rs` mixes:

1. orchestration
2. event-specific command creation
3. event-specific read queries
4. transport/bootstrap helpers

That blurs boundaries and hurts discoverability.

## Target boundary

### Service layer owns orchestration only

Keep in `service.rs`:

1. open DB / peer selection
2. auth/identity preconditions
3. cross-module orchestration
4. API response shaping

### Event modules own event logic

Move into event modules:

1. command creation helpers for their event type
2. read-model queries for their event type
3. projector behavior (already being localized in option 4)
4. selectors/resolvers specific to that event type

## Initial move list (high-value)

Move these out of `service.rs` first.

1. Message domain:
   - `svc_messages_conn`
   - `svc_send_conn`
   - message selector helper pathways
2. Reaction domain:
   - `svc_react_conn`
   - `svc_reactions_conn`
   - `svc_reactions_for_message_conn`
3. Deletion domain:
   - `svc_delete_message_conn`
   - `svc_deleted_message_ids_conn`
4. Removal domain:
   - `svc_remove_user_conn`

After move, `service.rs` should call module APIs and only map module return types into service response structs.

## Module splitting rule (mandatory)

When an event module gets too long or mixes concerns, split it into a directory.

### Trigger to split

Split if any is true:

1. file exceeds roughly 300-400 LOC
2. file contains 3+ concerns (wire + commands + queries + projector)
3. readability drops due unrelated sections

### Required split shape

Use a directory module with explicit files:

1. `event_modules/<name>/mod.rs`
2. `event_modules/<name>/wire.rs`
3. `event_modules/<name>/commands.rs`
4. `event_modules/<name>/queries.rs`
5. `event_modules/<name>/projector.rs`

`mod.rs` re-exports stable APIs so callers import from `event_modules::<name>`.

### Practical examples

Likely first candidates:

1. `message`
2. `reaction`
3. `message_deletion`

## Suggested implementation phases

### Phase 1: Introduce split scaffolding

1. Pick one pilot module (`message`) and convert file -> directory layout.
2. Keep external API stable via `mod.rs` re-exports.
3. Ensure no behavior changes.

### Phase 2: Move service-owned event functions

1. Move conn-level event commands/queries listed above.
2. Replace service implementations with thin delegations.
3. Remove duplicated SQL from service where module query APIs exist.

### Phase 3: Extend split pattern to touched modules

1. For any touched module that is large, apply split shape.
2. Keep transport/bootstrap logic out of event modules.
3. Keep cross-domain joins in service/orchestration if they combine multiple modules.

### Phase 4: Thin `service.rs`

1. Remove dead helpers after module extraction.
2. Keep only orchestration and response assembly.
3. Add comments only where orchestration is non-obvious.

### Phase 5: Documentation updates

Update both docs so future assistants keep locality boundaries.

1. `docs/PLAN.md`
2. `docs/DESIGN.md`

Add an explicit rule:

1. event-specific commands/queries/projectors belong in event modules
2. service is orchestration glue
3. long modules must split into `commands/queries/projector` structure

## Quality gates

Run before merge:

1. `cargo check`
2. `bash scripts/check_boundary_imports.sh`
3. `cargo test --lib projection::apply::tests -- --nocapture`
4. `cargo test --test replication_contract_tests -q`
5. `cargo test --test scenario_test test_zero_loss_stress -- --nocapture`

Run additional focused tests for any module split touched.

## Completion criteria

This option is done when:

1. event-specific service functions are moved to their event modules
2. `service.rs` is visibly thinner and orchestration-focused
3. at least one large event module uses the split layout pattern
4. PLAN/DESIGN document the boundary and split rule clearly
