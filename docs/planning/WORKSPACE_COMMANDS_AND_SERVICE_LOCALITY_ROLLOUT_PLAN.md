# Workspace-Centered Command Locality Rollout Plan

Date: 2026-02-20
Branch: `exec/workspace-command-locality-rollout-plan`
Worktree: `/home/holmes/poc-7-workspace-command-locality-plan`

## Goal

Adopt a `poc-6`-style locality rule:

1. Event-centered behavior lives in the event module for the event/process center.
2. Workflow commands are allowed in `commands.rs` (they are not second-class vs "simple" commands).
3. `service.rs` is orchestration-only and should not hold event-domain business logic.

POC policy: no backward compatibility shims are required unless they are temporary within this branch.

## Placement decision (resolved)

The following workflows belong in `workspace::commands.rs`:

1. Start new workspace.
2. Join workspace as a new user/device.
3. Add a new device to an existing workspace.

Rationale: all three are workspace-membership lifecycle operations and share trust-anchor/workspace context.

## Phase 0: Pre-flight

1. Rebase on latest `master`.
2. Keep baseline gates green:
   - `cargo check`
   - `bash scripts/check_boundary_imports.sh`

## Phase 1: Create workspace module command home

Current `workspace` is a flat file (`src/event_modules/workspace.rs`).
Convert to directory module:

1. `src/event_modules/workspace/mod.rs`
2. `src/event_modules/workspace/wire.rs`
3. `src/event_modules/workspace/projector.rs`
4. `src/event_modules/workspace/queries.rs`
5. `src/event_modules/workspace/commands.rs`

Rules:

1. Keep external API stable via `workspace::...` re-exports in `mod.rs`.
2. No behavior changes in this phase (pure move/split).

## Phase 2: Move the three onboarding workflows into `workspace::commands`

## 2.1 Start workspace

Move from service/identity orchestration into command API:

1. Source today:
   - `svc_bootstrap_workspace_conn`
   - `svc_create_workspace`
   - `ensure_identity_chain`
   - `identity::ops::bootstrap_workspace`
2. Target:
   - `workspace::commands::create_workspace(...)`
   - Return typed result struct with ids needed by service response.

## 2.2 Join workspace as new user/device

Move invite accept workflow center into workspace commands:

1. Source today:
   - `svc_accept_invite`
   - `identity::ops::accept_user_invite`
   - related service-local sequencing for key material + push-back + transition
2. Target:
   - `workspace::commands::join_workspace_as_new_user(...)`
   - Keep existing sequencing semantics unchanged.

## 2.3 Add new device

Move device-link accept workflow center into workspace commands:

1. Source today:
   - `svc_accept_device_link`
   - `identity::ops::accept_device_link`
2. Target:
   - `workspace::commands::add_device_to_workspace(...)`

## 2.4 Service callsite reduction

After moving command ownership:

1. `service.rs` should call workspace command APIs.
2. `service.rs` should not assemble identity chain internals directly.
3. Keep transport changes through intent/adapter contracts only.

## Phase 3: Roll same pattern across remaining service commands

After Phase 2 lands, migrate all other event-domain service command/query handlers to event-module ownership.

## 3.1 Service function inventory (from `src/service.rs`)

Event-domain commands/queries to migrate or verify-localized:

1. Message domain: `svc_send_conn`, `svc_messages_conn`, resolution helpers.
2. Reaction domain: `svc_react_conn`, `svc_reactions_conn`, `svc_reactions_for_message_conn`.
3. Deletion domain: `svc_delete_message_conn`, `svc_deleted_message_ids_conn`.
4. Removal domain: `svc_remove_user_conn`.
5. Invite/domain commands:
   - `svc_create_invite_conn`, `svc_create_device_link_invite_conn`,
   - `svc_create_invite`, `svc_create_invite_with_spki`, `svc_create_device_link_for_peer`.
6. Workspace/user/key list queries: `svc_users_conn`, `svc_workspaces_conn`, `svc_keys_conn`, `svc_view_conn`.

Orchestration-only service functions that should remain in service/node/runtime:

1. Runtime/network introspection: `svc_intro`, `svc_intro_attempts`, `svc_node_status`, `svc_transport_identity`.
2. Predicate/assert wrappers (`svc_assert_*`) if treated as service tooling.
3. Peer-level orchestration wrappers (`*_for_peer`) that only shape inputs/outputs.

## 3.2 Migration rule for each svc function

For each event-domain `svc_*` function:

1. Identify event/process center.
2. Move logic into that module's `commands.rs` or `queries.rs`.
3. Keep service wrapper thin: context load + module call + response shaping.

## 3.3 Completion target for Phase 3

1. No event-specific SQL in service for migrated domains.
2. No event creation/projection business logic in service for migrated domains.
3. Event modules provide the canonical command/query entrypoints.

## Phase 4: Docs + guardrails

Update docs to codify this as a stable project rule:

1. `docs/DESIGN.md`
2. `docs/PLAN.md`

Add/extend enforcement checks:

1. Boundary script checks for disallowed event-domain creation paths in `service.rs`.
2. Prefer path-based guardrails over reviewer memory.

## Test/Gate plan

Required per major phase:

1. `cargo check`
2. `bash scripts/check_boundary_imports.sh`
3. `cargo test --lib -q`
4. `cargo test --test replication_contract_tests -q`
5. `cargo test --test holepunch_test -q`

Additional for onboarding workflow phases:

1. Invite acceptance flow tests.
2. Device-link acceptance flow tests.
3. Identity/transport contract tests:
   - `cargo test --test identity_transport_contract_tests -q`

## Done criteria

1. The three workspace onboarding workflows are owned by `workspace::commands.rs`.
2. `service.rs` no longer hosts those workflow internals.
3. Remaining event-domain service commands follow the same locality pattern.
4. DESIGN/PLAN document the rule clearly for humans and LLMs.
5. Guardrails enforce the boundary.
