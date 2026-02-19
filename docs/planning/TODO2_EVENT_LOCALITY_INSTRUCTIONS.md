# TODO 2 Instructions: Event-Module Locality Follow-up

Date: 2026-02-19
Branch: `exec/todo2-event-locality-instructions`
Worktree: `/home/holmes/poc-7-todo2-event-locality`

## Goal

Complete the remaining service-thinning/locality work so event behavior is owned by `event_modules`, while `service.rs` is orchestration glue.

This branch is item 2 only. Do not take on identity-vs-transport contract redesign from TODO item 3 in this branch.

## Required start step

1. `git fetch origin`
2. `git rebase origin/master`

## Current gaps (as of branch start)

1. `src/service.rs` is still large and contains event-oriented logic paths.
2. Command dispatch exists (`src/event_modules/dispatch.rs`) but is not the default routing surface for service.
3. `invite_accepted` is prerequisite-free (good) but the force-valid/unblock behavior is still partly implicit (`RetryWorkspaceGuards`) instead of clearly expressed as a workspace-owned action.
4. PLAN/DESIGN do not yet state the locality contract in one explicit, enforceable section.

## Target boundary

1. `service.rs` owns:
   - request parsing, DB/session context loading,
   - cross-module orchestration,
   - response shaping.

2. `event_modules/*` own:
   - event creation commands,
   - event-specific queries,
   - projector logic,
   - event-type-local helper logic.

3. `projection/apply/*` owns:
   - generic execution of `WriteOp` + `EmitCommand`.

## Required work

### A) Finish command/query locality for content events

1. Audit and move remaining event-specific helpers from `service.rs` where ownership is unambiguous:
   - message
   - reaction
   - message_deletion
   - user_removed
2. Service functions should call event-module APIs, not inline event-specific SQL.
3. If a module exceeds readability bounds, keep the split layout (`wire`, `create`, `queries`, `projector`, `mod`).

### B) Promote registry-driven routing

1. Extend dispatch to cover both commands and queries (typed, explicit enums/structs).
2. Service should route through registry entry points for event-local operations.
3. Keep registry thin; module internals remain the true owners of behavior.

### C) Make invite_accepted force-valid path explicit

1. Keep `invite_accepted` dep-free.
2. Replace implicit workspace retry coupling with an explicit workspace-oriented command emission from invite_accepted projection.
3. The command should flow through normal apply command execution and dependency cascade.
4. Ensure behavior still matches TLA/model intent; if semantics shift, update model/docs first in the same branch.

### D) Update docs for future implementers

1. Update `docs/PLAN.md` and `docs/DESIGN.md` with a concise section that codifies:
   - event-module locality rule,
   - service orchestration-only rule,
   - registry-driven routing pattern,
   - module split rule for long event modules.

## Non-goals

1. No transport identity contract redesign (TODO item 3).
2. No protocol frame redesign.
3. No networking loop redesign.

## Suggested implementation order

1. Add/expand typed command+query registry surface.
2. Migrate one vertical slice (message + reaction + deletion + user_removed).
3. Refactor invite_accepted force-valid path to explicit workspace command emission.
4. Remove obsolete service helpers.
5. Update PLAN/DESIGN.

## Quality gates

1. `cargo check`
2. `bash scripts/check_boundary_imports.sh`
3. `cargo test --lib -q`
4. `cargo test --test replication_contract_tests -q`
5. `cargo test --test holepunch_test -q`
6. `cargo test --test scenario_test test_wrap_unwrap_encrypted_convergence -- --exact`

## Done criteria

1. `service.rs` has no event-type-specific SQL for clearly owned event modules.
2. Registry routing exists for both commands and queries used by service.
3. `invite_accepted` force-valid behavior is explicit and workspace-owned.
4. PLAN/DESIGN clearly document the locality contract and module-split pattern.
5. All quality gates pass.
