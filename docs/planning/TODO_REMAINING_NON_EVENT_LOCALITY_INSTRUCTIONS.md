# Remaining TODO Instructions (Excluding Event-Locality Worktree Scope)

Date: 2026-02-20
Branch: `exec/todo-remaining-non-event-locality-instructions`
Worktree: `/home/holmes/poc-7-todo-remaining-instructions`

## Purpose

Complete everything in `TODO.md` that is **not** already covered by the event-locality worktree plan:

- `/home/holmes/poc-7-workspace-command-locality-plan/docs/planning/WORKSPACE_COMMANDS_AND_SERVICE_LOCALITY_ROLLOUT_PLAN.md`

Use this document as the execution source of truth for this branch.

## Explicitly out of scope here (covered by event-locality plan)

1. Service-to-event-module migration phases for workspace onboarding workflows.
2. General service thinning for event-domain command/query routing.
3. Event-locality doc updates tied to that workflow migration.

## In scope (remaining TODO coverage)

1. Rename backlog completion (`TODO.md` rename plan + public API/symbol renames + migration order + done criteria).
2. Event-locality leftovers **not** covered by the workspace plan:
   - `invite_accepted` runtime semantics + TLA/doc conformance closure.
3. Identity + transport boundary follow-up items not already completed by current code.
4. Active docs consistency and stale-path cleanup.

## Required start steps

1. `git fetch origin`
2. `git rebase origin/master`
3. Baseline audit:
   - `cargo check`
   - `bash scripts/check_boundary_imports.sh`

## Execution stages

### Stage 1: Rename/vocabulary closure (TODO rename sections)

Goal: finish any remaining old naming across code/comments/active docs.

Required actions:

1. Audit and remove stale old-layer names in active code paths:
   - `network` -> `peering`
   - `replication` -> `sync`
   - `events` -> `event_modules`
   - `event_runtime` -> `event_pipeline`
2. Finish straggler symbol names still carrying old semantics (for example store/adapter symbols that still use `Replication*` wording where they are now sync-owned).
3. Remove transitional rename shims/re-exports that are no longer needed.
4. Ensure `docs/DESIGN.md`, `docs/PLAN.md`, `docs/INDEX.md`, and active `docs/planning/*.md` use current vocabulary.

Mandatory grep checks before marking this stage done:

1. `rg -n "crate::network|crate::replication|crate::events|crate::event_runtime" src tests`
2. `rg -n "src/network|src/replication|src/events|src/event_runtime|src/projection/pipeline\\.rs" docs --glob '!docs/archive/**'`
3. `rg -n "\\bReplicationStore\\b|SqliteReplicationStore|replication layer|network layer|event_runtime layer" src docs --glob '!docs/archive/**'`

### Stage 2: `invite_accepted` semantics + model/doc closure

Goal: close TODO event-locality leftovers around invite acceptance semantics.

Required actions:

1. Verify or implement prerequisite-free `invite_accepted` projection behavior.
2. Verify or implement explicit workspace force-valid command emission from `invite_accepted`.
3. Verify force-valid enters standard apply + unblock cascade (no special side path).
4. Ensure runtime-driving rows/commands are consumed by continuous peering/sync loops rather than requiring service-triggered one-off bootstrap hacks.
5. Compare behavior against `poc-6` trust-anchor semantics and `docs/tla/EventGraphSchema.tla`.
6. If semantics change, update TLA and DESIGN/PLAN in the same branch before code changes.

Required tests:

1. Existing projection/apply tests for `invite_accepted` guard retry/unblock.
2. Add/adjust tests if needed to prove:
   - dep-free accept event behavior,
   - workspace unblock via emitted command + cascade,
   - no regressions in bootstrap/join flow.

### Stage 3: Identity <-> transport boundary closure

Goal: enforce one clear contract between event/identity logic and transport identity materialization.

Required actions:

1. Move remaining identity-chain creation/acceptance ownership into event-centered command modules where still scattered.
2. Keep transport key/cert materialization in transport-owned adapter implementation only.
3. Ensure event/projection/service call transport changes via typed contract (`TransportIdentityIntent`-style), not direct install calls.
4. Remove duplicated identity-chain assembly from `service.rs` (for example `ensure_identity_chain`) if still redundant after Stage 1+2.
5. Ensure bootstrap sync path depends on sync/transport contracts, not event-module internals.
6. Add/extend boundary checks so direct transport install calls cannot leak into `service.rs`, `event_modules/*`, `projection/*`.
7. Update DESIGN/PLAN ownership language for this boundary.

Suggested verification:

1. `cargo test --test identity_transport_contract_tests -q`
2. Invite accept/device-link flow tests.

### Stage 4: Docs consistency + TODO closure

Goal: leave one unambiguous implementation map for future assistants.

Required actions:

1. Update active docs for final names and boundaries.
2. Keep legacy naming only in `docs/archive/*` with explicit historical disclaimer.
3. Update `TODO.md` checkboxes to reflect real completion status based on code/tests.
4. Add a short evidence matrix in this branch (`docs/planning/TODO_REMAINING_EVIDENCE.md`) mapping each TODO section/item -> file/test proof.

## Codex CLI feedback requirements (mandatory)

### A) Mid-implementation feedback pass

Run after Stage 2 or Stage 3 first draft implementation:

```bash
codex exec -C /home/holmes/poc-7-todo-remaining-instructions \
  "Review this branch against docs/planning/TODO_REMAINING_NON_EVENT_LOCALITY_INSTRUCTIONS.md.
  Find missing items, boundary leaks, and risky assumptions. Write actionable findings to feedback.md
  with severity labels and file references."
```

Address feedback before final audit.

### B) Final completion audit (must cover every checklist item)

Run when implementation is believed complete:

```bash
codex review --base master \
  "Audit this branch against docs/planning/TODO_REMAINING_NON_EVENT_LOCALITY_INSTRUCTIONS.md.
  Evaluate every required item and every stage gate. Output PASS/FAIL per item with concrete file/test evidence
  and list any remaining work." > codex_final_audit.md
```

Then:

1. Resolve all FAIL items.
2. Re-run the audit until all required items are PASS.
3. Commit `feedback.md` and `codex_final_audit.md` with final implementation changes.

## Global quality gates before merge

1. `cargo check`
2. `bash scripts/check_boundary_imports.sh`
3. `cargo test --lib -q`
4. `cargo test --test sync_contract_tests -q`
5. `cargo test --test holepunch_test -q`
6. `cargo test --test identity_transport_contract_tests -q`

## Done criteria

1. All TODO items outside the event-locality worktree scope are either:
   - completed in code/docs/tests, or
   - explicitly marked superseded with rationale in `TODO.md`.
2. Active docs and code vocabulary are aligned.
3. Boundary checks enforce identity/transport separation.
4. `codex_final_audit.md` reports PASS on all required items.
