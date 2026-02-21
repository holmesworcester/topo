# Identity Eventization Completion Instructions

Date: 2026-02-20
Branch: `exec/identity-eventization-completion-instructions`
Worktree: `/home/holmes/poc-7-identity-eventization-completion`

## Objective

Complete identity eventization so identity workflows are owned by event modules, while `service.rs` and runtime pipeline remain thin orchestration/execution layers.

This branch is for finishing identity eventization, not for unrelated renames or protocol changes.

POC policy: no backward-compatibility shims are required unless needed transiently during the refactor.

## Current state to fix

The code is currently only partially eventized:

1. `src/identity/ops.rs` still owns major workflow orchestration (`create_*_invite`, `accept_*`, `bootstrap_workspace`, retry flow).
2. `src/event_modules/workspace/commands.rs` delegates many core flows to `identity::ops` rather than owning command orchestration directly.
3. `src/service.rs` still exposes identity-specific orchestration (`svc_bootstrap_workspace_conn`).
4. `src/event_pipeline.rs` directly calls identity retry workflow (`retry_pending_invite_content_key_unwraps`).

## Required start steps

1. `git fetch origin`
2. `git rebase origin/master`
3. Baseline check:
   - `cargo check`

## Target ownership model (required)

1. `event_modules/*/commands.rs` own identity event workflows (event creation + sequencing).
2. `identity/*` owns reusable primitives/helpers only (crypto/data helpers, shared builders).
3. `service.rs` is a thin facade that routes to event-module commands and shapes responses.
4. `event_pipeline.rs` executes generic apply/command processing, not identity-special workflow orchestration.

## Hard success criteria (must all be true)

### SC1. No identity workflow orchestration entrypoints in `identity::ops`

`src/identity/ops.rs` must not contain public workflow entrypoints for workspace onboarding/invite acceptance.

Required removals/moves from `identity::ops` public API:

1. `bootstrap_workspace`
2. `create_user_invite`
3. `accept_user_invite`
4. `create_device_link_invite`
5. `accept_device_link`
6. `retry_pending_invite_content_key_unwraps`

These behaviors must be owned by event-module command APIs.

### SC2. `service.rs` contains no identity-specific workflow orchestration

`src/service.rs` must not expose identity workflow wrappers such as bootstrap/join orchestration helpers.

Required removals:

1. `svc_bootstrap_workspace_conn`
2. direct identity workflow sequencing that bypasses event-module command ownership.

### SC3. `event_pipeline.rs` has no identity-special workflow callouts

`src/event_pipeline.rs` must not call identity workflow functions directly (including retry flows). If retries are needed, they must be represented via normal apply/command paths.

### SC4. Event-module command ownership is explicit and test-covered

Event-module commands must provide the canonical APIs for:

1. workspace creation bootstrap chain
2. user invite creation
3. user invite acceptance
4. device-link invite creation
5. device-link acceptance

Tests must prove these paths still work and are replay-safe.

### SC5. Boundaries are machine-checkable

Add/update boundary checks so new direct imports of workflow functions from forbidden layers fail local checks.

## Implementation plan

### Phase 1: Move workflow ownership to event modules

1. Create/expand event-module command functions in workspace (or dedicated identity event module if introduced) for all five onboarding flows.
2. Preserve externally visible behavior and event ordering.
3. Keep helper logic in `identity/*` private or primitive-only.

### Phase 2: Thin service + pipeline

1. Replace service wrapper/orchestration calls with event-module command calls.
2. Remove `svc_bootstrap_workspace_conn`.
3. Remove identity-specific retry call from `event_pipeline.rs`; route through generic emitted commands if needed.

### Phase 3: Tighten contracts + tests

1. Add boundary checks (`scripts/check_boundary_imports.sh` or equivalent) for forbidden direct workflow usage.
2. Add/update tests proving invite creation/acceptance and device-link flows still converge.
3. Ensure replay path still reconstructs correct state from events.

### Phase 4: Docs and evidence

1. Update `docs/DESIGN.md` and `docs/PLAN.md` with final identity eventization boundary.
2. Add `docs/planning/IDENTITY_EVENTIZATION_COMPLETION_EVIDENCE.md` mapping each success criterion to concrete files/tests.

## Required command-level verification (before Codex audit)

Run these and attach outputs to evidence notes:

```bash
rg -n "pub fn (bootstrap_workspace|create_user_invite|accept_user_invite|create_device_link_invite|accept_device_link|retry_pending_invite_content_key_unwraps)" src/identity/ops.rs
rg -n "svc_bootstrap_workspace_conn|identity::ops::(bootstrap_workspace|accept_user_invite|accept_device_link|create_user_invite|create_device_link_invite|retry_pending_invite_content_key_unwraps)" src/service.rs src/event_pipeline.rs src/event_modules tests
bash scripts/check_boundary_imports.sh
cargo check
cargo test --lib -q
cargo test --test scenario_test -q
```

Interpretation requirement:

1. First `rg` must return no matches.
2. Second `rg` may only match allowed helper usages (non-workflow primitives) and test fixtures explicitly marked as fixture-only.
3. All quality gate commands must pass.

## Mandatory Codex CLI verification loop

### A) Mid-implementation review

Run after first complete draft implementation:

```bash
codex exec -C /home/holmes/poc-7-identity-eventization-completion \
  "Review this branch against docs/planning/IDENTITY_EVENTIZATION_COMPLETION_INSTRUCTIONS.md.
  Check each hard success criterion SC1-SC5 and identify missing work, regressions, or boundary leaks.
  Write findings in feedback.md with severity, file references, and concrete fixes."
```

Address all high/medium findings before final audit.

### B) Final PASS/FAIL audit (merge gate)

```bash
codex review --base master \
  "Audit this branch against docs/planning/IDENTITY_EVENTIZATION_COMPLETION_INSTRUCTIONS.md.
  For SC1, SC2, SC3, SC4, SC5 output PASS or FAIL with exact file/test evidence.
  Fail if any required command-level verification result is missing or ambiguous.
  End with a single overall verdict: READY_TO_MERGE or NOT_READY." > codex_final_audit.md
```

If any criterion is FAIL:

1. fix the code/tests/docs,
2. re-run the audit,
3. repeat until all criteria PASS and verdict is `READY_TO_MERGE`.

## Merge readiness checklist

All must be true:

1. SC1-SC5 all PASS.
2. `feedback.md` findings are resolved or explicitly waived with rationale.
3. `codex_final_audit.md` ends with `READY_TO_MERGE`.
4. `docs/planning/IDENTITY_EVENTIZATION_COMPLETION_EVIDENCE.md` exists and maps every criterion to proof.
