# Bootstrap Projection + Ongoing Peering Execution Plan

Date: 2026-02-20
Branch: `exec/bootstrap-projection-peering-unification`
Worktree: `/home/holmes/poc-7-bootstrap-projection-peering`

## Goal

Make invite bootstrap a projection-driven state transition, not a service-special one-shot workflow.

Target behavior:

1. `invite_accepted` remains dep-free and projects immediately.
2. Bootstrap transport metadata/trust is materialized from projection input/state.
3. Ongoing peering loops consume SQL state and perform both bootstrap and steady-state syncing.
4. Service accept paths stop doing direct one-shot bootstrap orchestration.

## Current mismatch to remove

1. `svc_accept_invite` / `svc_accept_device_link` run explicit one-shot bootstrap sync before and after identity-chain creation.
2. Service path requires bootstrap prerequisites before it can complete join path.
3. Bootstrap flow is split between service orchestration and runtime loops instead of being fully SQL-driven.

## Scope

In scope:

1. Accept/bootstrap flow semantics in `service`, projection, and peering runtime.
2. Queue/loop behavior for bootstrap dial targets and sync progression.
3. Tests proving bootstrap can progress from projected SQL state.
4. Removal or retirement of one-shot bootstrap workflow where redundant.

Out of scope:

1. Unrelated naming refactors.
2. Unrelated event-module locality migrations.

## Required start steps

1. `git fetch origin`
2. `git rebase origin/master`
3. Baseline checks:
   - `cargo check`
   - `cargo test --lib -q`

## Execution stages

### Stage 1: Lock target semantics with tests

Add/adjust tests first so the desired behavior is explicit:

1. `invite_accepted` is dep-free and projects trust anchor immediately.
2. Accept path does not require pre-sync workspace presence.
3. Bootstrap connectivity/sync can start from SQL bootstrap trust + address rows, via ongoing loop.
4. Workspace guard unblock still happens through normal retry/cascade path.

Suggested locations:

1. `src/projection/apply/tests/mod.rs`
2. `tests/scenario_test.rs` and/or `tests/replication_contract_tests.rs`
3. `src/peering/runtime/*` focused tests

### Stage 2: Projection-first accept semantics

Refactor accept flow so service records acceptance and context; runtime handles network progress:

1. Keep `InviteAccepted` creation local and immediate.
2. Ensure bootstrap context/trust rows are produced by projection-oriented flow.
3. Remove precondition checks that require bootstrap sync completion in service accept call.
4. Keep transport identity transitions contract-driven (adapter boundary intact).

### Stage 3: Ongoing peering handles bootstrap

Unify bootstrap and steady-state sync initiation in runtime loops:

1. Extend existing autodial/queue refresh to treat bootstrap trust rows as normal dial candidates.
2. Ensure trust oracle gating remains SQL-based (`is_peer_allowed`).
3. Ensure retry/backoff and loop cadence handle bootstrap targets without one-off service calls.
4. Preserve memory-safe behavior for large peer sets (no full-set materialization where avoidable).

### Stage 4: Join progression without one-shot service bootstrap

Ensure identity-chain completion works with async runtime progression:

1. Either stage follow-up join actions until prerequisites exist, or block cleanly and retry in runtime path.
2. Avoid hard rejects for expected transient bootstrap ordering gaps where retry is intended.
3. Make completion idempotent and safe across multiple sync rounds.

### Stage 5: Retire one-shot bootstrap workflow

After Stage 2-4 pass:

1. Remove (or strictly internalize behind runtime) `peering/workflows/bootstrap.rs` one-shot usage from accept services.
2. Remove dead code paths and stale comments that describe service-special bootstrap behavior.
3. Update docs to describe single SQL-driven peering model.

## Quality gates

1. `cargo check`
2. `cargo test --lib -q`
3. `cargo test --test replication_contract_tests -q`
4. `cargo test --test holepunch_test -q`
5. Targeted invite/device-link scenario tests exercising bootstrap and normal sync.

## Codex CLI feedback loop (mandatory)

### Mid-implementation feedback

Run after first end-to-end draft (before final cleanup):

```bash
codex exec -C /home/holmes/poc-7-bootstrap-projection-peering \
  "Review this branch against docs/planning/BOOTSTRAP_PROJECTION_ONGOING_PEERING_EXECUTION_PLAN.md.
  List missing requirements, regressions, and risk areas with severity and file references.
  Write results to FEEDBACK.md."
```

Then:

1. Address every finding.
2. Re-run the same command.
3. Repeat until no unresolved high/medium findings remain.

### Final completion audit (must be PASS for every requirement)

```bash
codex review --base master \
  "Audit this branch against docs/planning/BOOTSTRAP_PROJECTION_ONGOING_PEERING_EXECUTION_PLAN.md.
  Evaluate each stage and each gate with PASS/FAIL, with concrete file+test evidence.
  Confirm whether all instructions are completed." > CODEX_FINAL_AUDIT.md
```

Then:

1. Fix every FAIL item.
2. Re-run the final audit.
3. Repeat until all required items are PASS and the audit explicitly confirms all instructions are completed.

## Done criteria

1. Accept flows no longer depend on service-triggered one-shot bootstrap sync.
2. Bootstrap progress is driven by projected SQL state and ongoing peering loops.
3. `invite_accepted` remains dep-free and continues to drive trust-anchor/cascade semantics.
4. Tests cover bootstrap progression, retries, and steady-state convergence.
5. `FEEDBACK.md` and `CODEX_FINAL_AUDIT.md` show no unresolved required work.
