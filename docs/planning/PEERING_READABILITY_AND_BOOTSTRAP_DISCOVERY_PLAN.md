# Peering Readability + Bootstrap-as-Discovery Execution Plan

Date: 2026-02-21
Branch: `exec/peering-readability-plan-instructions`
Worktree: `/home/holmes/poc-7-peering-readability-plan`

## Objective

Improve peering organization for newcomer readability and hard-to-cheat testing.

Primary goals:

1. Bootstrap is an ongoing discovery/autodial state transition, not a production special workflow moment.
2. Peering responsibilities are easy to diagram and explain.
3. Peering-to-transport interaction is narrower and clearer for tests.
4. Production code paths avoid scattered special cases.

POC policy: no backward-compatibility shims are required in final state.

## System model to enforce

Runtime loop model:

1. projected SQLite state
2. target planner (includes bootstrap targets)
3. dial/accept supervisors
4. sync session runner
5. ingest writer
6. projected SQLite state

This is the mental model docs and code structure must match.

## Required start steps

1. `git fetch origin`
2. `git rebase origin/master`
3. Baseline:
   - `cargo check`
   - `bash scripts/check_boundary_imports.sh`

## Non-negotiable requirements

### R1. Bootstrap belongs to discovery/autodial in production

1. Production bootstrap progression must be driven by projected SQL trust/target rows and ongoing peering loops.
2. No production service-level one-shot bootstrap workflow path.

### R2. Test bootstrap helpers are test-only

1. Existing helper behavior from `peering/workflows/bootstrap.rs` should move to test-support location (for example `src/testutil/*` or `tests/support/*`) OR remain in module clearly marked/used only by tests.
2. Production runtime must not depend on test bootstrap helpers.

### R3. Single target-planning ownership

1. Consolidate target planning for autodial/discovery into one clear module surface.
2. mDNS-discovered targets and bootstrap-trust targets should flow through one planner/dispatcher path.

### R4. Narrow peering↔transport seam for readability

1. Peering modules should not scatter direct transport-concrete construction logic across many files.
2. Introduce/centralize a transport runtime seam used by peering for endpoint/session wiring (pragmatic seam for readability/testing, not for pluggable swaps).

### R5. Keep eventization boundary explicit

1. Eventize durable trust/identity authority transitions.
2. Do not eventize transport runtime mechanics (retry cadence, discovery timing, session lifecycle).
3. Update docs to state this explicitly.

## Mandatory implementation phases

### Phase 1: Consolidate production bootstrap ownership under discovery/runtime

1. Remove production ownership from `peering/workflows/bootstrap.rs`.
2. Ensure runtime bootstrap dialing is sourced from projected DB state and handled by ongoing autodial.
3. Keep behavior unchanged from user perspective.

### Phase 2: Unify target planning path

1. Create one planner module that yields dial targets from:
   - projected bootstrap trust rows
   - discovery (mDNS) candidates
2. Route both into one dispatch path (`PeerDispatcher`-style ownership).
3. Eliminate duplicate target-selection logic spread across runtime modules.

### Phase 3: Clarify peering↔transport seam

1. Centralize transport-concrete endpoint/session wiring used by peering.
2. Make connect/accept loops consume this seam rather than duplicating concrete setup in many files.
3. Preserve current contracts with sync/event_pipeline.

### Phase 4: Testability hardening

1. Add focused tests for target planning decisions (input DB/discovery events -> expected dial actions).
2. Add component tests for ongoing bootstrap autodial progression from projected rows.
3. Keep existing integration/QUIC tests for real session behavior.

### Phase 5: Docs and boundary checks

1. Update `docs/DESIGN.md` and `docs/PLAN.md` with the enforced model.
2. Add/adjust `scripts/check_boundary_imports.sh` rules for new ownership constraints.
3. Add evidence file mapping each criterion to proof.

## Hard success criteria (all required)

### SC1. Production bootstrap is discovery/autodial-owned

1. Production runtime path has no special bootstrap workflow dependency.
2. Bootstrap targets are consumed by ongoing autodial planning/dispatch.

### SC2. Bootstrap test helpers are not production-owned

1. No production entrypoint depends on test bootstrap helper module.
2. If helper module remains, it is test-only in ownership and usage.

### SC3. Target planning is single-owner and explicit

1. One module is the source of truth for dial target planning.
2. mDNS and bootstrap trust targets are routed through that single planner path.

### SC4. Peering↔transport boundary is cleaner

1. Transport-concrete wiring used by peering is centralized.
2. `accept`/`connect` loops are thinner and less duplicated.

### SC5. Docs reflect the real runtime model

1. `docs/DESIGN.md` and `docs/PLAN.md` describe the exact loop model.
2. Newcomer can identify one file for target planning and one for loop supervision.

### SC6. Tests and checks pass

1. boundary checks pass.
2. core compile/tests pass, including peering and scenario coverage.

## Required verification commands

Run and include outputs in evidence:

```bash
rg -n "peering::workflows::bootstrap|workflows/bootstrap" src
rg -n "target planner|autodial|PeerDispatcher|launch_mdns_discovery|collect_placeholder_invite_autodial_targets" src/peering
bash scripts/check_boundary_imports.sh
cargo check
cargo test --lib -q
cargo test --test scenario_test -q
cargo test --test holepunch_test -q
cargo test --test projectors -q
```

Interpretation requirements:

1. Bootstrap grep must not show production runtime ownership via `peering/workflows/bootstrap`.
2. Planner/dispatch ownership should be discoverable from one runtime planning path.
3. All quality gates pass.

## Mandatory Codex CLI iteration loop

### A) Mid-implementation feedback (required)

Run after first full draft (Phases 1-3):

```bash
codex exec -C /home/holmes/poc-7-peering-readability-plan \
  "Review this branch against docs/planning/PEERING_READABILITY_AND_BOOTSTRAP_DISCOVERY_PLAN.md.
  Check R1-R5 and SC1-SC6. Identify missing ownership moves, readability regressions,
  and boundary leaks. Write actionable findings with severity and file refs to feedback.md."
```

Address all High/Medium findings before final audit.

### B) Final merge-gate audit (required)

```bash
codex review --base master \
  "Audit this branch against docs/planning/PEERING_READABILITY_AND_BOOTSTRAP_DISCOVERY_PLAN.md.
  Report PASS/FAIL for SC1-SC6 with concrete file/test evidence.
  Fail if required command evidence is missing.
  End with READY_TO_MERGE or NOT_READY." > codex_final_audit.md
```

If any FAIL:

1. fix,
2. rerun audit,
3. repeat until all PASS and `READY_TO_MERGE`.

## Required evidence artifact

Create:

- `docs/planning/PEERING_READABILITY_AND_BOOTSTRAP_DISCOVERY_EVIDENCE.md`

Map each SC1-SC6 item to concrete file/test/command proof.

## Merge checklist

All must be true:

1. SC1-SC6 all PASS.
2. `feedback.md` has no unresolved High/Medium items.
3. `codex_final_audit.md` ends with `READY_TO_MERGE`.
4. Evidence file exists and covers all SC items.
