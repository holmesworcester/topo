# Projector TLA Conformance Test Instructions

Date: 2026-02-19
Branch: `exec/projector-tla-conformance-instructions`
Worktree: `/home/holmes/poc-7-projector-tla-conformance-instructions`

## Goal

Build a durable conformance test suite so projector behavior stays aligned with the TLA-derived spec.

Primary objective:
1. Every validation requirement in `docs/tla/projector_spec.md` has at least one runtime test.
2. Where possible, each requirement has both:
   - a valid/pass case, and
   - a deliberate violation/break case.
3. Projector logic remains close to model guards and fails CI on unmapped drift.

## Scope

In scope:
1. Pure projector unit tests (no DB I/O in the projector call itself).
2. Shared pipeline integration tests for checks that are not projector-local.
3. Coverage gate linking TLA mapping entries to runtime tests.

Out of scope:
1. Rewriting projector semantics.
2. Changing event protocol/wire formats.
3. Replacing existing scenario/networking tests.

## Core Principle

Not all TLA invariants are projector-only.

1. Event-local predicates belong in projector unit tests.
2. Shared engine concerns belong in pipeline tests (`projection/apply` + encrypted path).
3. End-to-end ordering/replay/cascade invariants remain integration/scenario tests.

Treat "TLA conformance" as a layered test contract, not one test style.

## Source of Truth

Use these files as normative mapping inputs:
1. `docs/tla/projector_spec.md`
2. `docs/tla/EventGraphSchema.tla`
3. `docs/tla/event_graph_schema_bootstrap.cfg`
4. `docs/tla/TransportCredentialLifecycle.tla`

If behavior changes are needed:
1. update TLA/spec docs first,
2. then update Rust behavior,
3. then update conformance tests.

## Test Architecture

### A) Projector Unit Tests (pure function contract)

Target each event projector function (for example `src/event_modules/*/projector.rs`).

For each projector:
1. build minimal `ParsedEvent` fixture(s),
2. build `ContextSnapshot` fixture(s),
3. call `project_pure(recorded_by, event_id_b64, parsed, ctx)`,
4. assert exact:
   - `ProjectionDecision` variant and reason class,
   - `write_ops` shape (tables, key fields, op type),
   - `emit_commands` shape.

Coverage requirement per modeled guard:
1. one acceptance case,
2. one rejection/block/no-op case attempting to break rule.

### B) Shared Pipeline Tests (non-projector-local rules)

Keep these in `src/projection/apply/tests/` (or split modules):
1. dependency presence/blocking and unblock cascade,
2. dep type checks,
3. signer resolution + signature verification,
4. encrypted wrapper path:
   - key missing,
   - decrypt failure,
   - disallowed inner type,
   - inner dep blocking keyed to outer event id.

These are required for TLA alignment but cannot be proven by projector unit tests alone.

### C) Replay/Order Conformance Tests

Add/extend replay-focused tests for model-critical properties:
1. out-of-order convergence,
2. idempotent replay,
3. stable terminal state across order permutations for selected flows,
4. deletion two-stage convergence invariants.

Use existing scenario/replay test infrastructure; do not duplicate full e2e harnesses.

## Conformance Matrix (Required Artifact)

Add a machine-readable test matrix file:
1. `docs/tla/projector_conformance_matrix.md` (or `.json`)

Each row must include:
1. `spec_id` (stable label),
2. source section (`projector_spec` table/guard/invariant),
3. `check_id` (runtime validation check identifier),
4. runtime layer (`projector_unit` | `pipeline_integration` | `replay_integration`),
5. test id/path,
6. polarity (`pass` | `break`).

Also add a runtime check catalog:
1. `docs/tla/runtime_check_catalog.md` (or `.json`)

Each runtime check entry must include:
1. `check_id`,
2. owner path/function (where the check lives),
3. `tla_guard_id` (or explicit `NON_MODELED::<reason>` waiver),
4. category (`projector_local` | `pipeline_shared` | `replay/order`).

## Coverage Gate (CI)

Add a check script (example):
1. `scripts/check_projector_tla_conformance.py`
2. `scripts/check_projector_tla_bijection.py` (meta test)

Gate rules:
1. every required `spec_id` has at least one linked test,
2. every guard-level `spec_id` has both pass and break polarity unless explicitly waived,
3. every runtime `check_id` maps to a `tla_guard_id` or explicit non-modeled waiver,
4. every TLA guard referenced by `projector_spec` has at least one runtime `check_id`,
5. every runtime `check_id` has at least one linked test row,
6. waivers require inline rationale in matrix/catalog and are reviewed as spec debt.

Suggested CI hook:
1. run script in existing test/check workflow before full integration suite.
2. fail fast if either direction is missing:
   - guard -> checks/tests missing,
   - check -> guard mapping missing.

This meta-test is mandatory and enforces the "vice versa" rule:
1. tests exist for every TLA guard,
2. every validation check has a TLA guard mapping.

## Suggested Implementation Order

### Phase 1: Matrix and IDs
1. Define stable `spec_id` labels from `docs/tla/projector_spec.md`.
2. Define stable `check_id` labels for runtime validation checks.
3. Build initial `runtime_check_catalog`.
4. Seed matrix with current test links.
5. Mark missing coverage explicitly.

### Phase 2: Pure projector unit harness
1. Add per-module projector test files (or a shared harness module).
2. Implement high-value guard tests first:
   - workspace trust-anchor guard,
   - invite acceptance trust-anchor write behavior,
   - removal/recipient constraints,
   - deletion author and tombstone behavior.

### Phase 3: Shared pipeline completeness
1. Fill missing dep/signer/encrypted shared-stage tests.
2. Ensure rejection/block reasons remain deterministic where required.

### Phase 4: Replay/order conformance
1. Add focused order-permutation tests for selected critical flows.
2. Add replay-from-log parity assertions for those flows.

### Phase 5: Enforce coverage gate
1. Turn on check script in CI/local checks.
2. Turn on bidirectional meta-test script.
3. Fail on newly unmapped spec entries.
4. Fail on unmapped runtime checks.

## Acceptance Criteria

1. Conformance matrix exists and is current.
2. Every validation requirement in `projector_spec.md` maps to at least one runtime test.
3. Guard-level requirements have pass + break tests unless documented waiver exists.
4. Projector unit tests cover event-local rules without DB side effects.
5. Shared pipeline and replay invariants are covered in integration layers.
6. CI fails on conformance mapping drift.
7. Bidirectional meta-test passes (guard->test and check->guard coverage).

## Recommended Test Locations

1. `src/event_modules/*/projector_tests.rs` for event-local pure tests.
2. `src/projection/apply/tests/` for shared stages.
3. `tests/scenario_test.rs` or focused new files for replay/order conformance.
4. `scripts/check_projector_tla_conformance.py` for matrix coverage.
5. `scripts/check_projector_tla_bijection.py` for guard/check vice-versa enforcement.

## Documentation Follow-up

After implementation branch starts:
1. update `docs/PLAN.md` with the conformance gating rule,
2. update `docs/DESIGN.md` with layered conformance model,
3. keep `docs/tla/projector_spec.md` and conformance matrix in lockstep.
