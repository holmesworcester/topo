# Unified Model Investigation Brief

## Goal
Design and validate a **single coherent formal model** (or strict layered refinement model) that covers:
1. Event graph validity and replay behavior.
2. Projection/materialized state transitions.
3. Transport trust materialization and credential state.
4. Connection outcomes for both outbound and inbound paths.

The objective is to ensure the system-level behavior is correct end-to-end, not just each layer in isolation.

## Why this investigation
Current models split concerns (event graph vs transport lifecycle). This can hide integration bugs where each layer is locally valid but cross-layer behavior is wrong.

## Required outcomes
1. A recommended architecture for a unified model approach:
   - Option A: one model with all state.
   - Option B: layered models with explicit refinement/bridge invariants.
   - Option C: hybrid (small executable integration model + larger layer models).
2. Concrete invariant set for cross-layer correctness, including:
   - Trust-source coherence between event-derived facts and SQL/materialized trust sets.
   - Local create/project behavior consistency (`is_local_create`-gated behavior).
   - Allowed-peer semantics vs connection acceptance/rejection.
   - Outbound dial path preference correctness (ongoing first, bootstrap fallback only as needed).
3. A realistic counterexample plan:
   - At least one known historical bug (pending trust suppression) should fail in bug mode and pass in fixed mode.
4. Feasibility assessment:
   - State-space cost estimates.
   - Recommended constant domains for fast CI checks vs deeper runs.

## Success criteria (strict)
1. There is an executable model-check workflow that can demonstrate:
   - A failing run for a bug configuration.
   - A passing run for the fixed configuration.
2. The model includes explicit cross-layer invariants (not only per-layer invariants).
3. The model avoids hand-wavy abstraction of connection behavior; inbound/outbound decision logic must be represented in state transitions.
4. Documentation explains exactly how each modeled variable maps to Rust runtime/projection code.

## No-cheat checks
1. No invariant may reference only one layer if it claims cross-layer correctness.
2. At least one invariant must bind all three surfaces: event facts, projected trust state, and connection decision.
3. Counterexample trace for bug mode must identify the exact transition where behavior diverges.
4. A fixed-mode run must complete with no invariant violations under the same reduced constant domain.

## Deliverables
1. `docs/tla/UNIFIED_MODEL_PLAN.md` with architecture decision and mapping table.
2. New `.tla` and `.cfg` files (or refinement additions) implementing chosen approach.
3. TLC run notes with exact commands and outcomes (bug fail + fix pass).
4. Update to `docs/tla/runtime_check_catalog.md` documenting new checks.

## Suggested first pass
1. Start with a **small integration model** using minimal domains (`Peers={alice,bob}`, small SPKI/Event sets).
2. Encode only core transitions needed for trust + connection decisions.
3. Add bridge invariants first, then expand behaviors.
4. Keep a dedicated `*_bug_repro.cfg` and `*_fix_repro.cfg` pair.

## Final step requirement
Before handoff/review, **commit completed work on this same worktree branch**.
