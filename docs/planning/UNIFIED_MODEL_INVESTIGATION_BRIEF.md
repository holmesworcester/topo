# Unified Model Investigation Brief

## Goal
Design and validate a **single coherent formal model** (or strict layered refinement model) that covers:
1. Event graph validity and replay behavior.
2. Projection/materialized state transitions.
3. Transport trust materialization and credential state.
4. Connection outcomes for both outbound and inbound paths.

The objective is to ensure the system-level behavior is correct end-to-end, not just each layer in isolation.

## Architecture decision for this investigation
Use **Option B (layered models with explicit refinement/bridge invariants)** as the default implementation path.

Rationale:
1. Existing `EventGraphSchema.tla` and `TransportCredentialLifecycle.tla` already provide useful layer-local coverage.
2. Product risk is in cross-layer mismatch (event facts vs projection rows vs connection behavior), which bridge invariants directly target.
3. State-space is expected to remain more tractable than a single all-in-one model while still enabling executable counterexamples.

Fallback:
- If Option B is not tractable under the CI/deep-run budgets below, use Option C only for the blocked surface and preserve Option B bridges for the rest.

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
   - Security properties (authorization, provenance, impersonation resistance, and removal-deny semantics).
3. **Projection row-write modeling requirement (explicit):**
   - Model projection as abstract write-intent actions (insert/delete/upsert) for the trust and connection-critical surfaces, not only final set equality.
   - Minimum covered row surfaces:
     - `peer_shared_spki_fingerprints` (ongoing trust source)
     - `invite_bootstrap_trust`
     - `pending_invite_bootstrap_trust`
     - connection-state materialization used by dial/accept decisions
   - Add bridge invariants that connect:
     - event facts -> projected write intents
     - projected write intents -> materialized trust/connection state
4. **Product-goal progress property set (explicit):**
   - Bootstrap viability: under admissible invite preconditions, nodes can eventually establish invite-labeled connectivity.
   - Upgrade viability: once PeerShared prerequisites are satisfied, nodes can eventually upgrade to ongoing/peer-labeled connectivity.
   - Sync sufficiency: once connected and non-removed, nodes can eventually project enough state to complete bootstrap workflow.
   - Dial fallback viability: when ongoing trust is unavailable but bootstrap trust is available, fallback is eventually attempted/allowed.
   - Progress properties must specify fairness assumptions explicitly.
5. A realistic counterexample plan:
   - At least one known historical bug (pending trust suppression) should fail in bug mode and pass in fixed mode.
6. Feasibility assessment:
   - State-space cost estimates.
   - Recommended constant domains for fast CI checks vs deeper runs.
   - Explicit tier policy:
     - Tier 1 (`fast_gate`) must converge and be CI-required.
     - Tier 2 (`interaction`) must remain bounded and run for trust/bootstrap changes.
     - Tier 3 (`deep`) runs nightly/manual with fixed budget ceilings.
   - Concrete runtime budgets:
     - CI-fast target: <= 2 minutes per config on baseline dev machine.
     - Deep-run target: <= 20 minutes for nightly/manual validation.

## Success criteria (strict)
1. There is an executable model-check workflow that can demonstrate:
   - A failing run for a bug configuration.
   - A passing run for the fixed configuration.
2. The model includes explicit cross-layer invariants (not only per-layer invariants).
3. The model avoids hand-wavy abstraction of connection behavior; inbound/outbound decision logic must be represented in state transitions.
4. Documentation explains exactly how each modeled variable maps to Rust runtime/projection code.
5. At least one executable progress/liveness check demonstrates bootstrap completion viability (connect + sync + upgrade) under documented fairness assumptions.
6. At least one bridge check is defined at row-write level (write-intent semantics), not only derived trust-set equality.
7. Security invariants are explicit bridge checks (not implied indirectly by general trust-coherence invariants).
8. A gate matrix is documented showing which configs are Tier 1/2/3 and which are mandatory in CI.

## No-cheat checks
1. No invariant may reference only one layer if it claims cross-layer correctness.
2. At least one invariant must bind all three surfaces: event facts, projected trust state, and connection decision.
3. Counterexample trace for bug mode must identify the exact transition where behavior diverges.
4. A fixed-mode run must complete with no invariant violations under the same reduced constant domain.
5. Progress checks must not be satisfied vacuously by disabling actions; fairness assumptions and enabledness conditions must be documented.
6. Any row-write bridge must name the modeled write action and the corresponding Rust projection path.
7. Security checks must include at least one negative property ("must never happen"), such as unauthorized connection acceptance.

## Deliverables
1. `docs/tla/UNIFIED_MODEL_PLAN.md` with architecture decision and mapping table.
2. New `.tla` and `.cfg` files (or refinement additions) implementing chosen approach.
3. TLC run notes with exact commands and outcomes (bug fail + fix pass).
4. Update to `docs/tla/runtime_check_catalog.md` documenting new checks.
5. Add a short "product-goal coverage" table showing where each goal is checked:
   - bootstrap connect
   - bootstrap completion sync sufficiency
   - ongoing upgrade path
   - fallback path behavior

## Suggested first pass
1. Start with **Option B bridge scaffolding** between `EventGraphSchema` and `TransportCredentialLifecycle`.
2. Add a small write-intent layer for trust/connection-critical rows before expanding to additional projector surfaces.
3. Use minimal domains first (`Peers={alice,bob}`, small SPKI/Event sets), then scale for deep runs.
4. Add bridge invariants first, then add progress properties with explicit fairness assumptions.
5. Keep dedicated config pairs:
   - `*_bug_repro.cfg` and `*_fix_repro.cfg` for known regression
   - `*_progress_fast.cfg` and `*_progress_deep.cfg` for product-goal viability

## Final step requirement
Before handoff/review, **commit completed work on this same worktree branch**.
