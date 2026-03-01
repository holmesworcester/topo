# Projector Context Query Locality Execution Plan

Date: 2026-03-01
Branch: `exec/projector-context-query-locality-instructions`
Worktree: `/home/holmes/poc-7-projector-context-query-locality-instructions`

## Goal

Replace the current ad hoc centralized projector-context assembly with a principled context-query model where projector-specific context ownership is local to the owning event module (or projector function), while preserving all existing validation/check behavior.

## Non-Negotiable Requirements

1. Projector-specific context must be local to the owning projector:
   - defined in the event module and/or projector-local query function,
   - not centralized in shared pipeline files.
2. Shared pipeline checks remain pipeline-owned:
   - dep presence/type,
   - signer resolution and signature verification,
   - encrypted-wrapper checks,
   - rejection/cascade mechanics.
3. `docs/PLAN.md` and `docs/DESIGN.md` must be updated to reflect the implemented architecture and current behavior before completion.
4. Work must be reviewed in this same worktree/branch, and feedback must be iterated until explicitly accepted.
5. Final step requirement: commit completed work on this same worktree branch before handoff or review.

## Current Baseline (to replace)

Projector context is currently built in one central function:

- `src/state/projection_state/apply/context.rs::build_context_snapshot`

This file currently mixes projector-specific context reads across event modules.

## Target Architecture

1. Projector-local context query ownership:
   - each event module that needs context provides its own context loader/query function(s), typically in:
     - `src/event_modules/<module>/queries.rs`, or
     - the module projector file when very small.
2. Shared apply path:
   - apply/dispatch layer asks the event module for context via a registry-declared context loader contract.
3. Context contract:
   - projector receives only the context it needs, with query semantics declared near the projector.
4. No projector-specific SQL in shared apply context code.

## Implementation Phases

### Phase 0: Baseline + Safety Net

1. Capture baseline checks:
   - `cargo check`
   - `bash scripts/check_boundary_imports.sh`
   - `python3 scripts/check_projector_tla_conformance.py`
   - `python3 scripts/check_projector_tla_bijection.py`
2. Record baseline outputs in a short evidence note under `docs/planning/`.

Success criteria:
1. Baseline commands complete and results are recorded.
2. No undocumented baseline failures.

### Phase 1: Introduce Context Loader Contract

1. Add a projector-context loader hook to event registration metadata.
2. Keep projector dispatch pure: `(recorded_by, event_id_b64, parsed, ctx) -> ProjectorResult`.
3. Implement default empty-context behavior for modules that require no extra context.

Success criteria:
1. Build passes with contract scaffolding.
2. Existing projectors still run with equivalent behavior.

### Phase 2: Migrate Projector-Specific Context to Event Modules

Migrate context query logic out of shared apply context builder into owning modules:

1. `workspace`: trust-anchor context.
2. `invite_accepted`: trust-anchor + bootstrap context + peer-shared supersession guard.
3. `user_invite` and `device_invite`: local-create + bootstrap-context gates.
4. `message`: signer-user mismatch + deletion-intent lookup.
5. `message_deletion`: signer-user mismatch + target author/tombstone/type checks.
6. `reaction`: signer-user mismatch + deleted-target check.
7. `secret_shared`: recipient-removed context.
8. `file_slice`: file descriptors + existing slice occupancy.

Rules:
1. Query logic must live with the owning module (or projector-local function).
2. Shared helpers are allowed only for reusable primitives, not ownership transfer.
3. Shared apply code may orchestrate, but must not own module-specific SQL predicates.

Success criteria:
1. No projector-specific query branches remain in shared apply context builder.
2. Each migrated module contains its own explicit context query function(s).
3. Projector unit tests still validate pass/break cases for mapped checks.

### Phase 3: Remove/Collapse Legacy Central Context Assembly

1. Delete or reduce `src/state/projection_state/apply/context.rs` so it no longer owns projector-specific context assembly.
2. Keep only truly pipeline-shared concerns in shared pipeline modules.

Success criteria:
1. Legacy centralized projector-context ownership is removed.
2. Code compiles with new ownership boundaries.

### Phase 4: Tests and Conformance

Run and fix until green:

1. `cargo check`
2. `bash scripts/check_boundary_imports.sh`
3. `cargo test --test projectors -q`
4. Targeted projector/apply tests for migrated modules
5. `python3 scripts/check_projector_tla_conformance.py`
6. `python3 scripts/check_projector_tla_bijection.py`

Add/adjust tests where needed to prove:
1. no behavior regressions,
2. projector-local checks still match runtime-check catalog mappings,
3. replay/order semantics remain intact for touched flows.

Success criteria:
1. All required checks pass.
2. No missing guard/check mapping introduced.

### Phase 5: Documentation Sync (Mandatory)

Update:

1. `docs/PLAN.md`
2. `docs/DESIGN.md`

Must include:
1. new context-query ownership model,
2. projector-local vs pipeline-shared boundary,
3. where context declarations live,
4. how this maps to conformance checks and review expectations.

Success criteria:
1. PLAN and DESIGN explicitly match implemented code structure.
2. No stale references to centralized projector-specific context builder.

### Phase 6: Review and Iterate Until Accepted

1. Request review in this same worktree/branch.
2. Log findings in `feedback.md` (or update existing review artifact).
3. Fix all High and Medium issues; address Low issues or document rationale.
4. Re-run required checks after each fix iteration.
5. Repeat review/fix cycle until explicit acceptance is recorded.

Success criteria:
1. Reviewer marks work accepted.
2. No unresolved High/Medium findings remain.

## Deliverables

1. Refactored context query ownership implemented in code.
2. Updated tests proving parity and guard coverage.
3. Updated `docs/PLAN.md` and `docs/DESIGN.md`.
4. Review artifact with accepted status.

## Final Checklist

1. All success criteria above met.
2. Required checks re-run and passing.
3. PLAN and DESIGN updated to latest implemented behavior.
4. Review completed and accepted in this worktree context.
5. Commit completed work on this same worktree branch before handoff or review.
