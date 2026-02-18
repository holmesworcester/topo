# Execution Plan: Remaining TODOs (Topo)

Date: 2026-02-17
Branch: `exec/all-remaining-todos-20260217`
Worktree: `/home/holmes/poc-7-remaining-todos`
Source baseline: `master` @ `02315d4`

## Scope

Complete the remaining open TODO tracks from `TODO.md`:

1. `#11` Unify transport identity architecture (single event-derived identity, no rotation sidecar)
2. `#14` Unify bootstrap key distribution via invite key wrap/unwrap (with out-of-order coverage + closure)
3. `#19` Finish TLA/spec mapping closure still tied to transport identity naming/model terms
4. `#20` Finish structural compatibility-cruft cleanup (schema/docs/runtime surfaces)
5. `#21` Interactive CLI isomorphism (route remaining REPL commands through service layer)

## Non-negotiable constraints

1. TLA-first for semantic changes (especially `#11`, `#14`, `#19`).
2. POC replacement policy: remove superseded paths in same round (no dual mode / no compat bridge).
3. Tests green at each stage (`cargo test` + targeted integration/model checks for touched area).
4. Add/adjust tests in same change where behavior changes.

## Dependency order

1. **Stage A (`#11` + `#19` transport terms):** choose final transport identity model and align TLA + docs + runtime authority.
2. **Stage B (`#14`):** finish invite wrap/unwrap lifecycle semantics and out-of-order behavior tests on top of Stage A authority model.
3. **Stage C (`#21`):** finish interactive REPL/service isomorphism after identity/key APIs are stable.
4. **Stage D (`#20`):** final structural cruft removal once earlier behavior paths are settled.

## Detailed execution

### Stage A: Transport identity simplification (`#11`) + mapping closure (`#19` subset)

1. Update TLA modules first (`EventGraphSchema.tla`, `TransportCredentialLifecycle.tla`, `projector_spec.md`) to selected single-authority semantics.
2. Remove sidecar-authority semantics from runtime (`local_transport_creds` as identity authority) and eliminate silent regeneration behavior.
3. Ensure transport allow/deny and tenant discovery consume only event-derived identity/trust sources.
4. Update DESIGN/PLAN language to one canonical authority model.
5. Verification:
   - `cargo test -q`
   - `docs/tla/tlc event_graph_schema_fast.cfg`
   - `docs/tla/tlc TransportCredentialLifecycle transport_credential_lifecycle_fast.cfg`

Acceptance:

1. Replay/rebuild identity continuity no longer depends on mutable sidecar identity state.
2. No runtime transport rotation side-path remains.
3. TLA/docs/runtime terminology consistent.

### Stage B: Invite key wrap/unwrap closure (`#14`)

1. Keep local `secret_key` dep model for encrypted decryption.
2. Ensure bootstrap key acquisition is solely wrap->unwrap through invite key path.
3. Add explicit out-of-order tests:
   - secret_shared arrives before prerequisite signer/deps,
   - encrypted wrapper arrives before unwrapped local key,
   - unblock/retry path converges once unwrap materializes.
4. Close PLAN/DESIGN/TLA wording for finalized behavior.

Acceptance:

1. Normal flow requires no raw PSK bootstrap input.
2. Wrap/unwrap ordering tests exist and pass.
3. Model/docs/runtime all describe same bootstrap key path.

### Stage C: Interactive CLI isomorphism (`#21`)

1. Move remaining interactive commands (`send`, `messages`, `status`, `react`, `delete`, `users`, `keys`) to service-layer APIs.
2. Keep REPL-only UX affordances (numeric aliases, formatting) in adapter layer only.
3. Remove direct SQL in interactive business logic where service/query API exists.
4. Add parity coverage for REPL command behavior vs service functions.

Acceptance:

1. Interactive command semantics owned by service layer.
2. REPL is thin adapter (parse/alias/render only).

### Stage D: Structural compatibility cleanup (`#20`)

1. Remove remaining compatibility framing in active DESIGN/PLAN.
2. Evaluate removing unused compatibility-only schema elements (e.g. `ingress_queue`) if runtime truly does not depend on them.
3. Rename/remove residual compat/legacy artifacts in runtime/tests that are no longer intentional hardening.
4. Keep archival historical notes only under archive docs.

Acceptance:

1. Active docs and runtime surfaces do not present compatibility-shim behavior as normative.
2. Unused compat-only schema/runtime artifacts removed where safe.

## Verification matrix (run before merge)

1. `cargo test -q`
2. Targeted suites for touched areas (at minimum):
   - `cargo test -q --test scenario_test`
   - `cargo test -q --test cli_test`
   - `cargo test -q --test two_process_test`
3. TLA checks:
   - `cd docs/tla && ./tlc event_graph_schema_fast.cfg`
   - `cd docs/tla && ./tlc TransportCredentialLifecycle transport_credential_lifecycle_fast.cfg`

## Deliverable checklist

1. `TODO.md` statuses updated only after tests/model checks pass for each completed stage.
2. No stale dual-path code left behind for replaced behavior.
3. Explicit notes in PR/commit messages for TLA change -> runtime change mapping.
