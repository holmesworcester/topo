# Identity Layer Removal Execution Plan

Date: 2026-02-21
Branch: `exec/identity-layer-removal-plan-instructions`
Worktree: `/home/holmes/poc-7-identity-layer-removal-plan`

## Objective

Eliminate `src/identity/` as a catch-all bucket and enforce strict ownership:

1. Event-domain identity logic lives in `src/event_modules/workspace/*`.
2. Transport credential/materialization logic lives in `src/transport/*`.
3. Only pure crypto primitives live in `src/crypto/*`.
4. No new logic should depend on `crate::identity::*` after migration.

POC policy: no backward-compatibility shims are required in final state.

## Required start steps

1. `git fetch origin`
2. `git rebase origin/master`
3. Baseline:
   - `cargo check`
   - `bash scripts/check_boundary_imports.sh`

## Scope

In scope:

1. Move all remaining code in `src/identity/ops.rs` to workspace event-module locality.
2. Move `src/identity/invite_link.rs` into workspace-owned invite module.
3. Move `src/identity/transport.rs` into `src/transport/identity.rs`.
4. Remove `pub mod identity;` and delete `src/identity/*`.
5. Update boundaries/tests/docs accordingly.

Out of scope:

1. New protocol design.
2. New network loop architecture.
3. Backward-compatible aliases/re-exports for old paths.

## Non-negotiable architecture requirements

### R1. Event ownership

All invite/event-building and content-key invite helpers currently in `identity::ops` must be owned by workspace event modules, not by a top-level identity module.

Examples that must relocate:

1. invite data/types currently in `ops.rs` (`InviteData`, `InviteType`, `JoinChain`, `LinkChain`, `InviteBootstrapContext`)
2. invite event builders (`create_user_invite_events`, `create_device_link_invite_events`)
3. content-key invite helpers (`ensure_content_key_for_peer`, wrap/unwrap, pending unwrap store/clear)

### R2. Transport ownership

Transport cert/key/SPKI logic currently in `identity::transport` must live under `src/transport/`.

Requirements:

1. keep install/load logic transport-owned
2. keep adapter boundary intact (`src/transport/identity_adapter.rs` remains sole install-intent bridge)
3. no direct raw install calls from service/event_modules/projection

### R3. Invite link locality

Invite link encode/decode is workspace-invite domain behavior and should be colocated with workspace event module logic.

Requirements:

1. move invite link payload encode/decode out of `src/identity/`
2. if bootstrap address parsing is reused by peering, extract tiny shared utility module (no new catch-all)

### R4. Eventization boundary clarity

Document and enforce:

1. eventize durable authority/policy transitions (trust, identity transitions)
2. do not eventize transport runtime mechanics (discovery, retries, session lifecycle)

### R5. Identity module elimination

Final tree must not include `src/identity/` or `pub mod identity;`.

## Mandatory migration order

### Phase 1: Move transport identity module first

1. Move `src/identity/transport.rs` -> `src/transport/identity.rs`.
2. Update all imports/call sites.
3. Keep behavior unchanged.

### Phase 2: Move invite link module

1. Move `src/identity/invite_link.rs` to workspace-owned location (for example `src/event_modules/workspace/invite_link.rs`).
2. Update `service.rs`, `workspace::commands`, and peering autodial imports.
3. Optionally extract address parser utility if needed by peering.

### Phase 3: Move `ops` content into workspace modules

1. Create workspace-local module splits as needed (`types.rs`, `invite_builders.rs`, `content_keys.rs`, etc.).
2. Move all non-crypto helper logic from `src/identity/ops.rs` into workspace modules.
3. Ensure `workspace::commands` owns canonical flow and helper APIs.
4. Move pure crypto-only helper(s) to `src/crypto/*` only if they are DB/event independent.

### Phase 4: Delete identity module

1. Remove `pub mod identity;` from `src/lib.rs`.
2. Delete `src/identity/mod.rs`, `src/identity/ops.rs`, `src/identity/invite_link.rs`, `src/identity/transport.rs`.
3. Compile/test and fix all imports.

### Phase 5: Boundary enforcement + docs

1. Strengthen `scripts/check_boundary_imports.sh`:
   - forbid `crate::identity::` imports anywhere in non-archive code
   - keep existing transport-install boundary checks
2. Update `docs/DESIGN.md` and `docs/PLAN.md` with final ownership map.
3. Add evidence file for merge review.

## Hard success criteria (all required)

### SC1: No identity module remains

1. `src/identity/` directory does not exist.
2. `src/lib.rs` has no `pub mod identity;`.

### SC2: Event-domain identity helpers are workspace-local

1. No `identity::ops::*` references anywhere.
2. Workspace module owns invite/event helper APIs and associated types.

### SC3: Transport identity logic is transport-local

1. No `identity::transport::*` references anywhere.
2. `src/transport/identity.rs` exists and is used.
3. Adapter install boundary remains enforced.

### SC4: Invite link logic is not top-level identity

1. No `identity::invite_link::*` references anywhere.
2. Invite link parser/encoder lives in workspace-local module (or explicitly justified small shared utility for address parsing only).

### SC5: Docs and boundary checks encode the new model

1. `scripts/check_boundary_imports.sh` fails on new `crate::identity::` usage.
2. `docs/DESIGN.md` and `docs/PLAN.md` describe the final ownership and eventization boundary.

## Required verification commands

Run and include outputs in evidence:

```bash
rg -n "pub mod identity;|crate::identity::|identity::(ops|transport|invite_link)" src tests
test ! -d src/identity
bash scripts/check_boundary_imports.sh
cargo check
cargo test --lib -q
cargo test --test scenario_test -q
cargo test --test projectors -q
```

Interpretation requirements:

1. First `rg` returns no matches.
2. `test ! -d src/identity` succeeds.
3. All quality gates pass.

## Mandatory Codex CLI iteration loop

### A) Mid-implementation feedback (required)

Run after Phases 2-3 draft implementation:

```bash
codex exec -C /home/holmes/poc-7-identity-layer-removal-plan \
  "Review this branch against docs/planning/IDENTITY_LAYER_REMOVAL_EXECUTION_PLAN.md.
  Check R1-R5 and SC1-SC5. Report missing migrations, boundary leaks, and risky shims.
  Write actionable findings with severity and file references to feedback.md."
```

Address all High/Medium findings before final audit.

### B) Final merge-gate audit (required)

```bash
codex review --base master \
  "Audit this branch against docs/planning/IDENTITY_LAYER_REMOVAL_EXECUTION_PLAN.md.
  Output PASS/FAIL for SC1-SC5 with exact file/test evidence.
  Fail if any required verification command output is missing.
  End with READY_TO_MERGE or NOT_READY." > codex_final_audit.md
```

If any FAIL:

1. fix,
2. rerun audit,
3. repeat until all PASS and `READY_TO_MERGE`.

## Required evidence artifact

Create:

- `docs/planning/IDENTITY_LAYER_REMOVAL_EVIDENCE.md`

It must map each SC1-SC5 item to concrete file and test/command proof.

## Merge checklist

All required:

1. SC1-SC5 all PASS.
2. `feedback.md` has no unresolved High/Medium findings.
3. `codex_final_audit.md` ends with `READY_TO_MERGE`.
4. Evidence file exists and includes proof for every SC item.
