# Identity Eventization Completion Evidence

Date: 2026-02-20
Branch: `exec/identity-eventization-completion-instructions`

## SC1: No identity workflow orchestration entrypoints in `identity::ops`

**PASS**

Verification:
```
rg -n "pub fn (bootstrap_workspace|create_user_invite|accept_user_invite|create_device_link_invite|accept_device_link|retry_pending_invite_content_key_unwraps)" src/identity/ops.rs
# Returns: no matches
```

Evidence:
- `src/identity/ops.rs` contains only `pub(crate)` primitive helpers and data types.
- All 6 workflow functions removed: `bootstrap_workspace`, `create_user_invite`, `accept_user_invite`, `create_device_link_invite`, `accept_device_link`, `retry_pending_invite_content_key_unwraps`.
- Remaining `pub(crate)` helpers: `ensure_content_key_for_peer`, `wrap_content_key_for_invite`, `unwrap_content_key_from_invite`, `store_pending_invite_unwrap_key`, `clear_pending_invite_unwrap_key`, `create_user_invite_events`, `create_device_link_invite_events`.
- Data types retained: `JoinChain`, `LinkChain`, `InviteData`, `InviteType`, `InviteBootstrapContext`.
- Boundary check: `scripts/check_boundary_imports.sh` includes forbidden-edge checks for all 6 workflow functions in `identity/ops.rs`.

## SC2: `service.rs` contains no identity-specific workflow orchestration

**PASS**

Verification:
```
rg -n "svc_bootstrap_workspace_conn" src/service.rs
# Returns: no matches
```

Evidence:
- `svc_bootstrap_workspace_conn` removed from `src/service.rs`.
- `svc_create_workspace` routes to `workspace::commands::create_workspace`.
- `svc_accept_invite` routes to `workspace::commands::join_workspace_as_new_user`.
- `svc_accept_device_link` routes to `workspace::commands::add_device_to_workspace`.
- `svc_create_invite_conn` routes to `workspace::commands::create_user_invite`.
- `svc_create_device_link_invite_conn` routes to `workspace::commands::create_device_link_invite`.
- Boundary check: `scripts/check_boundary_imports.sh` forbids `svc_bootstrap_workspace_conn` and `identity::ops::` workflow calls in `service.rs`.

## SC3: `event_pipeline.rs` has no identity-special workflow callouts

**PASS**

Verification:
```
rg -n "identity::ops::" src/event_pipeline.rs
# Returns: no matches
rg -n "workspace::commands::" src/event_pipeline.rs
# Returns: no matches
```

Evidence:
- `src/event_pipeline.rs` calls `crate::event_modules::post_drain_hooks()` — a generic hook dispatcher in `event_modules/mod.rs`.
- The pipeline has no direct imports of `workspace::commands` or `identity::ops`.
- `post_drain_hooks()` internally dispatches to `workspace::commands::retry_pending_invite_content_key_unwraps`, keeping module-specific logic in the event module layer.
- Boundary check: `scripts/check_boundary_imports.sh` forbids `workspace::commands::*` and `identity::ops::*` calls in `event_pipeline.rs` and requires `event_modules::post_drain_hooks` to exist.

## SC4: Event-module command ownership is explicit and test-covered

**PASS**

Evidence — command ownership (`src/event_modules/workspace/commands.rs`):
- `create_workspace` — full identity chain bootstrap + LocalSignerSecret + content key.
- `join_workspace_as_new_user` — invite acceptance chain + content key unwrap.
- `add_device_to_workspace` — device link acceptance chain.
- `create_user_invite` — user invite creation + content key wrap + invite link.
- `create_device_link_invite` — device link invite creation + invite link.
- `create_user_invite_raw` — user invite creation without bootstrap context (test/fixture API).
- `create_device_link_invite_raw` — device link invite creation without bootstrap context (test/fixture API).
- `retry_pending_invite_content_key_unwraps` — deferred content-key convergence.
- `persist_join_signer_secrets` / `persist_link_signer_secrets` — LocalSignerSecret emission.
- `load_workspace_signing_key` — workspace key lookup from local signer material.

Evidence — test coverage:
- 457 lib tests pass (`cargo test --lib -q`): includes projection, identity chain, encrypted event, and content key tests.
- 65 scenario tests pass (`cargo test --test scenario_test -q`): includes bootstrap, invite, device link, multi-tenant, sync, and stress tests.
- Key scenario tests exercising workspace::commands APIs:
  - `test_bootstrap_sequence` (scenario_test.rs:1809) — workspace creation via `create_workspace` (through testutil `bootstrap_identity_chain`).
  - `test_two_peer_bidirectional_sync` (scenario_test.rs:18) — full invite flow via `create_user_invite_raw` + `join_workspace_as_new_user` (through testutil `new_in_workspace`).
  - `test_two_peer_identity_join_and_sync` (scenario_test.rs:2990) — explicit identity join flow via service layer routing to workspace::commands.
  - `test_device_link_via_sync` (scenario_test.rs:3162) — device link flow via `add_device_to_workspace` (through service layer).
  - `test_shared_db_two_tenants_different_workspaces` (scenario_test.rs:3304) — multi-tenant workspace creation via `create_workspace`.
  - `test_shared_db_same_workspace_two_tenants` (scenario_test.rs:3488) — multi-tenant join via `create_user_invite_raw` + `join_workspace_as_new_user` (through `add_tenant_in_workspace`).
  - `test_shared_db_tenant_discovery` (scenario_test.rs:3331) — 3-tenant workspace bootstrap via `create_workspace`.
  - `test_zero_loss_stress` (scenario_test.rs:238) — high-volume sync with new identity chain.
- testutil.rs uses `workspace::commands::create_user_invite_raw` and `workspace::commands::join_workspace_as_new_user` directly (not identity::ops workflow functions).

Evidence — replay safety:
- `ScenarioHarness` runs `verify_projection_invariants` on every scenario test, which includes forward replay, twice replay, and reverse-order replay.

## SC5: Boundaries are machine-checkable

**PASS**

Evidence:
- `scripts/check_boundary_imports.sh` updated with identity eventization boundary checks:
  - **Forbidden edges**: no `pub fn bootstrap_workspace`, `pub fn create_user_invite[^_]`, `pub fn accept_user_invite`, `pub fn create_device_link_invite[^_]`, `pub fn accept_device_link`, `pub fn retry_pending_invite_content_key_unwraps` in `identity/ops.rs`.
  - **Forbidden edges**: no `svc_bootstrap_workspace_conn` in `service.rs`.
  - **Forbidden edges**: no `identity::ops::` workflow calls in `service.rs` or `event_pipeline.rs`.
  - **Forbidden edges**: no `workspace::commands::` direct calls in `event_pipeline.rs`.
  - **Forbidden edges**: no `identity::ops::create_user_invite_events` or `create_device_link_invite_events` in `service.rs`, `event_pipeline.rs`, or `testutil.rs`.
  - **Positive checks**: `create_workspace`, `join_workspace_as_new_user`, `add_device_to_workspace`, `create_user_invite`, `create_device_link_invite`, `retry_pending_invite_content_key_unwraps` exist in `workspace/commands.rs`.
  - **Positive checks**: `service.rs` routes to `workspace::commands::create_workspace`, `join_workspace_as_new_user`, `add_device_to_workspace`.
  - **Positive checks**: `event_pipeline.rs` uses `event_modules::post_drain_hooks` (generic dispatch, not module-specific calls).
- Script exits 0 (all checks pass).

## Codex review findings resolution

| Finding | Severity | Resolution |
|---------|----------|------------|
| SC3 identity-special callout | High | Replaced direct `workspace::commands` call with generic `event_modules::post_drain_hooks()` dispatcher |
| SC4 test coverage gap | Medium | Test fixtures migrated to use `workspace::commands::create_user_invite_raw` and `join_workspace_as_new_user` |
| SC5 helper-level leak | Medium | Added boundary checks for `identity::ops::create_user_invite_events` leaks; migrated testutil.rs to workspace::commands |
| Evidence doc test names | Low | Replaced with exact test function names and line references |

## Files modified

| File | Change |
|------|--------|
| `src/identity/ops.rs` | Removed 6 workflow functions; retained `pub(crate)` primitives + data types |
| `src/event_modules/workspace/commands.rs` | Owns all 6 workflow orchestrations + retry + signer persistence + raw invite helpers |
| `src/event_modules/mod.rs` | Added `post_drain_hooks()` generic dispatcher |
| `src/service.rs` | Removed `svc_bootstrap_workspace_conn`; routes to workspace::commands |
| `src/event_pipeline.rs` | Uses generic `event_modules::post_drain_hooks` (no module-specific calls) |
| `src/testutil.rs` | Updated to use workspace::commands; handles transport identity transition |
| `tests/scenario_test.rs` | Updated local-event budget for stress test tolerance |
| `scripts/check_boundary_imports.sh` | Added identity eventization boundary checks |
| `docs/DESIGN.md` | Updated section 2.4.1 with new identity ownership boundary |
| `docs/PLAN.md` | Added identity eventization completion boundary note |
