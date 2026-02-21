# Identity Eventization Completion Final Audit

Date: 2026-02-20
Branch: `exec/identity-eventization-completion-instructions`
Instructions: `docs/planning/IDENTITY_EVENTIZATION_COMPLETION_INSTRUCTIONS.md`

## Required verification commands

1. `rg -n 'pub fn (bootstrap_workspace|create_user_invite|accept_user_invite|create_device_link_invite|accept_device_link|retry_pending_invite_content_key_unwraps)' src/identity/ops.rs`
- Result: **no matches** (exit code `1`, empty output).

2. `rg -n 'svc_bootstrap_workspace_conn|identity::ops::(bootstrap_workspace|accept_user_invite|accept_device_link|create_user_invite|create_device_link_invite|retry_pending_invite_content_key_unwraps)' src/service.rs src/event_pipeline.rs src/event_modules tests`
- Result: **no matches** (exit code `1`, empty output).

3. `bash scripts/check_boundary_imports.sh`
- Result: **pass** (exit code `0`).
- Output:
  - `=== Forbidden edges ===`
  - `=== Positive contract checks ===`
  - `All boundary checks passed.`

4. `cargo check`
- Result: **pass** (exit code `0`).
- Output: `Finished dev profile ...`

5. `cargo test --lib -q`
- Result: **pass** (exit code `0`).
- Output: `test result: ok. 457 passed; 0 failed; ...`

6. `cargo test --test scenario_test -q`
- Result: **pass** (exit code `0`).
- Output: `test result: ok. 65 passed; 0 failed; ...`

## SC1
PASS

Evidence:
- Required SC1 symbol scan returned no matches:
  - `src/identity/ops.rs` (command #1 above).
- Boundary enforcement includes explicit SC1 bans and passed:
  - `scripts/check_boundary_imports.sh:72`
  - `scripts/check_boundary_imports.sh:74`
  - `scripts/check_boundary_imports.sh:76`
  - `scripts/check_boundary_imports.sh:77`

## SC2
PASS

Evidence:
- No `svc_bootstrap_workspace_conn` / forbidden `identity::ops::*` workflow usages in service (command #2 returned no matches).
- Service routes through event-module commands instead:
  - `src/service.rs:555` (`workspace::commands::create_workspace`)
  - `src/service.rs:952` (`workspace::commands::create_user_invite`)
  - `src/service.rs:980` (`workspace::commands::create_device_link_invite`)
  - `src/service.rs:1352` (`workspace::commands::join_workspace_as_new_user`)
  - `src/service.rs:1450` (`workspace::commands::add_device_to_workspace`)
- Boundary script checks and passes this boundary:
  - `scripts/check_boundary_imports.sh:89`
  - `scripts/check_boundary_imports.sh:92`
  - `scripts/check_boundary_imports.sh:93`
  - `scripts/check_boundary_imports.sh:94`
  - `scripts/check_boundary_imports.sh:95`

## SC3
PASS

Evidence:
- No forbidden identity workflow callouts in pipeline scan (command #2 returned no matches).
- Pipeline uses generic post-drain hook dispatch:
  - `src/event_pipeline.rs:312` (`crate::event_modules::post_drain_hooks(&db, &effective_rb)`)
- Boundary script explicitly forbids direct workflow calls and requires generic hook usage:
  - `scripts/check_boundary_imports.sh:98`
  - `scripts/check_boundary_imports.sh:99`
  - `scripts/check_boundary_imports.sh:100`
  - `scripts/check_boundary_imports.sh:101`
  - `scripts/check_boundary_imports.sh:102`
  - `scripts/check_boundary_imports.sh:103`
  - `scripts/check_boundary_imports.sh:104`
  - `scripts/check_boundary_imports.sh:105`
  - `scripts/check_boundary_imports.sh:136`

## SC4
PASS

Evidence (command ownership is explicit):
- Canonical workflow APIs exist in event-module commands:
  - `src/event_modules/workspace/commands.rs:81` (`create_workspace`)
  - `src/event_modules/workspace/commands.rs:205` (`join_workspace_as_new_user`)
  - `src/event_modules/workspace/commands.rs:342` (`add_device_to_workspace`)
  - `src/event_modules/workspace/commands.rs:418` (`create_user_invite`)
  - `src/event_modules/workspace/commands.rs:478` (`create_device_link_invite`)
  - `src/event_modules/workspace/commands.rs:530` (`retry_pending_invite_content_key_unwraps`)

Evidence (tests exercising workflow paths + replay safety):
- Scenario coverage includes bootstrap/invite/device-link and shared-DB join paths:
  - `tests/scenario_test.rs:1809` (`test_bootstrap_sequence`)
  - `tests/scenario_test.rs:2990` (`test_two_peer_identity_join_and_sync`)
  - `tests/scenario_test.rs:3162` (`test_device_link_via_sync`)
  - `tests/scenario_test.rs:3488` (`test_shared_db_same_workspace_two_tenants`)
  - `tests/scenario_test.rs:3550` (`test_mdns_two_peers_discover_and_sync`)
- Scenario utilities route join/invite flows via workspace commands/service paths:
  - `src/testutil.rs:191` (`new_in_workspace`)
  - `src/testutil.rs:226` (`create_user_invite_raw(...)`)
  - `src/testutil.rs:260` (`svc_accept_invite(...)`)
  - `src/testutil.rs:2350` (`add_tenant_in_workspace`)
  - `src/testutil.rs:2396` (`join_workspace_as_new_user(...)`)
- Replay-safe invariant enforcement:
  - `src/testutil.rs:1370` (`verify_projection_invariants` forward/idempotent/reverse/shuffle replay checks)
  - `src/testutil.rs:2507` (`ScenarioHarness` panic if `.finish()` omitted)
- Quality gates passed:
  - `cargo test --lib -q`: `457 passed`
  - `cargo test --test scenario_test -q`: `65 passed`

## SC5
PASS

Evidence:
- Boundary checks are machine-enforced in script and passed:
  - Forbidden identity workflow/public-entrypoint checks: `scripts/check_boundary_imports.sh:72`-`scripts/check_boundary_imports.sh:105`
  - Positive ownership/routing checks: `scripts/check_boundary_imports.sh:123`-`scripts/check_boundary_imports.sh:136`
- Required command passed:
  - `bash scripts/check_boundary_imports.sh` -> `All boundary checks passed.`

READY_TO_MERGE
