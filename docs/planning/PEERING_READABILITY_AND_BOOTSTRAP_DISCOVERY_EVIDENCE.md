# Peering Readability + Bootstrap-as-Discovery Evidence

Date: 2026-02-21
Branch: `exec/peering-readability-plan-instructions`

## SC1. Production bootstrap is discovery/autodial-owned

**PASS**

1. Production runtime path has no special bootstrap workflow dependency.
   - `run_node()` in `src/peering/runtime/mod.rs` uses `collect_all_bootstrap_targets()` and
     `spawn_bootstrap_refresher()` from `target_planner`, not any workflow/bootstrap module.
   - `rg -n "peering::workflows::bootstrap|workflows/bootstrap" src` returns only a comment
     in `testutil/bootstrap.rs` documenting the move.

2. Bootstrap targets are consumed by ongoing autodial planning/dispatch.
   - `target_planner::spawn_bootstrap_refresher()` polls SQL every 1s for new
     `invite_bootstrap_trust` rows and spawns connect loops via `PeerDispatcher`.
   - `target_planner::collect_all_bootstrap_targets()` reads from projected SQL state.

## SC2. Bootstrap test helpers are not production-owned

**PASS**

1. No production entrypoint depends on test bootstrap helper module.
   - Bootstrap helpers moved from `src/peering/workflows/bootstrap.rs` to
     `src/testutil/bootstrap.rs`.
   - `peering/workflows/mod.rs` no longer declares `pub mod bootstrap`.
   - Boundary check enforces: `check_no_match 'testutil::bootstrap' src/peering/`,
     `check_no_match 'testutil::bootstrap' src/service.rs`,
     `check_no_match 'testutil::bootstrap' src/event_pipeline.rs`.

2. Helper module is test-only in ownership and usage.
   - Only callers: `testutil/mod.rs` lines 112 and 270.
   - Module doc: "Bootstrap sync helpers -- test-only."

## SC3. Target planning is single-owner and explicit

**PASS**

1. One module is the source of truth for dial target planning.
   - `src/peering/runtime/target_planner.rs` owns all target planning:
     `PeerDispatcher`, `dispatch_bootstrap_target`, `collect_all_bootstrap_targets`,
     `load_bootstrap_targets`, `build_tenant_client_config`, `spawn_bootstrap_refresher`,
     `spawn_connect_loop_thread`, `normalize_discovered_addr_for_local_bind`.
   - Boundary check enforces: `check_required 'mod target_planner' src/peering/runtime/mod.rs`.

2. mDNS and bootstrap trust targets are routed through the same dispatch mechanism.
   - Both use `PeerDispatcher` for dedup/reconnect: mDNS discovery dispatches via
     `dispatcher.dispatch(peer_id, addr)`, bootstrap dispatches via
     `dispatch_bootstrap_target(&mut dispatcher, tenant_id, remote)` which internally
     uses the same `PeerDispatcher::dispatch` with composite key `"{tenant_id}@bootstrap"`.
   - `discovery.rs` imports `PeerDispatcher`, `DiscoveryAction` from `target_planner`.
   - `run_node()` imports `PeerDispatcher`, `dispatch_bootstrap_target` from `target_planner`.

## SC4. Peering-transport boundary is cleaner

**PASS**

1. Transport-concrete wiring used by peering is centralized.
   - `peering::loops::run_session()` in `src/peering/loops/mod.rs` centralizes:
     DualConnection construction, SessionMeta creation, QuicTransportSessionIo wiring,
     peer removal cancellation watch, and session handler invocation.

2. `accept`/`connect` loops are thinner and less duplicated.
   - `connect.rs` inner loop calls `run_session()` instead of 20+ lines of setup.
   - `accept.rs` inner loop calls `run_session()` instead of 20+ lines of setup.
   - Both removed direct imports of `DualConnection`, `QuicTransportSessionIo`,
     `CancellationToken`, `next_session_id`, `SessionMeta`, `PeerFingerprint`.

## SC5. Docs reflect the real runtime model

**PASS**

1. `docs/DESIGN.md` section 3.2.3 "Peering runtime loop model" describes the exact
   6-step loop: projected SQL state -> target planner -> dial/accept supervisors ->
   sync session runner -> ingest writer -> projected SQL state.
   Module ownership and eventization boundary are documented.

2. `docs/PLAN.md` section 17.4 "Node Daemon" updated with:
   - 17.4.1 Runtime loop model (6-step loop with canonical file refs)
   - 17.4.2 `run_node` startup sequence
   - 17.4.3 `PeerDispatcher` and unified target planning (both sources dispatch through same mechanism)

3. Newcomer can identify one file for target planning (`target_planner.rs`) and one
   for loop supervision (`loops/mod.rs` + `accept.rs`/`connect.rs`).

## SC6. Tests and checks pass

**PASS**

### Verification command outputs

```
$ rg -n "peering::workflows::bootstrap|workflows/bootstrap" src
src/testutil/bootstrap.rs:9://! Moved from `peering::workflows::bootstrap` ...
(comment only -- no production usage)

$ rg -n "target_planner|PeerDispatcher|dispatch_bootstrap_target|collect_all_bootstrap_targets" src/peering
(all references in target_planner.rs, discovery.rs, mod.rs -- single-owner)

$ bash scripts/check_boundary_imports.sh
=== Forbidden edges ===
=== Positive contract checks ===
All boundary checks passed.

$ cargo check
Finished `dev` profile [unoptimized + debuginfo] target(s)

$ cargo test --lib -q
test result: ok. 409 passed; 0 failed; 0 ignored

$ cargo test --test scenario_test -q
test result: ok. 65 passed; 0 failed; 0 ignored

$ cargo test --test holepunch_test -q
test result: ok. 4 passed; 0 failed; 0 ignored

$ cargo test --test projectors -q
test result: ok. 52 passed; 0 failed; 0 ignored
```

Total: 530 tests passing, all boundary checks passing.

## Codex feedback resolution

All 3 Medium findings from mid-implementation codex review resolved:

1. **R3/SC3 dispatch unification**: bootstrap targets now dispatch through `PeerDispatcher`
   via `dispatch_bootstrap_target()`, same mechanism as mDNS discovery.
2. **Boundary script path fix**: `src/event_pipeline/` corrected to `src/event_pipeline.rs`.
3. **docs/PLAN.md update**: section 17.4 rewritten with runtime loop model and ownership.
