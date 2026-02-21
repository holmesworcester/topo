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
     `invite_bootstrap_trust` rows and spawns connect loops.
   - `target_planner::collect_all_bootstrap_targets()` reads from projected SQL state.

## SC2. Bootstrap test helpers are not production-owned

**PASS**

1. No production entrypoint depends on test bootstrap helper module.
   - Bootstrap helpers moved from `src/peering/workflows/bootstrap.rs` to
     `src/testutil/bootstrap.rs`.
   - `peering/workflows/mod.rs` no longer declares `pub mod bootstrap`.
   - Boundary check enforces: `check_no_match 'testutil::bootstrap' src/peering/`.

2. Helper module is test-only in ownership and usage.
   - Only callers: `testutil/mod.rs` lines 112 and 270.
   - Module doc: "Bootstrap sync helpers -- test-only."

## SC3. Target planning is single-owner and explicit

**PASS**

1. One module is the source of truth for dial target planning.
   - `src/peering/runtime/target_planner.rs` owns all target planning:
     `PeerDispatcher`, `collect_all_bootstrap_targets`, `load_bootstrap_targets`,
     `build_tenant_client_config`, `spawn_bootstrap_refresher`, `spawn_connect_loop_thread`.
   - Boundary check enforces: `check_required 'mod target_planner' src/peering/runtime/mod.rs`.

2. mDNS and bootstrap trust targets are routed through that single planner path.
   - `discovery.rs` imports from `target_planner`: `PeerDispatcher`, `DiscoveryAction`,
     `normalize_discovered_addr_for_local_bind`.
   - `run_node()` imports from `target_planner`: `build_tenant_client_config`,
     `collect_all_bootstrap_targets`, `spawn_bootstrap_refresher`, `spawn_connect_loop_thread`.

## SC4. Peering-transport boundary is cleaner

**PASS**

1. Transport-concrete wiring used by peering is centralized.
   - `peering::loops::run_session()` in `src/peering/loops/mod.rs` centralizes:
     DualConnection construction, SessionMeta creation, QuicTransportSessionIo wiring,
     peer removal cancellation watch, and session handler invocation.

2. `accept`/`connect` loops are thinner and less duplicated.
   - `connect.rs` inner loop calls `run_session()` (line 237) instead of 20+ lines of setup.
   - `accept.rs` inner loop calls `run_session()` (line 256) instead of 20+ lines of setup.
   - Both removed direct imports of `DualConnection`, `QuicTransportSessionIo`,
     `CancellationToken`, `next_session_id`, `SessionMeta`, `PeerFingerprint`.

## SC5. Docs reflect the real runtime model

**PASS**

1. `docs/DESIGN.md` section 3.2.3 "Peering runtime loop model" describes the exact
   6-step loop: projected SQL state -> target planner -> dial/accept supervisors ->
   sync session runner -> ingest writer -> projected SQL state.
   Module ownership and eventization boundary are documented.

2. Newcomer can identify one file for target planning (`target_planner.rs`) and one
   for loop supervision (`loops/mod.rs` + `accept.rs`/`connect.rs`).

## SC6. Tests and checks pass

**PASS**

### Verification command outputs

```
$ rg -n "peering::workflows::bootstrap|workflows/bootstrap" src
src/testutil/bootstrap.rs:9://! Moved from `peering::workflows::bootstrap` ...
(comment only -- no production usage)

$ rg -n "target.planner|PeerDispatcher|collect_all_bootstrap_targets" src/peering
(all references in target_planner.rs, discovery.rs, mod.rs -- single-owner)

$ bash scripts/check_boundary_imports.sh
=== Forbidden edges ===
=== Positive contract checks ===
All boundary checks passed.

$ cargo check
Finished `dev` profile [unoptimized + debuginfo] target(s)

$ cargo test --lib -q
test result: ok. 405 passed; 0 failed; 0 ignored

$ cargo test --test scenario_test -q
test result: ok. 65 passed; 0 failed; 0 ignored

$ cargo test --test holepunch_test -q
test result: ok. 4 passed; 0 failed; 0 ignored

$ cargo test --test projectors -q
test result: ok. 52 passed; 0 failed; 0 ignored
```

Total: 526 tests passing, all boundary checks passing.
