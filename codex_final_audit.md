**Required Verification Command Outputs**

1. `rg -n "peering::workflows::bootstrap|workflows/bootstrap" src`
```text
src/testutil/bootstrap.rs:9://! Moved from `peering::workflows::bootstrap` to enforce test-only ownership
```

2. `rg -n "target planner|autodial|PeerDispatcher|launch_mdns_discovery|collect_placeholder_invite_autodial_targets" src/peering`
```text
src/peering/runtime/target_planner.rs:3://! Both bootstrap trust autodial and mDNS discovery route their targets through
src/peering/runtime/target_planner.rs:9://!   connect_loop cancellation on address changes (`PeerDispatcher`).
src/peering/runtime/target_planner.rs:33:// Discovery dispatch (PeerDispatcher)
src/peering/runtime/target_planner.rs:48:pub(crate) struct PeerDispatcher {
src/peering/runtime/target_planner.rs:52:impl PeerDispatcher {
src/peering/runtime/target_planner.rs:95:// Connect loop spawning (shared by bootstrap autodial and mDNS discovery)
src/peering/runtime/target_planner.rs:141:/// Load invite-seeded autodial targets for a set of known tenant IDs.
src/peering/runtime/target_planner.rs:174:/// Collect all bootstrap autodial targets across all local tenants.
src/peering/runtime/target_planner.rs:214:// Bootstrap autodial refresher
src/peering/runtime/target_planner.rs:217:/// Dispatch a bootstrap dial target through `PeerDispatcher`.
src/peering/runtime/target_planner.rs:223:    dispatcher: &mut PeerDispatcher,
src/peering/runtime/target_planner.rs:232:/// Spawns a background thread that polls for new bootstrap autodial targets
src/peering/runtime/target_planner.rs:235:/// after an invite is accepted (projection materializes trust rows -> autodial
src/peering/runtime/target_planner.rs:238:/// Uses `PeerDispatcher` for dedup/reconnect, the same dispatch mechanism
src/peering/runtime/target_planner.rs:243:    mut dispatcher: PeerDispatcher,
src/peering/runtime/target_planner.rs:258:                                "Skipping bootstrap autodial refresh for {}: {}",
src/peering/runtime/target_planner.rs:276:                        "bootstrap-autodial-refresh",
src/peering/runtime/target_planner.rs:304:    // -- PeerDispatcher tests --
src/peering/runtime/target_planner.rs:308:        let mut d = PeerDispatcher::new();
src/peering/runtime/target_planner.rs:316:        let mut d = PeerDispatcher::new();
src/peering/runtime/target_planner.rs:326:        let mut d = PeerDispatcher::new();
src/peering/runtime/target_planner.rs:336:        let mut d = PeerDispatcher::new();
src/peering/runtime/target_planner.rs:355:        let mut d = PeerDispatcher::new();
src/peering/runtime/target_planner.rs:383:        let mut d = PeerDispatcher::new();
src/peering/runtime/target_planner.rs:487:            "superseded bootstrap trust must not appear in autodial"
src/peering/runtime/target_planner.rs:494:        let db_path = tmp.path().join("autodial-hostname.db");
src/peering/runtime/target_planner.rs:628:        let mut d = PeerDispatcher::new();
src/peering/runtime/mod.rs:28:    PeerDispatcher,
src/peering/runtime/mod.rs:91:            discovery::launch_mdns_discovery(
src/peering/runtime/mod.rs:135:    // Bootstrap invite-based autodial: polls SQL trust state for bootstrap
src/peering/runtime/mod.rs:137:    let disable_placeholder_autodial = std::env::var("P7_DISABLE_PLACEHOLDER_AUTODIAL")
src/peering/runtime/mod.rs:144:    if disable_placeholder_autodial {
src/peering/runtime/mod.rs:147:        let autodial_targets = collect_all_bootstrap_targets(db_path)?;
src/peering/runtime/mod.rs:148:        let mut dispatcher = PeerDispatcher::new();
src/peering/runtime/mod.rs:149:        if !autodial_targets.is_empty() {
src/peering/runtime/mod.rs:152:                autodial_targets.len()
src/peering/runtime/mod.rs:155:        for (tenant_id, remote) in autodial_targets {
src/peering/runtime/mod.rs:163:                        "Skipping bootstrap autodial for {}: {}",
src/peering/runtime/mod.rs:181:                "bootstrap-autodial",
src/peering/runtime/mod.rs:186:        // Keep polling for runtime invite acceptance (shares PeerDispatcher dedup state)
src/peering/runtime/discovery.rs:4://! that auto-connect to discovered remote peers using `PeerDispatcher`.
src/peering/runtime/discovery.rs:21:    normalize_discovered_addr_for_local_bind, DiscoveryAction, PeerDispatcher,
src/peering/runtime/discovery.rs:29:pub(crate) fn launch_mdns_discovery(
src/peering/runtime/discovery.rs:78:                            let mut dispatcher = PeerDispatcher::new();
```

3. `bash scripts/check_boundary_imports.sh`
```text
=== Forbidden edges ===
=== Positive contract checks ===
All boundary checks passed.
```

4. `cargo check`
```text
Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.07s
```

5. `cargo test --lib -q`
```text
warning: unused imports: `CertificateDer` and `PrivatePkcs8KeyDer`
   --> src/transport/multi_workspace.rs:111:33
    |
111 |         use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    |                                 ^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^
    |
    = note: `#[warn(unused_imports)]` (part of `#[warn(unused)]`) on by default

warning: unused variable: `recorded_by`
   --> src/projection/apply/tests/mod.rs:212:5
    |
212 |     recorded_by: &str,
    |     ^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_recorded_by`
    |
    = note: `#[warn(unused_variables)]` (part of `#[warn(unused)]`) on by default

warning: unused variable: `net_eid`
   --> src/projection/apply/tests/mod.rs:516:9
    |
516 |     let net_eid = setup_workspace_event(&conn, recorded_by);
    |         ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_net_eid`

warning: unused variable: `net_eid`
   --> src/projection/apply/tests/mod.rs:589:9
    |
589 |     let net_eid = setup_workspace_event(&conn, recorded_by);
    |         ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_net_eid`

warning: unused variable: `net_eid`
   --> src/projection/apply/tests/mod.rs:729:9
    |
729 |     let net_eid = setup_workspace_event(&conn, recorded_by);
    |         ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_net_eid`

warning: unused variable: `net_eid`
   --> src/projection/apply/tests/mod.rs:944:9
    |
944 |     let net_eid = setup_workspace_event(&conn, recorded_by);
    |         ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_net_eid`

warning: unused variable: `net_eid_a`
   --> src/projection/apply/tests/mod.rs:966:9
    |
966 |     let net_eid_a = setup_workspace_event(&conn, tenant_a);
    |         ^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_net_eid_a`

warning: unused variable: `net_eid_a`
    --> src/projection/apply/tests/mod.rs:1190:9
     |
1190 |     let net_eid_a = setup_workspace_event(&conn, tenant_a);
     |         ^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_net_eid_a`

warning: unused variable: `net_eid_b`
    --> src/projection/apply/tests/mod.rs:1191:9
     |
1191 |     let net_eid_b = setup_workspace_event(&conn, tenant_b);
     |         ^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_net_eid_b`

warning: unused variable: `net_eid`
    --> src/projection/apply/tests/mod.rs:1329:9
     |
1329 |     let net_eid = setup_workspace_event(&conn, recorded_by);
     |         ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_net_eid`

warning: unused variable: `net_eid`
    --> src/projection/apply/tests/mod.rs:1395:9
     |
1395 |     let net_eid = setup_workspace_event(&conn, recorded_by);
     |         ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_net_eid`

warning: unused variable: `net_eid`
    --> src/projection/apply/tests/mod.rs:1610:9
     |
1610 |     let net_eid = setup_workspace_event(&conn, recorded_by);
     |         ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_net_eid`

warning: unused variable: `net_eid_a`
    --> src/projection/apply/tests/mod.rs:1696:9
     |
1696 |     let net_eid_a = setup_workspace_event(&conn, tenant_a);
     |         ^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_net_eid_a`

warning: unused variable: `net_eid`
    --> src/projection/apply/tests/mod.rs:2270:9
     |
2270 |     let net_eid = setup_workspace_event(&conn, recorded_by);
     |         ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_net_eid`

warning: unused variable: `net_eid`
    --> src/projection/apply/tests/mod.rs:2324:9
     |
2324 |     let net_eid = setup_workspace_event(&conn, recorded_by);
     |         ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_net_eid`

warning: unused variable: `net_eid`
    --> src/projection/apply/tests/mod.rs:2420:9
     |
2420 |     let net_eid = setup_workspace_event(&conn, recorded_by);
     |         ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_net_eid`

warning: unused variable: `net_eid`
    --> src/projection/apply/tests/mod.rs:2480:9
     |
2480 |     let net_eid = setup_workspace_event(&conn, recorded_by);
     |         ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_net_eid`

warning: unused variable: `net_eid`
    --> src/projection/apply/tests/mod.rs:2511:9
     |
2511 |     let net_eid = setup_workspace_event(&conn, recorded_by);
     |         ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_net_eid`

warning: unused variable: `net_eid`
    --> src/projection/apply/tests/mod.rs:2557:9
     |
2557 |     let net_eid = setup_workspace_event(&conn, recorded_by);
     |         ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_net_eid`

warning: unused variable: `net_eid`
    --> src/projection/apply/tests/mod.rs:2905:9
     |
2905 |     let net_eid = setup_workspace_event(&conn, recorded_by);
     |         ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_net_eid`

warning: unused variable: `net_eid`
    --> src/projection/apply/tests/mod.rs:3287:9
     |
3287 |     let net_eid = setup_workspace_event(&conn, recorded_by);
     |         ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_net_eid`

warning: unused variable: `net_eid`
    --> src/projection/apply/tests/mod.rs:3396:9
     |
3396 |     let net_eid = setup_workspace_event(&conn, recorded_by);
     |         ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_net_eid`

warning: unused variable: `ws_eid`
    --> src/projection/apply/tests/mod.rs:5429:9
     |
5429 |     let ws_eid = insert_event_raw(&conn, recorded_by, &ws_blob);
     |         ^^^^^^ help: if this is intentional, prefix it with an underscore: `_ws_eid`

warning: function `count_rejected` is never used
    --> src/projection/apply/tests/mod.rs:4055:4
     |
4055 | fn count_rejected(conn: &Connection, recorded_by: &str) -> i64 {
     |    ^^^^^^^^^^^^^^
     |
     = note: `#[warn(dead_code)]` (part of `#[warn(unused)]`) on by default

warning: function `sign_blob` is never used
   --> src/projection/create.rs:371:8
    |
371 |     fn sign_blob(key: &SigningKey, blob: &mut Vec<u8>) {
    |        ^^^^^^^^^

running 409 tests
....................................................................................... 87/409
....................................................................................... 174/409
....................................................................................... 261/409
....................................................................................... 348/409
.............................................................
test result: ok. 409 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 4.18s
```

6. `cargo test --test scenario_test -q`
```text
running 65 tests
.................................................................
test result: ok. 65 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 28.18s
```

7. `cargo test --test holepunch_test -q`
```text
running 4 tests
....
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.97s
```

8. `cargo test --test projectors -q`
```text
warning: function `assert_reject` is never used
  --> tests/projectors/harness.rs:95:12
   |
95 |     pub fn assert_reject(result: &ProjectorResult) {
   |            ^^^^^^^^^^^^^
   |
   = note: `#[warn(dead_code)]` (part of `#[warn(unused)]`) on by default

warning: function `assert_deletes_from_table` is never used
   --> tests/projectors/harness.rs:138:12
    |
138 |     pub fn assert_deletes_from_table(result: &ProjectorResult, table: &str) {
    |            ^^^^^^^^^^^^^^^^^^^^^^^^^

running 52 tests
....................................................
test result: ok. 52 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

**SC1-SC6 Audit**

- SC1: **PASS**
  - Production bootstrap path is runtime/autodial owned in `src/peering/runtime/mod.rs:135`, `src/peering/runtime/mod.rs:147`, `src/peering/runtime/mod.rs:187`.
  - Ongoing discovery from projected state is in `src/peering/runtime/target_planner.rs:174` and `src/peering/runtime/target_planner.rs:232`.
  - Required grep found no production `workflows/bootstrap` ownership, only a testutil comment.

- SC2: **PASS**
  - Test helper lives in `src/testutil/bootstrap.rs:1` and is documented test-only.
  - `src/peering/workflows/mod.rs:1` contains only `intro`/`punch`, no bootstrap module.
  - Boundary checks enforce no production use of test bootstrap helpers at `scripts/check_boundary_imports.sh:109`, `scripts/check_boundary_imports.sh:110`, `scripts/check_boundary_imports.sh:111`, `scripts/check_boundary_imports.sh:113`.
  - In-tree callers are testutil-owned (`src/testutil/mod.rs:117`, `src/testutil/mod.rs:270`).

- SC3: **PASS**
  - Single-owner planner module is explicit in `src/peering/runtime/target_planner.rs:1`.
  - Bootstrap targets dispatch through `PeerDispatcher` via `dispatch_bootstrap_target` in `src/peering/runtime/target_planner.rs:222`.
  - Runtime bootstrap path uses that dispatcher flow in `src/peering/runtime/mod.rs:156`.
  - mDNS path also uses `PeerDispatcher` from planner in `src/peering/runtime/discovery.rs:21` and `src/peering/runtime/discovery.rs:85`.
  - Combined bootstrap+discovery dispatch behavior is covered by test `src/peering/runtime/target_planner.rs:627`.

- SC4: **PASS**
  - Centralized transport seam is `run_session` in `src/peering/loops/mod.rs:130`.
  - Concrete QUIC/session wiring is centralized there (`src/peering/loops/mod.rs:140`, `src/peering/loops/mod.rs:152`).
  - Connect and accept loops both use that seam (`src/peering/loops/connect.rs:237`, `src/peering/loops/accept.rs:256`).

- SC5: **PASS**
  - Runtime 6-step loop model is documented in `docs/DESIGN.md:384` with steps at `docs/DESIGN.md:388`, `docs/DESIGN.md:389`, `docs/DESIGN.md:390`, `docs/DESIGN.md:391`, `docs/DESIGN.md:392`, `docs/DESIGN.md:393`.
  - Canonical ownership pointers exist in `docs/DESIGN.md:397` and `docs/DESIGN.md:398`.
  - Same model exists in `docs/PLAN.md:1938` with concrete file ownership at `docs/PLAN.md:1943` and `docs/PLAN.md:1945`.

- SC6: **PASS**
  - Boundary check passed.
  - Compile passed.
  - Required test gates passed: `cargo test --lib -q` (409), `scenario_test` (65), `holepunch_test` (4), `projectors` (52).
  - Required command evidence is present for every command listed in the plan.

READY_TO_MERGE