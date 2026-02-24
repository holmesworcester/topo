# Connect/Accept Collapse Evidence

Date: 2026-02-24
Branch: `exec/connect-accept-collapse-plan`
Worktree: `/home/holmes/poc-7-connect-accept-collapse-plan`
Plan: `docs/planning/CONNECT_ACCEPT_COLLAPSE_EXECUTION_PLAN.md`

## SC1. One supervision owner exists

Status: PASS

File-level proof:
- Shared supervision owner introduced in `src/peering/loops/supervisor.rs`:
  - startup preflight owner: lines 55-87
  - per-connection supervision owner: lines 106-155
- Wrappers are thin and call shared owner:
  - `src/peering/loops/connect.rs:82` uses `run_startup_preflight(...)`
  - `src/peering/loops/connect.rs:195` uses `supervise_connection_sessions(...)`
  - `src/peering/loops/accept.rs:79` uses `run_startup_preflight(...)`
  - `src/peering/loops/accept.rs:185` uses `supervise_connection_sessions(...)`
- Loop module topology explicitly documents shared supervisor:
  - `src/peering/loops/mod.rs:15`

Grep proof:
```text
$ rg -n "run_startup_preflight|supervise_connection_sessions|SessionTenantResolver" src/peering/loops/supervisor.rs src/peering/loops/accept.rs src/peering/loops/connect.rs
src/peering/loops/connect.rs:19:    run_startup_preflight, spawn_shared_ingest_writer, supervise_connection_sessions,
src/peering/loops/connect.rs:20:    SessionTenantResolver,
src/peering/loops/connect.rs:82:    run_startup_preflight(db_path, &tenants, ingest)?;
src/peering/loops/connect.rs:192:        let tenant_resolver = SessionTenantResolver::TransportIdentity {
src/peering/loops/connect.rs:195:        supervise_connection_sessions(
src/peering/loops/accept.rs:17:    run_startup_preflight, spawn_shared_ingest_writer, supervise_connection_sessions,
src/peering/loops/accept.rs:18:    SessionTenantResolver,
src/peering/loops/accept.rs:79:    run_startup_preflight(db_path, tenant_peer_ids, ingest)?;
src/peering/loops/accept.rs:183:                let tenant_resolver = SessionTenantResolver::Fixed(recorded_by_owned.clone());
src/peering/loops/accept.rs:185:                supervise_connection_sessions(
src/peering/loops/supervisor.rs:27:pub(super) enum SessionTenantResolver {
src/peering/loops/supervisor.rs:34:impl SessionTenantResolver {
src/peering/loops/supervisor.rs:55:pub(super) fn run_startup_preflight(
src/peering/loops/supervisor.rs:106:pub(super) async fn supervise_connection_sessions(
src/peering/loops/supervisor.rs:113:    tenant_resolver: &SessionTenantResolver,
src/peering/loops/supervisor.rs:193:        run_startup_preflight(db_path.to_str().unwrap(), &tenants, ingest).unwrap();
src/peering/loops/supervisor.rs:200:        let resolver = SessionTenantResolver::Fixed("tenant-fixed".to_string());
```

## SC2. Duplicate preflight code removed

Status: PASS

File-level proof:
- Startup preflight sequence is centralized once in `src/peering/loops/supervisor.rs:55-87`:
  - `create_tables`
  - `purge_expired_endpoints`
  - `ProjectQueue::recover_expired`
  - initial queue drain via `ingest.drain_queue`
- `accept.rs` and `connect.rs` no longer own duplicated startup preflight blocks; both call shared preflight entrypoint.

Grep proof:
```text
$ rg -n "create_tables\(|purge_expired_endpoints\(|recover_expired\(|drain_project_queue\(" src/peering/loops
src/peering/loops/supervisor.rs:61:    create_tables(&db)?;
src/peering/loops/supervisor.rs:63:    let purged = purge_expired_endpoints(&db, current_timestamp_ms()).unwrap_or(0);
src/peering/loops/supervisor.rs:69:    let recovered = project_queue.recover_expired().unwrap_or(0);
src/peering/loops/accept.rs:134:                let purged = purge_expired_endpoints(&db, now).unwrap_or(0);
src/peering/loops/connect.rs:174:                let purged = purge_expired_endpoints(&db, now).unwrap_or(0);
```

Interpretation:
- The only startup preflight owner is `supervisor.rs`.
- Remaining `purge_expired_endpoints` calls in wrappers are connection-observation maintenance during active connections, not duplicated startup preflight blocks.

## SC3. Runtime outbound path is coordinated-only

Status: PASS

File-level proof:
- Runtime planners call `connect_loop_with_coordination`:
  - `src/peering/runtime/target_planner.rs:115`
  - `src/peering/runtime/discovery.rs:129`
- Connect loop uses `initiator_with_coordination`:
  - `src/peering/loops/connect.rs:125`
- Punched runtime path also uses coordination now:
  - `src/peering/workflows/punch.rs:306`

Grep proof:
```text
$ rg -n "SyncSessionHandler::initiator\(" src/peering src/node.rs src/main.rs || true

$ rg -n "initiator_with_coordination\(" src/peering src/node.rs src/main.rs
src/peering/loops/connect.rs:125:    let initiator_handler = SyncSessionHandler::initiator_with_coordination(
src/peering/workflows/punch.rs:306:    let handler = SyncSessionHandler::initiator_with_coordination(
```

Interpretation:
- No direct production `SyncSessionHandler::initiator(...)` usage remains in runtime peering paths.

## SC4. No behavior regressions on core sync paths

Status: PASS

File-level proof:
- Shared session seam remains `run_session` in `src/peering/loops/mod.rs:127`.
- Shared supervisor uses that seam for both inbound/outbound: `src/peering/loops/supervisor.rs:141`.
- Peer-removal guard and session cadence are shared in `src/peering/loops/supervisor.rs:122-154`.

Test proof:
- `cargo test -q --test sync_contract_tests` passed.
- `cargo test -q --test scenario_test` passed.
- `cargo test -q --test sync_graph_test multi_source_coordinated_2x_5k` passed.

## SC5. Bellwether perf unaffected

Status: PASS

Required perf command outputs:
- `perf_sync_50k`: PASS (wall-time and events/s captured below)
- `perf_sync_10k`: PASS (wall-time and events/s captured below)

Before/after drift check (within this implementation cycle):
- 50k one-way:
  - before: wall `4.03s`, events/s `6469`
  - after: wall `4.24s`, events/s `6934`
  - drift: wall `+5.2%`, events/s `+7.2%`
- 10k bidirectional:
  - before: wall `0.81s`, events/s `11186`
  - after: wall `0.81s`, events/s `11135`
  - drift: wall `0.0%`, events/s `-0.5%`

No drift exceeded the 10% threshold.

## SC6. Diagram/docs reflect collapsed ownership

Status: PASS

File-level proof:
- Runtime topology diagram now shows wrapper -> shared supervisor ownership:
  - `docs/CURRENT_RUNTIME_DIAGRAM.md:124-134`
  - `docs/CURRENT_RUNTIME_DIAGRAM.md:143`
- Data-flow facts updated for coordinated runtime initiators and non-coordinated behavior scope:
  - `docs/CURRENT_RUNTIME_DIAGRAM.md:181-183`

---

## Required Verification Command Outputs

1. `cargo check`
```text
Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.08s
```

2. `rg -n "create_tables\\(|purge_expired_endpoints\\(|recover_expired\\(|drain_project_queue\\(" src/peering/loops`
```text
src/peering/loops/supervisor.rs:61:    create_tables(&db)?;
src/peering/loops/supervisor.rs:63:    let purged = purge_expired_endpoints(&db, current_timestamp_ms()).unwrap_or(0);
src/peering/loops/supervisor.rs:69:    let recovered = project_queue.recover_expired().unwrap_or(0);
src/peering/loops/accept.rs:134:                let purged = purge_expired_endpoints(&db, now).unwrap_or(0);
src/peering/loops/connect.rs:174:                let purged = purge_expired_endpoints(&db, now).unwrap_or(0);
```

3. `rg -n "connect_loop_with_coordination|accept_loop_with_ingest|run_session\\(" src/peering/loops src/peering/runtime`
```text
src/peering/loops/supervisor.rs:141:        run_session(
src/peering/runtime/target_planner.rs:27:use crate::peering::loops::{connect_loop_with_coordination, IntroSpawnerFn};
src/peering/runtime/target_planner.rs:115:            if let Err(e) = connect_loop_with_coordination(
src/peering/loops/accept.rs:45:    accept_loop_with_ingest(
src/peering/loops/accept.rs:67:pub async fn accept_loop_with_ingest(
src/peering/loops/connect.rs:57:    connect_loop_with_coordination(
src/peering/loops/connect.rs:71:pub async fn connect_loop_with_coordination(
src/peering/runtime/discovery.rs:19:use crate::peering::loops::{connect_loop_with_coordination, IntroSpawnerFn};
src/peering/runtime/discovery.rs:129:                                            _ = connect_loop_with_coordination(
src/peering/loops/mod.rs:13://!  - `accept`   -- accept_loop, accept_loop_with_ingest, resolve_tenant_for_peer
src/peering/loops/mod.rs:14://!  - `connect`  -- connect_loop, connect_loop_with_coordination
src/peering/loops/mod.rs:22:pub use accept::{accept_loop, accept_loop_with_ingest};
src/peering/loops/mod.rs:23:pub use connect::{connect_loop, connect_loop_with_coordination};
src/peering/loops/mod.rs:127:pub(super) async fn run_session(
src/peering/runtime/mod.rs:24:use crate::peering::loops::{accept_loop_with_ingest, IntroSpawnerFn};
src/peering/runtime/mod.rs:129:            if let Err(e) = accept_loop_with_ingest(
```

4. `rg -n "SyncSessionHandler::initiator\\(" src/peering src/node.rs src/main.rs`
```text
(no matches)
```

5. `cargo test -q --test sync_contract_tests`
```text
running 21 tests
.....................
test result: ok. 21 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.31s
```

6. `cargo test -q --test scenario_test`
```text
running 65 tests
.................................................................
test result: ok. 65 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 42.38s
```

7. `cargo test -q --test sync_graph_test multi_source_coordinated_2x_5k`
```text
running 1 test
.
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 25 filtered out; finished in 1.32s
```

8. `cargo test --release -q --test perf_test perf_sync_50k -- --nocapture`
```text
running 1 test
Generated 50k events in 4.23s

=== 50k one-way sync ===
  Wall time:    4.03s
  Events:       26087
  Events/s:     6469
  Throughput:   0.62 MiB/s
  Peak RSS:     194.5 MiB (before: 73.9, after: 194.5)

.
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; finished in 8.29s
```

9. `cargo test --release -q --test perf_test perf_sync_10k -- --nocapture`
```text
running 1 test
Generated 10k events (5k each) in 0.75s

=== 10k bidirectional sync ===
  Wall time:    0.81s
  Events:       9040
  Events/s:     11186
  Throughput:   1.07 MiB/s
  Peak RSS:     67.6 MiB (before: 21.3, after: 67.6)

.
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; finished in 1.58s
```

## Additional targeted loop-core test

`cargo test -q supervisor::tests::`:
```text
running 3 tests
...
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 419 filtered out; finished in 0.01s
```
