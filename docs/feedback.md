# Feedback: Runtime Supervisor Task Graph Mid-Implementation Review

Date: 2026-02-24
Reviewed against: `docs/planning/RUNTIME_SUPERVISOR_TASK_GRAPH_EXECUTION_PLAN.md`
Branch: `exec/runtime-supervisor-task-graph-plan`
Worktree: `/home/holmes/poc-7-runtime-supervisor-task-graph-plan`

## Findings

1. **High - Runtime ownership remained scattered across runtime modules (SC1/SC4 risk)**
   - Why it mattered: detached spawns in `runtime/mod.rs`, `runtime/target_planner.rs`, and `runtime/discovery.rs` blocked deterministic teardown guarantees.
   - Evidence at review time: direct `std::thread::spawn` usage in all three modules.
   - Fix applied:
     - Added `src/peering/runtime/supervisor.rs` as single runtime owner.
     - Moved target dispatch/bootstrap/discovery worker ownership under supervisor.
     - Refactored runtime helpers to spawn-free setup/dispatch-key modules.
   - Status: **RESOLVED**.

2. **Medium - Cancellable shutdown contract was incomplete for loop workers (SC4/SC6 risk)**
   - Why it mattered: supervisor cancel needed to propagate into accept/connect session loops and await termination.
   - Evidence at review time: connect/accept/session supervision APIs had no runtime cancellation input.
   - Fix applied:
     - Added cancellation-aware loop entry points and shutdown-aware session supervision:
       - `accept_loop_with_ingest_until_cancel`
       - `connect_loop_with_coordination_until_cancel`
       - `supervise_connection_sessions(..., shutdown)`
     - Added join/drain behavior in runtime supervisor.
   - Status: **RESOLVED**.

3. **Low - Ongoing-sync CLI gate used a race-prone exact bootstrap event-id assertion**
   - Why it mattered: strict event-id gate can race invite creation timing and produce flake unrelated to runtime supervisor ownership goals.
   - Evidence at review time: intermittent `test_cli_ongoing_sync` timeout while broader sync flow stayed healthy.
   - Fix applied:
     - Kept bootstrap readiness semantics but switched gate to deterministic convergence predicate (`message_count >= 1`) before ongoing-sync assertions.
   - Status: **RESOLVED**.

## Review Conclusion

- No unresolved High/Medium findings remain for SC1-SC8 scope.
- Proceeded to final SC audit and evidence capture.
