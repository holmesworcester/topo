# Runtime Supervisor Task Graph Execution Plan

Date: 2026-02-24  
Branch: `exec/runtime-supervisor-task-graph-plan`  
Worktree: `/home/holmes/poc-7-runtime-supervisor-task-graph-plan`

## Objective

Unify runtime control under one explicit supervisor task graph so runtime lifecycle is easy to reason about, test, and diagram.

Primary outcomes:

1. One runtime owner for long-lived task lifecycle.
2. No detached runtime spawn points scattered across modules.
3. Deterministic startup, state transitions, and shutdown.
4. Runtime topology that can be explained in one compact diagram.

## Scope

In scope:

1. `src/peering/runtime/{mod.rs,discovery.rs,target_planner.rs,startup.rs}`.
2. New supervisor module(s) under `src/peering/runtime/`.
3. Runtime state wiring from `src/node.rs` / `src/main.rs` as required.
4. Runtime-focused tests and documentation updates.

Out of scope:

1. Event module locality changes.
2. Transport protocol redesign.
3. Sync protocol message semantics changes.
4. CLI/RPC single-ingress redesign (tracked separately).

## Non-Negotiable Requirements

### R1. Single runtime task owner

1. Long-lived runtime tasks must be created and owned by one supervisor.
2. Runtime submodules must not spawn detached threads/tasks directly.
3. Ownership and cancellation policy must be explicit in one file.

### R2. Explicit runtime states

1. Supervisor state model must include `IdleNoTenants` and `Active`.
2. Transition conditions must be explicit and event-driven (tenant set changes, shutdown).
3. State transitions must not require daemon restart.

### R3. Unified target ingress path

1. Bootstrap targets and discovery targets both flow through one dispatch queue/path.
2. One dial dispatcher owns connect-loop worker lifecycle.
3. Duplicate target dispatch logic across modules must be removed.

### R4. Deterministic shutdown

1. Supervisor cancel must propagate to all runtime workers.
2. Runtime exit must await worker teardown (no orphan worker threads).
3. Shutdown should be idempotent and safe if called multiple times.

### R5. Readability-first runtime topology

1. Runtime control path must be small enough to trace top-down from one module.
2. Diagram docs must match real ownership.
3. Runtime worker inventory must be explicit and finite.

## Mandatory Implementation Phases

### Phase 0: Baseline and leak inventory

1. Record current runtime spawn loci and owner ambiguity.
2. Capture baseline test pass for runtime-related suites.

### Phase 1: Introduce runtime supervisor module

1. Add `src/peering/runtime/supervisor.rs` (or equivalent) as the only task owner.
2. Add explicit state enum (`IdleNoTenants`, `Active`).
3. Add cancellation tree (`tokio_util::sync::CancellationToken`) and worker handle registry.

### Phase 2: Move spawn points under supervisor

1. Move writer/accept/bootstrap-refresh/discovery-related long-lived spawns under supervisor methods.
2. Replace direct spawns in `runtime/mod.rs`, `target_planner.rs`, `discovery.rs` with supervisor calls.
3. Keep behavior stable first; avoid semantic rewrites during move.

### Phase 3: Unify target dispatch ingestion

1. Route bootstrap and discovery targets into one channel.
2. Single dispatcher task decides connect/reconnect/skip and owns loop lifecycle.
3. Preserve existing dedupe/reconnect semantics.

### Phase 4: Shutdown and failure policy hardening

1. Define explicit policy for worker failure (restart/backoff or fail runtime) per worker type.
2. Ensure shutdown waits for worker completion.
3. Add tests for orderly shutdown and no zombie tasks.

### Phase 5: Docs and evidence

1. Update `docs/CURRENT_RUNTIME_DIAGRAM.md` runtime section to show single supervisor ownership.
2. Add evidence doc mapping SCs to concrete code/test output.

## Strict Success Criteria (SCs)

### SC1. No runtime detached spawns outside supervisor

1. `src/peering/runtime/mod.rs`, `src/peering/runtime/target_planner.rs`, and `src/peering/runtime/discovery.rs` contain no `std::thread::spawn` or `tokio::spawn`.
2. Runtime worker spawns are centralized in supervisor implementation.

### SC2. Explicit runtime state machine present

1. Supervisor defines runtime states including `IdleNoTenants` and `Active`.
2. Transition code is centralized and test-covered.

### SC3. Unified target ingress path

1. Bootstrap + discovery target events pass through one dispatcher queue/path.
2. Dispatcher owns connect-loop lifecycle decisions.

### SC4. Deterministic shutdown

1. Supervisor shutdown cancels all workers and awaits termination.
2. No worker remains running after supervisor returns.

### SC5. Runtime behavior parity on core flows

1. Accept/connect behavior remains correct under normal operation.
2. Bootstrap autodial and discovery still function.

### SC6. Failure handling is explicit

1. Worker failure handling policy is encoded in supervisor.
2. Unexpected worker exits are surfaced through logs/tests.

### SC7. Docs reflect actual ownership

1. Runtime diagram names supervisor as task owner.
2. Removed references to scattered ownership in current runtime docs.

### SC8. Regression gates pass

1. Runtime-related tests pass after refactor.
2. Boundary checks and compile checks pass.

## Required Verification Commands (no-cheat)

```bash
# Spawn-locus elimination proof
rg -n "std::thread::spawn|tokio::spawn" src/peering/runtime/mod.rs src/peering/runtime/target_planner.rs src/peering/runtime/discovery.rs
rg -n "std::thread::spawn|tokio::spawn" src/peering/runtime/supervisor.rs

# State machine / supervisor presence proof
rg -n "IdleNoTenants|Active|CancellationToken|JoinSet|supervisor" src/peering/runtime

# Build + boundary checks
cargo check
bash scripts/check_boundary_imports.sh

# Runtime regression tests
cargo test --test holepunch_test -q
cargo test --test cli_test -q
cargo test --test sync_graph_test multi_source_coordinated_2x_5k -q
```

Expected interpretation:

1. Spawn grep on old files returns empty.
2. Spawn grep on supervisor file shows centralized worker ownership.
3. Tests pass without runtime lifecycle regressions.

## Required Evidence Artifact

Create:

- `docs/planning/RUNTIME_SUPERVISOR_TASK_GRAPH_EVIDENCE.md`

Evidence format:

1. SC1-SC8 table with PASS/FAIL.
2. For each SC: file references + grep output + test output.
3. Any temporary compromise marked with remediation follow-up.

## Mandatory Working Rules

1. Work only in `/home/holmes/poc-7-runtime-supervisor-task-graph-plan`.
2. Rebase on latest `master` before final review:
   - `git fetch origin`
   - `git rebase origin/master`
3. Run a Codex CLI feedback loop:
   - mid-implementation feedback in `feedback.md`
   - final SC audit in `codex_final_audit.md`
4. Commit on this worktree branch when implementation is complete.
5. Do not mark ready-to-merge unless SC1-SC8 are all PASS.
