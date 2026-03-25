# Local Operational Causality Model Plan

## Goal

Model the new local-operational-events architecture with the event graph as the
primary surface.

The central claim of the design is not merely that runtime state becomes
durable. The stronger claim is that behaviorally meaningful runtime actions are
causally justified by local events, and that projection is a pure reduction of
those events into desired state. The TLA model should therefore make causal
dependencies between events the center of the state machine.

## Scope of this model

This model intentionally focuses on the first architectural slice:

1. client configuration events,
2. listener reconciliation,
3. connection planning and authentication with stable `connection_id`,
4. sync-round selection and completion with stable `sync_round_id`,
5. a policy-leak bug mode where the runtime creates ad hoc resources without
   event cause.

This model does **not** attempt to cover:

1. responder-side bilateral stitching,
2. connection/session closure,
3. mDNS protocol detail,
4. dependency-fetch episodes,
5. full transport/frame semantics.

Those belong in later models or extensions once the causality core is stable.

## Model surfaces

The model has three surfaces.

### 1. Event surface

`occurred` is the primary state variable. It is the local event graph.

Event constructors in `LocalOperationalCausality.tla` correspond to the
event-module layer of the design:

1. `ClientDefined`
2. `StorageBound`
3. `ListenerConfigured`
4. `JobPolicyConfigured`
5. `ClientStarted`
6. `JobDue`
7. `ListenerBound`
8. `ConnectionPlanned`
9. `ConnectionAuthenticated`
10. `SyncWindowSelected`
11. `SyncRoundCompleted`

The `Deps(e)` operator is the heart of the model. It encodes the causal
dependencies between local operational events directly.

### 2. Projection surface

Projected state is modeled as pure operators over `occurred`:

1. `ProjectedClients`
2. `ProjectedStorage`
3. `ProjectedDesiredListeners`
4. `ProjectedEnabledJobs`
5. `ProjectedStartedClients`
6. `ProjectedPlannedConnections`
7. `ProjectedSelectedRounds`

This maps directly to the design claim that the event pipeline is generic and
that projector-owned SQLite state is a pure reduction from events, not a second
policy engine.

### 3. Thin runtime shell surface

The only mutable non-event state in the model is the thin external-I/O shell:

1. `actualListeners`
2. `actualConnections`
3. `actualSyncRounds`

These represent resources/episodes that exist in the outside world after the
runtime carries out a projected action and observes the result.

## Boundary mapping to the design

The model maps to the design layers like this.

### Event modules

Modeled by:

1. event constructors,
2. `Deps(e)`,
3. event-emission actions such as `EmitConnectionPlanned_`,
4. invariants like `InvEventDepsSatisfied`.

Why:

Event modules are where the semantics and causal rules live. The model puts
those rules in `Deps(e)` and in the guards that decide which events can be
appended next.

### Event pipeline

Modeled by:

1. pure projection operators (`Projected*`),
2. invariants that assert projected state is exactly caused by events,
3. the fact that no separate mutable “manager policy state” exists in the
   model.

Why:

This is the architecture claim that the pipeline is a generic durable execution
shell and that desired state is a pure reduction of the event graph.

### Connection manager

Modeled by:

1. `actualListeners`,
2. `actualConnections`,
3. `EmitListenerBound_`,
4. `EmitConnectionAuthenticated_`,
5. `BuggyAdHocListenerBound_` in bug mode.

Why:

The connection manager should only reconcile resources and report outcomes. It
must not invent resources without projected/event cause. The bug repro config
exists specifically to prove the model rejects that leak.

### Sync engine

Modeled by:

1. `EmitSyncWindowSelected_`,
2. `actualSyncRounds`,
3. `EmitSyncRoundCompleted_`.

Why:

The sync engine is treated as a protocol executor over an already-selected
round. It does not decide cadence or target selection in the model.

### Runtime shell / clock bridge

Modeled by:

1. `EmitJobDueConnect_`,
2. `EmitJobDueSync_`.

Why:

This is the minimal runtime bridge from time into the event graph.

## Key invariants and what they mean

1. `InvEventDepsSatisfied`
   Every occurred event has all of its causal predecessors present.
2. `InvStartedClientHasConfig`
   Client run state must be justified by client configuration events.
3. `InvActualListenerHasCausalBasis`
   A live listener may not exist without `client_listener_configured`,
   `client_started`, and `listener_bound`.
4. `InvActualConnectionHasCausalBasis`
   An authenticated connection may not exist without `connection_planned`.
5. `InvActualSyncHasCausalBasis`
   A completed sync round may not exist without `sync_window_selected`.
6. `InvEpisodeIdsComeFromPlanner`
   `connection_id` and `sync_round_id` are planner-owned episode ids, not
   ad hoc runtime artifacts.

## Bug / fix validation strategy

The model includes `UseBuggyPolicyLeak`.

When `UseBuggyPolicyLeak = TRUE`, the action `BuggyAdHocListenerBound_` is
enabled. It lets the runtime append `listener_bound` and create a live listener
without the required configuration/start event chain. This should violate:

1. `InvEventDepsSatisfied`
2. `InvNoAdHocRuntimeState`

When `UseBuggyPolicyLeak = FALSE`, that action is disabled and the same
invariants should pass.

## Progress check

The model also includes a small progress spec:

1. `SpecProgress`
2. `ProgressToSync`

This is not meant to prove the whole protocol. It only checks that under weak
fairness for the happy-path actions, the architecture can progress from client
configuration to a completed sync round without any hidden planner state.

## Files

1. `docs/tla/LocalOperationalCausality.tla`
2. `docs/tla/local_operational_causality_bug_repro.cfg`
3. `docs/tla/local_operational_causality_fix.cfg`
4. `docs/tla/local_operational_causality_progress.cfg`

## TLC commands

1. `./tlc LocalOperationalCausality local_operational_causality_bug_repro.cfg`
2. `./tlc LocalOperationalCausality local_operational_causality_fix.cfg`
3. `./tlc LocalOperationalCausality local_operational_causality_progress.cfg`

## TLC execution notes (2026-03-24)

The worktree-local `docs/tla/tlc` wrapper expects `docs/tla/tla2tools.jar` inside
the current worktree. This worktree did not have that jar copied in, so the
validation below used direct `java -cp /home/holmes/poc-7/docs/tla/tla2tools.jar ...`
invocations against the new spec module.

1. Bug repro:
   - Command:
     `java -XX:+UseParallelGC -cp /home/holmes/poc-7/docs/tla/tla2tools.jar tlc2.TLC -workers auto -config /home/holmes/poc-7/.codex-worktrees/local-operational-runtime-align/docs/tla/local_operational_causality_bug_repro.cfg /home/holmes/poc-7/.codex-worktrees/local-operational-runtime-align/docs/tla/LocalOperationalCausality`
   - Status: **FAIL (expected)**
   - Invariant: `InvEventDepsSatisfied`
   - Counterexample summary:
     `BuggyAdHocListenerBound_` emits `listener_bound` and creates a live
     listener with no `client_listener_configured` / `client_started` cause.
   - Stats:
     `66` states generated / `44` distinct / depth `14`

2. Fix config:
   - Command:
     `java -XX:+UseParallelGC -cp /home/holmes/poc-7/docs/tla/tla2tools.jar tlc2.TLC -workers auto -config /home/holmes/poc-7/.codex-worktrees/local-operational-runtime-align/docs/tla/local_operational_causality_fix.cfg /home/holmes/poc-7/.codex-worktrees/local-operational-runtime-align/docs/tla/LocalOperationalCausality`
   - Status: **PASS**
   - Stats:
     `46` states generated / `27` distinct / depth `14`

3. Progress config:
   - Command:
     `java -XX:+UseParallelGC -cp /home/holmes/poc-7/docs/tla/tla2tools.jar tlc2.TLC -workers auto -config /home/holmes/poc-7/.codex-worktrees/local-operational-runtime-align/docs/tla/local_operational_causality_progress.cfg /home/holmes/poc-7/.codex-worktrees/local-operational-runtime-align/docs/tla/LocalOperationalCausality`
   - Status: **PASS**
   - Property:
     `ProgressToSync`
   - Stats:
     `46` states generated / `27` distinct / depth `14`
