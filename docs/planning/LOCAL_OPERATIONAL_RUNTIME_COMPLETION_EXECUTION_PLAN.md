# Local Operational Runtime Completion Execution Plan

Date: 2026-03-25
Source branch: `codex/local-operational-runtime-align`
Implementation branch: `codex/local-operational-runtime-roadmap`
Implementation worktree: `/home/holmes/poc-7/.codex-worktrees/local-operational-runtime-roadmap`

## Snapshot Note

This branch includes the cherry-picked baseline from
`codex/local-operational-runtime-align` plus all roadmap implementation
commits. The implementation is in progress — see the gaps document for
current phase status.

## Worktree Rule

Do all execution work in a dedicated worktree.  
Do not execute this plan in `/home/holmes/poc-7`.

## Objective

Complete the architectural shift from runtime-owned policy to event-owned
policy so the system becomes:

1. event-owned in semantics,
2. SQLite-owned in operational memory,
3. runtime-thin in mechanics,
4. replayable and eventually simulatable across multiple clients.

## Architectural North Star

The end state is:

- event modules own behavior, meaning, policy, projected tables, and emitted
  commands,
- projectors remain pure and emit `WriteOp`s plus post-commit commands,
- SQLite stores all replay-relevant operational memory,
- runtime adapters only:
  - execute emitted commands,
  - observe external outcomes,
  - append local operational events,
  - reconcile desired resources to actual resources.

The runtime should be embarrassingly small.

The intended causal story is:

1. a shared or local event exists,
2. projection writes durable state and emits commands,
3. a thin adapter executes the command,
4. the adapter observes an external result,
5. the adapter authors another local operational event,
6. projection continues the chain.

## Guiding Rules

### Rule 1: Event ownership

If code answers either of these questions, it belongs in an event family:

1. What event should exist here?
2. What should happen next because of this event?

If code only answers mechanical questions like `bind`, `accept`, `dial`,
`send`, `recv`, sleep-until-cancel, or close-connection, it belongs in runtime.

### Rule 2: When to mint a local event

A new local event is needed only when the system:

1. observes something external, or
2. takes a branch that is not otherwise derivable from durable state.

### Rule 3: SQLite owns operational memory

No process-local state may remain behaviorally meaningful if that state is
important to replay, recovery, deterministic testing, or simulation.

### Rule 4: Append-only first

Projected semantic/operational tables should prefer append-only rows keyed by
event identity. Current state should be derived by query. Mutable rows are
allowed only for narrow infrastructure aids, and should be avoided when
possible.

### Rule 5: Events are the primary log

Runtime success-path tracing should be removed when equivalent local operational
events already provide durable causal history.

## Current Baseline

The current branch already has meaningful progress:

1. local operational event families exist under `src/event_modules/operational/`,
2. client lifecycle, connection planning, inbound/outbound connection outcomes,
   sync round start/completion, and sync window state are at least partially
   event-owned,
3. startup reconcile has been separated from the loop supervisor,
4. live-connection preference/slot policy has been separated from
   `runtime/peering/loops/mod.rs`,
5. `accept.rs` and `connect.rs` already delegate more to operational families.

The remaining work is to finish the architecture, not just add more events.

## Global Success Criteria

The roadmap is complete only when all of the following are true:

1. Runtime loops no longer decide trust, retry, fallback, precedence, cadence,
   lifecycle, or routing policy from ad hoc in-memory logic.
2. Event families own connection, sync, listener, discovery, client-lifecycle,
   and recurring-job semantics.
3. SQLite holds all replay-relevant client state:
   listener config, bind state, connection intent/state, sync planning state,
   client lifecycle state, recurring job state, provenance state, and any other
   important operational memory.
4. The remaining runtime can be described as:
   observe -> execute -> author event -> reconcile.
5. The bespoke supervisors have either been retired or reduced to generic
   reconcilers/executors.
6. Local operational events are the durable operational log.
7. The codebase has an explicit path to multi-client virtual-time replay and
   simulation.

## Mandatory Validation Rules

These apply throughout the roadmap:

1. Run targeted Rust tests for each changed phase.
2. Run at least one end-to-end or contract-style validation per phase, not just
   unit tests.
3. Whenever changing event schemas, signer-family rules, dependency checks,
   projector guards, `docs/tla/runtime_check_catalog.md`, or
   `docs/tla/projector_conformance_matrix.md`, also run:
   - `python3 scripts/check_projector_tla_conformance.py`
   - `python3 scripts/check_projector_tla_bijection.py`
4. No TLA/runtime claim may be added or updated without executable code/test
   coverage for that claim.

## Roadmap Overview

Recommended execution order:

1. Finish removing branchy runtime policy from connect/accept/session loops.
2. Event-own listener/resource lifecycle and finish host-side reconciliation.
3. Add the durable jobs/clock bridge.
4. Move connection maintenance policy fully into event families.
5. Finish event-own sync planning.
6. Record ingress provenance.
7. Add bilateral episode identity for connection and sync.
8. Build the replay/simulation harness.
9. Retire bespoke supervisors.
10. Reduce boilerplate and improve event-family ergonomics.
11. Add retention/TTL/logging cleanup and final conformance.

## Phase 1: Remove Remaining Branchy Runtime Policy

### Goal

Finish moving the remaining accept/connect/session-loop decisions into
operational families.

### Scope

Primary files:

- `src/runtime/peering/loops/connect.rs`
- `src/runtime/peering/loops/accept.rs`
- `src/runtime/peering/loops/supervisor.rs`
- related operational families under `src/event_modules/operational/`

### Deliverables

1. Outbound stale-dial retry and terminal stale-target logic are event-owned,
   not loop-local counter logic.
2. Session supervision returns a typed outcome instead of hardcoding generic
   `"session_ended"` close reasons.
3. Close/failure reasons are chosen by operational families, not by the loop.
4. Repeated-warning policy that still matters semantically is reduced or moved
   behind event-owned helpers.

### Success Criteria

1. `connect.rs` contains no branchy fallback/retry/stale-target policy beyond
   executing helper results.
2. `accept.rs` contains no auth or duplicate-live-connection policy.
3. `loops/supervisor.rs` contains no semantic close-reason policy.
4. All new connection/session terminal states are represented by local
   operational events or event-owned projected history.

### Required Checks

1. `cargo check --tests`
2. `cargo test runtime::peering::loops::connect::tests::fallback_policy_allows_typed_trust_rejection_with_fallback_cfg -- --nocapture`
3. `cargo test runtime::peering::loops::accept::tests::requested_tenant_auth_accepts_when_that_tenant_authorizes_remote_peer -- --nocapture`
4. Targeted tests for:
   - stale-failure streak accumulation,
   - stale-failure reset after success,
   - close-reason mapping.

### End-to-End Validation

1. An outbound dial repeatedly fails in a stale way and eventually produces the
   expected terminal local event/history state.
2. An authenticated connection runs a session that ends via cancellation or
   runtime shutdown and records the specific close reason expected by the event
   family.

## Phase 2: Event-Own Listener and Resource Lifecycle

### Goal

Treat listeners and other long-lived runtime resources as event-governed state.

### Scope

Primary files:

- `src/runtime/control/main.rs`
- new or expanded operational families for listener lifecycle
- relevant schema bootstrap in event-owned modules

### Deliverables

1. Desired listener state is projected from client lifecycle/resource events.
2. Listener bind/open/close outcomes become local operational events.
3. `client_started` / `client_stopped` determine desired listener existence.
4. The host reconciles desired resources instead of deciding policy itself.

### Success Criteria

1. No listener bind/open/close state lives only in process memory.
2. There is a clear event family for listener configuration and listener
   outcomes.
3. `main.rs` becomes a thin client/runtime reconciler rather than a policy
   owner.

### Required Checks

1. `cargo check --tests`
2. targeted tests for listener bind success, bind failure, and listener close
3. `cargo test client_lifecycle -- --nocapture`
4. `cargo test test_create_tables -- --nocapture`

### End-to-End Validation

1. Starting a client produces durable desired-listener state and listener-bound
   outcome.
2. Stopping a client produces durable listener-close state and no residual live
   listener.

## Phase 3: Add the Durable Jobs and Clock Bridge

### Goal

Replace hidden recurring behavior with durable due-work plus local clock-boundary
events.

### Scope

Recurring behaviors to migrate first:

1. outbound reconnect maintenance,
2. observed-endpoint refresh,
3. at least one sync cadence path,
4. key rotation or equivalent maintenance behavior if already close enough.

### Deliverables

1. A typed jobs registry in code.
2. Durable job-instance state in SQLite.
3. A clock bridge that emits local due events without owning policy.
4. `client_started` enables jobs and `client_stopped` suppresses them.

### Success Criteria

1. No connect/sync refresh cadence remains solely in loop-local timers.
2. Due-work state survives restart.
3. Job semantics live in event families/projected state, not in the clock
   driver.

### Required Checks

1. `cargo check --tests`
2. targeted tests for job activation/deactivation
3. restart-safety tests for due-work persistence
4. if schemas/guards/mappings change:
   - `python3 scripts/check_projector_tla_conformance.py`
   - `python3 scripts/check_projector_tla_bijection.py`

### End-to-End Validation

1. Start a client with active peers and observe a due reconnect/sync job produce
   the expected local event chain.
2. Restart the process and prove the same due work resumes from SQLite state.

## Phase 4: Move Connection Maintenance Policy Fully Into Event Families

### Goal

Eliminate policy ownership from the peering engine supervisor.

### Scope

Primary files:

- `src/runtime/peering/engine/supervisor.rs`
- `src/runtime/peering/engine/target_planner.rs`
- connection-plan and job operational families

### Deliverables

1. Precedence between bootstrap/discovery/observed targets is event-owned.
2. Worker supersession and reconnect policy are event-owned.
3. Refresh cadence leaves the supervisor and joins the durable jobs model.
4. The supervisor becomes a generic reconciler over projected desired work.

### Success Criteria

1. `engine/supervisor.rs` no longer decides source precedence in ad hoc logic.
2. `engine/supervisor.rs` no longer owns recurring refresh cadence.
3. Connect worker lifecycle is driven by projected desired state and due work.

### Required Checks

1. `cargo check --tests`
2. `cargo test runtime::peering::engine::supervisor::tests::discovery_and_observed_targets_follow_preferred_side_gate -- --nocapture`
3. targeted tests for worker supersession and reconnect decision stability

### End-to-End Validation

1. Competing bootstrap/discovery/observed targets produce the same winning
   connection plan regardless of runtime task interleaving.

## Phase 5: Finish Event-Owned Sync Planning

### Goal

Keep the sync engine as a protocol executor and move planning/cadence/range
semantics into sync operational families.

### Scope

Primary files:

- `src/runtime/sync_engine/session/initiator.rs`
- `src/runtime/sync_engine/session/windowing.rs`
- `src/runtime/sync_engine/session/responder.rs`
- sync operational families

### Deliverables

1. Sync cadence comes from durable job state, not local timers.
2. Range/window selection is event-owned or fully derivable from durable state.
3. Sync retry and termination policy are event-owned.
4. Manual sync control integrates with the same event-owned machinery.

### Success Criteria

1. No process-local planner state remains behaviorally meaningful.
2. Sync round planning is queryable from SQLite and/or represented by local
   operational events.
3. The sync engine only executes protocol work already decided elsewhere.

### Required Checks

1. `cargo check --tests`
2. targeted tests for outbound window/range selection
3. `cargo test --test sync_contract_tests -- --nocapture`
4. targeted cancellation/timeout/repair-round tests

### End-to-End Validation

1. A reconnect plus subsequent sync repair round uses the exact planned window
   encoded in durable state and records round start/completion causally.

## Phase 6: Record Ingress Provenance

### Goal

Make the system explain how a canonical event entered a client.

### Scope

Primary areas:

- receive-log/ingest path
- local operational provenance event family or provenance projection family

### Deliverables

1. A local fact tying canonical event ingestion to `connection_id`,
   `sync_round_id`, peer, and arrival context.
2. Query paths for “how did this event arrive?”
3. Causal linkage from sync rounds to concrete ingested events.

### Success Criteria

1. The system can trace any ingested canonical event to a transport/runtime
   episode.
2. Provenance is durable and restart-safe.

### Required Checks

1. `cargo check --tests`
2. targeted receive-log / ingest provenance tests
3. projection-path accept/reject tests for valid/invalid provenance context

### End-to-End Validation

1. Complete a sync exchange and prove a received canonical event can be traced
   to the exact connection and sync round that delivered it.

## Phase 7: Add Bilateral Episode Identity

### Goal

Make connection and sync episodes pairable across clients without making
production validity multi-client-aware.

### Scope

1. connection identifiers propagated through both sides,
2. sync-round identifiers with equivalent bilateral meaning,
3. simulator-only bridge edge assumptions documented.

### Deliverables

1. Stable `connection_id` semantics for both sides of a connection.
2. Stable sync-round identity semantics for both sides of a round.
3. Documentation for how a replay/simulator should stitch them.

### Success Criteria

1. Both sides can emit local events referencing the same transport episode id.
2. Same for sync rounds.
3. Production local-event validity remains single-client/local only.

### Required Checks

1. `cargo check --tests`
2. targeted tests showing both sides derive/carry the same episode ids

### End-to-End Validation

1. Two clients connect and exchange at least one sync round; their local event
   histories can be paired by episode ids without heuristic matching.

## Phase 8: Build the Replay and Simulation Harness

### Goal

Provide the future validation bar: replay and virtual-time simulation from
multi-client event sources.

### Scope

1. import multiple local event streams,
2. interleave on virtual time,
3. add simulation-only bridge edges,
4. project the merged stream.

### Deliverables

1. Replay tool for one client.
2. Multi-client import and merge path.
3. Virtual-time driver.
4. First deterministic scenario tests.

### Success Criteria

1. A merged replay can reproduce projected state transitions deterministically.
2. Simulation time can advance independently of wall time.
3. Bridge edges remain simulator-only and do not leak into production validity.

### Required Checks

1. deterministic replay tests
2. multi-client simulation tests
3. at least one scenario where simulation time differs from wall time

### End-to-End Validation

1. Replay a captured two- or three-client scenario and reproduce the expected
   connection, sync, and ingest provenance state.

## Phase 9: Retire Bespoke Supervisors

### Goal

Delete or collapse the remaining supervisors once they stop deciding policy.

### Retirement Order

1. `src/runtime/peering/loops/supervisor.rs`
2. `src/runtime/peering/engine/supervisor.rs`
3. `src/runtime/control/main.rs`

### Retirement Bars

#### `loops/supervisor.rs`

Retire or rename when:

1. connection-session close reasons are event-owned,
2. retry/backoff behavior is event-owned,
3. the file only executes session work and returns observation outcomes.

#### `engine/supervisor.rs`

Retire or rename when:

1. precedence, cadence, and worker supersession are event-owned,
2. connection workers are reconciled from projected desired state,
3. no ad hoc in-memory policy state remains necessary.

#### `main.rs`

Retire or shrink when:

1. client lifecycle and listener/resource state are fully event-owned,
2. startup reconcile is separate,
3. the host only bootstraps adapters and runs reconcilers.

### Success Criteria

1. Remaining supervisor files, if any, contain no semantic branch logic.
2. Runtime ownership can be explained without special-case supervisors.

### Required Checks

1. `cargo check --tests`
2. regression tests from all prior phases

### End-to-End Validation

1. Start, connect, sync, disconnect, stop, and recover a client while tracing
   behavior entirely through events and reconcilers rather than bespoke
   supervisors.

## Phase 10: Reduce Boilerplate and Improve Event-Family Ergonomics

### Goal

Keep the event-owned architecture while removing hand-written ceremony.

### Scope

1. operational family directories,
2. common basis-edge authoring helpers,
3. shared projector-context loader helpers,
4. shared wire helpers or higher-level schema helpers,
5. eventual simplification of local-event representation if warranted.

### Deliverables

1. family-directory organization for large operational families,
2. shared helper layer for common basis-edge local events,
3. fewer one-off `record_*` wrappers,
4. less duplicated parse/encode/context boilerplate.

### Success Criteria

1. Adding a new operational event mostly means declaring fields, projector, and
   authoring helper.
2. Repeated basis/context/wire code is centralized.
3. Behavior does not regress during ergonomics cleanup.

### Required Checks

1. `cargo check --tests`
2. representative event-family tests for all refactored families

### End-to-End Validation

1. Add or modify one representative operational event family and prove the new
   helper structure reduces code duplication without changing semantics.

## Phase 11: Retention, TTL, Logging Cleanup, and Final Convergence

### Goal

Finish the operational model by making local events manageable and by removing
the last redundant runtime logging.

### Scope

1. local event retention/TTL policy,
2. optional compaction rules,
3. runtime logging audit,
4. documentation convergence.

### Deliverables

1. TTL or compaction policy for local operational events,
2. guarantees that derived current-state queries still work after retention,
3. runtime logs reduced to mechanical diagnostics and exceptional failures,
4. design/docs updated to match the final ownership model.

### Success Criteria

1. Local operational events can be pruned safely according to policy.
2. Event history remains the primary operational log.
3. Documentation and runtime behavior agree.

### Required Checks

1. retention/TTL tests
2. `cargo check --tests`
3. if TLA mapping docs change:
   - `python3 scripts/check_projector_tla_conformance.py`
   - `python3 scripts/check_projector_tla_bijection.py`

### End-to-End Validation

1. Run a realistic scenario, prune retained local history according to policy,
   and confirm projected current-state queries still produce the expected
   answers.

## Final Definition of Done

Do not mark this architecture complete until all of the following are true:

1. The remaining runtime can be described as:
   - observe,
   - execute,
   - author event,
   - reconcile.
2. No runtime module outside event families decides durable policy from hidden
   local state.
3. All replay-relevant client state is event-owned or fully derived from
   event-owned projected SQLite state.
4. At least one multi-client replay/simulation path exists or is immediately
   executable from the produced event sources.
5. The bespoke supervisors are gone or reduced to generic executors.
6. The event-owned model is documented, validated, and test-backed end to end.

## Required Completion Workflow

1. Rebase the implementation worktree/branch on the latest intended base before
   finalizing.
2. Execute phases in order unless a written dependency analysis justifies
   reordering.
3. Keep an evidence log or SC audit document as phases complete.
4. Do not claim any SC complete without the listed checks and end-to-end
   validation.
5. If a phase changes event schemas, dependency rules, projector guards, or TLA
   mapping docs, update the mappings in the same change and run the required
   conformance scripts.
