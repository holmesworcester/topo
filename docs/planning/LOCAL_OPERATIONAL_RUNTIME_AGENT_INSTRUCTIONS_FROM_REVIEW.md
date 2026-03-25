# Local Operational Runtime Agent Instructions From Review

Date: 2026-03-25  
Target branch: `codex/local-operational-runtime-roadmap`  
Branch head reviewed for these instructions: `fd0e337450cc48f168487c93a71b765255ef9d5b`

## Purpose

These instructions translate the current review into an execution plan for the
active agent working on `codex/local-operational-runtime-roadmap`.

They are intentionally narrower than
`LOCAL_OPERATIONAL_RUNTIME_COMPLETION_EXECUTION_PLAN.md`.

Use them as the immediate execution contract for the branch in its current
state.

## Current Reality

Preserve this framing while working:

- the branch contains real architectural progress
- the branch does **not** satisfy the full roadmap SCs
- several later-phase modules are groundwork, not completion

Current phase status:

- Phase 1: partial
- Phase 2: not met
- Phase 3: partial
- Phase 4: partial
- Phase 5: partial
- Phase 6: not met
- Phase 7: not met
- Phase 8: not met
- Phase 9: not met
- Phase 10: not met
- Phase 11: partial

## Preserve These Wins

Do not regress or discard these existing gains:

- connection/client local operational event families already exist
- client lifecycle already projects durable runtime state
- sync rounds already have local operational events
- single-client replay exists as useful groundwork
- provenance has schema/helpers, even though it is not wired into production ingest
- durable jobs exist as a first bridge, even though they are not yet event-owned

## Do Not Claim Yet

Do not describe any of the following as complete:

- listener/resource lifecycle eventization
- event-owned clock bridge
- bilateral episode identity
- multi-client replay/simulation
- supervisor retirement
- full retention safety

If a phase is groundwork or a partial slice, say so explicitly.

## Execution Order

Work in this order:

1. fix roadmap metadata and phase-status claims
2. complete listener/resource lifecycle eventization
3. replace mutable/polled durable jobs with a true `job_due` event bridge
4. finish remaining branchy runtime-policy extraction from connect/supervisor
5. finish event-owned sync planning
6. wire ingress provenance into real ingest
7. add true bilateral episode identity
8. implement multi-client replay/simulation
9. retire supervisors only after the above are true
10. compress boilerplate and finalize retention/logging

Do not jump ahead to boilerplate cleanup or supervisor retirement while the
earlier semantic gaps remain open.

## Task 1: Fix Roadmap Metadata And Status Claims

The roadmap doc still claims an outdated source-tip snapshot and reads too much
like later phases are complete.

Primary files:

- `docs/planning/LOCAL_OPERATIONAL_RUNTIME_COMPLETION_EXECUTION_PLAN.md`
- `docs/planning/LOCAL_OPERATIONAL_RUNTIME_ROADMAP_GAPS_AND_INSTRUCTIONS.md`

### SC

- The roadmap doc no longer claims a stale source snapshot.
- The roadmap doc no longer implies that Phases 2-11 are complete.
- The roadmap doc clearly distinguishes implemented groundwork from completed
  roadmap phases.

### Checks

- `rg -n "4a7e3a|Source branch tip commit|Snapshot Note" docs/planning/LOCAL_OPERATIONAL_RUNTIME_COMPLETION_EXECUTION_PLAN.md`
- manual read of phase headings and summary language

### End-To-End Validation

- A fresh reader can compare the roadmap doc and the branch state without being
  misled about what is actually done.

## Task 2: Complete Listener And Resource Lifecycle Eventization

There is still no real listener event family. Runtime/client control still
directly reserves binds and spawns runtime.

Primary files:

- `src/runtime/control/main.rs`
- `src/event_modules/operational/mod.rs`
- new listener/resource event families under `src/event_modules/operational/`

### Required design rule

Opening a listener is not projector-side I/O. It is event-governed desired
state:

- listener desired state is projected
- a command causes the adapter to bind
- bind/open/close results are recorded as local events

### SC

- listener desired state is represented by local operational events
- bind success, bind failure, and listener close are local operational events
- `main.rs` reconciles projected listener/runtime state instead of deciding
  listener semantics directly

### Required Checks

- projection test: listener desired event accepted on valid path
- projection test: invalid/stale listener event rejected or blocked
- runtime test: bind success emits the right local event
- runtime test: bind failure emits the right local event
- runtime test: listener shutdown emits the right local event

### End-To-End Validation

- `client_started` leads to listener intent
- the adapter binds
- bind outcome is recorded as a local event
- `client_stopped` suppresses the listener and records shutdown/close state

## Task 3: Replace Mutable Durable Jobs With A True `job_due` Clock Bridge

The current `durable_jobs` table is a useful bridge, but it is still mutable
row state plus runtime polling/sleep.

Primary files:

- `src/event_modules/operational/durable_jobs.rs`
- `src/runtime/peering/engine/supervisor.rs`
- new `job_due` event family under `src/event_modules/operational/`

### Required design rule

Time crossing is one of the legitimate reasons to mint a local event.

The model must become:

- projected state says a recurring job is enabled and due
- the clock bridge emits `job_due`
- projection decides the next command
- runtime executes it mechanically

### SC

- a real local `job_due` event family exists
- clock/due crossing is recorded as a local event
- runtime no longer owns the semantic meaning of due recurring work
- mutable singleton rows are no longer the primary semantics for recurring work

### Required Checks

- projection test: valid `job_due` path accepted
- projection test: invalid/stale `job_due` path rejected or blocked
- restart test: due work survives restart and still yields the same local event
- targeted runtime test proving the clock bridge emits due events rather than
  just polling and updating rows

### End-To-End Validation

- a client with recurring work enabled can stop and restart
- overdue work still produces the correct local `job_due` event chain
- the same next command is emitted as in uninterrupted execution

## Task 4: Finish Branchy Runtime-Policy Extraction

The most important remaining runtime-owned policy is still in connection
maintenance and stale/fallback handling.

Primary files:

- `src/runtime/peering/loops/connect.rs`
- `src/runtime/peering/engine/supervisor.rs`
- related operational connection families

### Required design rule

Runtime loops should:

- execute a command
- observe a result
- author an event

They should not own retry policy, stale-target policy, precedence policy, or
worker supersession semantics.

### SC

- `connect.rs` contains no branchy stale/fallback policy beyond mechanical
  execution and event authoring
- the engine supervisor no longer owns refresh cadence or worker supersession
  semantics
- source precedence and stale-dial policy are derived from event-owned state

### Required Checks

- targeted test: repeated stale failures become terminal for the correct
  event-owned reason
- targeted test: successful authentication clears or supersedes stale-failure
  state appropriately
- targeted test: worker supersession follows event-owned policy, not loop-local
  branching

### End-To-End Validation

- competing connection candidates and repeated failures converge to the same
  connection history regardless of runtime interleaving or restart

## Task 5: Finish Event-Owned Sync Planning

Sync planner state is durable, but sync planning is still not fully event-owned.

Primary files:

- `src/runtime/sync_engine/session/windowing.rs`
- `src/runtime/sync_engine/session/initiator.rs`
- `src/event_modules/operational/sync_window_selected.rs`
- sync cadence/job families

### SC

- sync cadence is driven by local due events or projector-owned deterministic
  consequences of them
- sync window selection is event-owned, not just SQLite-backed runtime helper
  logic
- the sync engine executes already-selected rounds instead of deciding planning
  policy

### Required Checks

- projection test: valid sync-window selection path
- projection test: invalid/stale sync-window selection path
- sync contract tests for completion, cancellation, and replay safety

### End-To-End Validation

- after restart, the next selected sync window and resulting round behavior are
  the same as uninterrupted execution

## Task 6: Wire Ingress Provenance Into Real Ingest

The provenance module exists, but it is not production-wired.

Primary files:

- `src/event_modules/operational/ingress_provenance.rs`
- actual ingest/sync receive paths

### SC

- real ingest records provenance tying canonical-event arrival to connection,
  sync round, peer, and source context
- provenance is created on the production path, not just in isolated unit tests

### Required Checks

- targeted ingest-path test showing provenance is recorded on the valid path
- negative-path test showing provenance is absent or blocked when basis
  connection/round state does not exist

### End-To-End Validation

- for a received canonical event, the system can answer how it entered the node
  and through which connection/round

## Task 7: Add True Bilateral Episode Identity

Treat this phase as not met today.

The current branch has local `connection_id` and round identifiers, but not a
true cross-peer episode identity that a simulator can stitch cleanly.

Primary files:

- connection event families
- sync round event families
- any handshake/session metadata path needed to carry stitchable identity

### SC

- both sides of a connection expose stitchable shared episode identity
- both sides of a sync exchange expose stitchable shared round identity
- production validity remains single-client-local

### Required Checks

- test: both peers derive or carry the same connection episode identity
- test: both peers derive or carry the same sync round identity

### End-To-End Validation

- a two-client exchange can be paired on connection and round identity without
  heuristics beyond the intended bridge rules

## Task 8: Implement Real Multi-Client Replay/Simulation

Single-client replay is useful groundwork, but this phase is not done.

Primary files:

- `src/event_modules/operational/replay.rs`
- future simulation/merge module(s)

### SC

- the replay/simulation harness can import multiple clients
- it can interleave local streams on simulation time
- it can add simulation-only bridge edges between paired episodes
- it can project the merged result deterministically

### Required Checks

- deterministic replay test for imported multi-client streams
- test showing simulation-time ordering can differ from wall-time capture order
  while preserving expected projected results

### End-To-End Validation

- replaying a captured multi-client scenario yields the expected projected
  states across all participating clients

## Task 9: Retire Supervisors Only After Semantics Move Out

Do not retire or rename supervisors early.

Primary files:

- `src/runtime/peering/engine/supervisor.rs`
- `src/runtime/peering/loops/supervisor.rs`
- `src/runtime/control/main.rs`

### SC

- supervisor files either disappear or reduce to generic executor/reconciler
  roles
- no remaining supervisor file contains trust, fallback, cadence, precedence,
  or lifecycle policy decisions

### Required Checks

- `rg -n "trust|fallback|precedence|cadence|retry|supersed|lifecycle" src/runtime/peering/engine/supervisor.rs src/runtime/peering/loops/supervisor.rs src/runtime/control/main.rs`
- targeted regression tests proving behavior remains correct after the role
  reduction

### End-To-End Validation

- runtime behavior can be explained without caveats as:
  observe -> append local event -> project -> execute command -> append outcome

## Task 10: Boilerplate Reduction Comes Last

Do not spend the next slice on ergonomics alone.

Only do this after the remaining semantic gaps above are closed or nearly
closed.

### SC

- at least two operational families share a smaller common authoring/context
  pattern without regressions
- adding a new local operational event is materially cheaper than the current
  manual pattern

### Required Checks

- targeted unit tests for the refactored families
- no regression in parse/project/create behavior

### End-To-End Validation

- a newly introduced operational family can be added with less handwritten
  plumbing than the current baseline

## Task 11: Retention And Logging Cleanup Must Preserve Causality

The current retention work is still partial.

### SC

- retention is safe for every operational family it claims to manage
- pruning preserves latest causally winning state, not just newest timestamp
- runtime success-path logging is reduced only where events truly carry the
  durable operational narrative

### Required Checks

- prune-and-query tests per retained family
- negative tests showing superseded rows can be removed without changing
  current-state answers

### End-To-End Validation

- after retention runs, replay-relevant current-state and causal queries still
  return the same supported answers

## Minimum Proof Bar For Any Phase Claim

Do not mark a phase complete unless all three are true:

1. the SC is satisfied
2. the listed checks run and pass
3. at least one end-to-end validation demonstrates the delivered behavior

If one of those is missing, call the phase partial or groundwork, not complete.
