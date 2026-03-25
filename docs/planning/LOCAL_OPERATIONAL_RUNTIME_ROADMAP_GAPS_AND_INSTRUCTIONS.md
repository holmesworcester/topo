# Local Operational Runtime Roadmap Gaps And Instructions

Date: 2026-03-25  
Reviewed branch: `codex/local-operational-runtime-roadmap`  
Reviewed branch tip: `fd0e337450cc48f168487c93a71b765255ef9d5b`  
Current source branch: `codex/local-operational-runtime-align`  
Current source tip at review time: `88e1006c6358dc9d7ae7355f6b467b082a7776e0`

## Purpose

This document records the gap between:

1. the full Success Criteria (SCs) in
   `docs/planning/LOCAL_OPERATIONAL_RUNTIME_COMPLETION_EXECUTION_PLAN.md`, and
2. the actual implementation state on the current roadmap branch.

Use this as the execution reality check. Do not mark roadmap phases complete
unless the phase satisfies its own SCs, required checks, and end-to-end
validation criteria.

## Overall Verdict

This branch contains real progress, but it does **not** satisfy the full
roadmap SCs.

Current status by phase:

- Phase 1: partial
- Phase 2: not met
- Phase 3: partial
- Phase 4: partial
- Phase 5: partial
- Phase 6: not met
- Phase 7: partial
- Phase 8: not met
- Phase 9: not met
- Phase 10: not met
- Phase 11: partial

The branch currently looks like:

- meaningful groundwork for the target architecture,
- several partial implementations,
- later-phase scaffolding,
- but not phase-complete delivery.

## Immediate Instruction

Do not let commit titles, phase headings, or status notes imply that Phases
2-11 are complete.

If a phase is only scaffolding or a partial slice, say so explicitly in code,
docs, and commit messages. The execution bar is the roadmap SCs, not whether a
module or helper with the right name exists.

## Snapshot Mismatch

The roadmap doc still claims it is based on source tip
`4a7e3a3363c2baf1588ddefdfcdbdc5d26caa54d` in
`docs/planning/LOCAL_OPERATIONAL_RUNTIME_COMPLETION_EXECUTION_PLAN.md:3-21`.

That is stale. At review time:

- roadmap branch head is `fd0e337450cc48f168487c93a71b765255ef9d5b`
- source branch head is `88e1006c6358dc9d7ae7355f6b467b082a7776e0`

### Instruction

- Either update the snapshot metadata to match reality, or remove the exact
  pinned tip from the doc.
- Do not leave stale source-tip claims in execution docs.

### SC

- The roadmap doc no longer claims an outdated source snapshot.

### Checks

- `rg -n "4a7e3a|88e1006|Source branch tip commit|Snapshot Note" docs/planning/LOCAL_OPERATIONAL_RUNTIME_COMPLETION_EXECUTION_PLAN.md`

## Phase-By-Phase Gaps

### Phase 1: Remove Remaining Branchy Runtime Policy

This is improved, but not done.

Evidence:

- `src/runtime/peering/loops/connect.rs:174-177` still keeps in-memory fallback
  state with `fallback_has_connected_once` and `fallback_stale_failures`.
- `src/runtime/peering/loops/connect.rs:214-259` still decides stale-dial
  terminal branching locally.
- `src/runtime/peering/loops/supervisor.rs:37-70` is better because it returns
  typed `SessionOutcome`, but that only covers part of the policy extraction.

### Instruction

- Finish moving stale-dial threshold policy, startup warning policy, and any
  terminal stale-target reasoning into operational event families.
- The connect loop should execute a command, observe a result, and author an
  event. It should not own stateful retry policy.

### SC

- `connect.rs` contains no branchy stale/fallback policy beyond mechanical
  execution and event authoring.
- Session close classification is fully event-owned or event-family-owned.

### Required Checks

- Targeted connect-loop tests proving valid and invalid stale-target handling.
- At least one valid-path and one break-path projection test for the affected
  connection event family.

### End-To-End Validation

- A connection that repeatedly hits stale-dial failure must become terminal for
  the same reason whether run continuously or after restart/replay.

### Phase 2: Event-Own Listener and Resource Lifecycle

This phase is not met.

Evidence:

- There is no listener event family in
  `src/event_modules/operational/mod.rs:1-40`.
- `src/runtime/control/main.rs:2072-2127` still directly calls
  `reserve_idle_bind(...)` and `spawn_runtime(...)`.
- `rg -n "listener_|bind_failed|listener_bound|listener_closed|listener_configured" src/event_modules/operational src/runtime/control/main.rs`
  returns no event-family hits.

### Instruction

- Add real listener/resource lifecycle events under `src/event_modules/operational/`.
- Listener existence must be event-governed state, not just projected client
  state plus runtime mechanics.
- `main.rs` should reconcile desired listener/runtime state, not own listener
  semantics.

### SC

- Listener desired state, bind success, bind failure, and listener close are
  all represented as local operational events with projector-owned tables.
- `main.rs` no longer decides listener lifecycle policy.

### Required Checks

- Projection tests for listener-configured, listener-bound, listener-bind-failed,
  and listener-closed.
- Runtime tests for bind success, bind failure, and close.

### End-To-End Validation

- `client_started` causes listener intent to exist, bind results are emitted as
  events, and `client_stopped` suppresses listener existence.

### Phase 3: Add the Durable Jobs and Clock Bridge

This phase is partial.

Evidence:

- `src/event_modules/operational/durable_jobs.rs:65-76` defines a mutable
  `durable_jobs` table keyed by `(client_id, job_kind)`.
- `src/event_modules/operational/durable_jobs.rs:97-100` uses
  `ON CONFLICT ... DO UPDATE`.
- `src/event_modules/operational/durable_jobs.rs:109-110` and `179-183` use
  `UPDATE`.
- `src/runtime/peering/engine/supervisor.rs:512-664` still polls due jobs,
  sleeps, and marks completion from runtime code instead of turning due time
  into local events.

### Instruction

- Keep the job registry if useful, but move to the intended model:
  due time -> local `job_due` event -> projector decides next command.
- Do not treat mutable due rows plus runtime polling as phase completion.

### SC

- There is a real local `job_due` event family.
- Clock crossing is recorded as a local event.
- Runtime no longer owns the semantic meaning of due recurring work.

### Required Checks

- Valid-path and invalid-path projection tests for `job_due`.
- Restart-safe due-work tests.

### End-To-End Validation

- A client restarted after downtime still emits the correct due work from
  durable state and yields the same causal chain as uninterrupted execution.

### Phase 4: Move Connection Maintenance Policy Fully Into Event Families

This phase is partial.

Evidence:

- The jobs layer exists, but `src/runtime/peering/engine/supervisor.rs:512-664`
  still owns refresh-loop mechanics and due-work completion.
- Connection maintenance is still coordinated by the runtime task graph in
  `src/runtime/peering/engine/supervisor.rs`.

### Instruction

- Move connection refresh and worker supersession semantics out of the engine
  supervisor and into connection-plan and job event families.
- The supervisor should become a generic reconciler over desired workers.

### SC

- Source precedence, refresh cadence, and worker supersession are all derived
  from event-owned state.
- The engine supervisor no longer acts as a semantic brain.

### Required Checks

- Targeted tests for precedence, supersession, and reconnect cadence.

### End-To-End Validation

- Competing bootstrap/discovery/observed targets converge to the same desired
  connection state regardless of runtime interleaving.

### Phase 5: Finish Event-Owned Sync Planning

This phase is partial.

Evidence:

- `src/runtime/sync_engine/session/windowing.rs` still owns planner selection
  mechanics even though planner state is durable.
- `src/runtime/sync_engine/session/initiator.rs:128-141` still selects the
  outbound window in runtime code and then authors round events.
- `src/event_modules/operational/sync_window_selected.rs` explicitly describes
  itself as durable planner state for the "future" local event family.

### Instruction

- Complete the last step: range/window selection and cadence decisions must be
  event-owned, not just SQLite-backed runtime helpers.
- The sync engine should execute already-decided rounds, not plan them.

### SC

- Sync cadence and sync window selection are local events or projector-owned
  deterministic consequences of local due events.
- Runtime sync code no longer decides planning policy.

### Required Checks

- Projection tests for valid and invalid sync-window selection paths.
- Sync contract tests for completion, cancellation, and replay safety.

### End-To-End Validation

- Replaying a client across restarts yields the same next sync window and round
  behavior from durable state alone.

### Phase 6: Record Ingress Provenance

This phase is not met.

Evidence:

- `src/event_modules/operational/ingress_provenance.rs` defines helper/query
  code, but `rg -n "record_ingress_batch|query_provenance|count_events_in_round" src tests`
  shows only module-local tests and no production call sites.

### Instruction

- Wire provenance recording into real ingest paths.
- Provenance must be created by the actual sync/ingest path, not just exist as
  an unused helper.

### SC

- Production ingest records provenance tying canonical-event arrival to
  connection, sync round, peer, and arrival context.

### Required Checks

- At least one projection/ingest-path test showing provenance written on the
  valid path.
- At least one negative-path test showing it is blocked or absent when the
  basis connection/round does not exist.

### End-To-End Validation

- For a received canonical event, the system can answer which connection and
  sync round delivered it.

### Phase 7: Add Bilateral Episode Identity

This phase is partial.

Evidence:

- Connection and round identifiers exist in local families, but there is no
  clear simulator-facing bridge layer yet.
- No implemented simulation bridge or bilateral pairing path is present in the
  operational modules.

### Instruction

- Keep shared episode identity separate from shared event ids.
- Carry stable `connection_id` and `sync_round_id` semantics through both sides
  so the later simulator can stitch them deterministically.

### SC

- Both sides of a connection/sync exchange expose stitchable episode identity.
- Production validity remains single-client-local.

### Required Checks

- Tests proving both sides can derive or carry the same episode identity.

### End-To-End Validation

- A two-client exchange can be paired on `connection_id` and `sync_round_id`
  without ad hoc heuristics.

### Phase 8: Build the Replay and Simulation Harness

This phase is not met.

Evidence:

- `src/event_modules/operational/replay.rs:1-8` explicitly says full
  multi-client merge and virtual-time simulation are deferred.
- The implemented API is `replay_single_client(...)`.

### Instruction

- Do not claim this phase complete until multi-client import, interleaving, and
  virtual-time execution exist.
- Keep single-client replay, but label it as groundwork for Phase 8.

### SC

- A replay/simulation harness can import multiple clients, interleave local
  streams, add simulation-only bridge edges, and project the merged history.

### Required Checks

- Deterministic replay tests for multi-client imported streams.

### End-To-End Validation

- A recorded multi-client scenario can be replayed on simulation time and
  produce the expected projected state transitions.

### Phase 9: Retire Bespoke Supervisors

This phase is not met.

Evidence:

- `src/runtime/peering/engine/supervisor.rs` is still a central runtime
  supervisor.
- `src/runtime/peering/loops/supervisor.rs` still exists as a specialized
  supervision layer.
- `src/runtime/control/main.rs:2063-2145` still acts as the host-side
  reconciler and lifecycle owner.

### Instruction

- Do not call a supervisor retired until it contains no branchy semantic
  policy.
- Rename remaining pieces to `reconciler` or `executor` only when that is
  actually true.

### SC

- Runtime supervisor files either disappear or reduce to generic adapter,
  reconciler, or executor roles.

### Required Checks

- No remaining runtime supervisor file contains trust, fallback, cadence,
  precedence, or lifecycle policy decisions.

### End-To-End Validation

- Runtime behavior can be explained as:
  observe -> append local event -> project -> execute command -> append outcome.

### Phase 10: Reduce Boilerplate and Improve Event-Family Ergonomics

This phase is not met.

Evidence:

- The branch still uses many flat operational files with repeated wire/context
  patterns.
- The local-event authoring path is still largely manual.

### Instruction

- Do not treat new modules alone as progress here.
- Centralize common basis-edge loading, current-leaf resolution, and local
  event authoring patterns.

### SC

- Adding a new local operational event no longer requires another full custom
  parse/encode/context boilerplate stack.

### Required Checks

- Refactor at least two existing operational families to the shared abstraction
  without behavior regression.

### End-To-End Validation

- A newly added operational event family is materially smaller than the current
  handwritten pattern.

### Phase 11: Retention, TTL, Logging Cleanup, and Final Convergence

This phase is partial.

Evidence:

- `src/event_modules/operational/retention.rs:1-78` prunes only a few tables.
- It keeps "latest" rows by `created_at` and `rowid`, not by causal-leaf
  semantics.
- This is not yet a full retention policy for the operational model.

### Instruction

- Retention must preserve causal correctness, not just latest timestamp.
- Logging cleanup should continue only after the event stream fully carries the
  durable operational narrative.

### SC

- TTL/retention is safe for all local operational histories that claim to be
  pruneable.
- Retention keeps the latest causally winning rows, not just the newest by
  timestamp.

### Required Checks

- Prune-and-query tests for every retained operational family.
- Negative tests showing stale/superseded rows can be pruned without changing
  current-state queries.

### End-To-End Validation

- After retention runs, replay-relevant current-state and causal queries still
  return the same answers for supported families.

## Execution Order Recommendation

Use this order:

1. fix snapshot metadata and phase-status claims
2. complete Phase 2 listener/resource lifecycle
3. complete Phase 3 true clock-bridge eventization
4. finish remaining Phase 1 and Phase 4 runtime-policy extraction
5. complete Phase 5 sync planning ownership
6. wire Phase 6 provenance into real ingest
7. complete Phase 7 bilateral episode identity
8. complete Phase 8 multi-client replay/simulation
9. retire supervisors only after the above are done
10. compress boilerplate and finalize retention/logging

## Evidence Checks Run For This Review

These checks passed on reviewed branch head `fd0e337450cc48f168487c93a71b765255ef9d5b`:

- `cargo check --tests`
- `cargo test start_runtime_enables_durable_jobs_stop_disables -- --nocapture`
- `cargo test record_and_query_provenance -- --nocapture`
- `cargo test replay_single_client_projects_client_started -- --nocapture`

These passing checks show that scaffolding compiles and narrow unit tests work.
They do **not** prove the roadmap SCs are met.
