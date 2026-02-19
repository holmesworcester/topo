# Option 3 Execution Instructions: Pure Functional Projectors

Date: 2026-02-19
Branch: `exec/event-locality-opt3-pure-projectors`
Worktree: `/home/holmes/poc-7-event-locality-opt3`

## Scope

Convert projector logic to a `poc-6`-style pure-functional model:

1. Projectors are pure functions over `(event, context snapshot)`.
2. Projectors do not execute SQL side effects directly.
3. Projectors return deterministic outputs:
   - rows/write ops to apply
   - emitted commands/effects to execute after apply

This branch should focus on projector architecture and application flow.

## Mandatory model references

1. `poc-6` pure projector pattern and docs:
   - `/home/holmes/poc-6/docs/quiet-protocol-specification.md` (invite acceptance and trust anchoring sections)
   - `/home/holmes/poc-6/docs/tla/EventGraphSchema.tla`
2. `poc-7` model source of truth:
   - `docs/tla/EventGraphSchema.tla`
3. If semantics change, update TLA + docs first (`docs/PLAN.md`, `docs/DESIGN.md`), then code.
4. Required doc content for this branch:
   - pure projector `ProjectorResult` contract
   - command/effect execution stage semantics
   - deletion intent + tombstone lifecycle
   - replay/reorder/idempotence deletion invariants

## Core contract to implement

1. `project_pure(event, ctx) -> ProjectorResult`
2. `ProjectorResult` includes:
   - `write_ops`: inserts/updates/deletes/tombstones/guard rows
   - `emit_commands`: follow-on actions to run in a command executor stage
3. Apply engine executes `write_ops` transactionally, then executes `emit_commands` via explicit handlers.

## InviteAccepted expectations

1. Keep `invite_accepted` as local trust-anchor event.
2. It should remain projector-driven and deterministic.
3. Force-valid workspace should be represented as an emitted command/effect (not ad hoc service-side imperative logic).
4. Normal unblock cascade should proceed through the standard event pipeline.

## Deletion-specific requirements (important)

Pure functional deletion handling must preserve correctness under replay/reorder/idempotence:

1. Deletion projector should emit tombstone/intention writes, not hidden in-place imperative behavior.
2. Duplicate deletion events must be idempotent and deterministic.
3. Author/authorization checks must remain deterministic from projected/read-model state.
4. Reaction/message cleanup should be represented as explicit emitted commands/effects (or explicit write ops), not implicit side effects.
5. Reorder behavior must converge:
   - deletion before target should block/park deterministically
   - target arrival should unblock via standard cascade
6. Replay must produce identical final tombstone/message/reaction state.

## Deletion contract details (implement this way)

Use a two-stage model so deletes stay deterministic when events arrive out of order.

1. `Delete*` projector emits an idempotent `deletion_intent` write keyed by stable identity:
   - `workspace_id`
   - `target_kind` (message/reaction/etc)
   - `target_id`
2. If target exists in projected state, projector also emits target tombstone write ops in same apply batch.
3. If target does not exist yet, projector only records intent; it does not perform imperative retries.
4. Target-creation projectors must check for matching `deletion_intent` rows in their context snapshot and immediately tombstone on first materialization.
5. Cleanup work (for example message delete -> reaction tombstones) must be explicit:
   - emitted command(s), or
   - explicit deterministic write ops
   - never hidden side effects in service/network loops.
6. Deletion state must be monotonic:
   - active -> tombstoned is allowed
   - tombstoned -> active is not allowed by replay
7. Physical row removal is a separate compaction concern; projector semantics should prefer tombstones.

## Deletion invariants and tests (hard to cheat)

Add tests that validate observable invariants, not implementation details.

1. Duplicate delete event replay leaves state unchanged after first application.
2. Delete-before-create converges to the same final state as create-before-delete.
3. Restart/replay from event log reproduces identical tombstone state.
4. Authorization failure paths are deterministic from projected context snapshot.
5. Cleanup fanout is complete:
   - no live reactions remain for tombstoned message
   - no query can surface deleted entities.
6. Command execution idempotence:
   - emitted command identities are stable (derive from event identity)
   - re-running command executor does not mutate final state.

## Parallelization note

This branch is parallelizable with option 1+2 branch, but coordinate on shared contracts:

1. Command/effect enum shapes
2. Event-module ownership boundaries
3. Service/registry call expectations

Keep integration points explicit in docs to avoid merge friction.

## Acceptance checks

1. Functional projector contract is used for migrated event types.
2. Deletion paths pass replay/reorder/idempotence tests.
3. `InviteAccepted` trust-anchor behavior remains TLA-aligned.
4. `docs/PLAN.md` and `docs/DESIGN.md` updated with:
   - pure projector + command execution model
   - explicit deletion intent/tombstone contract
   - replay/reorder/idempotence invariants for deletion flows
5. Test gates:
   - `cargo test --test replication_contract_tests -q`
   - `cargo test --test holepunch_test -q`
   - relevant scenario replay invariance suites.
