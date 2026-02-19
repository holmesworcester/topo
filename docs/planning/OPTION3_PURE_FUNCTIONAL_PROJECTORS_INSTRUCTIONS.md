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
4. `docs/PLAN.md` and `docs/DESIGN.md` updated with pure projector + command execution model.
5. Test gates:
   - `cargo test --test replication_contract_tests -q`
   - `cargo test --test holepunch_test -q`
   - relevant scenario replay invariance suites.
