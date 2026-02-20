# Feedback: exec/todo-remaining-non-event-locality-instructions

Date: 2026-02-20
Reviewed against: `docs/planning/TODO_REMAINING_NON_EVENT_LOCALITY_INSTRUCTIONS.md`

## Findings (post Stage 2+3 review)

### Fixed in this round

1. **Low — Straggler "replication" comment in sync session module**
   `src/sync/session/mod.rs:1`: "Replication session logic" → "Sync session logic"
   Fixed.

2. **Low — Straggler "replication" comment in sync receiver**
   `src/sync/session/receiver.rs:1`: "replication sessions" → "sync sessions"
   Fixed.

3. **Low — Straggler "replication::session" reference in peering loops**
   `src/peering/loops/mod.rs:46`: "replication::session" → "sync::session"
   Fixed.

4. **Low — Straggler "event_runtime" reference in event_pipeline comment**
   `src/event_pipeline/ingest_runtime.rs:31`: "event_runtime" → "event_pipeline", "projection::pipeline" → "projection::apply"
   Fixed.

### No remaining actionable findings

After fixing the 4 straggler comments above:

- Zero `replication`, `event_runtime`, `src/network/`, or `src/events/` references remain in `src/`.
- All mandatory grep checks pass clean.
- `cargo check` passes.
- `bash scripts/check_boundary_imports.sh` passes.
- All quality gate tests pass (446 lib, 21 sync_contract, 11 identity_transport_contract, 4 holepunch).

## What was verified

1. Stage 1 rename closure: all 3 mandatory grep checks clean in src/tests/active docs.
2. Stage 2 invite_accepted:
   - Prerequisite-free projection: `INVITE_ACCEPTED_META.dep_fields: &[]`, `signer_required: false`
   - Force-valid emission: `EmitCommand::RetryWorkspaceEvent` in `invite_accepted.rs:132`
   - Standard cascade: `RetryWorkspaceEvent` → `project_one()` in `write_exec.rs:80-96`
   - TLA conformance: `InviteAccepted` in `LocalRoots`, 4 invariants in `EventGraphSchema.tla`
   - 5 projector tests + 1 integration test (`test_invite_accepted_guard_retry_on_workspace`)
3. Stage 3 identity/transport boundary:
   - Contract: `TransportIdentityIntent` + `TransportIdentityAdapter` in `transport_identity_contract.rs`
   - Sole adapter: `ConcreteTransportIdentityAdapter` in `transport/identity_adapter.rs`
   - No raw install leaks (boundary script enforces)
   - Bootstrap path: contracts-only (no event_module imports)
   - 11 contract tests passing
4. Stage 4 docs consistency:
   - Active docs use current vocabulary
   - Archive docs have historical disclaimers
   - TODO.md items 1-26 status matches code evidence
   - Evidence matrix complete at `docs/planning/TODO_REMAINING_EVIDENCE.md`
