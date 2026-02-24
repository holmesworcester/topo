# Option D Runtime-State Reorg Execution Plan

Branch: `exec/option-d-runtime-state-reorg-plan`  
Worktree: `/home/holmes/poc-7-option-d-reorg-plan`

## Worktree Rule

Do all reorg work only in `/home/holmes/poc-7-option-d-reorg-plan`.  
Do not implement any part of this plan in another worktree.

## Goal

Restructure `src/` toward Option D boundaries:

- `runtime/` for runtime orchestration
- `state/` for persistence, pipeline, projection state
- `shared/` for small cross-cutting primitives
- `event_modules/` at top-level (no `domain/` wrapper)

Keep behavior unchanged. This is a mechanical layout and module-boundary cleanup.

## Target Directory Shape (No Files)

```text
src/
├── event_modules/
├── runtime/
│   ├── control/
│   │   └── rpc/
│   ├── setup/
│   ├── peering/
│   │   ├── loops/
│   │   ├── nat/
│   │   ├── engine/
│   │   └── workflows/
│   ├── sync_engine/
│   │   └── session/
│   └── transport/
├── shared/
│   ├── contracts/
│   └── crypto/
├── state/
│   ├── db/
│   ├── pipeline/
│   └── projection_state/
│       └── apply/
│           └── tests/
└── testutil/
```

## Minimal Tweaks Required

1. Remove `domain/` wrapper entirely. `event_modules/` stays top-level.
2. Rename `runtime/peering/runtime` to `runtime/peering/engine`.
3. Add `runtime/setup/` and move endpoint/tenant startup assembly there.
4. Keep `shared/` intentionally small:
   - allowed: contracts, crypto, protocol, tuning
   - disallowed: feature logic, orchestration, DB writes, sync loops
5. Draw a hard ownership line:
   - `state/pipeline`: ingest persistence, queueing, effects boundary
   - `runtime/sync_engine`: session control/data orchestration and coordination

## Move Map (Source -> Target)

- `src/rpc/*` -> `src/runtime/control/rpc/*`
- `src/main.rs` -> `src/runtime/control/main.rs`
- `src/node.rs` -> `src/runtime/control/node.rs`
- `src/service.rs` -> `src/runtime/control/service.rs`
- `src/assert.rs` -> `src/runtime/control/assert.rs`
- `src/db_registry.rs` -> `src/runtime/control/db_registry.rs`
- `src/peering/*` -> `src/runtime/peering/*`
- `src/runtime/*` (old tiny module) -> `src/runtime/sync_engine/runtime.rs` (or delete if obsolete)
- `src/transport/*` -> `src/runtime/transport/*`
- `src/sync/*` -> `src/runtime/sync_engine/*`
- `src/event_pipeline/*` -> `src/state/pipeline/*`
- `src/projection/*` -> `src/state/projection_state/*`
- `src/db/*` -> `src/state/db/*`
- `src/contracts/*` -> `src/shared/contracts/*`
- `src/crypto/*` -> `src/shared/crypto/*`
- `src/protocol.rs` -> `src/shared/protocol.rs`
- `src/tuning.rs` -> `src/shared/tuning.rs`
- `src/event_modules/*` stays `src/event_modules/*`
- `src/testutil/*` stays `src/testutil/*`

## Implementation Sequence

1. Create scaffolding modules and re-export shims first.
2. Move files with `git mv` in small batches (control, state, runtime, shared).
3. Rename `runtime/peering/runtime` to `runtime/peering/engine`.
4. Introduce `runtime/setup` and route startup assembly through it.
5. Update `mod.rs`, `lib.rs`, and imports crate-wide.
6. Remove temporary shims only after tests are green.
7. Update docs that reference old paths.

## Guardrails

- No protocol format changes.
- No SQLite schema/migration semantic changes.
- No behavior changes in sync or trust policy.
- No moving `event_modules` under `domain`.

## Acceptance Criteria (Strict)

1. `src/` shape matches target structure above.
2. No `src/domain` path exists.
3. No `src/peering/runtime` path exists; replaced by `src/runtime/peering/engine`.
4. `src/runtime/setup` exists and owns startup endpoint/tenant wiring.
5. `shared/` contains only allowed low-level primitives.
6. `cargo check` passes.
7. `cargo test -q trust_resolution_uses_sql_state` passes.
8. `cargo test -q test_is_peer_allowed_checks_all_sources` passes.
9. `docs/CURRENT_RUNTIME_DIAGRAM.md` remains consistent with renamed boundaries.

## Completion Workflow

1. Rebase this branch on current `master`.
2. Re-run validation commands.
3. Request review/feedback in this same worktree.
4. Address feedback until accepted.
5. Commit all final changes to this branch.
