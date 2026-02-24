# Option D Directory-Only Reorg Execution Plan

Branch: `exec/option-d-runtime-state-reorg-plan`  
Worktree: `/home/holmes/poc-7-option-d-reorg-plan`

## Worktree Rule

Do all work only in `/home/holmes/poc-7-option-d-reorg-plan`.  
Do not execute this plan in any other worktree.

## Scope (This Plan Only)

This plan is limited to directory/file organization changes:

- move files and folders to Option D locations
- update `mod.rs`, `lib.rs`, and `use` paths required by those moves
- preserve existing behavior

## Out Of Scope (Do Not Do Here)

- no logic/behavior refactors
- no API/semantic changes
- no protocol or SQL schema/migration changes
- no architecture redesign work beyond path layout
- no extra simplification efforts not required for path compilation

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

## Required Structural Tweaks

1. Keep `event_modules/` top-level. Do not add a `domain/` wrapper.
2. Rename `runtime/peering/runtime` directory to `runtime/peering/engine`.
3. Create `runtime/setup/` directory (directory-organization step only).

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

1. Rebase this branch on latest `master`.
2. Create target directories and temporary `mod.rs` scaffolding as needed.
3. Move files with `git mv` in small batches.
4. Update module declarations and imports so code compiles.
5. Remove temporary scaffolding that is no longer needed.

## Guardrails

- Function bodies should not change except import/module-path fixes.
- Keep changes mechanical and reviewable.
- Prefer rename/move diffs over content edits.

## Acceptance Criteria (Strict)

1. `src/` directory shape matches the target above.
2. No `src/domain` path exists.
3. No `src/peering/runtime` path exists; replaced by `src/runtime/peering/engine`.
4. `src/runtime/setup` directory exists.
5. Code compiles: `cargo check`.
6. Structural-only intent is preserved (no behavioral deltas introduced).

## Completion Workflow

1. Rebase on latest `master` again before finalizing.
2. Re-run `cargo check`.
3. Get review/feedback in this same worktree.
4. Address feedback until accepted.
5. Commit final directory-organization changes to this branch.
