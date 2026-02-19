# Option 4 Execution Instructions: Event-Module Projector Locality

Date: 2026-02-19
Branch: `exec/event-locality-opt4-module-projector-locality`
Worktree: `/home/holmes/poc-7-event-locality-opt4`

## Goal

Move projector ownership into event modules so each module owns its full event lifecycle:

1. wire shape and parsing
2. schema metadata
3. projector logic
4. module-local command/query APIs

Keep behavior equivalent to current `master` unless a fix is explicitly required.

## Priority outcome

Primary outcome is readability and locality, not new features.

1. `projection/apply.rs` becomes orchestration-only.
2. `event_modules/*` owns event semantics.
3. `projection/projectors.rs` and `projection/identity.rs` stop being behavior hubs.

## Pre-flight (required)

Before implementing, rebase this branch on latest `master`:

1. `git fetch origin`
2. `git rebase origin/master`

If conflicts appear, resolve in favor of current `master` behavior, then re-apply locality changes.

## Current baseline to replace

Current pure-projector behavior exists but remains centrally splayed in:

1. `src/projection/projectors.rs`
2. `src/projection/identity.rs`
3. `src/projection/apply.rs` dispatch match

This option finishes the locality move by relocating projector implementations to event modules.

## Target architecture

### A. Registry-driven projector dispatch

Extend event metadata contract so event modules register projector handlers.

Suggested shape:

1. Add projector function pointer to `EventTypeMeta` in `src/event_modules/registry.rs`.
2. Pipeline dispatch uses registry lookup only (no large `match` for projectors).
3. `apply.rs` still handles shared orchestration stages:
   - dependency checks
   - signer verification
   - context snapshot build
   - write op execution
   - emit command execution
   - unblock cascade

### B. Module-owned projectors

Each event module file (or module folder if split later) defines its own pure projector function.

Examples:

1. `src/event_modules/message.rs` defines message projector.
2. `src/event_modules/reaction.rs` defines reaction projector.
3. `src/event_modules/message_deletion.rs` keeps two-stage deletion-intent projector.
4. identity modules (workspace/invite/user/peer/etc.) each own their projector logic.

### C. Remove central behavior splay

After migration:

1. `src/projection/projectors.rs` should be removed or reduced to temporary adapters only.
2. `src/projection/identity.rs` should be removed or reduced to temporary adapters only.
3. final dispatch should not require a giant event-type `match` for projector semantics.

## Migration plan (implementation order)

### Phase 1: Contract and scaffolding

1. Introduce registry projector hook type.
2. Add module-level projector entrypoints without changing behavior.
3. Keep temporary adapters so tests remain green during move.

### Phase 2: Content events move

Move projectors first for:

1. message
2. reaction
3. signed_memo
4. secret_key
5. message_attachment
6. file_slice
7. message_deletion

Preserve existing `ProjectorResult` semantics exactly.

### Phase 3: Identity events move

Move identity projector logic into event modules:

1. workspace
2. invite_accepted
3. user_invite
4. device_invite
5. user
6. peer_shared
7. admin
8. removals
9. secret_shared
10. transport_key

### Phase 4: Central splay removal

1. Remove now-dead dispatcher logic from `src/projection/apply.rs`.
2. Remove `src/projection/identity.rs` if unused.
3. Remove `src/projection/projectors.rs` if unused.
4. Keep `apply.rs` focused on runtime orchestration only.

### Phase 5: Doc updates

Update architecture docs so future assistants do not reintroduce splay:

1. `docs/PLAN.md`
2. `docs/DESIGN.md`

Explicitly document that event semantics must live in event modules, not central projector files.

## Deletion model requirements (must preserve)

Do not regress the current two-stage deletion model.

1. Deletion projector records deterministic `deletion_intents`.
2. If target exists, projector emits tombstone + cascade write ops.
3. If target does not exist, intent remains and target projector tombstones on first materialization.
4. signer-user mismatch and author checks stay deterministic via context snapshot.
5. replay/reorder invariants remain identical.

## POC policy

Backwards compatibility with old internal abstractions is not required. Prefer clarity and directness over compatibility shims.

## Suggested code pattern (example)

In each event module, expose a projector function that receives parsed event + context and returns `ProjectorResult`.

```rust
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    // module-owned semantics here
}
```

Then registry metadata references this function.

## Acceptance checklist

All must pass before merge:

1. `cargo check`
2. `bash scripts/check_boundary_imports.sh`
3. `cargo test --lib deletion_invariant -- --nocapture`
4. `cargo test --test replication_contract_tests -q`
5. `cargo test --test scenario_test test_zero_loss_stress -- --nocapture`

Also run any focused tests added/changed by the refactor.

## Completion criteria

This option is complete when:

1. event projector semantics are owned by event modules
2. central projector splay is removed
3. pipeline code is thinner and orchestration-only
4. docs clearly describe this locality rule for future implementers
