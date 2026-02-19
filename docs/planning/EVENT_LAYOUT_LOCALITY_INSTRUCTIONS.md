# Event Layout Locality Instructions

Date: 2026-02-19
Branch: `exec/layout-locality-instructions`
Worktree: `/home/holmes/poc-7-layout-locality-instructions`

## Goal

Replace the monolithic `src/event_modules/fixed_layout.rs` model with locality-first ownership:

1. Event-specific wire sizes/offsets live with the event module.
2. Shared cross-event wire helpers stay centralized.
3. Do not create extra files for small events.

This is an architecture + refactor plan. Behavior must remain equivalent.

## Core Rule Set

1. If an event module is a single file (`foo.rs`), keep that event's layout constants in `foo.rs`.
2. If an event module is a folder (because event logic is large), put layout constants in `foo/layout.rs`.
3. Shared primitives used by many events belong in a single shared module (suggested: `src/event_modules/layout/common.rs`).
4. Event modules must not import another event module's layout constants.
5. Keep registry centralized (`src/event_modules/registry.rs`) and import exported per-event constants from each owning module.

## Non-Goals

1. No protocol semantics change.
2. No event type renumbering.
3. No projector behavior changes.
4. No dependency policy changes.
5. No broad module naming rewrite outside the layout concern.

## Current Pain

`src/event_modules/fixed_layout.rs` mixes:

1. Shared primitives (`read_text_slot`, `write_text_slot`, common wire math), and
2. Per-event sizes/offsets for many event types.

That creates low locality and makes event changes span unrelated files.

## Target Structure

Suggested minimum structure:

1. `src/event_modules/layout/common.rs`
2. `src/event_modules/layout/mod.rs`
3. Per-event inline layout in single-file modules:
   - `src/event_modules/reaction.rs`
   - `src/event_modules/workspace.rs`
   - `src/event_modules/user.rs`
   - etc.
4. Per-event `layout.rs` only for folderized modules:
   - `src/event_modules/message/layout.rs` (already folderized)
   - future folderized events only when needed for logic size.

## Shared Module Scope (`layout/common.rs`)

Keep only cross-event primitives here:

1. `COMMON_HEADER_BYTES`
2. `SIGNATURE_TRAILER_BYTES`
3. Encrypted generic helpers that are truly cross-event (`encrypted_wire_size(...)`, etc.)
4. Text slot helpers and `TextSlotError`
5. Generic utility helpers with no event ownership

Do not place `message_offsets`, `reaction_offsets`, etc. in shared.

## Per-Event Ownership Examples

Examples of ownership after migration:

1. `message` owns `MESSAGE_WIRE_SIZE`, `MESSAGE_CONTENT_BYTES`, and `message_offsets`.
2. `reaction` owns `REACTION_WIRE_SIZE`, `REACTION_EMOJI_BYTES`, and `reaction_offsets`.
3. `workspace` owns `WORKSPACE_WIRE_SIZE`, `NAME_BYTES` usage decisions, and `workspace_offsets`.
4. `peer_shared` owns `PEER_SHARED_WIRE_SIZE` and `peer_shared_offsets`.

If two events share a field budget value (for example display name width), keep only the generic budget in `layout/common.rs` and keep each event's offsets local.

## Suggested Migration Sequence

### Phase 1: Scaffolding

1. Create `src/event_modules/layout/common.rs`.
2. Move shared helpers/constants from `fixed_layout.rs` into `layout/common.rs`.
3. Add compatibility re-exports if needed to keep compile green during move.

### Phase 2: Event-by-event locality moves

1. Move each event's offsets/sizes into owning module.
2. Update parser/encoder imports to use local constants.
3. Keep changes mechanical; no logic changes.

Recommended order:

1. `message` (folderized)
2. `reaction`
3. `signed_memo`
4. `workspace`, `user`, `peer_shared`
5. attachment/file-slice/encrypted
6. remaining identity/admin/invite/remove modules

### Phase 3: Registry and callsite cleanup

1. Update any registry/test imports that currently use `fixed_layout::*`.
2. Remove stale `fixed_layout` references.
3. Keep registry as central metadata authority, not layout owner.

### Phase 4: Remove monolith

1. Delete `src/event_modules/fixed_layout.rs` once unused.
2. Ensure no import path still references it.

## Guardrails

1. Do not create a folder for an event solely to hold layout constants.
2. If an event is still concise, keep a single `*.rs` file.
3. Split into folder only when event logic size/complexity warrants it.
4. If split happens later, move that event's inline layout block to `layout.rs` within the new folder.

## Verification

Run at minimum:

1. `cargo check`
2. `cargo test event_modules -- --nocapture`
3. `cargo test projection::apply -- --nocapture`
4. `cargo test --test replication_contract_tests -q`
5. `bash scripts/check_boundary_imports.sh`

Also run any event-specific wire roundtrip tests touched by migration.

## Acceptance Criteria

1. No per-event layout constants remain in a global monolith.
2. Single-file events own their layout inline.
3. Folderized events own layout in `layout.rs`.
4. Shared common helpers exist in one shared location.
5. Tests pass without semantic behavior changes.

## Documentation Follow-up

Once implementation branch starts, update:

1. `docs/PLAN.md`
2. `docs/DESIGN.md`

State the locality rule explicitly so future contributors do not reintroduce a global event layout monolith.
