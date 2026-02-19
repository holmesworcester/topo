# Option 1+2 Execution Instructions: Event Locality + Registry Dispatch

Date: 2026-02-19
Branch: `exec/event-locality-opt12`
Worktree: `/home/holmes/poc-7-event-locality-opt12`

## Scope

This branch is for:

1. Option 1: move event-specific command/query logic out of `src/service.rs` into event-owned modules.
2. Option 2: add typed command/query registry dispatch so service paths call event-module handlers.

Do not attempt Option 3 (pure functional projector conversion) in this branch.

## Goals

1. Maximize locality: for each event type, keep schema + create/query helpers + projector entrypoints close together.
2. Thin `service`: service should mostly provide DB/tenant context, auth inputs, and output shaping.
3. Reduce scattered SQL in service paths.
4. Keep behavior identical (no semantic protocol changes in this branch).

## Non-Goals

1. No invite/bootstrap semantic rewrites.
2. No trust-anchor model changes.
3. No cascade algorithm redesign.

## Required alignment docs

1. `TODO.md` (Event-module locality follow-up section).
2. `docs/PLAN.md` and `docs/DESIGN.md` must be updated with the new layering pattern so future implementers do not re-scatter event logic in `service.rs`.

## Suggested implementation sequence

1. Pick one vertical slice first: `message` + `reaction` + `message_deletion` + `user_removed`.
2. Move create/query helpers from `service.rs` into event-owned modules.
3. Introduce typed registry dispatch (commands and queries) in `events` layer.
4. Convert service methods to call registry/event-module APIs.
5. Expand same pattern to remaining clear event-owned slices.

## Acceptance checks

1. `service.rs` no longer embeds event-specific SQL for migrated slices.
2. Service methods still expose same external response shapes.
3. `cargo test --test replication_contract_tests -q`
4. `cargo test --test holepunch_test -q`
5. `bash scripts/check_boundary_imports.sh`

## Notes for follow-on branch

Option 3 is expected to run in parallel branch `exec/event-locality-opt3-pure-projectors` and should consume these APIs/contracts where possible.
