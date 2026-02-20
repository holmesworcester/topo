# TODO 1 Instructions: Symbol Rename Cleanup

Date: 2026-02-19
Branch: `exec/todo1-symbol-rename-instructions`
Worktree: `/home/holmes/poc-7-todo1-symbol-rename`

## Goal

Finish the remaining naming cleanup for protocol/sync/session symbols so names communicate boundaries without reading implementation details.

POC rule: do not preserve backward-compatibility aliases unless they are needed briefly within the same branch during the refactor. Final branch state should remove old names.

## Required start step

1. `git fetch origin`
2. `git rebase origin/master`

## Remaining rename targets (from TODO)

1. `protocol::SyncMessage` naming:
   - Rename enum `SyncMessage` to `Frame` in `src/protocol.rs`.
   - Rename helpers `parse_sync_message` -> `parse_frame`, `encode_sync_message` -> `encode_frame`.
   - Export directly from `src/protocol.rs` using the new names.

2. Session runner naming:
   - `run_sync_initiator_dual` -> `run_sync_initiator`.
   - `run_sync_responder_dual` -> `run_sync_responder`.
   - Update all imports/callers in `src/` and `tests/`.

3. Session IO naming:
   - Rename `SessionIo` trait in `src/contracts/network_contract.rs` to `TransportSessionIo`.
   - Rename `SessionIoParts` to `TransportSessionIoParts`.
   - Rename `SessionIoError` to `TransportSessionIoError`.
   - Rename `src/transport/session_io.rs` to `src/transport/transport_session_io.rs`.
   - Rename concrete transport adapter `SyncSessionIo` to `QuicTransportSessionIo`.

4. Sync session type naming:
   - Confirm there is no concrete `sync::Session` type left.
   - If any new/remaining generic `Session` type exists in `sync`, rename to `SyncSession`.

## Constraints

1. No runtime behavior changes.
2. No protocol wire changes.
3. No compatibility shim left behind in final state unless justified in commit message.

## Execution order

1. Rename protocol frame symbols (`SyncMessage` family) first.
2. Rename sync runner function names second.
3. Rename IO contract symbols third.
4. Rename transport session IO module/file and concrete adapter name.
5. Update tests and internal docs/comments for final names.

## Mandatory searches before commit

1. `rg -n "\\bSyncMessage\\b|parse_sync_message|encode_sync_message" src tests`
2. `rg -n "run_sync_initiator_dual|run_sync_responder_dual" src tests`
3. `rg -n "\\bSessionIo\\b|SessionIoParts|SessionIoError|session_io" src tests`
4. `rg -n "crate::protocol::SyncMessage" src tests`

All should return zero relevant hits (ignoring archived docs if they are not touched in this branch).

## Quality gates

1. `cargo check`
2. `bash scripts/check_boundary_imports.sh`
3. `cargo test --test replication_contract_tests -q`
4. `cargo test --test holepunch_test -q`

## Done criteria

1. Public names use `Frame`, `run_sync_initiator`, `run_sync_responder`, and `TransportSessionIo*` consistently.
2. No old symbol names remain in `src/` or `tests/`.
3. All quality gates pass.
