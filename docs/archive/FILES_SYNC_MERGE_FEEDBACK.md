# File-Sync Merge Review (post-revert)

> **Historical feedback; file paths may not match the current source tree.**

## Commit reviewed
- `13a4a44` (`Universal signing, PeerKey deprecation, and file slice authorization`)

## What was wrong
- `src/main.rs` used `SELECT ... FROM peers_shared ... LIMIT 1` when selecting the local signer for CLI bootstrap, which can pick a non-local peer in multi-peer state.
- `src/projection/pipeline.rs` retried file-slice guard blocks by scanning all guard-blocked file-slice events on every `message_attachment` projection (O(history) behavior).
- `src/projection/projectors.rs` authorized file slices by `file_id -> first descriptor signer` without deterministic tie-breaking or conflict handling when multiple descriptors share a `file_id`.

## Fixes applied on `files-sync-fixup`
- Local signer selection is now explicit/local-only:
  - added `local_peer_signers` mapping and legacy recovery path.
  - removed arbitrary `peers_shared LIMIT 1` selection.
  - files: `src/main.rs:500`, `src/main.rs:560`, `src/main.rs:611`.
- File-slice guard unblock is now targeted by `file_id`:
  - added `file_slice_guard_blocks(peer_id, file_id, event_id)`.
  - `message_attachment` projection retries only the waiting slices for that file.
  - files: `src/projection/pipeline.rs:247`, `src/projection/pipeline.rs:257`.
- File-slice/descriptor relationship is now explicit at projection:
  - added `file_slices.descriptor_event_id`.
  - deterministic descriptor selection and conflicting-signer rejection.
  - files: `src/projection/projectors.rs:265`, `src/projection/projectors.rs:322`.
- Schema migration for both changes:
  - file: `src/db/migrations.rs:356` (migration `15`).

## Tests run
- `cargo test --test cli_test -- --nocapture`
- `cargo test projection::pipeline::tests::test_file_slice -- --nocapture`
- `cargo test projection::pipeline::tests::test_file_slice_unblocks_when_signer_arrives -- --nocapture`
- `cargo test projection::pipeline::tests::test_file_slice_wrong_signer_rejected -- --nocapture`
- `cargo test --test scenario_test test_identity_then_messaging -- --nocapture`

## Remaining design gaps (not fixed in this patch)
- TLA model includes a local non-shared `Peer` identity event, but runtime still centers local authoring on `PeerShared*` and ad hoc local signer tables:
  - spec reference: `docs/tla/EventGraphSchema.tla:73`.
  - implementation currently has no `Peer` event type in Rust event registry.
- Several CLI/perf/scenario tests still model "independent identities + blocked remote messages" as expected behavior, which is useful for policy coverage but not a realistic end-user messaging scenario:
  - examples: `tests/cli_test.rs:150`, `tests/perf_test.rs:156`, `tests/scenario_test.rs:39`.

## Recommended next phase
- Implement first-class local `Peer` event + `peer_self` mapping (poc-6 style) and make all local signer selection flow through it.
- Add realistic cross-peer sync tests that bootstrap shared workspace first, then assert remote messages project (while keeping blocked-policy tests separately scoped).
