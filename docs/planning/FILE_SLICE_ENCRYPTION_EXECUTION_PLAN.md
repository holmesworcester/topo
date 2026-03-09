# File Slice Encryption Execution Plan

Date: 2026-03-09
Branch/worktree context for this task:
- Branch: `codex/file-slice-encryption`
- Worktree: `/home/holmes/poc-7-file-slice-encryption`
- Base: local `master` after merging the effective file download rate work

## Summary

Change file transfer so file slices are sent as outer `encrypted` events whose
inner event is `file_slice`, while preserving:

1. correct file sync and `save-file` behavior,
2. correct attachment/file MiB/s display,
3. acceptable sync performance,
4. efficient streaming decrypt/save behavior for large files.

This plan intentionally does not preserve backward compatibility for plain outer
`file_slice` transfer in the normal send-file path.

## Decisions already made

1. **Use outer `EncryptedEvent`**.
   Do not invent a custom AEAD layout inside `FileSliceEvent`.

2. **Encrypt slices only**.
   `FileEvent` metadata stays cleartext for now. Only slice transfer changes.

3. **Reuse existing content-key machinery**.
   Use `FileEvent.key_event_id` / existing content key handling as the AES key
   reference for slice encryption.

4. **Black-box acceptance target comes first**.
   Before the refactor, add the missing high-level CLI acceptance test if it
   does not already exist.

5. **Transport privacy policy must be explicit**.
   Whether an event type is allowed to travel as plaintext or must be outer
   encrypted should be encoded in metadata/registry policy and tested, not left
   as convention.

6. **`save-file` must become streaming and timed**.
   The CLI result should report how long decrypt+save took, and the
   implementation must not require the whole file plaintext in memory.

## Problem

Today normal file uploads create outer `file_slice` events. The current
effective download-rate feature works by linking incoming slice-carrying sync
runs to file slice event IDs so the UI can show a real MiB/s number. Moving
file slices to outer `encrypted(file_slice)` changes the receive-time event
shape, so both transport behavior and the MiB/s linkage logic need to be
updated together.

## Goals

1. Normal file transfer emits outer `encrypted(file_slice)`.
2. `save-file` restores exact original bytes after sync.
3. Downloaded attachments still show MiB/s in `topo messages`.
4. Downloaded files still show MiB/s in `topo files`.
5. Local-only files still do not show fake download MiB/s.
6. The refactor has a stable end-to-end CLI acceptance test.
7. Transport privacy policy for event types is explicit and tested.
8. `save-file` reports elapsed decrypt/save time.
9. `save-file` decrypts and writes incrementally so large files can fit within
   the iOS NSE memory target.

## Non-goals

1. No file metadata encryption in this change.
2. No per-file bespoke AEAD format.
3. No backward compatibility requirement for normal plaintext slice transfer.
4. No acceptance of whole-file plaintext buffering during `save-file`.

## Required execution order

1. Add or tighten the high-level black-box CLI acceptance test first.
2. Implement outer `encrypted(file_slice)` transport.
3. Update receive-side MiB/s linkage logic for `encrypted(file_slice)`.
4. Refactor `save-file` to stream decrypt/write and report elapsed time.
5. Add transport/privacy policy checks and tests.
6. Run targeted tests and perf spot checks.
7. Commit the completed work on `codex/file-slice-encryption`.

## Black-box CLI acceptance target

Before the refactor, ensure there is a high-level CLI test that proves, using
CLI-observable behavior only:

1. Alice sends a file.
2. Bob syncs it.
3. Bob sees the attachment complete.
4. Bob sees MiB/s in `topo messages`.
5. Bob sees MiB/s in `topo files`.
6. `save-file` restores exact original bytes.

This test should not inspect whether the transferred slice events are outer
encrypted. That is a lower-level contract check and should live in separate
tests.

## Design

### 1. Outer encrypted file slices

Update normal file transfer to emit:

- outer event type: `encrypted`
- `inner_type_code`: `file_slice`
- encryption path: existing `create_encrypted_event_synchronous(...)`

Do not add a custom nonce/tag/ciphertext layout to `FileSliceEvent`.

### 2. Keying model

Use the existing `FileEvent.key_event_id` / content key machinery as the AES
key reference for slice encryption. This keeps file transfer aligned with the
existing encrypted-event path and avoids inventing a separate key-distribution
scheme in this change.

### 3. MiB/s linkage requirement

The current effective download-rate feature depends on linking incoming
slice-carrying sync runs to event IDs during receive.

Since file slices will now arrive as outer `encrypted` events, the receive-side
capture predicate must record `(run_id, event_id)` links for outer
`encrypted(file_slice)` traffic. If this is missed, file downloads may still
work, but the MiB/s display will silently disappear.

### 4. Streaming save-file requirement

Current `save-file` behavior accumulates the entire file plaintext in memory
before writing it to disk. That is not acceptable for this work.

Refactor `save-file` so it:

1. reads slices in order,
2. decrypts each slice independently,
3. writes each slice directly to the output stream/file,
4. truncates the final slice to the real file length,
5. avoids building the whole plaintext file in memory,
6. reports total elapsed decrypt+save time in the CLI output/result.

The implementation should be viable for large files under the iOS NSE memory
target (`24 MiB` operational budget).

### 5. Explicit transport privacy policy

Introduce or reuse explicit metadata describing whether an event type:

1. must be outer encrypted,
2. may be plaintext,
3. is plaintext-only.

`file_slice` should be explicitly marked so the normal transfer path requires
outer encryption. Do not rely on implicit code-path conventions.

## Implementation areas

### `src/event_modules/message/commands.rs`

Update:

1. `send_file_for_peer`
2. any synthetic file-generation path that is intended to model real file
   transfer behavior

These paths should emit outer `encrypted(file_slice)` instead of outer
`file_slice`.

### `src/runtime/sync_engine/session/data_plane.rs`

Update the receive-side capture predicate so it recognizes outer
`encrypted(file_slice)` for effective download-rate linkage.

### `src/event_modules/file/queries.rs`

Ensure save/load behavior continues to work with `encrypted(file_slice)` as the
normal transfer format, and refactor `save-file` to stream decrypted slice
output instead of buffering the whole file in memory.

### `src/runtime/control/main.rs` and related response structs

Update CLI-visible `save-file` output so the command reports elapsed
decrypt+save time in addition to bytes written.

### Registry / metadata

Add or extend explicit transport privacy policy metadata so the expected outer
transport posture of event types is encoded and testable.

## Test plan

### Black-box CLI tests

1. Ensure the high-level file sync/save/MiB-s acceptance test exists before the
   transport refactor.
2. Keep or update the local-file CLI test proving local files do not show fake
   download MiB/s.
3. Add or update black-box CLI coverage so `save-file` output includes elapsed
   decrypt/save time.

### Unit / integration tests

1. Receive-side capture predicate:
   - `encrypted(file_slice)` matches
   - `encrypted(message)` does not match
   - plaintext `message` does not match
   - plaintext `file` does not match
   - plaintext `file_slice` does not match if the new format fully drops
     plaintext slice transport

2. File roundtrip:
   - prove `save-file` restores exact bytes when slices are outer
     `encrypted(file_slice)`
   - prove `save-file` streams correctly for multi-slice files without relying
     on whole-file plaintext accumulation

3. Transport/privacy policy:
   - every relevant event type is explicitly classified
   - `file_slice` is not left implicitly plaintext

4. Large-file save behavior:
   - add realistic coverage for large multi-slice save/decrypt behavior
   - if practical, include a low-memory test or explicit bounded-memory helper
     assertion so the path stays viable for the iOS target

## Verification

Run targeted tests for:

1. the high-level black-box CLI file-transfer target,
2. capture-predicate behavior,
3. file save/decrypt behavior,
4. local-file no-rate behavior,
5. transport/privacy policy coverage,
6. `save-file` elapsed-time output.

Then run these perf spot checks and report the numbers:

1. `cargo test --release --test perf_test perf_sync_10k -- --nocapture`
2. `cargo test --release --test sync_graph_test catchup_large_file_4x_400_slices -- --ignored --nocapture --test-threads=1`
3. large-file save/decrypt perf measurements for at least `100 MB` and `1 GB`
   and record them in `docs/PERF.md`

## Success criteria

1. Normal file transfer uses outer `encrypted(file_slice)`.
2. Bob can sync and save files correctly.
3. Downloaded attachments/files still show MiB/s.
4. Local-only files still do not show fake MiB/s.
5. The refactor has a stable black-box CLI acceptance test.
6. Transport privacy policy is explicit and tested.
7. Perf spot checks remain acceptable relative to the current post-file-rate
   `master` baseline.
8. `save-file` reports elapsed decrypt/save time.
9. `save-file` no longer buffers whole-file plaintext in memory.
10. Large-file save/decrypt perf numbers are recorded in `docs/PERF.md`.
11. The completed work is committed on `codex/file-slice-encryption`.
