# Phase 7 — Per-File Key in Descriptor (deferred)

## Status

**Deferred to a follow-up commit.** Not landed in the initial PoC
pass.

## Why deferred

Phase 7 requires a wire-format change to `File` (type 24) to add a
`file_key: [u8; 32]` field. This is a cross-cutting edit:

- `src/event_modules/file/wire.rs` — add `FieldSpec::FixedBytes("file_key", 32)`
  to `FILE_FIELDS`; update the `FileEvent` struct, `parse_file`,
  `encode_file`, and the offsets module.
- `src/event_modules/file/layout.rs` (if present) — update offsets.
- `src/event_modules/file_slice/projector.rs:83-89` — validate slice
  ciphertext against the descriptor's `file_key` instead of the
  current transport `key_event_id`.
- `src/event_modules/layout/common.rs:269-270` —
  `test_per_event_wire_sizes` asserts `FILE_WIRE_SIZE = 536`; update
  to the new size (536 + 32 = 568).
- `topo-verus-proofs` layout mirror — update `encode_file_v1` /
  related verified codec helpers.
- All test fixtures that reference the current `FILE_WIRE_SIZE` or
  encode/decode `File` blobs need regeneration.

None of it is hard; it's broad surgery that warrants its own focused
commit with a full test pass once the other phases have validated the
overall approach.

## What Phase 7 delivers

- Each uploaded file gets a fresh symmetric `F_k` generated at upload
  time.
- File slices are encrypted under `F_k` (not the epoch key).
- The `File` descriptor carries `F_k` in its plaintext (which is
  itself encrypted to the epoch key via the outer `Encrypted`
  wrapper).
- Message rewrap / delete cascades naturally handle `F_k` — when
  the descriptor's plaintext is cascade-purged, `F_k` is gone;
  slices encrypted under `F_k` become undecryptable.
- **Key property:** slice bytes are NEVER re-encrypted on epoch
  rotation. Only the message descriptor (containing `F_k`) gets
  rewrapped under the new epoch key. Cheap.

## Current PoC behavior (without Phase 7)

File slices are encrypted under the epoch key via the existing
transport `key_event_id` path. Under Per-Message FS, that
`key_event_id` now points at a `message_key` event, so slices are
effectively encrypted under per-message `K_m` — which means:

- Deletion correctly cascade-purges slices' keys alongside the
  message.
- Rotation (not implemented under Per-Message FS since messages never
  rekey) doesn't apply.
- The cost is a slight semantic overload: `key_event_id` on a
  `file_slice` points at the owning message's `message_key`, not at a
  dedicated file-level key.

This is adequate for the PoC's FS goals. The Phase 7 refactor is a
bandwidth optimization for large-file workloads, not a correctness
requirement.

## Next commit scope (when Phase 7 lands)

1. Wire change in `file/wire.rs`.
2. Dual-path in `file_slice/projector.rs`: look up `file_key` from
   descriptor first; fall back to legacy `key_event_id` if
   descriptor's `file_key` is zero (backwards compat with existing
   fixtures).
3. Regenerate test fixtures.
4. Update `topo-verus-proofs` encode helpers.
5. Add a `FILE_WIRE_SIZE` migration test.
