# RBSR Merkle-Clamp Spike

> Historical spike/example. The code in this note is intentionally archived on a separate branch and is not part of `master`.

## Summary

This archive preserves a standalone implementation attempt of the non-homomorphic RBSR construction from:

1. `rbsr.pdf`
2. `rbsr_nonhomomorphic.pdf`

The spike replaced the vendored negentropy range fingerprint path with a Merkle-clamped backend and added a persisted auxiliary index for `shared_event_index`.

## Archive Location

Use these refs to inspect the spike code:

1. Archive branch: `archive/rbsr-merkle-clamp-spike`
2. Archived implementation commit: `69c4a96c21ee0af630c6087e87c2428f0187c1ba`
3. Local working branch during development: `codex/merkle-clamp-rbsr`

Example commands:

```bash
git show 69c4a96c21ee0af630c6087e87c2428f0187c1ba
git switch archive/rbsr-merkle-clamp-spike
git diff master..archive/rbsr-merkle-clamp-spike
```

## What The Spike Implemented

1. A Merkle-clamped negentropy storage backend in `vendor/negentropy`.
2. A persisted workspace-local Merkle index for `shared_event_index`.
3. Range-session loading from the persisted Merkle index instead of rebuilding a `NegentropyStorageVector` from SQL rows on each session.
4. Delete/update wiring so shared-event removals also invalidate the persisted sync-side index.

Primary code areas on the archived branch:

1. `vendor/negentropy/src/storage.rs`
2. `vendor/negentropy/src/types.rs`
3. `src/state/db/shared_event_merkle.rs`
4. `src/runtime/sync_engine/session/range_session.rs`
5. `src/state/db/store.rs`
6. `src/state/pipeline/phases.rs`
7. `src/state/projection/purge.rs`

## Validation Snapshot

Representative validation recorded during the spike:

1. `cargo test -j 1 shared_event_merkle --lib -- --test-threads=1`
2. `cargo test -j 1 --test cli_live_file_sync_test -- --exact test_cli_live_message_during_large_file_sync --test-threads=1`
3. `cargo test -j 1 --test cli_test test_cli_bidirectional_sync -- --exact --test-threads=1`
4. `cargo +stable test -j 1 --release --test daemon_perf_test perf_sync_10k -- --nocapture --exact --test-threads=1`

Recorded 10k perf result on the archived spike branch:

1. Wall time: `2.63s`
2. Throughput: `3802 msgs/s`
3. Peak daemon VmHWM: `44.6 MiB`

The repo later kept only documentation changes on `master`; this spike remained separate because it materially changed the sync storage model and was not adopted as the default implementation path.

## Why It Was Archived Instead Of Merged

1. It adds significant complexity relative to the stock rebuild-per-session negentropy path.
2. It changes the maintenance model from a simple session-local rebuild to a persisted sync-side auxiliary structure.
3. The experiment was useful as a concrete example and research artifact, but the project decision on `master` remained to keep the production path simpler.

## Use As A Reference

If this work is revisited later, treat it as:

1. a concrete example of a Merkle-clamped RBSR design in this codebase,
2. a reference for the persisted-index schema and update hooks, and
3. a starting point for future experiments rather than a drop-in production branch.
