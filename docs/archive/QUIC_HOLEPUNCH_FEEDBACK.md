# Feedback: `quic-holepunch` (latest)

> **Historical document; file paths and module names may not match the current source tree.**

## Snapshot
- Branch: `quic-holepunch` (`/home/holmes/poc-7-quic-holepunch`)
- Relative to `origin/master`: `0 behind / 6 ahead`
- Latest reviewed commits:
  - `b0737e2` (`--intro-worker` integration, `spawn_local` architecture updates, NAT netns script)
  - `dd7a47d` (DESIGN/PLAN documentation expansion)
- Validation run on February 9, 2026:
  - `cargo test --test holepunch_test -- --nocapture` -> 3 passed
  - `bash -n tests/netns_nat_test.sh` -> syntax OK
  - Note: full netns NAT script was not executed in this run.

## What Is Strong
1. `--intro-worker` integration into `sync` closes a real operational gap for long-lived introducers (`src/main.rs:821`).
2. Moving intro handling to `spawn_local` + `LocalSet` is the right direction for `!Send` state and listener concurrency (`src/sync/engine.rs:790`, `src/sync/punch.rs:231`).
3. New NAT script is thorough and debuggable (namespace topology, nft rules, diagnostic dumps on failure) (`tests/netns_nat_test.sh`).
4. Docs now explain architecture, NAT assumptions, and pitfalls clearly enough for future contributors (`docs/DESIGN.md:130`, `docs/PLAN.md:1393`).

## Findings
1. Documentation mismatch in wire type.
   - `PLAN.md` says IntroOffer is "type 7" (`docs/PLAN.md:1396`), but code uses `0x30` (`src/sync/mod.rs:26`).
   - Recommendation: update docs to `0x30` to avoid protocol confusion.
2. Runtime model inconsistency between docs and integrated intro-worker path.
   - Docs warn that cross-runtime `endpoint.connect()` via `spawn_blocking` can deadlock handshake (`docs/PLAN.md:1477`).
   - `sync --intro-worker` currently runs intro worker in `spawn_blocking` with a new runtime and calls `run_intro_worker(... endpoint ...)` (`src/main.rs:828`).
   - Recommendation: either run intro worker on the same LocalSet/runtime as endpoint I/O, or explicitly document why this call path is safe.
3. Test gap for the new integrated mode.
   - Existing tests validate one-shot intro and punch flow (`tests/holepunch_test.rs`), but there is no automated test covering `sync --intro-worker` behavior directly.
   - Recommendation: add one integration test that exercises the integrated worker mode end-to-end.

## Recommendation
1. This branch remains the best merge candidate.
2. Fix the two consistency items (protocol type doc + runtime model note/refactor) before final merge.
3. Add automated coverage for integrated `--intro-worker` mode to lock in the newest behavior.
