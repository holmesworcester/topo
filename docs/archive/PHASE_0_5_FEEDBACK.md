# Phase 0.5 Feedback (`78271a2`)

> **Historical document; file paths and module names may not match the current source tree.**

Assumption for this review:
- Phase 0 feedback in `PHASE_0_FEEDBACK.md` is already addressed.
- This document focuses only on Phase 0.5 changes (`recorded_by` + `recorded_events` + scoped CLI/query behavior).

Scope reviewed:
- Commit `78271a2` (`Implement Phase 0.5: workspace-scoped recording with recorded_by and recorded_events`)
- Files:
  - `src/db/schema.rs`
  - `src/identity.rs`
  - `src/main.rs`
  - `src/sync/engine.rs`
  - `src/testutil.rs`
  - `tests/scenario_test.rs`
  - `tests/cli_test.rs`
  - `tests/perf_test.rs`

## Findings (severity ordered)

1. High: schema migration is not backward compatible with existing Phase 0 databases.
- Evidence:
  - `src/db/schema.rs` changes `messages` primary key to `(recorded_by, message_id)` and adds `idx_messages_recorded`.
  - `create_tables` still uses only `CREATE TABLE IF NOT EXISTS` and `CREATE INDEX IF NOT EXISTS` (no ALTER/migration path).
  - Repro (validated): a DB with the old `messages` schema fails on startup with `no such column: recorded_by` when creating `idx_messages_recorded`.
- Impact:
  - Existing DBs fail to open for normal CLI operations after upgrade.
- Action:
  - add a versioned migration step:
    - detect old `messages` schema,
    - create `messages_v2` with `(recorded_by, message_id)` PK,
    - backfill old rows with a chosen recorded scope (or sentinel + reproject),
    - swap tables and re-create indexes.
  - add a migration test from a Phase 0 fixture DB.

2. Medium: `recorded_events.recorded_at` is populated from event `created_at`, not local receipt/record time.
- Evidence:
  - `src/sync/engine.rs` inserts `recorded_events(..., recorded_at, source)` using `created_at_ms` from the envelope for `"quic_recv"`.
  - local create paths (`src/main.rs`, `src/testutil.rs`) also write `created_at_ms` as `recorded_at`.
- Impact:
  - `recorded_at` cannot represent local observation time or delivery lag.
  - remote timestamp skew/manipulation distorts operational metrics and debugging.
- Action:
  - use local wall clock at insert time for `recorded_at`,
  - keep event `created_at` in canonical event/projection fields separately,
  - add tests asserting `recorded_at` monotonicity under delayed/reordered ingest.

3. Medium: identity lookup helper can silently mint a new identity during read paths.
- Evidence:
  - `local_identity_from_db` in `src/identity.rs` calls `load_or_generate_cert`.
  - read/query commands (`messages`, `status`, `assert-*`) call `local_identity_from_db`.
- Impact:
  - if cert/key files are missing/corrupt, read commands can generate a new cert and implicitly rotate local identity.
  - scoped queries then appear empty/misaligned without explicit operator signal.
- Action:
  - split identity access into:
    - `load_identity_from_db` (no generation, fail if missing),
    - `load_or_generate_identity_from_db` (explicitly for bootstrap commands).
  - use no-generate path for query/assert/status commands.

4. Medium: isolation coverage is still single-workspace and does not prove cross-workspace non-overlap.
- Evidence:
  - `tests/scenario_test.rs::test_recorded_events_isolation` validates per-peer scoped counts in one two-peer exchange.
  - no test with two independent workspace/key sets in one run.
- Impact:
  - regressions in query scoping or recorder identity handling may pass current tests.
- Action:
  - add a Phase 0.5.1 isolation test:
    - workspace set A (`peerA1`, `peerA2`) + workspace set B (`peerB1`, `peerB2`),
    - sync within each set only,
    - assert no cross-set rows in `recorded_events` and scoped message queries.

## What is good and should be preserved

1. `recorded_by` is threaded through ingest and projection writes consistently.
2. `recorded_events` uniqueness (`UNIQUE(peer_id, event_id)`) gives idempotent replay/re-receive behavior.
3. CLI assertions are now scoped for message/recorded counts, matching the tenant-safe intent.
4. Test utilities now align transport cert identity with local recorder identity.

## Suggested follow-up order

1. Fix migration safety first (blocking issue for upgradeability).
2. Correct `recorded_at` semantics and add timing-oriented tests.
3. Split identity load vs generate behavior to avoid accidental identity mutation.
4. Add two-workspace isolation tests as a guardrail before Phase 1/2 projection complexity.
