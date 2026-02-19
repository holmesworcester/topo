# Fixed-Length Event Fields: Execution And Handoff Plan

> **Historical plan; file paths may not match the current source tree.** `src/events/` is now `src/event_modules/`.

Date: 2026-02-16
Owner branch: `plan/fixed-length-fields`
Worktree: `/home/holmes/poc-7-fixed-length-fields-plan`
Base commit: `47e2982` (`origin/master` at branch creation)

## Baseline Snapshot (Verified)

The plan branch starts from clean `origin/master` (no local modifications).

Baseline checks run in this worktree:

1. `cargo test --test cli_test -q` (pass)
2. `cargo test --test interactive_test -q` (pass)

Known non-blocking warning at baseline:

- `src/sync/engine.rs:1087` unused variable `allowed_peers`

## Objective

Remove variable-length fields from canonical event wire formats and enforce a strict fixed-layout parser model (langsec-first).

The canonical parser rules after this work:

1. Event body length is deterministic by type code (and, for encrypted wrappers, deterministically by `inner_type_code` mapping).
2. No parser control flow uses untrusted `*_len` or `*_count` fields to determine canonical body boundaries.
3. Canonical encodings are unique (single valid byte representation per logical event).

## Scope

Event types currently using variable-length canonical wire components:

1. `message` (`content_len`) (`src/events/message.rs`)
2. `reaction` (`emoji_len`) (`src/events/reaction.rs`)
3. `signed_memo` (`content_len`) (`src/events/signed_memo.rs`)
4. `encrypted` (`ciphertext_len`) (`src/events/encrypted.rs`)
5. `file_slice` (`ciphertext_len`) (`src/events/file_slice.rs`)
6. `message_attachment` (`filename_len`, `mime_len`) (`src/events/message_attachment.rs`)
7. `bench_dep` (`dep_count`) (`src/events/bench_dep.rs`)

## Non-Goals

1. Backward-compat read/write windows (POC policy: remove old paths in the same round).
2. Transport frame-level message delimiting changes (keep existing sync framing).
3. Parallel feature work unrelated to wire/parser determinism.

## Hard Requirements

1. Follow TLA/spec-first sequencing before semantic Rust changes.
2. All touched areas must have passing tests at each stage.
3. New/changed semantics must include tests in the same stage.
4. **Add a crude guardrail test that fails when length fields reappear in canonical event wire formats.**

## Implementation Strategy (Recommended)

### 1) Replace variable canonical layouts in-place (POC cutover)

Given no backward-compat requirement, update canonical layouts directly and remove old variable parser/encoder logic in the same change set.

### 2) Centralize fixed layout constants

Create one source of truth for fixed budgets and offsets (for example `src/events/fixed_layout.rs`) used by both parser and encoder paths.

### 3) Encrypted/file slicing approach

For encrypted/file payloads, avoid explicit variable length fields by making payload size deterministic:

1. `encrypted`: ciphertext size is derived from `inner_type_code` because inner plaintext types become fixed-size.
2. `file_slice`: use canonical fixed slice ciphertext size; pad final plaintext chunk deterministically before encryption; reconstruct file using existing attachment metadata (`blob_bytes`) for final truncation.

## Phase Plan

## Phase 0: Preflight And Freeze

Tasks:

1. Confirm branch/worktree and baseline commit.
2. Record baseline test outputs in PR notes.
3. Do not start parser edits until spec/TLA phase is done.

Verification:

1. `git status -sb` (clean)
2. `cargo test --test cli_test -q`
3. `cargo test --test interactive_test -q`

## Phase 1: Spec + TLA Alignment First

Tasks:

1. Update `docs/DESIGN.md` canonical wire-format section to require fixed-size canonical event fields.
2. Update `docs/PLAN.md` to remove `var_bytes` / `var_string` as canonical wire field types.
3. Update `docs/tla/projector_spec.md` boundary notes to explicitly separate:
   - modeled event-graph semantics,
   - non-modeled parser canonicalization guarantees enforced in Rust.
4. Update any TLA comments/assumptions where parser constraints are implied but not explicit.

Verification:

1. `cd docs/tla && ./tlc event_graph_schema_fast.cfg`
2. `cd docs/tla && ./tlc transport_credential_lifecycle_fast.cfg`
3. If needed for changed invariants: `cd docs/tla && ./tlc event_graph_schema.cfg`

Acceptance for Phase 1:

1. DESIGN/PLAN explicitly state fixed canonical fields.
2. TLA checks pass for changed model/docs scope.
3. Mapping docs are internally consistent.

## Phase 2: Fixed Layout Spec Table (Code Constants)

Tasks:

1. Add explicit fixed layout constants per type (field sizes, offsets, total lengths).
2. Define canonical text slot rules:
   - UTF-8 required,
   - zero-padding required in unused bytes,
   - no non-zero bytes after canonical text terminator.
3. Define fixed dep slot policy for `bench_dep` (fixed max dep slots, no variable dep_count).
4. Define deterministic encrypted payload sizing map by `inner_type_code`.

Verification:

1. Unit tests for layout constants/offset sanity (exact total lengths, non-overlap, stable offsets).
2. Compile check: `cargo test -q events::` (or full `cargo test -q` if no test filter available).

## Phase 3: Parser/Encoder Rewrite (No Length Fields)

Tasks:

1. Rewrite parsers in listed event files to exact-size decoding by fixed offsets.
2. Remove `*_len`/`dep_count` boundary parsing logic from canonical paths.
3. Rewrite encoders to emit fixed-size canonical forms only.
4. Remove old variable-layout parser/encoder branches in the same phase.

### Required Crude Guardrail Test (user-requested)

Add a test (for example `tests/wire_no_length_fields_guard_test.rs`) that scans canonical event source files and fails if variable-length field markers are present.

Initial denylist (minimum):

1. `content_len`
2. `emoji_len`
3. `ciphertext_len`
4. `filename_len`
5. `mime_len`
6. `dep_count`

Notes:

1. This is intentionally crude and not a full proof.
2. Keep it as a regression tripwire in CI so reintroduction of obvious length fields fails fast.

Verification:

1. New guard test fails before parser cleanup and passes after cleanup.
2. Per-type parser tests pass.
3. `cargo test -q`

## Phase 4: Projection/Create Path Updates

Tasks:

1. Update event creation paths (`projection/create.rs`, emit helpers, and callers) to produce only fixed canonical wire events.
2. Update any encryption/file helpers to align with fixed payload sizing.
3. Remove or rewrite helper code assuming variable body lengths.

Verification:

1. Event creation integration tests for message, reaction, memo, encrypted, attachment, and file_slice pass.
2. Replay/scenario tests touching these events pass.

Suggested commands:

1. `cargo test --test scenario_test -q`
2. `cargo test --test sync_graph_test -q`
3. `cargo test -q`

## Phase 5: Test Expansion (Strictness + Regression)

Tasks:

1. Add golden-byte tests for each fixed-layout event type.
2. Add negative parse tests for:
   - truncation,
   - trailing bytes,
   - non-zero padding,
   - malformed UTF-8 in fixed text slots,
   - forbidden dep slot shapes.
3. Add idempotent encode/decode canonicalization tests.
4. Ensure the crude denylist test remains in the suite.

Verification:

1. `cargo test -q`
2. If expensive tests are split by suite, run touched suites explicitly and record commands in PR.

## Final Acceptance Checklist

1. No canonical event parser relies on variable length/count fields to determine body boundaries.
2. All seven scoped variable-layout event types have fixed canonical layouts and tests.
3. Crude denylist guard test exists and passes.
4. DESIGN/PLAN/TLA mapping docs reflect fixed canonical format expectations.
5. Full test suite is green for touched areas, with commands/results captured in PR.

## Handoff Notes For Implementing Assistant

1. Treat this as one cutover: do not keep dual old/new parser behavior.
2. Land in small commits by phase, but keep branch always green after each commit.
3. If any layout budget decision is uncertain, pause and get explicit sign-off before changing event bytes.
4. Keep the crude denylist test even after deeper parser tests exist; it is a cheap regression detector.
