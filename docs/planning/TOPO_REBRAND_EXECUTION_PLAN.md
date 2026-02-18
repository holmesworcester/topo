# Topo Rebrand Execution Plan

Date: 2026-02-18
Target branch: `exec/topo-rebrand`
Worktree: `/home/holmes/poc-7-topo-rebrand`
Goal: rename project-facing naming to **Topo** consistently, with light 🐭 branding in CLI/help/runtime output.

## Handoff Instructions

1. Work only in `/home/holmes/poc-7-topo-rebrand`.
2. Do not modify files in other worktrees.
3. Keep tests green at each phase (`cargo check`, targeted tests, then full `cargo test` at end).
4. Preserve behavior unless this plan explicitly changes wording/branding.

## Naming Policy (Canonical)

1. Product display name: `Topo`.
2. CLI command and crate package identifier stay lowercase: `topo`.
3. Gentle emoji branding: use `🐭 Topo` in user-facing surfaces where it improves recognition (help/about, daemon startup logs).
4. No protocol-level rename in this task (for example `quiet://` remains unchanged).
5. No schema/event type rename in this task unless a user-visible string depends on it.

## Scope

In scope:

1. CLI/help/about/version display text.
2. Runtime log text that users/operators commonly see.
3. Docs and examples that still call the product `poc-7`/`POC7` in active guidance.
4. Test expectations that assert old branding text.

Out of scope:

1. Wire-format/protocol token changes.
2. DB schema/table renames.
3. Large historical archive rewrites (only fix actively referenced docs/indexes).

## Phase Plan

### Phase 0: Inventory and Classification

Run inventory search and classify hits into:

1. User-facing runtime strings (must change).
2. Active docs/examples (must change).
3. Historical/archive context (usually leave unless referenced by active docs).
4. Internal-only identifiers (optional; change only if low-risk and clearly improves consistency).

Recommended search seed:

1. `rg -n "poc-7|POC7|p7d|p7ctl|Poc-7|POC 7" src tests docs`

Deliverable:

1. Short checklist in commit message or notes of changed categories.

### Phase 1: CLI and Runtime Branding

Update user-facing CLI surfaces:

1. Top-level clap metadata/help/about to display Topo branding.
2. Add subtle emoji branding in help/about text (for example `🐭 Topo`).
3. Ensure daemon start/stop logs use `Topo` wording consistently.
4. Keep machine-readable outputs stable (do not add emoji to outputs consumed by tests/scripts unless tests are updated and output remains deterministic).

Guardrails:

1. Do not add emoji to raw IDs, event dumps, or any parse-sensitive output.
2. Keep error messages concise and unchanged unless they contain old branding.

### Phase 2: Active Docs and Examples

Update active docs to `Topo` naming where appropriate:

1. `docs/INDEX.md`
2. `docs/PLAN.md` and `docs/DESIGN.md` only where product name references appear.
3. `TODO.md` references that describe runtime/CLI name.
4. Examples/snippets that invoke command names should remain `topo` (lowercase binary).

Do not mass-edit archive docs unless linked by active docs.

### Phase 3: Tests and Output Expectations

Update tests that assert old text:

1. CLI tests expecting old daemon/help naming.
2. RPC/other tests if they match literal old branding strings.

Add one regression guard test (or script assertion) that checks obvious stale branding is absent from active runtime-facing files.

Suggested lightweight guard:

1. Search active runtime entrypoints for `poc-7` and fail if present where user-facing.

### Phase 4: Final Consistency Pass

1. Re-run inventory search from Phase 0.
2. Manually review remaining hits and justify any kept instances.
3. Ensure final naming split is coherent:
   - display: `Topo`
   - binary/crate: `topo`

## Verification

Required:

1. `cargo check`
2. `cargo test --test cli_test`
3. `cargo test --test rpc_test`
4. `cargo test`

Optional but recommended:

1. Spot-run `topo --help` and `topo start` to verify visible branding text.

## Acceptance Criteria

1. User-facing branding consistently says `Topo`.
2. CLI/help includes gentle `🐭` branding in approved locations.
3. Binary invocation remains `topo` and all existing command semantics still work.
4. No protocol/schema changes introduced by this rebrand pass.
5. Full test suite passes.

