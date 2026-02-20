# Stream 2: Identity Compatibility Cleanup

> **Historical document; file paths and module names may not match the current source tree.**

## Goal

Finish transport-identity rename cleanup by removing compatibility shims and reducing legacy CLI/name surface area.

## Scope

1. Remove compatibility shim module and old symbol exports.
2. Tighten CLI wording and aliases around transport identity naming.
3. Clean remaining legacy references in active docs tied to this rename.

## Dependencies

1. Alias retirement must be coordinated with Stream 1 because alias callers are in Stream 1-owned files:
   - `tests/cli_test.rs`
   - `tests/netns_nat_test.sh`
2. If Stream 2 does not own caller updates, defer alias removal and leave a tracked follow-up note.

## Owned Files

1. `src/identity.rs`
2. `src/lib.rs`
3. `src/main.rs`
4. `docs/IDENTITY_RENAME_PLAN.md`

## Non-Goals

1. No trust model redesign.
2. No test trust-path refactors (Stream 1).
3. No event-type removals (`peer_key`, `bench_dep`) (Stream 4).

## Work Items

1. Remove `src/identity.rs` compatibility re-exports if no internal callers remain.
2. Remove `pub mod identity;` from `src/lib.rs`.
3. Split CLI cleanup into two phases:
   - Phase A: normalize help/status wording to transport identity terms.
   - Phase B: evaluate alias retirement only after dependent caller updates are merged.
4. Alias retirement candidates in Phase B:
   - `identity` alias for `transport-identity`
   - `backfill-identity` alias for `backfill-transport-identity`
5. Update help/status text that still references old naming.
6. Update `docs/IDENTITY_RENAME_PLAN.md` from migration plan to completion record (or archive status note).

## Acceptance Criteria

1. No internal code depends on old `identity::*` transport symbols.
2. CLI naming is consistent with transport identity terminology.
3. Alias decision is explicit:
   - either aliases are removed with caller updates in the same wave, or
   - aliases are intentionally retained with a documented follow-up owner.
4. Rename plan doc no longer lists already-completed migration steps as pending.
5. `cargo check --all-targets` passes.

## Validation Commands

```bash
rg -n "identity::|load_identity_from_db|local_identity_from_db|cert_paths_from_db" src tests
rg -n 'arg\("identity"\)|\bidentity --db\b|backfill-identity' tests src docs
cargo check --all-targets
```

## Risks

1. Breaking user scripts that still call legacy aliases.
2. Hidden external dependency on shim exports.

## Mitigations

1. If alias removal is too disruptive, land in two commits:
   - first: code-shim removal internal only
   - second: alias removal with release-note/docs note
2. Keep small migration note in docs for one release window if needed.
