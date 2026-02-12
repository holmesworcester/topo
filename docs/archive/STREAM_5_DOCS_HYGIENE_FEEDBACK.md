# Feedback: Stream 5 Docs Archive Hygiene

## Decision
Approved.

## What I Checked
1. Archive moves are clean and discoverable (`docs/archive/...` + new `docs/INDEX.md`).
2. Updated PLAN references align with current code state (variable-length framing + pinned cert verifier).
3. Active doc status headers are consistent across edited docs.
4. Link targets in `docs/INDEX.md` resolve.

## Validation Run
- `cargo check --all-targets` (pass; baseline warnings only)
- Manual link existence check for `docs/INDEX.md` entries (pass)
