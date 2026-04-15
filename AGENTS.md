# AGENTS Instructions (poc-7)

## Worktree Discipline

Never do implementation work in the main worktree at `/home/holmes/poc-7`.
Before editing code, running task validation, or committing, create or switch to
a dedicated git worktree for the task.

## Instruction Quality Gate

When creating instructions for an assistant in this repo:

1. Include explicit Success Criteria (SCs).
2. Include explicit tests/checks that prove each SC is satisfied.
3. Include end-to-end validation checks showing all delivered functionality works as expected, not only SC-specific checks.

## Test Surface Preference

Prefer CLI end-to-end tests for new user-visible or runtime behavior. When a
test needs data that is not available through the CLI/RPC surface, add a
first-class daemon/CLI observability or query surface instead of reaching into
internal SQL tables from the test.

## Formal Maintenance Gate

When changing repo command-entry files, projector registration/families,
runtime/state decision seams, or Verus proof modules:

1. Success Criteria:
   - Every changed or new `src/**/commands.rs` and `src/**/commands_api.rs`
     file is indexed in `docs/planning/COMMAND_FORMAL_COVERAGE.md` with a
     Verus mirror and concrete targeted checks.
   - Every changed or new runtime/state decision seam remains indexed in
     `docs/planning/FORMAL_SEAM_COVERAGE.md`.
   - Every new non-module file under `verus-proofs/src/` is indexed in
     `docs/planning/FORMAL_SEAM_COVERAGE.md`.
   - Every changed covered runtime command/seam/projector path also changes at
     least one mapped Verus mirror in the same diff.
   - Registered projector families remain assigned to Verus-covered projector
     proof modules, and their TLA/runtime mapping rows stay current.
2. Required checks:
   - Run `scripts/run_merge_readiness_checks.sh targeted`. This is the primary
     agent/merge-readiness gate and must pass before merge.
   - Run `python3 scripts/check_formal_seam_coverage.py` after seam/proof-map
     edits.
   - Run `python3 scripts/check_command_formal_coverage.py` after
     command/projector coverage edits.
   - Run `python3 scripts/check_formal_mirror_updates.py` after touching any
     covered runtime command/seam/projector path.
   - Run `python3 scripts/check_projector_tla_conformance.py` and
     `python3 scripts/check_projector_tla_bijection.py` when projector mapping
     rows change.
3. End-to-end validation:
   - Each changed command or projector path must keep at least one executable
     pass case and one executable reject/conflict/break case.

## Model Conformance Gate

When changing event schemas, signer-family rules, dependency checks, projector
guards, `docs/tla/runtime_check_catalog.md`, or
`docs/tla/projector_conformance_matrix.md`:

1. Success Criteria:
   - The runtime change has an executable pass case and an executable break case.
   - The affected TLA/runtime check mapping is updated in the catalog or matrix
     in the same change.
   - No TLA/runtime check may be claimed in repo instructions or docs without a
     concrete code path or executable test covering it.
2. Required checks:
   - Run targeted Rust tests that exercise the changed validation path.
   - Run `python3 scripts/check_projector_tla_conformance.py` and
     `python3 scripts/check_projector_tla_bijection.py` when you update the
     touched mapping rows and expect those rows to stay current.
3. End-to-end validation:
   - At least one projection-path test must prove the changed event is accepted
     on the valid path and rejected or blocked on the invalid path.
