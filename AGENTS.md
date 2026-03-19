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
