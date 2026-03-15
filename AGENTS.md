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
