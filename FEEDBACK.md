# Feedback: Issue 1 - Cascade Single Entrypoint

## Findings

1. Medium: Guard retry path appears to do a broad scan of `recorded_events` for each InviteAccepted-triggered retry, which can become `O(history)` per retry on large datasets (`src/projection/pipeline.rs:462`).
2. Low: This is likely acceptable short term, but it should be bounded or indexed by the exact retry candidate set to avoid replay/runtime slowdown under large backlogs.

## Evidence

- Targeted tests passed:
  - `test_multi_dep_event_projects_only_when_all_resolve`
  - `test_cascade_and_direct_produce_same_state`
  - `test_encrypted_inner_dep_cascade_unblock`
  - `test_invite_accepted_guard_retry_on_workspace`
  - `test_file_slice_guard_retry_after_cascaded_attachment`

## Summary

Core behavior looks correct and test-backed. Main gap is retry-query scalability under large event histories.
