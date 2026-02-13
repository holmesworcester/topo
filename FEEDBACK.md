# Feedback: Issue 2 - Strict Parse Length

## Findings

1. No blocking correctness issues found in reviewed scope.
2. Low: Keep parser discipline in future event additions by requiring both `TooShort` and `TrailingData` checks in review/test checklist.

## Evidence

- Event parser strictness tests passed:
  - `test_fixed_size_rejects_trailing_data`
  - `test_variable_size_rejects_trailing_data`
- Sync protocol bounds tests passed:
  - `test_neg_message_too_large`
  - `test_neg_message_at_limit_ok`
  - `test_have_list_too_many_ids`
  - `test_have_list_at_limit_ok`

## Summary

The strict trailing-data and bounds-hardening work looks good and is covered by focused tests.
