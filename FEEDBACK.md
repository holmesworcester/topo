# Feedback: Issue 3 - Create Event Valid Contract

## Findings

1. High: Regression in bootstrap/testutil flows where blocked creation is now surfaced as an error but call sites still `expect` success (`src/testutil.rs`). This breaks scenario coverage.
2. High: `test_device_link_via_sync` fails because `create_user_invite_boot_with_key` uses sync creation semantics before its dependency chain is complete (`tests/scenario_test.rs:1599` before acceptance at `tests/scenario_test.rs:1606`).
3. Medium: Contract split (`sync` strict vs `staged` permissive) is directionally correct, but pre-anchor/test bootstrap paths need explicit migration to staged APIs.

## Evidence

- Passed:
  - `test_create_signed_event_sync_returns_blocked_error`
  - `test_create_signed_event_staged_returns_ok_on_blocked`
  - `test_invite_accept_produces_valid_identity`
  - `test_true_out_of_order_identity_chain`
- Failed:
  - `test_device_link_via_sync`

## Summary

This branch has a blocker: at least one scenario path still assumes old permissive behavior and must be migrated to staged creation or reordered.
