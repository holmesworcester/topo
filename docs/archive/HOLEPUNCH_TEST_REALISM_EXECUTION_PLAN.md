# Hole-Punch Test Realism: Execution And Handoff Plan

> **Historical plan; completed. Retained for reference.**

Date: 2026-02-16
Owner branch: `plan/holepunch-test-realism`
Worktree: `/home/holmes/poc-7-holepunch-realism-plan`
Base commit: `47e2982` (`origin/master` at branch creation)

## Objective

Remove realism gaps in hole-punch/intro tests by eliminating manual endpoint-observation writes and aligning test transport trust behavior with production dynamic trust lookup.

Primary TODO targets:

1. `P1: Remove manual endpoint observation writes in hole-punch integration test`
2. `P2: Align test transport setup with production dynamic trust lookup`

## Current Fake Surface

1. `tests/holepunch_test.rs` manually calls `record_endpoint_observation(...)` for introducer state setup.
2. Multiple test helpers use static `AllowedPeers::from_fingerprints(...)` where production now favors runtime DB trust lookups (`is_peer_allowed`).

## Primary Files

1. `tests/holepunch_test.rs`
2. `src/testutil.rs`
3. optional helper additions under `src/testutil.rs` for dynamic endpoint mode

## Constraints

1. Hole-punch integration should derive observations from real runtime traffic where possible.
2. Dynamic trust lookup mode should be default for realism-sensitive integration tests.
3. Static pin mode should remain only for pinning-policy-focused tests.

## Phase Plan

## Phase 0: Baseline Verification

Required commands:

1. `cargo test --test holepunch_test -q`
2. `cargo test --test scenario_test -q`

## Phase 1: Introduce Dynamic Trust Test Endpoint Mode

Tasks:

1. Add test helper endpoint mode that resolves trust via DB (`is_peer_allowed`) at handshake time.
2. Keep static pin helper available for explicit policy tests.
3. Add helper-level tests or assertions to validate selected mode.

Verification:

1. `cargo test --test holepunch_test -q`
2. any new helper unit tests in `src/testutil.rs`

## Phase 2: Remove Manual Endpoint Observation Writes

Tasks:

1. Replace manual `record_endpoint_observation(...)` setup in hole-punch test with runtime-generated observations.
2. Ensure intro sender derives freshest endpoints from organically observed traffic.
3. Keep test deterministic via explicit timing/retry windows and assertions.

Verification:

1. `rg -n "record_endpoint_observation\(" tests/holepunch_test.rs` has no direct test setup writes (except intentional low-level unit tests if any).
2. `cargo test --test holepunch_test -q`

## Phase 3: Migrate Realism-Sensitive Tests To Dynamic Mode

Tasks:

1. Migrate main hole-punch happy-path and core integration flows to dynamic trust mode.
2. Leave static pin usage only in targeted trust-boundary tests.
3. Document test-mode intent at call sites.

Verification:

1. `cargo test --test holepunch_test -q`
2. `cargo test --test scenario_test -q`

## Phase 4: Regression Gate

Required commands:

1. `cargo test --test holepunch_test -q`
2. `cargo test --test cli_test -q`
3. `cargo test --test scenario_test -q`
4. `cargo test -q`

## Acceptance Checklist

1. No manual endpoint-observation seeding in hole-punch integration setup.
2. Dynamic trust endpoint mode exists and is used by realism-sensitive tests.
3. Static pin mode is limited to policy tests.
4. Regression gate passes.
