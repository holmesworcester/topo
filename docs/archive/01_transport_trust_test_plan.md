# Stream 1: Transport Trust Test Modernization

> **Historical document; file paths and module names may not match the current source tree.**

## Goal

Reduce prototype-style cert pinning assumptions in test flows and move tests toward identity-derived trust behavior, while preserving a small explicit cert-pinning coverage set.

## Scope

1. Modernize integration tests that currently depend on ad hoc SPKI pin setup for normal workflows.
2. Keep explicit pinning tests for transport policy boundaries.
3. Reduce duplicate mTLS setup logic across tests by using one helper path.

## Owned Files

1. `src/testutil.rs`
2. `tests/cli_test.rs`
3. `tests/holepunch_test.rs`
4. `tests/netns_nat_test.sh`

## Non-Goals

1. No production transport policy changes in `src/main.rs` or `src/transport/*`.
2. No schema changes.
3. No `peer_key`/`bench_dep` removal (handled in Stream 4).

## Work Items

1. Introduce a clearer trust-mode helper in `testutil`:
   - identity-derived trust mode for default integration flows.
   - explicit pinning mode retained for negative/policy tests.
2. Refactor test callers to use the helper instead of custom cert/fingerprint boilerplate where possible.
3. Reclassify test intent:
   - functional sync/holepunch tests should not be accidentally asserting pinning behavior.
   - dedicated pinning tests keep strict `--pin-peer` assertions.
4. Add or update test comments so trust model expectations are explicit.

## Acceptance Criteria

1. Pinning behavior still has dedicated tests proving reject/accept semantics.
2. At least one major integration flow no longer manually wires cert fingerprints in test code.
3. Test helper duplication for cert+fingerprint extraction is reduced.
4. `cargo test --test cli_test -- --nocapture` passes.
5. `cargo test --test holepunch_test -- --nocapture` passes.

## Validation Commands

```bash
cargo check --all-targets
cargo test --test cli_test -- --nocapture
cargo test --test holepunch_test -- --nocapture
bash -n tests/netns_nat_test.sh
```

## Risks

1. Accidentally weakening pinning coverage while simplifying tests.
2. Flaky behavior if helper refactor changes timing/ordering.

## Mitigations

1. Keep one explicit negative unpinned test and one explicit positive pinned test.
2. Preserve existing timeouts first; tune only if failures are reproducible.

