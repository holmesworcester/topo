# Stream 4: Legacy Event Surface Pruning (`peer_key`)

> **Historical plan; file paths may not match the current source tree.** `src/events/` is now `src/event_modules/`; `src/projection/pipeline.rs` is now `src/projection/apply/`.

## Goal

Shrink protocol and projection complexity by retiring deprecated `peer_key` paths while keeping prototyping/perf scaffolding intact.

## Scope

1. Retire deprecated `peer_key` flow.
2. Update tests that currently rely on `peer_key`.
3. Keep `bench_dep` unchanged during active prototyping.

## Owned Files

1. `src/events/peer_key.rs`
2. `src/events/mod.rs`
3. `src/projection/signer.rs`
4. `src/projection/projectors.rs`
5. `src/projection/pipeline.rs`
6. `src/projection/encrypted.rs`
7. `src/testutil.rs`
8. `tests/scenario_test.rs`
9. `tests/holepunch_test.rs`

## Dependencies

1. Run after Wave 1 streams merge (recommended), especially Stream 1 and Stream 2.

## Non-Goals

1. No transport trust redesign.
2. No docs archive migration (Stream 5).

## Work Items

1. `peer_key`:
   - decide one of:
     - full removal from runtime, or
     - parse-only compatibility with no new production creation path.
   - align signer resolution to identity chain signers (`peer_shared`) as default path.
2. Update affected tests:
   - scenario tests using `create_peer_key`.
   - holepunch tests creating synthetic `peer_key` events as sync fixtures.
3. Remove unreachable/unused imports and helper functions created by legacy flow.

## Acceptance Criteria

1. Deprecated `peer_key` flow is either removed or tightly compatibility-scoped.
2. `bench_dep` remains available for topo/perf prototype tests.
3. No warnings for unused legacy helper code introduced by old paths.
4. `cargo check --all-targets` passes.
5. Core projection/sync tests still pass.

## Validation Commands

```bash
cargo check --all-targets
cargo test projection::pipeline::tests -- --nocapture
cargo test --test scenario_test -- --nocapture
cargo test --test holepunch_test -- --nocapture
```

## Risks

1. High blast radius across parser/projection/tests.
2. Backward-compat concerns for existing serialized events.
3. Accidental impact to `bench_dep` perf scaffolding.

## Mitigations

1. Land in steps:
   - Step A: test harness migration off `create_peer_key`
   - Step B: runtime/projection `peer_key` retirement
2. Keep explicit compatibility tests if parse-only support is retained.
3. Leave `bench_dep` code paths untouched unless explicitly requested.
