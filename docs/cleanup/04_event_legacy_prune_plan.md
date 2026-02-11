# Stream 4: Legacy Event Surface Pruning (`peer_key`, `bench_dep`)

## Goal

Shrink protocol and projection complexity by removing or quarantining legacy event artifacts that remain from prototype/perf scaffolding.

## Scope

1. Remove `bench_dep` from production event registry path.
2. Retire or sharply isolate deprecated `peer_key` flow.
3. Update tests that currently rely on these legacy types.

## Owned Files

1. `src/events/peer_key.rs`
2. `src/events/bench_dep.rs`
3. `src/events/mod.rs`
4. `src/projection/signer.rs`
5. `src/projection/projectors.rs`
6. `src/projection/pipeline.rs`
7. `src/projection/encrypted.rs`
8. `tests/scenario_test.rs`
9. `tests/topo_cascade_test.rs`
10. `tests/file_throughput.rs`

## Dependencies

1. Run after Wave 1 streams merge (recommended), especially Stream 1 and Stream 2.

## Non-Goals

1. No transport trust redesign.
2. No docs archive migration (Stream 5).

## Work Items

1. `bench_dep`:
   - remove from production registry and `ParsedEvent` if possible.
   - move topo/perf scaffolding to test-local type or dedicated benchmark-only module.
2. `peer_key`:
   - decide one of:
     - full removal from runtime, or
     - parse-only compatibility with no new production creation path.
   - align signer resolution to identity chain signers (`peer_shared`) as default path.
3. Update affected tests:
   - scenario tests using `create_peer_key`.
   - throughput/topo tests relying on legacy event codes.
4. Remove unreachable/unused imports and helper functions created by legacy flow.

## Acceptance Criteria

1. `bench_dep` is not part of production event path.
2. Deprecated `peer_key` flow is either removed or tightly compatibility-scoped.
3. No warnings for unused legacy helper code introduced by old paths.
4. `cargo check --all-targets` passes.
5. Core projection/sync tests still pass.

## Validation Commands

```bash
cargo check --all-targets
cargo test projection::pipeline::tests -- --nocapture
cargo test --test scenario_test -- --nocapture
cargo test --test topo_cascade_test -- --nocapture
```

## Risks

1. High blast radius across parser/projection/tests.
2. Backward-compat concerns for existing serialized events.

## Mitigations

1. Land in steps:
   - Step A: `bench_dep` isolation
   - Step B: `peer_key` migration
2. Keep explicit compatibility tests if parse-only support is retained.

