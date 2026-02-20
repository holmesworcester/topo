# Misplaced/Superfluous Cleanup Handoff

> **Historical document; file paths and module names may not match the current source tree.**

## Branch + Worktree

- Branch: `exec/cleanup-misplaced-and-superfluous`
- Worktree: `/home/holmes/poc-7-cleanup-misplaced-superfluous`
- Base: current `master` at branch creation time

## Goal

Clean up remaining misplaced/redundant module surfaces after the peering/sync/protocol renames, with emphasis on newcomer readability and sharp boundaries.

## Non-Goals

- Backward compatibility shims are not required in this POC.
- Do not redesign event semantics or sync protocol behavior.
- Do not change TLA/model behavior; this is structure + API cleanup.

## Required Constraints

- Keep behavior unchanged.
- Keep boundary checks passing.
- Prefer direct canonical module paths over re-export aliases.
- Keep edits incremental and reviewable (small commits per workstream).

## Workstream 0: Start Clean

1. Rebase branch on latest `master` before making edits.
2. Run baseline checks to confirm starting point:
   - `cargo check`
   - `bash scripts/check_boundary_imports.sh`

## Workstream 1: Fix `event_modules` Feature Gate Bug

Problem:
- `src/lib.rs` currently gates `event_modules` behind `feature = "discovery"`.
- `event_modules` is core runtime/event logic and is required even with discovery disabled.
- `cargo check --no-default-features` fails because of this.

Tasks:
1. In `src/lib.rs`, remove the discovery cfg from `pub mod event_modules;`.
2. Ensure only discovery-specific modules/functions are cfg-gated (not the whole event layer).
3. Verify:
   - `cargo check --no-default-features`
   - `cargo check`

Done when:
- No unresolved `crate::event_modules` errors in no-default-features build.

## Workstream 2: Keep `protocol` as Wire, Move Runtime Workflows to `peering`

Problem:
- `src/protocol/bootstrap.rs`, `src/protocol/intro.rs`, and `src/protocol/punch.rs` are runtime peering workflows, not wire definitions.
- This blurs “protocol/wire” vs “peering/runtime” boundaries.

Target direction:
- `src/protocol/` should contain wire concerns (`wire.rs`, message types/codecs, constants).
- Bootstrap/intro/hole-punch operational logic should live under `src/peering/` (or a clearly named peering submodule).

Suggested target layout:
- `src/peering/workflows/bootstrap.rs`
- `src/peering/workflows/intro.rs`
- `src/peering/workflows/punch.rs`
- `src/peering/workflows/mod.rs`

Tasks:
1. Move these modules from `protocol` to `peering` workflow namespace.
2. Update imports/call sites:
   - `src/node.rs`
   - `src/service.rs`
   - `src/testutil.rs`
   - peering loops/runtime and tests
3. Keep `crate::protocol::SyncMessage`, codecs, and message constants in canonical protocol/wire module.
4. Remove transitional re-export aliases unless absolutely necessary.

Done when:
- No runtime workflow code remains under `src/protocol/` except wire-oriented definitions.
- Tests compile without legacy alias paths.

## Workstream 3: Relocate Root-Level Identity/Invite Modules

Problem:
- Root-level `src/invite_link.rs`, `src/identity_ops.rs`, and `src/transport_identity.rs` are domain-specific and currently look “stray”.

Goal:
- Group identity/invite logic under a clearer domain namespace to improve locality.

Suggested target layout:
- `src/identity/mod.rs`
- `src/identity/invite_link.rs`
- `src/identity/ops.rs`
- `src/identity/transport.rs`

Tasks:
1. Move files and wire module exports.
2. Update call sites in:
   - `src/service.rs`
   - `src/protocol/*` or moved peering workflow files
   - `src/testutil.rs`
   - CLI/RPC paths as needed
3. Keep names direct (`identity::ops`, `identity::invite_link`, `identity::transport`).

Done when:
- Root crate surface no longer has these identity/invite implementation files at top level.
- Imports read as domain-local paths.

## Workstream 4: Remove Remaining Superfluous Surfaces

Candidates (evaluate and prune):
1. `src/event_pipeline/mod.rs` re-export of `IngestItem` if unused (`event_pipeline::IngestItem`).
2. `src/node.rs` thin wrapper vs direct `peering::runtime` surface.

Guideline:
- Keep one canonical public entry path per concern.
- If a wrapper adds no policy or abstraction, remove it and update call sites.

Done when:
- No dead/redundant exports remain from this list.

## Verification Matrix (Required Before Merge)

Run:
- `cargo check`
- `cargo check --no-default-features`
- `bash scripts/check_boundary_imports.sh`
- `cargo test --test replication_contract_tests -q`
- `cargo test --test holepunch_test -q`
- `cargo test --test rpc_test -q`

If module moves touch broader paths, also run:
- `cargo test --test scenario_test -q`

## Suggested Commit Slicing

1. `fix: ungate event_modules from discovery feature`
2. `refactor: move bootstrap/intro/punch workflows from protocol to peering`
3. `refactor: relocate identity/invite modules under identity namespace`
4. `cleanup: remove redundant node/event_pipeline surfaces`

## Reviewer Checklist

- `protocol` means wire definitions only.
- `peering` means runtime network workflows.
- identity/invite logic is colocated in one namespace.
- no compatibility shims introduced.
- no behavior change in sync/ingest flows.
- boundary checks and tests pass.
