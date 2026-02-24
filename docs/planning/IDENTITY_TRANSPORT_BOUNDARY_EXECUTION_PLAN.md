# Identity + Transport Boundary: Salvage Plan

Date: 2026-02-24
Source: salvaged from `exec/identity-transport-boundary-refactor` and reconciled with current `master`.

## Goal

Keep identity/event workflow ownership and transport identity materialization ownership explicit, with minimal service-layer coupling.

## Current Baseline on `master`

Already in place:

1. Typed contract exists at `src/contracts/transport_identity_contract.rs`.
2. Concrete adapter exists at `src/transport/identity_adapter.rs` and is the raw install boundary.
3. Workspace identity workflows are command-owned in `src/event_modules/workspace/commands.rs`.
4. Service routes invite/device-link/workspace flows through workspace command wrappers.
5. Identity scope convergence is explicit via `crate::db::finalize_identity(...)`.

## Ownership Model (Target and Guardrail)

1. Event modules own event-domain workflow semantics and command/query APIs.
2. Transport adapter owns cert/key materialization and `local_transport_creds` mutation.
3. Service owns orchestration only:
   - input parsing
   - caller scope/context selection
   - command invocation
   - response shaping

Contributor rule:

1. If code creates or sequences identity-chain events, put it in workspace event-module commands.
2. If code installs transport cert/key identity, put it behind `TransportIdentityAdapter`.
3. Service should not add event-specific SQL or raw transport install calls.

## Remaining Work (Narrow, High-Value)

1. Tighten boundary checks in `scripts/check_boundary_imports.sh` for identity-specific edges only:
   - forbid raw transport install calls outside `transport/identity_adapter.rs`;
   - forbid new service-level calls into identity primitive helpers when command wrappers exist.
2. Keep service wrappers short and naming-clear for invite/device-link/create-workspace paths.
3. Keep docs aligned:
   - `docs/DESIGN.md` should state ownership in one short section;
   - `docs/PLAN.md` should reference this ownership model as the default implementation rule.

## Validation

Minimum validation after any identity-boundary change:

1. `cargo check`
2. `bash scripts/check_boundary_imports.sh`
3. `cargo test --test cli_test -q`
4. `cargo test --test holepunch_test -q`
5. `cargo test --test sync_graph_test -q`

## Done Criteria

1. Identity workflow entrypoints remain in event-module commands.
2. Raw transport identity install remains adapter-only.
3. Service remains orchestration-thin for identity paths.
4. Boundary checks fail on violations and docs describe the same boundary the code enforces.
