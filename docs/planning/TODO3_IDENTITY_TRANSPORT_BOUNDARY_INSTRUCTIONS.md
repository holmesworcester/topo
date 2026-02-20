# TODO 3 Instructions: Identity + Transport Boundary Contract

Date: 2026-02-19
Branch: `exec/todo3-identity-transport-boundary-instructions`
Worktree: `/home/holmes/poc-7-todo3-identity-transport`

## Goal

Make the identity/event layer and transport identity layer interact through one explicit contract surface.

Primary outcomes:

1. Event/identity logic owns *what transition should happen*.
2. Transport adapter owns *how cert/key identity is materialized*.
3. Service owns only orchestration ordering and response shaping.
4. Projection side effects issue typed intents, not ad hoc transport calls.

POC policy: no backward compatibility shims are required in final state unless needed transiently during refactor.

## Required start step

1. `git fetch origin`
2. `git rebase origin/master`

## Current pain points

1. `service.rs` still calls transport install functions directly in invite/device-link flows.
2. Projection apply executes `RefreshTransportCreds` by calling transport install directly from write executor.
3. Identity flow logic is split across `service.rs`, `identity/ops.rs`, and projection side-effects without one typed contract.
4. This makes sequencing harder to reason about and harder to test in isolation.

## Target contract

Introduce a typed event->transport intent contract in `src/contracts/`.

### Suggested API shape

```rust
pub enum TransportIdentityIntent {
    InstallInviteBootstrapIdentity {
        invite_private_key: [u8; 32],
    },
    InstallPeerSharedIdentityFromSigner {
        recorded_by: String,
        signer_event_id: [u8; 32],
    },
}

pub trait TransportIdentityAdapter {
    fn apply_intent(
        &self,
        conn: &rusqlite::Connection,
        intent: TransportIdentityIntent,
    ) -> Result<String, TransportIdentityError>;
}
```

Notes:

1. Return value is the installed transport peer id (`recorded_by`) where applicable.
2. Adapter may read `local_signer_material` for signer-key resolution.
3. Keep contract sync/connection-free; this is DB + identity materialization only.

## Ownership after refactor

1. `event_modules` / `identity` commands:
   - emit `TransportIdentityIntent` requests at semantic transition points.
2. `transport` adapter implementation:
   - performs actual cert/key install (`install_peer_key_transport_identity`, `install_invite_bootstrap_transport_identity`).
3. `service`:
   - calls commands/orchestrators,
   - applies intents via adapter,
   - performs `migrate_recorded_by` after successful identity transition.
4. `projection/apply`:
   - executes emitted intents via adapter-facing command executor path,
   - no direct calls to transport install internals.

## Required changes

### A) Add explicit contract + adapter

1. Add `src/contracts/transport_identity_contract.rs` with:
   - `TransportIdentityIntent`
   - `TransportIdentityAdapter` trait
   - typed error type
2. Re-export from `src/contracts/mod.rs`.
3. Add concrete adapter impl in transport-owned module, for example:
   - `src/transport/identity_adapter.rs`
4. Adapter must be the **only** place calling raw install functions.

### B) Replace direct service calls

1. Update invite/device-link accept flow in `src/service.rs`:
   - remove direct calls to install functions,
   - use adapter + intent.
2. Update bootstrap install paths similarly.
3. Keep orchestration flow unchanged semantically (ordering preserved).

### C) Replace projection-side ad hoc refresh command

1. Replace/upgrade `EmitCommand::RefreshTransportCreds` with an explicit intent-carrying variant, e.g.:
   - `EmitCommand::ApplyTransportIdentityIntent { intent: ... }`
2. `local_signer_secret` projector should emit explicit `InstallPeerSharedIdentityFromSigner` intent for `signer_kind == peer_shared`.
3. `projection/apply/write_exec.rs` should route that through adapter, not call transport install functions directly.

### D) Reduce duplicated identity assembly in service

1. Identify and remove duplicated identity-chain assembly path(s) where event-module/identity command already exists.
2. Keep exactly one authoritative command path for:
   - user invite accept
   - device link accept
   - identity bootstrap assembly.

### E) Add boundary enforcement

1. Add/extend boundary checks so only adapter module may import/use:
   - `install_peer_key_transport_identity`
   - `install_invite_bootstrap_transport_identity`
2. Disallow direct use from `service.rs`, `event_modules/*`, `projection/apply/*`.

## Test strategy (hard-to-cheat)

### 1) Contract tests with fake adapter

Add focused tests that inject a fake `TransportIdentityAdapter` and assert:

1. exact intents emitted,
2. exact order,
3. no duplicate/implicit transitions.

Suggested files:

1. `tests/identity_transport_contract_tests/*.rs`

### 2) Projection command path tests

For `local_signer_secret` projection:

1. projector emits intent command for peer_shared signer kind,
2. apply executor routes through adapter,
3. verify transition occurs only after event projection point.

### 3) Boundary grep tests

Add grep-based test/script assertions:

1. direct install function references are confined to adapter module(s),
2. violations fail CI/local checks.

### 4) End-to-end smoke

Run invite accept and device-link flows to confirm no behavior regression:

1. bootstrap identity install,
2. post-push-back peer_shared identity transition,
3. `recorded_by` migration remains correct.

## Quality gates

1. `cargo check`
2. `bash scripts/check_boundary_imports.sh`
3. `cargo test --lib -q`
4. `cargo test --test sync_contract_tests -q`
5. `cargo test --test holepunch_test -q`
6. targeted invite/device-link tests (existing ones):
   - trust/bootstrap path tests in `tests/cli_test.rs` and/or `tests/scenario_test.rs`

## Done criteria

1. One explicit typed contract mediates event/identity -> transport identity transitions.
2. `service.rs`, event modules, and projection apply do not call raw install functions directly.
3. Adapter is the sole raw transport identity installer boundary.
4. Contract tests and boundary checks enforce this and are hard to bypass.
5. Invite/device-link flow behavior remains unchanged from user perspective.

## Implementation notes for assistant

1. Preserve current sequencing around push-back sync before peer_shared transition.
2. Avoid mixing unrelated renames in this branch.
3. Keep commits small and intention-revealing:
   - contract scaffold,
   - call-site migration,
   - tests/boundary checks,
   - cleanup.
