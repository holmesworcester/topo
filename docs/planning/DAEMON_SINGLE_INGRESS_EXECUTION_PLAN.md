# Daemon Single-Ingress Execution Plan

Date: 2026-02-24  
Branch: `exec/daemon-single-ingress-plan`  
Worktree: `/home/holmes/poc-7-daemon-single-ingress-plan`

## Objective

Simplify bootstrap and runtime flow with one rule: commands enter through one daemon API path, and peering runtime activates from projected tenant state.

Primary outcomes:

1. One command ingress route (`CLI -> RPC -> command`), including `create-workspace` and `accept`.
2. Control daemon can start with zero tenants (no hard bootstrap prerequisite).
3. Peering runtime is lifecycle-managed (`IdleNoTenants` -> `Active`) without daemon restart.
4. Secret material remains event-sourced but local-only (`share_scope=local`) and never sent on sync.

## Scope

In scope:

1. `src/main.rs` (CLI command routing/autostart behavior).
2. `src/rpc/{server.rs,protocol.rs,client.rs}` (single ingress, startup behavior).
3. `src/node.rs` and `src/peering/runtime/**` (runtime activation/deactivation when tenant set changes).
4. `src/event_modules/workspace/**` + local-secret helpers for remaining non-event secret writes.
5. `tests/{rpc_test.rs,cli_test.rs,cheat_proof_realism_test.rs}` and any new targeted tests.
6. `docs/CURRENT_RUNTIME_DIAGRAM.md`, `docs/DESIGN.md`, `docs/PLAN.md` updates for the new flow.

Out of scope:

1. UI state eventization (`active_peer`, channel selection, invite refs).
2. Broad event schema redesign unrelated to bootstrap/runtime activation.
3. Backward compatibility shims for legacy bootstrap paths (POC: prefer clean final model).

## Non-Negotiable Requirements

### R1. Single command ingress

1. `create-workspace` and `accept` must route through RPC, not direct command calls in `main.rs`.
2. `main.rs` must not invoke workspace command functions directly.
3. CLI path behavior may change if needed; readability and single-route consistency take priority.

### R2. Daemon-first control plane per DB

1. Control daemon start must succeed on an empty DB (no tenant identity yet).
2. Runtime network loops are a managed child state, not startup precondition.
3. If daemon for selected DB is not running, CLI should start/attach automatically before issuing RPC (except explicit `start`/`stop` handling).

### R3. Runtime activation from projection state

1. Runtime enters active mode when discoverable tenants exist.
2. Runtime re-check is triggered after commands that can create tenants (`create-workspace`, `accept`, `accept-link`).
3. No manual daemon restart required to transition from bootstrap to active sync.

### R4. DB isolation is explicit

1. One daemon instance per DB/socket scope.
2. Auto-start/attach logic must respect `--db` and `--socket`.
3. Commands must never accidentally hit a daemon for a different DB.

### R5. Secret material is event-sourced local-only

1. Secret writes required for replay/unblock behavior must be represented as events with `share_scope=local`.
2. Remaining imperative secret writes in command/workflow code must be removed or explicitly justified as migration-only.
3. Sync egress must continue enforcing shared-only transmission.

### R6. Diagram clarity

1. Diagrams must show one ingress and two daemon runtime states (`IdleNoTenants`, `Active`).
2. No special direct-bootstrap arrow outside the RPC path.

## Mandatory Implementation Phases

### Phase 0: Baseline and path inventory

1. Capture current direct ingress callsites and bootstrap assumptions.
2. Capture baseline test pass for CLI/RPC suites.

### Phase 1: Remove direct bootstrap command path

1. Delete direct-only command branch in `main.rs` for `create-workspace` and `accept`.
2. Route both through existing RPC methods.
3. Keep user-facing output compatibility where practical; do not preserve duplicate internals.

### Phase 2: Daemon ensure/attach behavior

1. Add a single helper that resolves target socket for DB and ensures daemon availability.
2. Non-lifecycle commands use ensure+RPC path (including bootstrap commands).
3. Explicit lifecycle commands (`start`, `stop`) remain explicit.

### Phase 3: Split control daemon from peering runtime activation

1. `start` launches control daemon even when no tenants exist.
2. Introduce runtime manager with explicit state (`IdleNoTenants`, `Active`).
3. Trigger runtime reevaluation on tenant-changing commands and/or periodic lightweight checks.

### Phase 4: Local-secret eventization completion

1. Audit `workspace/identity_ops.rs` + related command paths for direct writes to `local_signer_material` / secret tables.
2. Replace remaining operational secret writes with local-only event emission + projector application.
3. Keep sync egress shared-only gate intact (`Store::get_shared` path).

### Phase 5: Docs, tests, and evidence

1. Update runtime diagrams/docs to reflect final flow.
2. Add targeted regression tests for:
   - daemon start on empty DB,
   - bootstrap commands through RPC with daemon auto-start,
   - runtime activation without restart,
   - local-only secret events never replicated.

## Hard Success Criteria (all required)

### SC1. No direct bootstrap command calls in CLI

1. `src/main.rs` has no direct calls to `create_workspace_for_db` or `accept_invite`.
2. `Direct-only commands` bootstrap section is removed.

### SC2. One ingress route in practice

1. `topo create-workspace` succeeds via RPC when daemon absent (autostart or attach behavior).
2. `topo accept` succeeds via RPC when daemon absent (autostart or attach behavior).

### SC3. Daemon can start with empty DB

1. `topo start --db <fresh>` does not fail due to missing tenants.
2. `topo status --db <fresh>` reports daemon/control-plane readiness and idle/no-tenant runtime state.

### SC4. Runtime transitions without restart

1. After `create-workspace` or `accept` against an already-running daemon, runtime activates automatically.
2. No manual `topo stop`/`topo start` needed.

### SC5. DB/socket isolation holds

1. Two DBs can run independent daemons concurrently.
2. Commands scoped to DB A never mutate/query DB B daemon state.

### SC6. Secret path is local-only event-sourced

1. Workspace/bootstrap secret persistence uses local events, not ad-hoc direct table writes in runtime command flow.
2. Egress data path still sends only `share_scope='shared'` events.
3. Local-only secret events appear in `events` table and projection replay works.

### SC7. Documentation matches code

1. `docs/CURRENT_RUNTIME_DIAGRAM.md` shows single ingress and runtime state split.
2. `docs/DESIGN.md` and `docs/PLAN.md` describe the same ownership model.

### SC8. Regression gates pass

1. Existing relevant CLI/RPC tests pass.
2. New targeted tests for SC2-SC6 pass.

## Required Verification Commands (no-cheat checks)

```bash
# Ingress checks
rg -n "create_workspace_for_db\\(|accept_invite\\(" src/main.rs
rg -n "Direct-only commands" src/main.rs

# Runtime bootstrap assumptions
rg -n "No local identities found|bootstrap a workspace|accept an invite first" src/peering/runtime src/node.rs

# Secret write audit (must be zero in runtime command paths; projector/migrations/tests excluded)
rg -n "INSERT OR REPLACE INTO local_signer_material|DELETE FROM local_signer_material|INSERT INTO secret_keys|UPDATE secret_keys|DELETE FROM secret_keys" \
  src/event_modules src/service.rs src/rpc src/main.rs \
  -g'!**/migrations.rs' -g'!**/tests/**'

# Shared-only egress gate still present
rg -n "get_shared\\(|share_scope = 'shared'" src/sync src/db/store.rs

# Core test suites
cargo check
cargo test --test rpc_test -q
cargo test --test cli_test -q
cargo test --test cheat_proof_realism_test -q
```

Expected interpretation:

1. Ingress grep in `main.rs` returns no direct bootstrap command function calls.
2. Secret write audit returns no imperative secret writes in runtime command flow.
3. Shared-only egress grep confirms local-only events cannot leak over sync.

## Required Evidence Artifact

Create:

- `docs/planning/DAEMON_SINGLE_INGRESS_EVIDENCE.md`

Evidence format:

1. SC1-SC8 table with PASS/FAIL.
2. For each SC: file proof + grep proof + test/command proof.
3. Explicitly call out any temporary exceptions and why they are safe.

## Mandatory Working Rules

1. Work only in `/home/holmes/poc-7-daemon-single-ingress-plan`.
2. Rebase on latest `master` before final review:
   - `git fetch origin`
   - `git rebase origin/master`
3. Run Codex CLI review loop at least twice:
   - mid-implementation feedback in `feedback.md`
   - final audit with SC-by-SC verdict in `codex_final_audit.md`
4. Commit on this branch when implementation is complete.
5. Do not mark ready-to-merge unless all SC1-SC8 are PASS.
