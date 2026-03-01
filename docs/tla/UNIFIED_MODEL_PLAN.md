# Unified Model Plan (Option B)

## Decision
This investigation uses **Option B**: layered models with explicit refinement/bridge invariants.

Primary layers:
1. `EventGraphSchema.tla` (event validity, replay, projected event facts, connection state machine)
2. `TransportCredentialLifecycle.tla` (materialized trust sources, credential source, dial preference)

Bridge objective:
- Prove event facts and projection writes refine into transport/runtime trust and connection outcomes used by networking behavior.

## Product goals to prove
1. Nodes can bootstrap.
2. Nodes can connect.
3. Nodes can sync enough state to complete bootstrap.
4. Nodes can upgrade from invite/bootstrap connectivity to ongoing connectivity.
5. Ongoing-first dial policy is preserved, with bootstrap fallback when needed.

## Scope boundaries
In scope:
1. Trust-critical and connection-critical projection outputs.
2. Invite and PeerShared path from create/accept through connection upgrade.
3. Counterexample for known pending-trust suppression bug.

Out of scope (first pass):
1. Arbitrary credential rotation/revocation machinery beyond current POC assumptions.
2. Full SQL schema coverage unrelated to trust/connection decisions.
3. Full payload/message convergence semantics outside bootstrap completion path.

## Bridge model shape
Use a small integration/bridge module (new `UnifiedBridge.tla`) that imports/embeds reduced abstractions from both layers and adds a write-intent surface.

State surfaces:
1. Event facts surface (`EF_*`): trusted-peer facts, invite ownership, connection phases.
2. Projection write-intent surface (`PW_*`): abstract inserts/deletes/upserts for trust and connection rows.
3. Materialized runtime surface (`RT_*`): trust sets, active credential source, allowed/auth outcomes, dial preference.

## Write-intent abstraction (required)
Model projection writes as explicit actions (not only derived equality):
1. `PW_InsertPeerSharedTrust(p, spki, event_id)`
2. `PW_InsertBootstrapTrust(p, spki)`
3. `PW_InsertPendingBootstrapTrust(p, spki)`
4. `PW_DeleteBootstrapTrust(p, spki)` when superseded
5. `PW_DeletePendingBootstrapTrust(p, spki)` when superseded
6. `PW_SetConnState(p, state)` for invite/peer progression

Each write intent must map to a Rust projection path in a table in this file.

## Core bridge invariants (safety)
1. `BrInv_TrustedPeerRefinesRuntimeTrust`:
   event-level trusted peer fact implies corresponding runtime trust membership (via projected row semantics).
2. `BrInv_RuntimeTrustHasEventCause`:
   runtime trust membership must be justified by event fact + corresponding write intent history.
3. `BrInv_PendingOnlyOnInviter`:
   pending trust row/materialized trust may exist only for invite creator context (`is_local_create` equivalent).
4. `BrInv_AllowedPeerMatchesAuthDecision`:
   if runtime allowed set contains remote active SPKI then connection-auth decision can succeed; otherwise deny.
5. `BrInv_OngoingPreferred`:
   ongoing trust source implies ongoing dial preference.
6. `BrInv_BootstrapFallbackOnlyWhenNeeded`:
   bootstrap fallback selected only when ongoing path unavailable and bootstrap/pending trust exists.
7. `BrInv_RowToMaterializedExactness`:
   materialized trust sets are exact reductions of write-intent rows (after supersession/expiry rules).

## Progress properties (liveness)
Use explicit fairness assumptions over projection and connection transition families.

1. `BrLive_BootstrapConnectEventually`:
   if invite acceptance preconditions hold and no exclusion/removal blockers, eventually invite connectivity is established.
2. `BrLive_PeerUpgradeEventually`:
   if invite connectivity active and PeerShared prerequisites hold, eventually peer/ongoing connectivity is established.
3. `BrLive_BootstrapCompletionSyncEventually`:
   once connected and admissible, eventually required bootstrap-completion facts are projected/materialized.
4. `BrLive_FallbackAttemptEventually`:
   if ongoing unavailable and bootstrap trust available, eventually fallback dial path is chosen/attempted.

## Fairness assumptions
Document and encode at minimum:
1. Projection fairness: enabled projection/write-intent actions are not perpetually postponed.
2. Connection fairness: enabled connect/ack/upgrade actions are not perpetually postponed.
3. Environment fairness constraints are minimal and explicit (no hidden scheduler oracle).

## Bug/fix reproducibility
Use a parameterized bug toggle aligned with current regression class:
1. `UseBuggyPendingGate = TRUE` reproduces pending-trust suppression behavior.
2. `UseBuggyPendingGate = FALSE` validates corrected behavior.

Required result:
1. Bug config violates at least one bridge invariant or progress property with a short counterexample.
2. Fix config passes same check set under same domain.

## Constants and run budgets
Fast CI domain (target <= 2 minutes):
1. `Peers = {alice, bob}`
2. Small SPKI/event domains (2-3 elements each)
3. Bootstrap path event subset only

Deep domain (target <= 20 minutes):
1. `Peers = {alice, bob}`
2. Expanded SPKI/event sets
3. Add additional transitions around supersession/expiry

## Proposed files
1. `docs/tla/UnifiedBridge.tla`
2. `docs/tla/unified_bridge_bug_repro.cfg`
3. `docs/tla/unified_bridge_fix_repro.cfg`
4. `docs/tla/unified_bridge_progress_fast.cfg`
5. `docs/tla/unified_bridge_progress_deep.cfg`

## Mapping table (initial)
| Bridge surface | Rust/runtime concept |
|---|---|
| `EF_InviteCreator` | `recorded_events.source` / `is_local_create` |
| `PW_InsertPendingBootstrapTrust` | projector `WritePendingBootstrapTrust` |
| `PW_InsertBootstrapTrust` | `record_invite_bootstrap_trust()` path |
| `PW_InsertPeerSharedTrust` | `peer_shared_spki_fingerprints()` materialization |
| `RT_TrustedSPKIs` | `allowed_peers_from_db()` trust union |
| `RT_CanAuthenticate` | `is_peer_allowed()` and transport trust check |
| `RT_DialPreference` | connect-loop ongoing-first with bootstrap fallback |

## Runtime check catalog update plan
Add new check ids in `docs/tla/runtime_check_catalog.md`:
1. `CHK_BRIDGE_ROW_TO_RUNTIME_TRUST`
2. `CHK_BRIDGE_PENDING_LOCAL_CREATE`
3. `CHK_BRIDGE_ALLOWED_PEER_AUTH`
4. `CHK_BRIDGE_ONGOING_PREFERENCE`
5. `CHK_BRIDGE_BOOTSTRAP_FALLBACK`
6. `CHK_BRIDGE_BOOTSTRAP_PROGRESS`
7. `CHK_BRIDGE_UPGRADE_PROGRESS`
8. `CHK_BRIDGE_SYNC_COMPLETION_PROGRESS`

## TLC execution notes template
1. `cd docs/tla`
2. `./tlc UnifiedBridge unified_bridge_bug_repro.cfg`
3. `./tlc UnifiedBridge unified_bridge_fix_repro.cfg`
4. `./tlc UnifiedBridge unified_bridge_progress_fast.cfg`
5. `./tlc UnifiedBridge unified_bridge_progress_deep.cfg`

Record:
1. command
2. elapsed time
3. states / distinct states
4. violation or pass status
5. brief counterexample summary when failing
