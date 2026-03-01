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
1. `PW_ProjectPeerShared(p, spki)` (insert + supersede bootstrap/pending rows)
2. `PW_ProjectBootstrap(p, spki)`
3. `PW_ProjectPendingWrite(p, spki)`
4. `PW_ProjectPendingSuppressed(p, spki)` (bug toggle path, for repro only)
5. `PW_DialOngoing(p, q)` / `PW_DialBootstrapFallback(p, q)` / `PW_UpgradeConn(p, q)`
6. `PW_Deny(p, q)` when removal/exclusion is established

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

## Security bridge invariants (required)
1. `BrSec_ConnectionRequiresAuthorization`:
   any accepted/active connection state must imply remote active credential is authorized by runtime trust policy for that peer context.
2. `BrSec_NoTrustWithoutProvenance`:
   no materialized trust entry may exist without admissible event cause and corresponding projection write intent.
3. `BrSec_NoPendingTrustOnJoiner`:
   pending bootstrap trust must never materialize for non-inviter contexts (anti-privilege-escalation property).
4. `BrSec_SourceBindingConsistency`:
   credential source and trust-source labels cannot disagree with their event/row provenance.
5. `BrSec_RemovalDeniesConnectivity`:
   once removal/exclusion cause is projected for a peer relation, ongoing authorization for that relation is denied (or forced to fallback/deny, based on policy).
6. `BrSec_NoIdentityCollisionInAuthPath`:
   identity used for authorization is unique and cannot authenticate as multiple peers in the same state.

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
5. `BrLive_RemovalConvergesToDeny`:
   once removal/exclusion is established, eventual auth outcome converges to deny for the removed relation.

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

## Convergence policy (CI + deep)
The objective is not "all configs always exhaustive"; the objective is:
1. mandatory convergent gate configs in CI,
2. bounded interaction/deep configs for extra coverage,
3. no model/code drift for guarded behavior.

Tier definitions:
1. Tier 1 (`fast_gate`): exhaustive and convergent; required on every PR.
2. Tier 2 (`interaction`): exhaustive where feasible at 2-peer interaction scope; run pre-merge for trust/bootstrap changes.
3. Tier 3 (`deep`): larger domains and progress stress; run nightly/manual with budget caps.

Runtime targets:
1. Tier 1: <= 2 minutes per config.
2. Tier 2: <= 8 minutes per config (or documented as manual pre-merge when not CI-tractable).
3. Tier 3: <= 20 minutes per config.

Initial gating matrix:
1. `EventGraphSchema`: `event_graph_schema_fast.cfg` (Tier 1), `event_graph_schema.cfg` (Tier 2), `event_graph_schema_expanded_single_peer.cfg` and `event_graph_schema_bootstrap.cfg` (Tier 3).
2. `TransportCredentialLifecycle`: `transport_credential_lifecycle_fast.cfg` (Tier 1), `transport_credential_lifecycle.cfg` (Tier 2), bug/fix repro pair (Tier 2/Tier 3 depending domain).
3. `UnifiedBridge`: `unified_bridge_fix_repro.cfg` + `unified_bridge_progress_fast.cfg` (Tier 1), `unified_bridge_bug_repro.cfg` (Tier 2 repro evidence), `unified_bridge_progress_deep.cfg` (Tier 3).

Drift controls (required):
1. Every cross-layer invariant must map to a check id in `runtime_check_catalog.md` or `NON_MODELED::<reason>`.
2. Model-only guards that are not implemented in code must be removed or explicitly waived.
3. Bug-mode counterexample and fix-mode pass must remain runnable under the same reduced domain.

## Best-use gap closure checklist
1. Establish mandatory Tier 1 convergent checks for all three model families.
2. Keep Tier 2 and Tier 3 runs bounded and documented with command + elapsed time + states explored.
3. Keep bridge invariants scoped to trust/connection-critical surfaces first; avoid unrelated SQL breadth.
4. Maintain explicit mapping tables: event facts -> write intents -> runtime decisions.
5. Treat any model/code mismatch as a first-class defect (update code or update model; no silent drift).

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
| `EF_RemovalOrExclusion` | `user_removed` / `peer_removed` projection effects |
| `PW_ProjectPendingWrite` | projector `WritePendingBootstrapTrust` |
| `PW_ProjectBootstrap` | `record_invite_bootstrap_trust()` path |
| `PW_ProjectPeerShared` | `peer_shared_spki_fingerprints()` materialization + supersession of bootstrap/pending trust rows |
| `PW_DialBootstrapFallback` | `runtime/peering/loops/connect` fallback branch |
| `PW_DialOngoing` / `PW_UpgradeConn` | ongoing-first dial/upgrade behavior in `runtime/peering/loops/connect` |
| `PW_Deny` | removal/exclusion deny path in transport authz + connect lifecycle |
| `RT_TrustedSPKIs` | `allowed_peers_from_db()` trust union |
| `RT_CanAuthorize` | `is_peer_allowed()` and transport trust check |
| `RT_DialPreference` | connect-loop ongoing-first with bootstrap fallback |

## Runtime check catalog status
Bridge check ids are now listed in `docs/tla/runtime_check_catalog.md` under
`Unified Bridge Checks (Planned Integration Surface)`:
1. `CHK_BRIDGE_ROW_TO_RUNTIME_TRUST`
2. `CHK_BRIDGE_PENDING_LOCAL_CREATE`
3. `CHK_BRIDGE_ALLOWED_PEER_AUTH`
4. `CHK_BRIDGE_ONGOING_PREFERENCE`
5. `CHK_BRIDGE_BOOTSTRAP_FALLBACK`
6. `CHK_BRIDGE_BOOTSTRAP_PROGRESS`
7. `CHK_BRIDGE_UPGRADE_PROGRESS`
8. `CHK_BRIDGE_SYNC_COMPLETION_PROGRESS`
9. `CHK_BRIDGE_SEC_CONN_AUTHZ`
10. `CHK_BRIDGE_SEC_TRUST_PROVENANCE`
11. `CHK_BRIDGE_SEC_PENDING_INVITER_ONLY`
12. `CHK_BRIDGE_SEC_SOURCE_BINDING`
13. `CHK_BRIDGE_SEC_REMOVAL_DENY`
14. `CHK_BRIDGE_SEC_IDENTITY_COLLISION`

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

## TLC execution notes (2026-02-28)
1. `./tlc UnifiedBridge unified_bridge_bug_repro.cfg`
   - Status: **FAIL (expected)**
   - Invariant: `BrInv_LocalInviteProjectsPending`
   - Stats: 3584 generated / 1907 distinct / depth 8 / 0s
   - Counterexample: `PW_ProjectPendingSuppressed` triggers when inviter local credential is already peer_shared-trusted, dropping pending write intent.
2. `./tlc UnifiedBridge unified_bridge_fix_repro.cfg`
   - Status: **PASS**
   - Stats: 1720185 generated / 161047 distinct / depth 18 / 7s
3. `./tlc UnifiedBridge unified_bridge_progress_fast.cfg`
   - Status: **PASS**
   - Stats: 3740535 generated / 358255 distinct / depth 19 / 1m49s
   - Temporal branch checks: 20 branches completed with no violations.
