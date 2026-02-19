# Trust Projection Eventization Instructions

## Goal
Move transport trust persistence to an event+projection model as far as practical, with minimal protocol churn and no trust-regression risk.

Primary target:
1. remove imperative writes from service/bootstrap flows to:
- `invite_bootstrap_trust`
- `pending_invite_bootstrap_trust`
2. make those rows projection-owned state derived from event facts + explicitly modeled local context.

## Hard Constraints
1. Keep strict mTLS behavior unchanged (`is_peer_allowed` remains authoritative at handshake).
2. Preserve inviter-side pre-accept trust (invitee first dial must still pass).
3. Preserve joiner-side accepted bootstrap trust until steady-state PeerShared trust supersedes it.
4. No weakening of removal semantics (`UserRemoved`/`PeerRemoved` must still deny trust).
5. Avoid broad redesign of sync protocol framing.

## Design Direction
### A) Projection-owned trust rows
1. `pending_invite_bootstrap_trust` should be produced by projection from locally-created invite events.
2. `invite_bootstrap_trust` should be produced by projection from `InviteAccepted` + bootstrap context.

### B) Local bootstrap context is explicit
`InviteAccepted` event does not currently carry `bootstrap_addr/bootstrap_spki`.
Use a small local durable context table (projection input), e.g. `bootstrap_context` keyed by `(recorded_by, invite_event_id)` with:
1. `bootstrap_addr`
2. `bootstrap_spki_fingerprint`
3. timestamps (`observed_at`, optional expiry)

Service/bootstrap code may write context rows, but should not write trust rows directly.

### C) Trust checks become read-only (preferred)
`is_peer_allowed` currently performs supersede updates on read.
Target: move supersession side effects into projection/maintenance path so trust checks are pure reads.

## Implementation Plan
### Phase 1: Baseline + tests
1. Add characterization tests around existing trust behavior:
- inviter pre-accept pending trust allows first dial
- joiner accepted trust after `InviteAccepted`
- supersession when PeerShared-derived trust appears
- removal-driven deny remains intact

### Phase 2: Add projection input context
1. Add `bootstrap_context` table migration.
2. Add DB helpers for upsert/read of context rows.
3. Update bootstrap/service paths to persist context rows only.

### Phase 3: Move pending trust writes out of service
1. Stop calling `record_pending_invite_bootstrap_trust` from service flows.
2. In identity projection path, emit/write pending trust rows when invite events are locally-created and context is sufficient.

### Phase 4: Move accepted trust writes out of service
1. Stop calling `record_invite_bootstrap_trust` from service flows.
2. In `InviteAccepted` projection handling, materialize accepted bootstrap trust using context + event IDs.

### Phase 5: Optional cleanup
1. Make trust check path read-only by removing supersede-on-read mutations.
2. Perform supersession in projection-triggered maintenance or explicit sweeper path.

## File Starting Points
- `src/service.rs`
- `src/db/transport_trust.rs`
- `src/projection/identity.rs`
- `src/projection/apply.rs`
- `src/db/migrations.rs`
- `src/transport/trust_oracle.rs`
- trust-related tests in `src/db/transport_trust.rs` and scenario/networking tests

## Durable State Audit (what should and should not be event+projection)
### Good candidates for projection ownership
1. trust authorization rows (`pending_invite_bootstrap_trust`, `invite_bootstrap_trust`)
2. derived trust/identity views tied directly to event facts

### Usually NOT event-projection (keep operational/local)
1. queue/lease state: `project_queue`, `egress_queue`, `wanted_events`
2. reconciliation caches: `neg_items`, `neg_blocks`, `neg_meta`
3. runtime observations/telemetry: `peer_endpoint_observations`, `intro_attempts`, `peer_transport_bindings`
4. local secret material: `local_transport_creds`, local signer key tables

Rule of thumb:
- shared canonical product semantics => event + projection
- local execution machinery, leases, telemetry, or private key material => non-event operational state

## Acceptance Criteria
1. Service layer no longer writes trust rows directly.
2. Trust rows converge via projection.
3. Existing invite/bootstrap/connect flows still pass.
4. No regression in strict trust checks and removal semantics.
5. Tests explicitly cover pre-accept, post-accept, supersession, and removal.
