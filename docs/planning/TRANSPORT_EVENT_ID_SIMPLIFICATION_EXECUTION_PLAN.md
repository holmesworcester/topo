# Transport/Event Identity Simplification Execution Plan

## Goal

Reduce transport identity complexity while preserving strict pinned mTLS and multi-tenant runtime behavior.

Core direction:
1. Keep `event_id` as canonical event-graph identity.
2. Keep transport SPKI fingerprint explicit as boundary identity (`transport_fingerprint`).
3. Make event projection the owner of invite bootstrap trust materialization as much as possible.
4. Minimize direct service-layer transport trust writes.
5. Add event-indexed mapping from projected peer events to transport fingerprints for deterministic lookup.

## Scope (This Change)

In scope:
1. TLA-first modeling of simplified trust/identity behavior with ongoing-first + bootstrap-fallback semantics.
2. Add explicit projected transport fingerprint materialization on `peers_shared` rows and index by it.
3. Add query API to resolve event-graph peer identity from transport fingerprint.
4. Remove direct command-layer pending-bootstrap trust writes in workspace invite creation paths (use projected outcome instead).
5. Improve naming clarity in transport boundary APIs/comments (`transport_fingerprint` terminology).
6. Add runtime dial behavior: ongoing identity first, bootstrap-fallback identity on trust rejection.
7. Validate with targeted tests.

Out of scope:
1. Invite-link expiry schema/payload changes.
2. Bootstrap key expiry derivation from invite expiry.

## Success Criteria

Functional criteria:
1. `PeerShared` projection stores deterministic `transport_fingerprint` derived from projected public key.
2. There is an indexed lookup path: `(recorded_by, transport_fingerprint) -> peer_shared_event_id`.
3. Workspace invite creation no longer writes pending bootstrap trust directly via `record_pending_invite_bootstrap_trust`.
4. Pending bootstrap trust still appears via normal projection flow for local invite creation.
5. Outbound dial policy is ongoing-first, with bootstrap fallback attempted only on trust-rejection handshakes.
6. Bootstrap-fallback sessions are bounded (single sync session then close).

Correctness criteria:
1. Existing projector and runtime tests pass for affected modules.
2. New unit tests cover transport fingerprint projection and reverse lookup.
3. No non-projection callsites remain in workspace command paths for pending bootstrap trust writes.

Readability criteria:
1. Transport-facing code paths use explicit `transport_fingerprint` terminology in key boundary comments/method names.
2. Plan includes explicit future-work note for invite-expiry-derived bootstrap key TTL.

## Phase Plan

### Phase 1 (First): TLA model

Deliverable:
1. New TLA module modeling simplified identity relation:
   - event-graph peer id is canonical,
   - transport fingerprint is boundary identity,
   - steady-state trust + bootstrap trust coexistence,
   - ongoing-first preference with bootstrap fallback on rejection.

Checks:
1. Type and invariant checks under TLC config.
2. Invariants documenting desired simplification properties.

### Phase 2: Event-indexed transport fingerprint projection

Deliverable:
1. Add `transport_fingerprint` column to `peers_shared` schema (with migration-safe additive behavior).
2. Add `(recorded_by, transport_fingerprint)` index.
3. Update `peer_shared` projector to materialize fingerprint deterministically.
4. Add query helper to resolve peer-shared `event_id` by transport fingerprint.

Checks:
1. Unit tests for projection field correctness and reverse lookup behavior.

### Phase 3: Remove direct command-side pending trust writes

Deliverable:
1. Remove direct `record_pending_invite_bootstrap_trust` calls from:
   - `create_user_invite`
   - `create_device_link_invite`
2. Keep event + bootstrap_context append flow intact.
3. Rely on projected trust materialization path.

Checks:
1. Existing invite/bootstrap projection tests continue to pass.

### Phase 4: Naming clarity pass

Deliverable:
1. Add explicit `transport_fingerprint()` accessor in connection/session boundary wrappers.
2. Update key comments and local variable names in connect/accept loops for clarity.

Checks:
1. Compile/tests pass.

### Phase 5: Validation and assessment

Deliverable:
1. Run targeted tests for projectors, transport trust, and relevant runtime loops.
2. Write simplification-power assessment:
   - complexity removed now,
   - complexity retained by hard constraints,
   - next simplification candidates.

### Phase 6: Runtime fallback wiring

Deliverable:
1. Add optional tenant bootstrap-fallback client config builder derived from projected pending invite key material.
2. Wire connect-loop dial policy:
   - attempt ongoing identity first,
   - retry with bootstrap fallback only for mTLS trust-rejection failures.
3. Restrict fallback use to bootstrap-ingress workers (not discovery workers).
4. Bound bootstrap-fallback connections to one sync session before close.

Checks:
1. Unit coverage for trust-rejection classification and fallback-config availability.
2. Runtime peering tests continue passing.

## Future Work (Explicit)

1. Add invite expiry to invite-link payload + projected invite state.
2. Derive `bootstrap_key_expires_at = invite_expires_at + grace`.
3. Enforce expiry in bootstrap identity fallback selection.
4. Purge expired bootstrap key material and bootstrap trust rows with operational metrics.

## Execution Status

Completed in this branch:
1. Phase 1 TLA update (identity index + ongoing-first/fallback invariants) completed in `docs/tla/TransportCredentialLifecycle.tla` and cfg files.
2. Phase 2 projection/index/query work completed (`peers_shared.transport_fingerprint`, index, reverse lookup helper).
3. Phase 3 command-side pending trust writes removed from workspace invite creation paths.
4. Phase 4 naming clarity pass completed with explicit `transport_fingerprint()` accessors on transport boundary wrappers.
5. Phase 5 validation completed with targeted Rust tests; TLC execution is currently blocked in this workspace because `tlc2.TLC` (jar/classpath) is unavailable.
6. Phase 6 runtime fallback wiring completed:
   - added `build_tenant_bootstrap_fallback_client_config_from_db`,
   - connect loops now dial ongoing-first and retry with bootstrap fallback only for trust-rejection failures,
   - fallback is enabled only for bootstrap-ingress workers,
   - fallback connections run one sync session then close.
7. Follow-up simplification: removed trust-specific projection `EmitCommand` variants (`WritePendingBootstrapTrust`, `WriteAcceptedBootstrapTrust`, `SupersedeBootstrapTrust`) by projecting trust rows directly and consuming bootstrap trust via `peer_shared` write ops.
