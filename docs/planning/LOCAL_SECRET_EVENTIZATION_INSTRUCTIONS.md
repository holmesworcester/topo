# Local Secret Eventization Instructions

> **Executed; file paths may not match the current source tree.** `src/projection/identity.rs` is now split across event modules under `src/event_modules/`.

## Goal
Move local signer private-key persistence from service-owned ad-hoc tables to local non-shareable canonical events + projection-owned state.

Primary target:
1. eliminate service-owned authority tables:
- `local_peer_signers`
- `local_user_keys`
- `local_workspace_keys`
2. model local signer material as durable local events that replay deterministically.
3. treat `local_transport_creds` as a derived cache/materialization from projected local signer state.

## Why This Work Exists
Current state is split:
1. content secret material (`secret_key`, `secret_shared`) is already eventized.
2. signer private keys are still persisted imperatively in `src/service.rs`.
3. these signer tables are created lazily in service helpers (not migration-owned, not projector-owned).
4. runtime does not currently implement a first-class local `Peer` event type, even though `docs/tla/EventGraphSchema.tla` models one (`Peer == "peer"`).

Net effect: local durable signer state is replay-incomplete and less coherent than the rest of the event/projection model.

## Hard Constraints
1. No trust regression: signer lookup and signature verification behavior must remain equivalent.
2. No bootstrap/invite/device-link regression.
3. No weakening of local-only semantics (private key events must never be shareable).
4. Keep one projection entrypoint (`project_one`) and shared signer pipeline intact.
5. TLA-first coherence: model updates precede behavior changes in Rust.

## TLA-First Requirement (Mandatory)
Update model/docs before code if semantics change.

At minimum update:
1. `docs/tla/EventGraphSchema.tla`
2. `docs/tla/projector_spec.md`
3. relevant cfg files in `docs/tla/*.cfg` if new event types are added to active sets
4. `docs/PLAN.md` and `docs/DESIGN.md` to match final naming/ownership

Model requirements:
1. represent local signer-secret source as local-only events.
2. define dependency relation from local signer-secret events to signer identity events (or explicit rationale if dependency is not required).
3. state invariant that signer private-key projection rows are derived only from local signer-secret events.
4. keep existing invite trust-anchor cascade semantics aligned with model.
5. key-wrap dependency model:
- `encrypted` hard-depends on local secret event id.
- `secret_shared.key_event_id` is a verified hint for deterministic key identity, not a hard projection dependency.
- recipient-side unwrap/materialization from `secret_shared` must produce a local secret event whose id matches the hint.

## Design Direction
### A) Introduce explicit local signer-secret event model
Choose one of:
1. one polymorphic local event type (e.g. `local_signer_secret`) with fields:
- `signer_event_id`
- `signer_kind` (`workspace|user|peer_shared`)
- `private_key_bytes`
2. three explicit local event types:
- `workspace_secret`
- `user_secret`
- `peer_secret`

Either option must be:
1. local-only share scope
2. projection-owned into signer-material tables
3. replayable and idempotent

### B) Projection owns local signer material
Projection should populate a single durable view (or equivalent):
- `local_signer_material(recorded_by, signer_event_id, signer_kind, private_key, created_at, superseded_at)`

Then signer loaders read only projection-owned rows.

### C) Transport creds as derived cache
`local_transport_creds` should be cache/materialization from projected local peer signer state:
1. projector and/or maintenance path derives cert/key from projected peer signer secret
2. transport identity loaders remain read-only over cache
3. cache rebuild is possible from replayed local signer-secret events

### D) Replay ordering guarantee (required)
Do not rely on event processing order for correctness.

Rules:
1. any event that semantically needs secret material must carry explicit `event_id` deps to the local secret event(s), so normal dep blocking/cascade enforces ordering.
2. startup/runtime must not expose command/network paths that require local signer secrets until replay catches up (replay-complete barrier).
3. if a path requires local signer material and replay has not yet projected it, fail explicitly with a deterministic error (no silent fallback key generation).

### E) Key-wrap dependency model (preferred)
This branch adopts the following model explicitly:
1. `encrypted` events declare dependency on local-only secret event id (`key_event_id`).
2. `secret_shared` carries `key_event_id` as identity metadata/hint but does not dep-block on that id.
3. when recipient projects/handles `secret_shared`, it unwraps and materializes local secret event; projector/handler verifies materialized event id == hinted `key_event_id`.
4. once local secret event becomes valid, normal dep cascade unblocks any waiting `encrypted` events.
5. out-of-order replay (secret_shared before local secret event, encrypted before local secret event) must converge via normal block/unblock flow.

## Implementation Plan
### Phase 0: Characterize current behavior
1. tests around bootstrap, invite acceptance, device-link, and send paths that currently rely on local signer tables.
2. assert restart/reopen behavior still finds local signer keys.

### Phase 1: TLA + spec updates first
1. encode local signer-secret event semantics in TLA.
2. update projector spec and dependency notes, including key-wrap dependency model (`encrypted` hard dep, `secret_shared` hint semantics).
3. align PLAN/DESIGN terminology before Rust changes.

### Phase 2: Event schema + parser
1. add new local signer-secret event type(s) in `src/event_modules/*`.
2. set local share scope and dependency metadata.
3. add fixed-layout/registry wiring + tests.
4. update `secret_shared` dependency metadata so `key_event_id` is not a hard dep (retain type/shape validation as hint).

### Phase 3: Projector path
1. add projector(s) that materialize signer private-key projection rows.
2. keep idempotence and first-write/replace semantics explicit.
3. ensure projection is tenant-scoped (`recorded_by`).
4. enforce `secret_shared` unwrap/materialization check: materialized local secret event id must match carried `key_event_id` hint.

### Phase 4: Service refactor
1. stop writing `local_peer_signers`, `local_user_keys`, `local_workspace_keys` as authority.
2. service emits local signer-secret events instead.
3. loading helpers read projection-owned signer material.

### Phase 5: Transport cache alignment
1. ensure `local_transport_creds` derivation path follows projected local peer signer state.
2. remove/limit direct imperative authority writes where feasible.

### Phase 6: Legacy cleanup
1. migrate or drop obsolete local signer tables.
2. remove create-table-on-demand helpers from `src/service.rs`.
3. keep `migrate_recorded_by` aligned to new tables only.

## File Starting Points
- `src/service.rs`
- `src/identity_ops.rs`
- `src/event_modules/mod.rs`
- `src/event_modules/registry.rs`
- `src/projection/identity.rs`
- `src/projection/apply.rs`
- `src/db/migrations.rs`
- `src/db/mod.rs`
- `src/transport_identity.rs`
- `docs/tla/EventGraphSchema.tla`
- `docs/tla/projector_spec.md`
- `docs/PLAN.md`
- `docs/DESIGN.md`

## Tests To Add/Adjust
1. bootstrap persists local signer material through local events + projection.
2. invite accept persists local user/peer signer material through local events + projection.
3. device-link creation/accept still works after restart.
4. signer lookup for send/react/delete commands uses projected local signer state.
5. replay from events reconstructs signer material and (if enabled) transport cache.
6. encrypted events block on missing local secret events and unblock after local secret projection.
7. secret_shared can project before local secret exists; recipient materialization later unblocks encrypted via normal cascade.

### Replay Test Matrix (Required)
1. Full reprojection rebuild:
- start from persisted `events` + `recorded_events` only (drop/clear signer-material projections and cache tables),
- rerun projection/replay,
- assert signer material is fully reconstructed and command signing works.
2. Restart replay:
- bootstrap or accept invite,
- close process and reopen DB,
- run replay path,
- assert same signer identities/keys are available.
3. Deterministic local event replay:
- ingest same local signer-secret event twice (or replay twice),
- assert idempotent projection rows and stable key lookup.
4. Cache regeneration:
- clear `local_transport_creds`,
- regenerate from projected local signer state,
- assert resulting peer_id/SPKI matches expected deterministic identity.
5. Out-of-order resilience:
- apply relevant local signer-secret and dependent identity/signing events out of order via recorded stream,
- assert final projected signer material converges after cascade/replay.
6. Out-of-order key-wrap replay:
- ingest `secret_shared` first, then `encrypted`, then materialized local secret event,
- assert `encrypted` transitions block -> valid via normal cascade,
- assert materialized local secret event id matches `secret_shared.key_event_id` hint.

## Acceptance Criteria
1. service layer no longer treats `local_peer_signers`, `local_user_keys`, `local_workspace_keys` as authoritative persistence.
2. local signer key state is event-sourced (local-only) and projection-owned.
3. `local_transport_creds` is explicitly cache/materialization, not primary authority.
4. TLA/spec/docs updated first and aligned with implementation.
5. no regression in bootstrap, invite, device-link, and signed content flows.
6. key-wrap replay semantics are deterministic:
- `encrypted` depends on local secret event id;
- `secret_shared.key_event_id` is validated as hint;
- out-of-order replay converges without imperative repair paths.

## Open Design Questions (resolve before coding)
1. one polymorphic local signer-secret event vs three explicit event types?
2. should signer-secret events depend on signer identity event id, or be allowed pre-identity with later binding?
3. supersession policy for key rotation: replace-by-signer-event-id, timestamp, or explicit rotation event?
4. do we need explicit projector command to refresh `local_transport_creds`, or a separate maintenance pass?
5. should `secret_shared` unwrap/materialization stay in identity_ops/service helpers or move into projector command path for stricter replay isomorphism?
