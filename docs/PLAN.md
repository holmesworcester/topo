# Simplification Plan For Rust `poc-7`

## 1. Implementation Order (Authoritative)

This document is ordered exactly as we should build it.

1. `Phase -1`: CLI + daemon around the current simple prototype.
2. `Phase 0`: mTLS + QUIC transport baseline finalized.
3. `Phase 0.5`: Provisional multi-workspace/tenant routing smoke test (CLI-supplied key material).
4. `Phase 1`: Event schema, recording semantics, and multitenancy foundation.
5. `Phase 2`: Projector core and dependency blocking (without full queue complexity).
6. `Phase 2.5`: Shared signer substrate (`signed_by` dependency blocking + signature verification ordering).
7. `Phase 2.6`: Multitenancy scoped-projection/query gate (with signer substrate active).
8. `Phase 3`: Encrypted events using the same dependency/projector model, tested first with per-instance PSK.
9. `Phase 4`: Durable queue architecture (`ingress`, `project`, `egress`) and workers.
10. `Phase 5`: Non-identity special-case projector logic (deletion/emitted-events).
11. `Phase 6`: Performance hardening, observability, scaling, and low-memory iOS mode.
12. `Phase 7`: TLA-first minimal identity layer for trust-anchor cascade, removal, and sender-subjective encryption.

Scheduling note:
- two-tier multitenancy plan:
  - Phase 0.5 proves provisional transport/workspace separation and CLI workspace views.
  - Phase 2.6 proves scoped projection/query separation once projector + signer substrate exist.
- `signed_by` dependency blocking + signature verification ordering is tackled in Phase 2.5.
- Phase 2.5 and Phase 2.6 must be complete before starting identity projectors in Phase 7.

## 1.1 `codex-simplified` baseline gap audit (current state)

Current code in `poc-7` (post-move from `codex-simplified`) is a useful sync prototype, but has deliberate gaps relative to this plan:

1. Fixed-size wire/event assumptions:
   - `src/wire/mod.rs` uses fixed `ENVELOPE_SIZE = 512`.
   - `src/sync/protocol.rs` uses fixed `EVENT_SIZE = 1 + ENVELOPE_SIZE`.
2. mTLS is not yet pinned/strict:
   - `src/transport/mod.rs` uses permissive server-cert verification (`SkipServerVerification`) and no mandatory peer pinning.
3. Projection pipeline is still message-specific and sync-engine-coupled:
   - `src/sync/engine.rs` does inline parse/project for message rows.
   - no global `project_one(recorded_by,event_id)` entrypoint yet.
4. No dependency blocking model yet:
   - no `blocked_event_deps` / unblock/requeue flow.
5. No per-tenant receive journal yet:
   - no `recorded_events(recorded_by,event_id,recorded_at,source)` in active code path.
6. No queue family from this plan yet:
   - no `project_queue` / `egress_queue` lease-retry helpers shared across workers.
7. Identity/trust-anchor/removal model not implemented:
   - no split invite types (`user_invite`, `device_invite`) and no TLA-derived identity projector guards.
8. No shared signer substrate yet:
   - no uniform `signed_by` dependency blocking + signature verification ordering across event types.
9. No two-tier multitenancy verification yet:
   - no Phase 0.5 routing smoke coverage and no post-projector scoped-projection gate.

Gap-to-phase mapping:
- wire framing + schema normalization -> `Phase 1`
- strict pinned mTLS -> `Phase 0`
- provisional workspace routing smoke -> `Phase 0.5`
- projector entrypoint + dep/blocking core -> `Phase 2`
- shared signer dependency + signature pipeline -> `Phase 2.5`
- scoped multitenancy projection/query gate -> `Phase 2.6`
- encryption adapter + key deps -> `Phase 3`
- queue/worker architecture -> `Phase 4`
- deletion/emits explicit rules -> `Phase 5`
- trust-anchor/invite/removal/sender-keys -> `Phase 7`

---

## 2. Core Simplifications To Preserve

- Terminology: use `workspace` (event + domain term) for the peer set and shared context; reserve "network" for transport/networking.
- Connection/sync state is protocol/runtime state, not canonical events.
- Canonical events are durable, replayable, and mostly projector-autowritable.
- Local-only events remain canonical events, selected by `event_type` policy.
- Event format stays flat. No universal `deps` field and no universal `payload` object.
- Any schema field that references `event_id` is a dependency source.
- Use one blocker mechanism for everything, including missing keys for encrypted events.
- Blocked-event normalcy rule:
  - blocked events are still canonical/shareable facts and can be expected end-states for some tenants.
  - after a sync session, appropriately blocked events do not indicate protocol failure.
  - expected examples include encrypted content for non-recipients and key-share events for non-recipients.
- No per-event transit wrapper. QUIC + mTLS secures the channel.
- Use separate tables for permanent canonical data vs operational queues.
- Use separate invite event types (`user_invite`, `device_invite`), not one multimodal invite with `mode=*`.
- Deterministic emitted event types stay inside the emitted-event rule flow but are unsigned for determinism (`no signed_by/signer_type/signature`).

## 2.1 Locked design requirements (explicit)

These are required, not optional:

1. One projector entrypoint for all ingest paths.
   - `local_create`, `wire_receive`, `replay`, and unblock requeue all converge on the same `project_one(recorded_by, event_id)` path.
2. One dependency engine for all event types.
   - dependency refs come only from schema metadata on flat fields.
   - no per-type ad-hoc dependency checker.
3. Split invite types with shared implementation core.
   - keep separate event types (`user_invite`, `device_invite`) for model clarity.
   - implement with one shared invite projector helper/spec mapping.
4. One key-wrap event model across phases.
   - PSK bootstrap phase and identity sender-keys phase use the same key-wrap event/projector path.
   - only key source and wrapping algorithm differ.
5. DRY queue mechanics.
   - `project_queue` and `egress_queue` share generic claim/lease/retry/backoff helper code.
6. Isomorphism requirement.
   - once canonical event bytes are persisted, source differences disappear (`local_create == wire_receive == replay`) for projection logic.
7. Shared projection tables with tenant-scoped autowrite.
   - all peers write into the same per-event projection tables (no per-peer table fanout).
   - subjective/projected rows carry tenant scope and use composite identity (`peer_id`, `event_id`) semantics.
8. Emitted-event self-projection rule.
   - projector side effects should emit canonical events; each emitted event projects to its own event table via its own projector/autowrite path.
   - direct cross-event table writes are rare operational exceptions only.
9. Blocked-is-not-failure requirement.
   - blocked rows that are policy-appropriate for a tenant (for example non-recipient encrypted/key-share events) are expected and must not be treated as sync failure.

---

## 3. Phase -1: CLI + Daemon First

Build this before queue complexity.

### Deliverables

- One daemon per profile/peer with local RPC control socket.
- Thin CLI (`p7ctl`) for non-interactive control.
- Stable JSON responses and exit codes.
- Assertion-first testing commands:
  - `assert-now <predicate>`
  - `assert-eventually <predicate> --timeout-ms <n> --interval-ms <n>`
  - optional `assert-stable <predicate> --for-ms <n>`

### Why first

- Locks in operational UX for human + agent workflows.
- Lets LLM self-play loops run through real commands instead of ad-hoc waits.
- Provides a stable harness before deeper internal refactors.

### Exit criteria

- Two daemons exchange chat events over QUIC.
- CLI can create/query/assert deterministically in scripts.
- Real-time feel is acceptable with current simple path.

### Status: COMPLETE

Phase -1 is functionally complete. All deliverables are met:
- `sync`, `send`, `messages`, `status`, `generate` CLI commands work.
- `assert-now` and `assert-eventually` commands enable deterministic scripting.
- CLI integration tests use assert commands (no ad-hoc wait helpers).
- JSON output is not required; human-readable output is sufficient.

---

## 4. Phase 0: mTLS + QUIC Baseline

### Deliverables

- Peer-authenticated QUIC sessions with certificate pinning/validation policy.
- Runtime protocol messages (sync/intros/holepunch negotiation) handled outside canonical events.

### Invariants

- No transit event wrapping layer in this model.
- Phase 0 does not require event signature/dependency implementation.
- Event signature/dependency enforcement is delivered in Phase 2.5 (`signed_by` blocking + signature verification ordering).
- Transport authentication must remain separate from event authorization semantics.

### Exit criteria

- Reconnect/retry behavior is stable across daemon restarts.
- mTLS identity is plumbed into peer/session context.

## 4.1 mTLS reference model to follow

Primary model (use this first):
- `/tmp/poc-7-mtls/src/transport/mod.rs`
- `/tmp/poc-7-mtls/src/transport/cert.rs`

Secondary reference (CLI + optional pin flags, less strict):
- `/home/holmes/poc-7=codex-attempt/src/transport/mod.rs`
- `/home/holmes/poc-7=codex-attempt/src/main.rs`

Do not use as final security model:
- permissive verifier pattern in current `poc-7/src/transport/mod.rs`.

## 4.2 Required mTLS design

1. Every peer has a persistent cert identity per profile:
   - certificate DER
   - private key PKCS#8 DER
   - extracted SPKI bytes (for pinning / identity lookup)
2. Phase 0 trust source is CLI/profile supplied peer pubkeys:
   - daemon startup config supplies allowed remote cert public keys (SPKI pins).
   - no dependency on identity-event projection for initial mTLS allowlist.
3. Pin peers by expected SPKI from this configured allowlist, not by socket address.
4. Enforce pinning on both sides:
   - server verifies client cert SPKI against pinned store
   - client verifies server cert SPKI against pinned store
5. No production fallback to `SkipServerVerification`.
6. Use long-lived cert keys for peer authentication in transport:
   - QUIC uses TLS 1.3 handshake key agreement, so session keys still get forward secrecy.
7. Connection identity mapping for metadata/projection context:
   - `recorded_by` = local identity bound to the local cert/private key used for this daemon/profile.
   - `via_peer_id` = remote identity resolved from authenticated remote cert SPKI mapping.
8. Scope for this phase: invited-member allowlist only.
   - do not implement removal/disconnection policy yet.
9. Identity-phase migration rule:
   - once Phase 7 identity model lands, replace/augment CLI allowlist with projected mapping from identity events (`peer_id -> cert SPKI`).

## 4.3 Implementation checklist (assistant-safe)

1. Port cert helper types/functions from mtls branch (`SelfSignedCert`, base64 SPKI helpers).
2. Add `PeerKeyStore` trait + concrete store (static/in-memory first; profile-backed later):
   - Phase 0 source: CLI/profile allowlist of permitted SPKI pins.
   - identity phase source: projected mapping `peer_id -> expected SPKI`.
   - reverse lookup by `SPKI -> peer_id` once identity mapping exists.
3. Add `PinnedCertVerifier` implementing:
   - `rustls::client::danger::ServerCertVerifier`
   - `rustls::verify::ClientCertVerifier` (or `rustls::server::danger::ClientCertVerifier` depending on rustls version in branch)
4. Server endpoint:
   - use `.with_client_cert_verifier(...)`
   - use `.with_single_cert(...)`
5. Client endpoint:
   - use custom cert verifier with pinned store
   - use `.with_client_auth_cert(...)`
6. Add positive and negative tests:
   - pinned peer connects successfully
   - unpinned peer is rejected
7. Plumb authenticated connection identity into sync session context:
   - local `recorded_by` from local cert profile identity.
   - remote `via_peer_id` from verified remote cert SPKI lookup (or pre-identity stable key id derived from SPKI).
8. Reject connections where verified cert SPKI is not in the active allowlist source (CLI/profile list now, identity-projected mapping later).

## 4.4 Common mTLS mistakes to avoid

- Do not generate a new certificate each startup for the same profile in daemon mode.
- Do not identify peers by `remote_address()` for policy decisions.
- Do not leave optional insecure mode on by default.
- Do not invent a second transport-only peer identifier when `peer_id` mapping already exists.
- Do not couple event-level authorization to transport identity; transport and event signatures are complementary.
- Do not delay Phase 0 on identity projection plumbing; use CLI/profile SPKI allowlist first.

---

## 4.5 Phase 0.5: Provisional Multi-Workspace Routing Smoke

Goal: validate basic workspace/tenant separation early, before deep projector/identity complexity.

### Deliverables

1. Start two provisional workspace/tenant contexts from CLI/profile supplied key material.
2. Route transport ingress into the correct tenant scope (`recorded_by`) for each context.
3. Expose CLI workspace selector/scope so reads show each workspace independently.
4. Demonstrate separate `recorded_events` history per workspace with no cross-display.

### Scope boundaries

- This is a routing/scope smoke phase, not full identity semantics.
- It uses the same temporary trust source as Phase 0 (CLI/profile allowlist), not identity events.
- Signature/dependency enforcement is still deferred to Phase 2.5.

### Exit criteria

1. Two workspace contexts can run concurrently and exchange events in isolation.
2. Event created/received in workspace A does not appear in workspace B scoped CLI queries.
3. Basic scoped DB checks pass for `recorded_events` and at least one projected table.

---

## 5. Phase 1: Event Schema, Recording Semantics, and Multitenancy Foundation

## 5.1 Single-source event schema

Define event shape once and drive these from it:
- wire encode/decode
- canonical signing bytes metadata (consumed by signer substrate in Phase 2.5)
- signer metadata fields (`signed_by`, `signer_type`, `signature`)
- validation scaffolding
- projector auto-row mapping metadata
- dependency extraction metadata (`is_event_ref`, `required`)

Field encoding kinds:
- `fixed_bytes(N)`
- `u8/u16/u32/u64`
- `var_bytes(len_prefix=u16|max_len=...)`
- `var_string(len_prefix=u16|max_len=..., utf8=true)`

## 5.2 Wire format direction

- Flat fields per type.
- Deterministic field order from schema.
- Fixed field definitions but variable total event sizes by type.
- Length-prefixed framing for sync transport.

This supports large events like `file_slice` while keeping deterministic signing/parsing.

`codex-simplified` migration note:
- current code paths using global fixed sizes (`ENVELOPE_SIZE`, `EVENT_SIZE`) must be treated as temporary.
- replace with:
  1. sync frame header carrying message type + payload length,
  2. event decoder dispatch by `event_type` schema,
  3. per-type bounds checks from schema max lengths.
- `payload_len` is a framing delimiter, not semantic authority:
  - for fixed-size event types it must exactly match schema size,
  - for variable-size types decoder must consume exactly `payload_len`,
  - any mismatch rejects the frame.
- do not keep any global fixed event blob size constant once Phase 1 is complete.

## 5.3 Signer and recording semantics (explicit)

- `signed_by`: canonical signer reference (event id).
- `signer_type`: signer keyspace discriminator (`peer | user | workspace | invite`).
- `recorded_by`: local tenant peer identity that recorded/projected the event.
- `signed_by`/`signer_type` and `recorded_by` are intentionally separate concerns.
- No `recorded_via` field.
- `recorded_by` is derived from authenticated local connection/profile identity, not from event payload claims.
- Remote transport identity for metadata is `via_peer_id`, resolved from verified cert SPKI -> `peer_id`.

## 5.4 Event classes

1. Canonical shared events: durable + shareable.
2. Canonical local-only events: durable + replayable, not shared.
3. Protocol/runtime messages: non-canonical, not in event DAG.

Shareability is by `event_type` policy, not by separate event tables.

## 5.5 Minimal durable data model

```sql
CREATE TABLE events (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    blob BLOB NOT NULL,
    share_scope TEXT NOT NULL,         -- 'shared' | 'local' from event_type policy
    created_at INTEGER NOT NULL,
    inserted_at INTEGER NOT NULL
);

CREATE TABLE recorded_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_id TEXT NOT NULL,             -- semantic: recorded_by
    event_id TEXT NOT NULL,
    recorded_at INTEGER NOT NULL,      -- local receive/create time for this tenant
    source TEXT NOT NULL,              -- local_create | quic_recv | import
    UNIQUE(peer_id, event_id)
);
CREATE INDEX idx_recorded_peer_order ON recorded_events(peer_id, id);
CREATE INDEX idx_recorded_peer_event ON recorded_events(peer_id, event_id);

CREATE TABLE valid_events (
    peer_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    PRIMARY KEY (peer_id, event_id)
);

CREATE TABLE rejected_events (
    peer_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    rejected_at INTEGER NOT NULL,
    PRIMARY KEY (peer_id, event_id)
);

CREATE TABLE peer_endpoint_observations (
    recorded_by TEXT NOT NULL,
    via_peer_id TEXT NOT NULL,
    origin_ip TEXT NOT NULL,
    origin_port INTEGER NOT NULL,
    observed_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (recorded_by, via_peer_id, origin_ip, origin_port, observed_at)
);
CREATE INDEX idx_peer_endpoint_expires
    ON peer_endpoint_observations(recorded_by, via_peer_id, expires_at);
CREATE INDEX idx_peer_endpoint_lookup
    ON peer_endpoint_observations(recorded_by, via_peer_id, origin_ip, origin_port);
```

### Tenant-safety rule

- Subjective tables are keyed by tenant identity first (`peer_id`/`recorded_by`).
- Query/projection APIs should use a tenant-bound wrapper (`TenantDb { peer_id, tx }`) rather than raw DB handles.
- `recorded_events` is the per-event receive journal (`recorded_at` ~= local `received_at`).
- Endpoint/IP metadata is intentionally separate and append-only in `peer_endpoint_observations` for frequent TTL purge and intro hinting.
- If needed, `first_seen`/`last_seen` are derived by `MIN(observed_at)`/`MAX(observed_at)` queries, not stored via in-place updates.

## 5.6 Table creation and naming conventions (required)

Table lifecycle:
1. Use a migration runner with ordered schema versions (`schema_migrations` table).
2. Core tables are created by core migrations (`events`, queues, `recorded_events`, etc.).
3. Event projection tables are created by event-module migrations registered in the event registry.
4. Startup must run migration + registry/schema consistency checks and fail fast on mismatch.

Naming and ownership:
1. Do not infer table names by pluralization heuristics.
2. Each event module declares explicit constants/metadata:
   - `event_type` (for example `message`)
   - `projection_table` (for example `messages`)
3. Default shape is one event module -> one projection table -> one autowrite mapping.
4. Exceptions are explicit and documented (deletion/tombstones, join tables, operational queue tables).

Multitenant scoping in shared tables:
1. Keep one shared physical table per event type (no per-peer table fanout).
2. Subjective/projected rows must include tenant scope key (`peer_id` / `recorded_by`).
3. Use composite keys/indexes with tenant first (for example `(peer_id, event_id)`).
4. For subjective autowrite tables, default uniqueness is exactly one row per `(peer_id, event_id)` unless the event spec explicitly defines a different shape.

Why this rule exists:
- keeps schema ergonomic and queryable,
- preserves `poc-6`-style tenant scoping guarantees,
- prevents assistants from inventing per-tenant table proliferation.

## 5.7 Replay-idempotency harness baseline (required)

Phase 1 must introduce a standard event-store replay harness and make it mandatory for scenario coverage.

Required checks per tenant scope (`recorded_by`):
1. replay-once: rebuild projection state from canonical event store order and compare with baseline.
2. replay-twice idempotency: run replay again on already replayed state; no additional changes.
3. reverse-order replay: replay canonical events in reverse order; final projected state matches baseline.

Harness policy:
1. these checks run automatically after every scenario test that writes canonical events.
2. source of truth is canonical event store rows (`events` + scoped subjective state), not transient in-memory state.
3. comparisons use deterministic table-state fingerprints (same mechanism as replay/reproject/reorder invariants).

---

## 6. Phase 2: Projector Core Before Full Queues

Implement projection semantics before adding heavy queue machinery.

## 6.1 Projector contract

Keep projector core pure and worker orchestration imperative.
All code paths call the same projector entrypoint:
- `project_one(recorded_by, event_id) -> ProjectionDecision`

```rust
enum ProjectionDecision {
    Valid(ProjectorEffects),
    Block { missing: Vec<EventId> },
    Reject { reason: String },
}

struct ProjectorEffects {
    auto_row: Option<AutoRow>,
    extra_writes: Vec<WriteOp>,
    emit_events: Vec<NewEvent>,
    commands: Vec<Command>,
}
```

Entry-point requirement:
- `local_create`, `wire_receive`, `replay`, and unblock retries must all invoke `project_one`.
- no alternate projection code paths for specific ingestion sources.

DRY split (required):
- Shared projection pipeline code owns:
  1. canonical event load/decode dispatch,
  2. dependency extraction + missing-dependency block writes,
  3. signer resolution + signature verification ordering (Phase 2.5),
  4. terminal state writes (`valid`/`block`/`reject`) + queue transitions,
  5. generic effect application (`auto_row`, `emit_events`, common write helpers).
- Per-event projector code owns only:
  1. event-specific predicate/policy checks,
  2. event-specific effect declaration (`ProjectorEffects`) for the shared applier.
- Per-event projector code must not implement its own dependency walker, signer verifier, queue handling, or terminal-state writer.

### Default behavior

- Most event types use predicate + auto-write.
- Auto-write is typically `INSERT OR IGNORE` of flat event fields + metadata.
- Auto-write is tenant-scoped in shared tables (`peer_id`/`recorded_by` included in subjective rows and keys).
- Validation order for signed events is fixed:
  1. dependency extraction/check (including signer dependency),
  2. signature verification using resolved signer key,
  3. authorization/policy predicate checks,
  4. autowrite/effects.

### Emitted-event rule (required)

When a projector emits event `X`:
1. emit canonical event `X` only (to `events` + normal queue flow),
2. let `X` project through `X`'s own projector/autowrite into `X`'s table.

Do not directly write into another event type's projection table as a side effect, except for rare non-event operational writes explicitly documented in that projector.

Deterministic emitted-event exception (still under this rule):
1. deterministic emitted event types remain canonical events and still follow `emit -> persist -> self-project`.
2. for deterministic event ids/bytes, these types are unsigned:
   - schema omits `signed_by`, `signer_type`, and `signature`,
   - signer dependency/signature stages are skipped for those types only.
3. validation for these types is deterministic-derivation checks from dependencies/context, not signature checks.

### Explicit exceptions

- `message_deletion` and deletion cascade rules.
- deterministic emitted-event patterns (for example key material derivations) using the unsigned deterministic exception above.
- identity-specific exceptions (`invite_accepted`, removal enforcement) are deferred to Phase 7.

## 6.2 Dependency handling (blocked-only first)

Start with only blocked-edge persistence.

```sql
CREATE TABLE blocked_event_deps (
    peer_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    blocker_event_id TEXT NOT NULL,
    PRIMARY KEY (peer_id, event_id, blocker_event_id)
);
CREATE INDEX idx_blocked_by_dep ON blocked_event_deps(peer_id, blocker_event_id);
```

Rules:
- Extract refs from schema-marked fields on each projection attempt.
- If required refs are present: continue projection.
- If any required refs are missing: write rows in `blocked_event_deps` and return `Block`.
- Signer refs (`signed_by` + `signer_type`) are dependency metadata and use the same blocking/unblocking path.
- Signature verification is attempted only after signer deps and other required deps are available (signed event types only).
- Do not persist full `event_dependencies` yet.
- Use one dependency resolver for all event families (content, identity, encrypted wrappers, invites).
- Dependency extraction is driven by event schema metadata only (`is_event_ref`, `required`, conditional requirement flags).

When full dependency table is justified later:
- reverse-edge analytics/debugging,
- heavy dependency introspection,
- or proven perf bottleneck from repeated lookups.

## 6.3 Set-based unblock (Kahn-compatible with multiple blockers)

- An event can have N blocker rows.
- It is runnable when no blocker rows remain.

Use set-based SQL when blocker `X` becomes valid:

```sql
DELETE FROM blocked_event_deps
WHERE peer_id = ? AND blocker_event_id = ?;

INSERT OR IGNORE INTO project_queue (peer_id, event_id, available_at)
SELECT DISTINCT c.peer_id, c.event_id, ?
FROM blocked_event_deps_candidates c
WHERE NOT EXISTS (
    SELECT 1
    FROM blocked_event_deps b
    WHERE b.peer_id = c.peer_id AND b.event_id = c.event_id
);
```

Set-based SQL means operating on sets of rows at once instead of per-event loops. It is helpful for unblock/requeue because one newly valid event can unblock many dependents.

## 6.4 Event creation API (simple and testable)

Use one primitive with two entry points:

- `persist_and_enqueue(event_blob, peer_id) -> event_id`
- `create_event_sync(...) -> event_id`
- `create_events_batch(events, project_now: bool) -> Vec<EventId>`

`create_event_sync` should inline projection until terminal (`valid`, `blocked`, or `rejected`) so command chains can immediately use prior event ids.

Imperative orchestration contract (poc-6 style ergonomics):
- default `create_event_sync` must return success only when the created event is `valid` for `recorded_by`.
- if terminal state is `blocked` or `rejected`, return an error containing `event_id` + terminal reason.
- this guarantees call-site sequencing:
  - `a = create_event_sync(...)`
  - `b = create_event_sync(depends_on=a, ...)`

Implementation note:
- even synchronous create uses the same internal pipeline:
  - `persist_and_enqueue` -> `project_one` loop (same code as worker mode)
- do not add a separate "local fast-path" projector.

## 6.5 Optional TLA checkpoint for blocking/unblocking (only if needed)

Usually not required at this stage, but useful if blocker behavior gets ambiguous:
- model only `valid`, `blocked_event_deps`, and unblock transitions,
- verify multi-blocker convergence and no-lost-unblock behavior,
- then map those guards directly into projector dependency checks.

## 6.6 Phase 2.5: Shared signer substrate (required before identity)

Implement one signer pipeline for all signed event types:
1. signer metadata is schema-declared (`signed_by`, `signer_type`, `signature`).
2. missing signer dependency uses normal blocking/unblocking (`blocked_event_deps`).
3. resolve signer key by (`signer_type`, `signed_by`) only after dependency resolution.
4. invalid signature is `Reject`, never `Block`.
5. signer verification helper path is shared across signed event families (no identity-specific signer path later).
6. deterministic emitted event types are explicitly schema-marked unsigned (`signer_required=false`) and excluded from signer-stage enforcement.

This phase should be completed immediately after Phase 2 and before Phase 3/Phase 7 work.

## 6.7 Phase 2.6: Multitenancy Scoped Projection/Query Gate (Tier 2)

Goal: validate full tenant/workspace scoping after projector + signer substrate are active.

Required checks:
1. Run two workspace/tenant contexts in one DB with shared physical projection tables.
2. Project overlapping event shapes in both tenants and verify subjective rows remain isolated by tenant key (`peer_id`/`recorded_by`).
3. Confirm signer pipeline behavior remains tenant-scoped (missing/invalid signer in tenant A does not leak effects into tenant B).
4. Verify CLI workspace selection only reads tenant-scoped data.
5. Add/keep a DB scoping checker that fails on unscoped reads/writes.

Exit criteria:
1. Cross-tenant leak tests fail correctly when scope guards are removed.
2. Re-enable scope guards and pass full scoped projection/query suite.
3. This gate passes before identity projector implementation (Phase 7).

---

## 7. Phase 3: Encrypted Events With The Same Model

Goal: encrypted events behave like normal events for dependencies and projection.
Precondition: Phase 2.5 signer substrate and Phase 2.6 multitenancy gate are already active.

## 7.1 Registry integration

- Encrypted wrapper is a normal event type in the same event registry.
- It uses flat fields, for example: `key_event_id`, `inner_type_code`, `ciphertext`, `nonce`, `auth_tag`.
- `inner_type_code` is mandatory (fixed-width) for this phase.
- Do not make `inner_type_code` optional while `ciphertext` remains variable-length.
- No separate encryption registry.

## 7.2 Materialization model (definition)

"Materialization" means converting an encrypted wrapper into a transient normal event view:

1. parse and verify the encrypted wrapper envelope,
2. resolve/decrypt using dependency-provided key material,
3. decode plaintext into a typed flat `EventView` from the same registry,
4. pass that `EventView` into the normal projector path.

Important:
- materialization is an adapter step, not a second projection system.
- no persisted plaintext queue is required for baseline.
- after materialization, projection is isomorphic to cleartext event projection.

## 7.3 No nested encrypted events

Rule:
- If decrypted inner type resolves to encrypted wrapper type, `Reject(nested_encrypted_not_allowed)`.

## 7.4 Projection flow for encrypted wrapper

1. Parse outer encrypted event from canonical `events.blob`.
2. Extract outer deps from its flat event-ref fields (`key_event_id`, plus any other refs).
3. If outer deps missing: write `blocked_event_deps` and return `Block`.
4. Verify signature/auth over canonical encrypted bytes.
5. Decrypt ciphertext using key from `key_event_id`.
6. Decode inner event with normal registry.
7. Verify decoded inner type matches outer `inner_type_code`; mismatch -> `Reject(inner_type_mismatch)`.
8. If inner type is encrypted wrapper: reject.
9. Extract inner deps from inner schema metadata.
10. If inner deps missing: write `blocked_event_deps` using outer `event_id` and return `Block`.
11. Call the normal projector for the inner type.
12. Mark outer event `valid` only after inner projection succeeds.

## 7.5 Plaintext storage policy

- Default: no persisted plaintext queue.
- Decrypted plaintext exists in memory only for projection.
- Optional later optimization: short-lived decrypted cache with TTL.

This preserves one blocker model and one projector model.

## 7.6 Initial encrypted-event test strategy (PSK first)

Start encryption correctness with a deliberately crude harness before identity key wrapping:

1. Give each test daemon/instance a configured AES PSK (same PSK for happy-path suites; mismatched PSK for negative suites).
2. Materialize this as a local key event during test setup, and reference that key via normal `key_event_id` dependency fields.
   - the materialized key event must be recorded/projected in the correct tenant scope (`recorded_by` for that test peer/workspace).
3. Run encrypted projection through the exact same block/unblock flow as other events:
   - missing key event -> `Block`
   - key present + decrypt/auth failure -> `Reject`
   - key present + decrypt/auth success -> normal inner projector path
4. Keep all replay/reorder invariants enabled while on PSK mode.

This isolates queue/projection/dependency correctness from identity/envelope complexity.
- keep the same key-wrap event type + projector logic that will be used in Phase 7 identity sender-keys; only key source differs.

---

## 8. Phase 4: Durable Queues and Workers

Add full queue machinery after projection + signer + encryption semantics are stable.

## 8.1 Queue tables

```sql
CREATE TABLE ingress_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_id TEXT NOT NULL,
    from_addr TEXT,
    received_at INTEGER NOT NULL,
    frame BLOB NOT NULL
);

CREATE TABLE project_queue (
    peer_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    available_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    lease_until INTEGER,
    PRIMARY KEY (peer_id, event_id)
);

CREATE TABLE egress_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    connection_id TEXT NOT NULL,
    frame_type TEXT NOT NULL,          -- event | neg_msg | have_list | ...
    event_id TEXT,
    payload BLOB,
    enqueued_at INTEGER NOT NULL,
    available_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    lease_until INTEGER,
    sent_at INTEGER,
    dedupe_key TEXT
);
CREATE UNIQUE INDEX idx_egress_pending_event
    ON egress_queue(connection_id, event_id)
    WHERE frame_type = 'event' AND sent_at IS NULL;
CREATE UNIQUE INDEX idx_egress_dedupe
    ON egress_queue(dedupe_key)
    WHERE dedupe_key IS NOT NULL AND sent_at IS NULL;
```

Keep canonical and queue data separate:
- permanent: `events`, `recorded_events`, projection outputs
- operational/transient: `ingress_queue`, `project_queue`, `blocked_event_deps`, `egress_queue`

## 8.2 Why not one generic jobs table

A single table sounds simple but mixes incompatible concerns:
- very different retention and purge policies,
- different dedupe keys and lease semantics,
- harder indexing and worse observability.

Separate queue tables stay simpler operationally.

## 8.3 Worker stages

1. `ingress worker`: QUIC frame -> canonical event insert -> record by tenant -> insert endpoint observation row (append-only) -> enqueue project.
2. `project worker`: claim row -> project path (`valid`/`block`/`reject`) -> dequeue.
3. `egress worker`: dequeue by `connection_id` -> send frame -> mark `sent_at`/retry.
4. `cleanup worker`: purge stale ingress/sent egress rows, reclaim expired leases, TTL-purge old endpoint observations.

Queue DRY requirement:
- implement generic queue helper traits/functions once (`claim_batch`, `renew_lease`, `mark_done`, `mark_retry/backoff`).
- reuse them for both `project_queue` and `egress_queue` to avoid diverging retry/lease semantics.

## 8.4 Egress queue creation (matching working `poc-7` shape)

Create rows from:
1. Negentropy reconciliation producer (`have_ids` we can send).
2. Incoming `HaveList` request producer.
3. Local protocol producers for control frames.

For event transfer, queue `event_id` only and fetch canonical blob at send time.

## 8.5 Project queue dedupe + purge

- `project_queue` is transient, not history.
- Do not enqueue if already terminal or currently blocked.
- If duplicate enqueue races happen, worker should fast-drop after terminal check.
- On terminal decision (`valid`, `reject`, `block`), remove row from `project_queue` in the same transaction as state write.

Recommended enqueue guard:

```sql
INSERT OR IGNORE INTO project_queue (peer_id, event_id, available_at)
SELECT ?, ?, ?
WHERE NOT EXISTS (
    SELECT 1 FROM valid_events v
    WHERE v.peer_id = ? AND v.event_id = ?
)
AND NOT EXISTS (
    SELECT 1 FROM rejected_events r
    WHERE r.peer_id = ? AND r.event_id = ?
)
AND NOT EXISTS (
    SELECT 1 FROM blocked_event_deps b
    WHERE b.peer_id = ? AND b.event_id = ?
);
```

## 8.6 Role of `attempts`

`attempts` is retry bookkeeping, not business state.

Use it for:
- backoff scheduling (`available_at`),
- lease recovery after crashes/timeouts,
- dead-letter/alert threshold if needed.

If a queue is always synchronous at first, this can remain mostly zero until retry logic is enabled.

## 8.7 Atomicity boundaries

Must be atomic:
1. canonical event insert + recorded insert + project enqueue.
2. projection state transition (`valid`/`block`/`reject`) + project dequeue.
3. unblock updates + requeue.

Need not be atomic with projection:
- transport send,
- cleanup/purge,
- metrics/logging.

## 8.8 Conflict policy (`INSERT OR IGNORE` vs upsert)

Use `INSERT OR IGNORE` for:
- immutable canonical events,
- idempotent projection materialization,
- queue dedupe insertions,
- append-only endpoint observation rows.

Use `ON CONFLICT DO UPDATE` for:
- mutable cursor/checkpoint state,
- lease/heartbeat/retry metadata,
- sync state snapshots.

Avoid broad `INSERT OR REPLACE`.

---

## 9. Phase 5: Special Cases That Stay Explicit

These should not be forced into generic auto-write behavior.

1. `message_deletion` and cascade/tombstone semantics.
2. deterministic emitted-event flows where projection emits another event.
   - these flows still obey emitted-event rule and are unsigned by schema policy for determinism.

Deletion is special and should remain explicit.

---

## 10. Phase 6: Performance + Operational Hardening

Start simple, then tune.

- Prefer SQLite durable queues over a pure in-memory cascade pipeline.
- Tune batch sizes and indexes from measurements.
- Enable WAL and prepared statements.
- Keep queue purges explicit and predictable.
- Add invariants/metrics for blocked counts, retry growth, and queue age.
- Add a dedicated `low_mem_ios` runtime mode for iOS NSE constraints.

`low_mem_ios` requirements:
- target steady-state RSS at or below `24 MiB` during sustained sync/projection.
- keep memory bounded with strict in-flight caps (queue claims, decode buffers, batch sizes).
- prefer one writer connection + minimal readers; avoid large in-memory caches/prefetch.
- degrade throughput before violating memory ceiling (memory safety over speed).
- validate at scale (`>= 1_000_000` canonical events on disk) with stable memory.

Recommended initial size policy:
- `EVENT_MAX_BLOB_BYTES = 1_048_576` (1 MiB soft cap)
- `FILE_SLICE_TARGET_BYTES = 262_144` (256 KiB)
- `FILE_SLICE_MAX_BYTES = 1_048_576` (1 MiB hard cap)

`file_slice` events can be much larger than legacy simulator limits and are signed/verified like other events.

---

## 11. Phase 7: Minimal Identity Layer + Crude Sender-Subjective Encryption

This is a final functional phase after the core projection/queue path is stable.
Prerequisite: Phase 2.5 signer substrate is complete before identity projector implementation begins.

## 11.1 Phase gate: TLA+ causal model first

Before writing identity/removal/encryption projectors in Rust:
1. Confirm signer pipeline from Phase 2.5 is active:
   - missing `signed_by` dependency blocks,
   - unblocked signer enables signature verification,
   - invalid signature rejects (not block).
2. Build/update a TLA+ model of causal relationships and guards for this phase.
3. Model split invite types (`user_invite`, `device_invite`) and trust-anchor semantics.
4. **Model network binding**: network events must be parameterized by network id, and the trust anchor must bind to a specific network. The model must prove that foreign network events (for networks the peer did not accept an invite for) can never become valid. Without this, the model cannot distinguish between valid and invalid network events, making it insufficiently expressive for multi-network scenarios. See `InvNetAnchor`, `InvSingleNetwork`, `InvForeignNetExcluded` invariants.
5. **Model invite-derived trust anchor binding**: the trust anchor must bind deterministically to the network referenced by the invite, not by a free nondeterministic choice at `invite_accepted` time. The model captures which network an invite references when the first invite is recorded (`inviteNet` variable); `invite_accepted` then reads `inviteNet` to set the trust anchor. This ensures the binding mechanism is faithful to the real protocol where the invite blob carries a `network_id`. See `InvTrustAnchorMatchesInvite` invariant.
6. Verify bootstrap/self-invite, join, device-link, and removal safety invariants.
7. Freeze a projector-spec mapping table: each projector predicate/check maps to a named TLA guard.

Projector implementations should mirror TLA conditions as directly as possible.

## 11.2 Minimal identity scope

Only include identity and policy needed for:
- trust-anchor bootstrap/join cascade
- self-invite bootstrap flow
- device linking
- removal enforcement
- recipient selection for encrypted message key wraps

## 11.3 Split invite event types (no mode switch)

Use separate types:
- `user_invite` (invites a user identity)
- `device_invite` (invites/links a peer device to a user)
- `invite_accepted` (records accepted link data + `workspace_id`)

Do not use one `invite` type with `mode=user|peer`.

Implementation requirement:
- keep one shared invite projector helper with per-type policy tables (signer/dependency checks).
- this keeps logical separation for TLA/model checking while avoiding duplicated Rust control flow.

## 11.4 Trust-anchor cascade requirements (from `poc-6`/TLA model)

Required behavior:
- `invite_accepted` records trust anchor intent for `workspace_id` (per `recorded_by` peer scope).
- `workspace` is not valid until corresponding trust anchor exists.
- invites are never force-valid; they validate only through signer/dependency chain.

Self-invite bootstrap sequence must stay explicit:
1. create `workspace` event (integrity self-sign only).
2. create bootstrap `user_invite` signed by workspace authority.
3. accept invite locally -> `invite_accepted(workspace_id=...)`.
4. normal cascade unblocks: `workspace -> user_invite -> user -> device_invite -> peer_shared`.

## 11.5 Crude sender-keys model (phase-1 style, no key history yet)

Use the sender-subjective O(n) baseline from `docs/group-encryption-design-aspects.md`
("Maximally simple.../Phase 1: baseline correctness and healing with O(n) key broadcast"):
- sender creates a fresh local-only `secret` key event per message,
- sender emits one `secret_shared`-style key-wrap event per perceived eligible recipient peer pubkey,
- encrypted content event references the key event id through normal dependency fields,
- each sender wraps to all perceived eligible members for each message (intentionally crude).
- use the same key-wrap event type/projector path introduced in Phase 3 PSK mode.

Not in scope yet:
- key history availability/backfill guarantees,
- optimized tree cover (TreeKEM update paths),
- advanced healing policies.

## 11.6 Minimal removal rule in this phase

- `user_removed` / `peer_removed` projection updates eligibility state.
- from first message after observing removal, sender must exclude removed peers from key wraps.
- no historical re-encryption; only forward behavior is required in this phase.

## 11.7 TLA-to-projector conformance rule

- Keep model alignment with `docs/tla/BootstrapGraph.tla` and `docs/tla/EventGraphSchema.tla`.
- Extend/adjust model events for split invites (`user_invite`, `device_invite`).
- For each identity-phase projector, include a referenced guard list in comments/docs.
- Treat divergence between projector logic and TLA guards as a spec bug that must be resolved before adding behavior.

---

## 12. Testing Plan (In Build Order)

## 12.1 CLI/daemon and agent loop tests

- CLI commands are deterministic and script-friendly.
- Prefer `assert-eventually` over ad-hoc sleeps/waits.
- `create_event_sync` chaining works for imperative orchestration:
  - event A created+projected synchronously,
  - event B created next line with dependency on A,
  - B succeeds without manual waits.

## 12.2 Encrypted-event bootstrap tests (PSK harness)

1. Happy path: all peers share PSK, encrypted events project end-to-end.
2. Missing key dep: encrypted event blocks until key event appears.
3. Wrong PSK/decrypt failure: event is rejected, not blocked.
4. Reorder: ciphertext before key events converges after unblock.
5. Replay/reproject: same final state from canonical events.
6. Tenant-scoped PSK materialization: each local PSK key event is recorded by the intended `recorded_by` tenant only.
7. Two-set isolation harness:
   - set A: peer+peer+PSK_A,
   - set B: peer+peer+PSK_B,
   - verify no decrypt/projection crossover and no cross-tenant read leakage.

## 12.3 Projection correctness tests

- Valid/block/reject decisions per event type.
- Blocked-only dependency behavior with multiple blockers.
- Set-based unblock correctness.
- Blocked-normalcy invariants:
  - policy-appropriate blocked rows may remain after sync and are not test failures by themselves.
  - non-recipient encrypted messages/key-shares are expected blocked cases.
- Signer substrate invariants:
  - missing signer dependency blocks,
  - invalid signature rejects,
  - valid signature passes and continues policy checks.
- Deterministic emitted unsigned invariants:
  - emitted deterministic types omit signer fields by schema,
  - deterministic derivation checks gate validity instead of signature checks.
- Encrypted wrapper flow, including nested-encryption rejection.
- Encrypted wrapper `inner_type_code` invariants:
  - mandatory field present for every encrypted wrapper event,
  - mismatch between outer `inner_type_code` and decrypted inner type rejects.
- Source-isomorphism checks: `local_create`, `wire_receive`, and `replay` converge through the same `project_one` semantics and yield identical projected state.

## 12.4 Replay/reproject/reorder invariants

1. Replay invariance: replay from canonical events yields same projected end state.
2. Replay idempotency: replaying again on already replayed state (2x replay) yields no state change.
3. Reverse-order replay invariance: replaying canonical events in reverse order yields same end state.
4. Reproject invariance: wipe projections and reproject yields same state.
5. Reorder invariance: out-of-order ingest converges to same state.
6. Operational queues are excluded from end-state equality checks.

Harness rule:
- run these replay/reproject/reorder checks automatically after every scenario test that mutates the event store.

Use deterministic table-state fingerprints for comparisons.

## 12.5 Multitenancy tests

1. Single-DB scoping checker test (like `poc-6`): ensure subjective queries are tenant-scoped.
2. Two-daemon integration test: separate peer identities record/project without overlap.
3. Cross-tenant leak tests: fail if rows from peer A appear in peer B scoped reads.

## 12.6 Identity and invite-cascade tests (final phase)

TLA-led acceptance:
1. Model invariants pass for split-invite causal graph before projector implementation is finalized.
2. Rust projector predicates map 1:1 to TLA guard conditions for identity/removal/encryption gate checks.

Behavior tests:
1. Self-invite bootstrap: trust anchor recorded, then normal cascade to first `peer_shared`.
2. User-join flow via `user_invite` keeps signer/dependency blocking semantics.
3. Device-link flow via `device_invite` keeps signer/dependency blocking semantics.
4. No force-valid invites: invite remains blocked until signer path is valid.
5. Removal enforcement: removed peers stop receiving new key wraps.
6. Sender-subjective baseline: each sent encrypted message yields wraps for all currently eligible recipients.

## 12.7 Real QUIC system tests

- 2-node bootstrap and sync.
- 3-node out-of-order convergence.
- reconnect/retry/backoff behavior.

---

## 13. What We Remove From `poc-6`

- Loopback/simulator paths in production runtime.
- Connection/sync canonical event types.
- Ad-hoc bootstrap reprojection paths that bypass blocker logic.

Keep:
- local-only canonical events where replay matters,
- transport-intro/holepunch related canonical events if needed,
- recorded-event model for replayability and tenant-scoped history.

---

## 14. Immediate MVP Cut

Fastest coherent milestone:

1. Finish Phase `-1`, `0`, `1`, and `2` with a small event set.
2. Complete Phase `2.5` signer substrate.
3. Add Phase `3` encrypted wrapper with PSK test harness for one core content path.
4. Add minimal Phase `4` queues.
5. Add deletion special-case behavior after baseline sync is stable.
6. Add final Phase `7` identity + invite cascade + sender-subjective key wraps.

---

## 15. Assistant Execution Playbook (High-detail)

Use this section as the implementation contract. If code conflicts with this section, update code to match this section unless user overrides.

## 15.1 Cross-phase non-negotiables

1. No alternate projection path:
   - all projection must converge on `project_one(recorded_by,event_id)`.
2. No alternate dependency resolver:
   - dependency refs come from schema metadata only.
3. No insecure transport default:
   - pinned mTLS required unless explicitly running dedicated test mode.
4. No fixed global event blob size after Phase 1.
5. No queue-specific retry logic duplication:
   - shared claim/lease/retry/backoff helpers only.
6. No per-tenant table fanout:
   - shared projection tables with tenant-scoped keys/indices only.
7. No cross-table direct projection for emitted events:
   - emitted events must project via their own event projector/autowrite path.
8. No alternate signer pipeline:
   - all signed event types use the same dependency-then-signature-verification ordering.

## 15.2 Phase `-1` implementation checklist (CLI + daemon)

Must implement:
1. daemon process with profile-scoped db path and control socket.
2. non-interactive CLI for create/query/assert operations.
3. stable JSON output and non-zero exit on assertion failure.

Common mistakes:
- embedding business logic in CLI command handlers instead of daemon API.
- relying on sleep/wait commands rather than assertion semantics.

Definition of done:
- two daemons exchange at least one message via real QUIC,
- `assert-eventually` based scripts run deterministically.

## 15.3 Phase `0` implementation checklist (mTLS baseline)

Must implement:
1. persistent cert identity per profile.
2. pinned-cert verifier on both client and server.
3. Phase 0 allowlist source is CLI/profile supplied cert SPKI pins, not socket address.
4. session context binds:
   - local `recorded_by` from local cert profile identity.
   - remote `via_peer_id` from verified cert SPKI mapping (identity-backed once Phase 7 lands).
5. unit/integration tests for allowed and denied peers.
6. migration note implemented:
   - Phase 7 switches allowlist source to projected identity events (`peer_id -> cert SPKI`).

Common mistakes:
- using generated ephemeral cert each restart in daemon mode.
- leaving permissive cert verifier as default behavior.

Definition of done:
- unpinned peer connection fails at handshake,
- pinned invited peer sync succeeds repeatedly across daemon restarts.

## 15.4 Phase `1` implementation checklist (schema + wire + recording)

Must implement:
1. event registry metadata describing fields and dependency refs.
2. length-prefixed sync framing with variable event lengths by type.
3. minimal `recorded_events` journaling and endpoint observation table.
4. tenant wrapper APIs for subjective reads/writes.
5. standard replay harness with mandatory checks:
   - replay once,
   - replay twice (idempotency),
   - reverse-order replay.
6. scenario test runner hook that executes replay harness after each scenario test touching canonical events.

Common mistakes:
- retaining fixed `ENVELOPE_SIZE` assumptions in parser/send path.
- inferring dependencies from ad-hoc code instead of schema metadata.
- treating replay checks as optional/manual instead of default harness behavior.

Definition of done:
- at least two event types decode via schema-driven parsers,
- replay invariants pass in standard harness (`once`, `twice`, `reverse-order`) after every scenario test.

## 15.5 Phase `2` implementation checklist (projector + blocked deps)

Must implement:
1. `project_one(recorded_by,event_id)` entrypoint.
2. blocked-only dependency persistence (`blocked_event_deps`).
3. set-based unblock and requeue SQL.
4. `create_event_sync` success-only-on-valid contract.
5. explicit DRY split enforcement:
   - shared pipeline handles deps/signer/queues/terminal writes,
   - per-event projector handles predicate + effect declaration only.

Common mistakes:
- adding a separate local create fast-path projector.
- storing full dependency graph prematurely.

Definition of done:
- out-of-order events with multiple blockers converge correctly,
- imperative command chains (`a=create_sync(); b=create_sync(depends_on=a)`) work without waits.

## 15.5A Phase `2.5` implementation checklist (signer substrate)

Must implement:
1. schema metadata for signer fields (`signed_by`, `signer_type`, `signature`).
2. signer dependency blocking via `blocked_event_deps`.
3. signer resolution + signature verification after dependency resolution and before policy checks.
4. invalid signature -> `Reject` (not `Block`).
5. shared signer helper path across all signed event families.
6. deterministic unsigned exemption:
   - schema flag (for example `signer_required=false`) for deterministic emitted types,
   - signer pipeline skips only those explicitly marked types.

Common mistakes:
- verifying signatures before dependency resolution.
- creating identity-specific signature paths that diverge from core projector flow.

Definition of done:
- signer-missing blocks then unblocks when signer arrives,
- invalid signatures deterministically reject,
- signed cleartext and signed encrypted-wrapper events follow the same signer pipeline,
- deterministic emitted unsigned events validate via deterministic derivation checks and remain replay/reproject stable.

## 15.6 Phase `3` implementation checklist (encrypted adapter)

Must implement:
1. encrypted wrapper as a normal registry type.
2. mandatory `inner_type_code` field in encrypted wrapper schema.
3. materialization adapter (decrypt -> inner `EventView` -> normal projector).
4. enforce `inner_type_code` == decoded inner type.
5. nested encrypted rejection.
6. PSK harness tests before identity wrapping.

Common mistakes:
- introducing a separate persisted plaintext queue too early.
- introducing separate dependency logic for key blockers.
- making `inner_type_code` optional while relying on variable-length ciphertext framing.

Definition of done:
- missing key blocks, wrong key rejects, correct key projects,
- reorder/replay invariants hold for encrypted events.

## 15.7 Phase `4` implementation checklist (durable queues/workers)

Must implement:
1. queue tables (`ingress`, `project`, `egress`) with transactional boundaries.
2. shared queue helper functions for claim/lease/retry.
3. egress creation from reconciliation and request-list producers.
4. queue cleanup + TTL maintenance jobs.

Common mistakes:
- using one generic jobs table for all queues.
- mixing canonical durable rows and operational queue rows in one table.

Definition of done:
- crash/restart recovers and completes pending work,
- retries/backoff and lease recovery are observable and deterministic.

## 15.8 Phase `5` implementation checklist (special projectors)

Must implement:
1. explicit deletion/tombstone/cascade projector.
2. explicit deterministic emitted-event handling.

Common mistakes:
- forcing deletion into generic auto-write logic.

Definition of done:
- deletion-before-target and target-before-deletion converge identically.

## 15.9 Phase `6` implementation checklist (hardening)

Must implement:
1. batch/index tuning driven by measurements.
2. queue health metrics (`age`, `attempts`, blocked counts).
3. endpoint observation TTL purging.
4. `low_mem_ios` mode with explicit knobs (SQLite cache, channel/batch limits, worker concurrency caps).
5. long-run memory test at million-event scale showing `<= 24 MiB` steady-state RSS target in low-memory mode.

Common mistakes:
- premature micro-optimizations before invariant/test stability.
- optimizing throughput in low-memory mode at the cost of memory bound violations.

Definition of done:
- long-running sync remains stable and bounded in memory/storage.
- low-memory mode is reliable and repeatable under iOS NSE-style memory limits.

## 15.10 Phase `7` implementation checklist (TLA-first identity)

Must implement:
1. TLA model updated first for split invites and trust-anchor guards.
2. projector predicate mapping table from TLA guards.
3. split invite events (`user_invite`, `device_invite`) with shared helper core.
4. sender-subjective O(n) key wrapping baseline (no key history yet).
5. removal excludes removed peers from subsequent wraps.
6. preserve Phase 2.5 signer pipeline (do not add identity-specific signature fast paths).

Common mistakes:
- implementing projector rules before guard/model freeze.
- re-introducing multimodal invite event (`mode=*`).

Definition of done:
- TLA invariants pass for bootstrap, join, device-link, and removal flows,
- Rust behavior matches TLA guard mapping in tests.

## 15.11 PR slicing guidance (to reduce assistant mistakes)

Recommended PR sequence:
1. transport mTLS hardening only.
2. wire framing + schema registry scaffolding.
3. projector entrypoint + dependency resolver + blocked deps.
4. create_sync API contract and tests.
5. signer substrate (Phase 2.5): signer dep blocking + signature ordering tests.
6. encrypted adapter + PSK tests.
7. queue/worker architecture and shared queue helper extraction.
8. deletion special-case projector.
9. TLA model update + identity phase implementation.

Rule:
- each PR must include at least one failing test made to pass by that PR.
