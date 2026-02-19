# How to implement Topo

> **Status: Active** — Authoritative implementation plan for all phases.

## 0. POC Compatibility Posture (Explicit)

This project is a POC and prioritizes clarity/simplicity over backward compatibility.

1. Cross-epoch backward compatibility is **not required** by default (wire formats, projected schemas, DB layout, and migrations may change).
2. If an old DB/protocol epoch is encountered, fail fast with a clear recreate/reset path instead of adding compatibility shims.
3. Add backward compatibility only when explicitly requested for a specific test objective or transition window.

## 1. Implementation Order (Authoritative)

This document is ordered exactly as we should build it.

1. `Phase 1`: CLI + daemon around the current simple prototype.
2. `Phase 2`: mTLS + QUIC transport baseline finalized.
3. `Phase 3`: Provisional multi-workspace/tenant routing smoke test (CLI-supplied key material).
4. `Phase 4`: Event schema, recording semantics, and multitenancy foundation.
5. `Phase 5`: Projector core and dependency blocking (without full queue complexity).
6. `Phase 6`: Shared signer substrate (`signed_by` dependency blocking + signature verification ordering).
7. `Phase 7`: Multitenancy scoped-projection/query gate (with signer substrate active).
8. `Phase 8`: Encrypted events using the same dependency/projector model, tested first with per-instance PSK.
9. `Phase 9`: Durable queue architecture (`ingress`, `project`, `egress`) and workers.
10. `Phase 10`: Non-identity special-case projector logic (deletion/emitted-events).
11. `Phase 11`: Performance hardening, observability, scaling, and low-memory iOS mode.
12. `Phase 12`: TLA-first minimal identity layer for trust-anchor cascade, removal, and sender-subjective encryption.
13. `Phase 13`: Functional multitenancy — one node hosting N tenant identities in a shared DB with one shared QUIC endpoint and per-tenant routing/discovery.

Scheduling note:
- two-tier multitenancy plan:
  - Phase 3 proves provisional transport/workspace separation and CLI workspace views.
  - Phase 7 proves scoped projection/query separation once projector + signer substrate exist.
- `signed_by` dependency blocking + signature verification ordering is tackled in Phase 6.
- Phase 6 and Phase 7 must be complete before starting identity projectors in Phase 12.
- Phase 13 depends on Phase 12 identity flows (bootstrap_workspace, accept_user_invite) being stable.

## 1.1 `codex-simplified` baseline gap audit (current state)

Current code in Topo (post-move from `codex-simplified`) is a useful sync prototype, but has deliberate gaps relative to this plan:

1. ~~Fixed-size wire/event assumptions~~ **RESOLVED**: wire protocol moved to `src/sync/protocol.rs` with variable-length framing and `EVENT_MAX_BLOB_BYTES = 1 MiB` cap. No global fixed envelope size remains.
2. ~~mTLS is not yet pinned/strict~~ **RESOLVED**: `src/transport/mod.rs` now uses `PinnedCertVerifier` with BLAKE2b-256 SPKI fingerprint pinning on both client and server sides. No permissive verifier remains in production paths.
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
   - no Phase 3 routing smoke coverage and no post-projector scoped-projection gate.

Gap-to-phase mapping:
- wire framing + schema normalization -> `Phase 4`
- strict pinned mTLS -> `Phase 2`
- provisional workspace routing smoke -> `Phase 3`
- projector entrypoint + dep/blocking core -> `Phase 5`
- shared signer dependency + signature pipeline -> `Phase 6`
- scoped multitenancy projection/query gate -> `Phase 7`
- encryption adapter + key deps -> `Phase 8`
- queue/worker architecture -> `Phase 9`
- deletion/emits explicit rules -> `Phase 10`
- trust-anchor/invite/removal/sender-keys -> `Phase 12`

---

## 2. Core Simplifications To Preserve

- Terminology: `workspace` is the event and domain term for the peer set and shared context; "network" refers only to transport/networking.
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
- `invite_accepted` is local trust-anchor binding:
  - it binds trust anchor from carried `workspace_id` in peer scope (first-write-wins),
  - it is not gated by the root-workspace trust-anchor guard itself,
  - conflicting `workspace_id` for an already anchored peer scope is rejected.
- Trust-anchor guards apply to root workspace events (foreign root ids must not become valid).
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
10. Guard-placement requirement.
   - `invite_accepted` is a local anchor-binding event, not a global invite-presence gate.
   - trust-anchor gating belongs on root workspace event validity.
   - do not use pre-projection raw-blob capture tables as authority for trust-anchor binding.

## 2.2 CLI Architecture Principle

Every CLI instance is a real peer-to-peer device. All user-facing commands go through daemon RPC to the service layer:

1. **One service layer**: business logic lives in event modules (`src/event_modules/`) for event-specific concerns and `src/service.rs` for orchestration. CLI subcommands are thin UI adapters that call daemon RPC, which dispatches to service functions.
2. **Real networking**: invite acceptance uses real QUIC bootstrap sync, not in-process event copying. The daemon manages ongoing sync with discovered peers.
3. **Testing equivalence**: CLI integration tests exercise the full path (CLI binary → RPC → service → DB/sync). No separate interactive surface exists; the daemon-backed CLI is the single command interface.
4. **No synthetic shortcuts**: no `copy_event_chain`, no direct DB-to-DB event transfers, no bypass of the sync/projection pipeline. Every event flows through the same ingest path it would in production.

## 2.3 Device Architecture

1. **One CLI instance = one device**: each running `topo` process is a device with its own transport identity and persistent state.
2. **Multiple tenants per device**: a single device can host many tenants, each participating in arbitrary (potentially overlapping) workspaces.
3. **Zeroconf discovery**: mDNS/DNS-SD discovers peers on the same workspace on the local machine or LAN (enabled by default via `discovery` feature).
4. **Single-port QUIC endpoint**: one shared endpoint serves all tenants via multi-workspace cert resolver (SNI routing). Inbound trust is union-scoped; outbound dials use per-tenant client configs with tenant-scoped trust.
5. **Shared batch writer**: all tenants on a device share one batch writer for projection, grouped by `recorded_by`.

---

## 3. Phase 1: CLI + Daemon First

Build this before queue complexity.

### Deliverables

- One daemon per profile/peer with local RPC control socket.
- Thin CLI (`topo`) for non-interactive control.
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

Phase 1 is functionally complete. All deliverables are met:
- `sync`, `send`, `messages`, `status`, `generate` CLI commands work.
- `assert-now` and `assert-eventually` commands enable deterministic scripting.
- CLI integration tests use assert commands (no ad-hoc wait helpers).
- JSON output is not required; human-readable output is sufficient.

---

## 4. Phase 2: mTLS + QUIC Baseline

### Deliverables

- Peer-authenticated QUIC sessions with certificate pinning/validation policy.
- Runtime protocol messages (sync/intros/holepunch negotiation) handled outside canonical events.

### Invariants

- No transit event wrapping layer in this model.
- Phase 2 does not require event signature/dependency implementation.
- Event signature/dependency enforcement is delivered in Phase 6 (`signed_by` blocking + signature verification ordering).
- Transport authentication must remain separate from event authorization semantics.

### Exit criteria

- Reconnect/retry behavior is stable across daemon restarts.
- mTLS identity is plumbed into peer/session context.

## 4.1 mTLS implementation (current state)

Phase 2 mTLS is implemented in the main codebase:
- `src/transport/mod.rs`: `PinnedCertVerifier` with BLAKE2b-256 SPKI fingerprint pinning (both client and server).
- `src/transport/cert.rs`: self-signed certificate generation and SPKI extraction helpers.

Historical reference branches (`poc-7-mtls`, `poc-7=codex-attempt`) are no longer needed for implementation guidance.

## 4.2 Required mTLS design

1. Every peer has a persistent cert identity per profile:
   - certificate DER
   - private key PKCS#8 DER
   - extracted SPKI bytes (for pinning / identity lookup)
2. Current Phase 2 implementation status (transitional):
   - daemon startup config supplies allowed remote cert public keys (SPKI pins).
   - local cert/key are file-backed per profile.
3. Required end-state trust source:
   - transport allow/deny must be derived from SQL trust state rooted in identity:
     - PeerShared-derived SPKIs (steady-state; SPKI computed directly from PeerShared public key),
     - accepted invite-link bootstrap rows (`invite_bootstrap_trust`),
     - inviter-side pending invite bootstrap rows (`pending_invite_bootstrap_trust`),
     - bootstrap rows are TTL-bounded and consumed when matching steady-state trust appears,
     - not CLI/file pin lists as authority.
   - shorthand model term: `TrustedPeerSet = PeerShared_SPKIs U invite_bootstrap_trust U pending_invite_bootstrap_trust`.
   - trust inputs are not only `invite`/`invite_accepted`; they include the full identity policy graph (for example peer/user/device/admin/removal state).
4. Done: CLI/profile SPKI allowlist (`--pin-peer`) removed as trust authority.
   File cert/key is a local cache/materialization artifact, not authority.
5. Pin peers by expected SPKI from active projected trust state, not by socket address.
6. Enforce pinning on both sides:
   - server verifies client cert SPKI against pinned store
   - client verifies server cert SPKI against pinned store
7. No production fallback to `SkipServerVerification`.
8. Use long-lived cert keys for peer authentication in transport:
   - QUIC uses TLS 1.3 handshake key agreement, so session keys still get forward secrecy.
9. Connection identity mapping for metadata/projection context:
   - `recorded_by` = local identity bound to the local cert/private key used for this daemon/profile.
   - `via_peer_id` = remote identity resolved from authenticated remote cert SPKI mapping.
10. Scope for this phase: invited-member allowlist with removal policy.
   - Removal events (`PeerRemoved`) deny new TLS handshakes and tear down active sessions.
11. Identity-phase migration rule:
   - once Phase 12 identity model lands, transport policy runs from projected identity events (`peer_id -> cert SPKI`) and related projected policy rows.
12. TLS key material modeling rule (end-state):
   - local TLS cert/public/private key material is represented by local events with normal dependency ordering.
   - runtime may materialize active TLS objects from projected event state.
   - persisted files are optional cache, not policy authority.

## 4.3 Implementation checklist (assistant-safe)

1. Port cert helper types/functions from mtls branch (`SelfSignedCert`, base64 SPKI helpers).
2. Add `PeerKeyStore` trait + concrete store:
   - transitional source: CLI/profile allowlist of permitted SPKI pins (completed Phase 2 behavior).
   - required source: projected identity mapping (`peer_id -> expected SPKI`) and related projected policy state.
   - reverse lookup by `SPKI -> peer_id` once identity mapping exists.
   - TODO (retrofit completed Phase 2 behavior): switch verifier default from transitional source to projected source.
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
8. Reject connections where verified cert SPKI is not in the active allowlist source (projected source in end-state; transitional source only until retrofit is complete).
9. Add local TLS credential materialization path from projected local key events.
   - if file serialization exists, treat it as cache of projected state.
   - reject startup when cache conflicts with projected key state.

## 4.4 Common mTLS mistakes to avoid

- Do not generate a new certificate each startup for the same profile in daemon mode.
- Do not identify peers by `remote_address()` for policy decisions.
- Do not leave optional insecure mode on by default.
- Do not invent a second transport-only peer identifier when `peer_id` mapping already exists.
- Do not couple event-level authorization to transport identity; transport and event signatures are complementary.
- Do not forget the mandatory retrofit: transitional CLI/profile SPKI allowlist must be removed as policy authority once identity projection lands.
- Do not treat file cert/key storage as trust authority.

---

## 4.5 Phase 3: Provisional Multi-Workspace Routing Smoke

Goal: validate basic workspace/tenant separation early, before deep projector/identity complexity.

### Deliverables

1. Start two provisional workspace/tenant contexts from CLI/profile supplied key material.
2. Route transport ingress into the correct tenant scope (`recorded_by`) for each context.
3. Expose CLI workspace selector/scope so reads show each workspace independently.
4. Demonstrate separate `recorded_events` history per workspace with no cross-display.

### Scope boundaries

- This is a routing/scope smoke phase, not full identity semantics.
- It uses the same temporary trust source as Phase 2 (CLI/profile allowlist), not identity events.
- Signature/dependency enforcement is still deferred to Phase 6.

### Exit criteria

1. Two workspace contexts can run concurrently and exchange events in isolation.
2. Event created/received in workspace A does not appear in workspace B scoped CLI queries.
3. Basic scoped DB checks pass for `recorded_events` and at least one projected table.

---

## 5. Phase 4: Event Schema, Recording Semantics, and Multitenancy Foundation

## 5.1 Single-source event schema

Define event shape once and drive these from it:
- wire encode/decode
- canonical signing bytes metadata (consumed by signer substrate in Phase 6)
- signer metadata fields (`signed_by`, `signer_type`, `signature`)
- validation scaffolding
- projector auto-row mapping metadata
- dependency extraction metadata (`is_event_ref`, `required`)

Field encoding kinds:
- `fixed_bytes(N)`
- `u8/u16/u32/u64`
- `fixed_text(N, utf8=true, zero_pad=true)` — fixed-size UTF-8 text slot, zero-padded after content
- `fixed_ciphertext(N)` — fixed-size opaque byte slot

Removed (no longer canonical):
- ~~`var_bytes(len_prefix=u16|max_len=...)`~~
- ~~`var_string(len_prefix=u16|max_len=..., utf8=true)`~~

No canonical event parser uses a length or count field to determine body boundaries.

## 5.2 Wire format direction

- Flat fields per type.
- Deterministic field order from schema.
- Every canonical event type has a fixed total wire size (deterministic by type code).
- Encrypted events have wire size deterministic by `inner_type_code`.
- Length-prefixed framing for sync transport (frame-level `payload_len` only; no in-event length fields).

This supports deterministic parsing by type dispatch and fixed offsets (langsec-first).

`payload_len` is a framing delimiter, not semantic authority:
- it must exactly match the schema-defined fixed size for the event type,
- for encrypted events it must match the size determined by `inner_type_code`,
- any mismatch rejects the frame.

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
5. Prototype schema epoch is explicit (`schema_epoch`) and checked at startup.
6. No backward compatibility is provided across prototype epochs: if an old DB is detected (legacy `schema_migrations` without current epoch marker), startup must fail with a clear "recreate DB" error.

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

Phase 4 must introduce a standard event-store replay harness and make it mandatory for scenario coverage.

Required checks per tenant scope (`recorded_by`):
1. replay-once: rebuild projection state from canonical event store order and compare with baseline.
2. replay-twice idempotency: run replay again on already replayed state; no additional changes.
3. reverse-order replay: replay canonical events in reverse order; final projected state matches baseline.

Harness policy:
1. these checks run automatically after every scenario test that writes canonical events.
2. source of truth is canonical event store rows (`events` + scoped subjective state), not transient in-memory state.
3. comparisons use deterministic table-state fingerprints (same mechanism as replay/reproject/reorder invariants).

---

## 6. Phase 5: Projector Core Before Full Queues

Implement projection semantics before adding heavy queue machinery.

## 6.1 Pure functional projector contract

Projectors are **pure functions** over `(ParsedEvent, ContextSnapshot)`. They return
a deterministic `ProjectorResult` containing write operations and emitted commands.
They do not execute SQL or any other side effects directly.

All code paths call the same projector entrypoint:
- `project_one(recorded_by, event_id) -> ProjectionDecision`

```rust
struct ProjectorResult {
    decision: ProjectionDecision,   // Valid | Block | Reject | AlreadyProcessed
    write_ops: Vec<WriteOp>,        // deterministic state mutations
    emit_commands: Vec<EmitCommand>, // follow-on actions for command executor
}

enum WriteOp {
    InsertOrIgnore { table, columns, values },
    Delete { table, where_clause },
}

enum EmitCommand {
    RetryWorkspaceGuards,
    RetryFileSliceGuards { file_id },
    RecordFileSliceGuardBlock { file_id, event_id },
}
```

Entry-point requirement:
- `local_create`, `wire_receive`, `replay`, and unblock retries must all invoke `project_one`.
- no alternate projection code paths for specific ingestion sources.
- Internal cascade optimization: `project_one_step` (the 7-step algorithm without cascade) is used by the Kahn cascade worklist to avoid redundant recursive cascade. `apply_projection` executes `emit_commands` (which handles guard retries), so the cascade only manages Kahn dependency unblocking. All projection stages are shared; the split is a performance optimization, not an alternate path.

Apply engine execution stages:
1. Pipeline builds `ContextSnapshot` from DB (the only DB reads the projector needs).
2. Pipeline calls pure projector → receives `ProjectorResult`.
3. Pipeline executes `write_ops` transactionally (only on Valid/AlreadyProcessed).
4. Pipeline executes `emit_commands` via explicit handlers (only on Valid).
5. Pipeline handles guard-block commands on Block decisions (e.g., file_slice guard blocks).

DRY split (required):
- Shared projection pipeline code owns:
  1. canonical event load/decode dispatch,
  2. dependency extraction + missing-dependency block writes,
  3. signer resolution + signature verification ordering (Phase 6),
  4. building `ContextSnapshot` from the database,
  5. executing `write_ops` and `emit_commands`,
  6. terminal state writes (`valid`/`block`/`reject`) + queue transitions.
- Per-event projector code owns only:
  1. event-specific predicate/policy checks,
  2. returning `ProjectorResult` with deterministic `write_ops` and `emit_commands`.
- Per-event projector code must not access the database, implement its own dependency walker, signer verifier, queue handling, or terminal-state writer.

### Default behavior

- Most event types use predicate + auto-write.
- Auto-write is typically `InsertOrIgnore` WriteOps of flat event fields + metadata.
- Auto-write is tenant-scoped in shared tables (`peer_id`/`recorded_by` included in subjective rows and keys).
- Validation order for signed events is fixed:
  1. dependency extraction/check (including signer dependency),
  2. signature verification using resolved signer key,
  3. authorization/policy predicate checks,
  4. pure projector dispatch → WriteOps + EmitCommands.

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

- `message_deletion` uses the two-stage deletion intent + tombstone model (see Phase 10).
- deterministic emitted-event patterns (for example key material derivations) using the unsigned deterministic exception above.
- identity-specific exceptions (`invite_accepted` trust-anchor binding via `RetryWorkspaceGuards` command, removal enforcement) implemented via EmitCommand handlers.

### Deletion intent + tombstone contract (Phase 10)

Two-stage model so deletes stay deterministic when events arrive out of order:

1. `MessageDeletion` projector emits an idempotent `deletion_intent` write keyed by
   `(recorded_by, target_kind="message", target_id)`.
2. If target exists in projected state, projector also emits tombstone + cascade delete
   WriteOps in same apply batch.
3. If target does not exist yet, projector only records intent; no imperative retries.
4. Target-creation projectors check for matching `deletion_intent` rows in their
   `ContextSnapshot` and immediately tombstone on first materialization, using the
   original deletion event's identity for replay invariance.
5. Cleanup work (message delete → reaction tombstones) is explicit `Delete` WriteOps.
6. Deletion state is monotonic: `active → tombstoned` allowed, `tombstoned → active` forbidden.
7. Physical row removal is a separate compaction concern.

Deletion invariants validated by tests:
1. Duplicate replay leaves state unchanged after first application.
2. Delete-before-create converges to identical final state as create-before-delete.
3. Full replay reproduces identical tombstone state.
4. Authorization failure paths are deterministic from projected context.
5. No live reactions remain for tombstoned message.
6. Command execution idempotence: intent identities are stable, re-running does not mutate state.

## 6.2 Dependency handling (blocked-edge + header first)

Start with blocker-edge persistence plus a small blocked-header table.

```sql
CREATE TABLE blocked_event_deps (
    peer_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    blocker_event_id TEXT NOT NULL,
    PRIMARY KEY (peer_id, event_id, blocker_event_id)
);
CREATE INDEX idx_blocked_by_dep_covering
    ON blocked_event_deps(peer_id, blocker_event_id, event_id);

CREATE TABLE blocked_events (
    peer_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    deps_remaining INTEGER NOT NULL,
    PRIMARY KEY (peer_id, event_id)
);
```

Rules:
- Extract refs from schema-marked fields on each projection attempt.
- If required refs are present: continue projection.
- If any required refs are missing: dedupe blockers, write rows in `blocked_event_deps`, write `blocked_events.deps_remaining` from unique blocker count, and return `Block`.
- Signer refs (`signed_by` + `signer_type`) are dependency metadata and use the same blocking/unblocking path.
- Signature verification is attempted only after signer deps and other required deps are available (signed event types only).
- `blocked_event_deps` remains the canonical blockedness check for queue admission guards.
- `blocked_events.deps_remaining` is the performance counter used by the cascade scheduler.
- Do not persist full `event_dependencies` yet.
- Use one dependency resolver for all event families (content, identity, encrypted wrappers, invites).
- Dependency extraction is driven by event schema metadata only (`is_event_ref`, `required`, conditional requirement flags).

When full dependency table is justified later:
- reverse-edge analytics/debugging,
- heavy dependency introspection,
- or proven perf bottleneck from repeated lookups.

## 6.3 Counter-based cascade unblock (Kahn-compatible with multiple blockers)

- An event can have N blocker rows.
- It is runnable when `blocked_events.deps_remaining` reaches zero.

Use counter-based unblock when blocker `X` becomes valid:

Implementation shape:
- Read candidates from `blocked_event_deps` by (`peer_id`, `blocker_event_id`) using the covering index.
- For each candidate, decrement `blocked_events.deps_remaining`.
- If remaining deps are > 0, keep it blocked.
- If remaining deps reach 0, delete the `blocked_events` row and project the event through the canonical entrypoint.
- When a projected event becomes `Valid`, use it as the next blocker in the same cascade worklist.
- If projection returns `Block { missing }` (for example encrypted inner deps), write deduped blocker rows plus a new `blocked_events` header row.
- Keep `blocked_event_deps` read-only inside the per-step cascade loop.
- After cascade transitions occur, bulk-clean `blocked_event_deps` rows for events now terminal (`valid` or `rejected`).
- Run guard retries after dep cleanup so guard queries see current dep state.

Design tradeoff:
- SQL-only unblock (`DELETE ... RETURNING` + blocker-row existence checks) is simpler.
- Current code keeps the counter path because branch-local topo-cascade measurements showed roughly 2x higher throughput.
Do not route in-call cascade fanout through `project_queue`.

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

### Two-API design decision (investigated and confirmed)

The codebase provides two create-and-project entry points reflecting distinct caller needs:

1. **`create_event_sync`** (strict, PLAN-normative): returns `Ok(event_id)` only when projection reaches `Valid` or `AlreadyProcessed`. Returns `Err(Blocked { event_id, missing })` or `Err(Rejected { event_id, reason })` otherwise. All user-facing service commands (`svc_send`, `svc_react`, `svc_delete_message`, `svc_generate`) use this API.

2. **`create_event_staged`** (lenient, bootstrap-only): wraps `Blocked` errors into `Ok(event_id)` via `event_id_or_blocked`. Used exclusively in identity bootstrap paths (`bootstrap_workspace`, `ensure_identity_chain`) where events like `Workspace` are created before their trust-anchor dependency exists and are expected to block until the anchor arrives.

This split is intentional and correct: it preserves the strict contract for user-facing orchestration while allowing bootstrap chains to store pre-dependency events without aborting.

Test index for this contract:
- `test_create_signed_event_sync_returns_blocked_error` — strict API blocked→Err
- `test_create_signed_event_staged_returns_ok_on_blocked` — staged API blocked→Ok
- `test_create_reaction_before_target` — blocked event DB state
- `test_svc_react_errors_on_blocked` — service layer propagation
- `test_svc_delete_errors_on_blocked` — service layer propagation
- `test_svc_send_succeeds_on_valid` — valid→Ok
- `test_ensure_identity_chain_tolerates_workspace_blocked` — staged bootstrap
- `test_create_event_sync_contract_valid_only` — explicit §6.4 contract
- `test_create_event_sync_contract_blocked_returns_err_with_event_id` — error shape contract

## 6.5 Optional TLA checkpoint for blocking/unblocking (only if needed)

Usually not required at this stage, but useful if blocker behavior gets ambiguous:
- model `valid`, `blocked_event_deps`, `blocked_events.deps_remaining`, and unblock transitions,
- verify multi-blocker convergence and no-lost-unblock behavior,
- then map those guards directly into projector dependency checks.

## 6.6 Phase 6: Shared signer substrate (required before identity)

Implement one signer pipeline for all signed event types:
1. signer metadata is schema-declared (`signed_by`, `signer_type`, `signature`).
2. missing signer dependency uses normal blocking/unblocking (`blocked_event_deps` + `blocked_events`).
3. resolve signer key by (`signer_type`, `signed_by`) only after dependency resolution.
4. invalid signature is `Reject`, never `Block`.
5. signer verification helper path is shared across signed event families (no identity-specific signer path later).
6. deterministic emitted event types are explicitly schema-marked unsigned (`signer_required=false`) and excluded from signer-stage enforcement.

This phase should be completed immediately after Phase 5 and before Phase 8/Phase 12 work.

## 6.7 Phase 7: Multitenancy Scoped Projection/Query Gate (Tier 2)

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
3. This gate passes before identity projector implementation (Phase 12).

---

## 7. Phase 8: Encrypted Events With The Same Model

Goal: encrypted events behave like normal events for dependencies and projection.
Precondition: Phase 6 signer substrate and Phase 7 multitenancy gate are already active.

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
3. If outer deps missing: write `blocked_event_deps` + `blocked_events` and return `Block`.
4. Verify signature/auth over canonical encrypted bytes.
5. Decrypt ciphertext using key from `key_event_id`.
6. Decode inner event with normal registry.
7. Verify decoded inner type matches outer `inner_type_code`; mismatch -> `Reject(inner_type_mismatch)`.
8. If inner type is encrypted wrapper: reject.
9. Extract inner deps from inner schema metadata.
10. If inner deps missing: write `blocked_event_deps` + `blocked_events` using outer `event_id` and return `Block`.
11. For decrypted inner events, skip dep type-code enforcement (inner deps may target encrypted wrappers that carry admissible plaintext).
12. Run the normal shared signer+projector stage for the inner type.
13. Mark outer event `valid` only after inner projection succeeds.

## 7.5 Plaintext storage policy

- Default: no persisted plaintext queue.
- Decrypted plaintext exists in memory only for projection.
- Optional later optimization: short-lived decrypted cache with TTL.

This preserves one blocker model and one projector model.

## 7.6 Encrypted-event test strategy

Encryption tests use deterministic local key materialization (shared key bytes + deterministic `created_at_ms` from BLAKE2b hash) to set up key state on both sender and recipient sides. This matches the production invite-key wrap/unwrap flow where both parties derive identical `secret_key` event IDs.

Test harness contract:
1. Materialize key as a local `secret_key` event in the correct tenant scope (`recorded_by`).
2. Run encrypted projection through the standard block/unblock flow:
   - missing key event → `Block`
   - key present + decrypt/auth failure → `Reject`
   - key present + decrypt/auth success → inner dep/signer/dispatch stages
3. Keep all replay/reorder invariants enabled.

The same `secret_shared` event type and wrap/unwrap projector logic is used for both bootstrap (wrap to invite key) and runtime (wrap to peer key) key distribution. Only the recipient key source differs.

---

## 8. Phase 9: Durable Queues and Workers

Add full queue machinery after projection + signer + encryption semantics are stable.

## 8.1 Queue tables

```sql
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
- operational/transient: `project_queue`, `blocked_event_deps`, `blocked_events`, `egress_queue`
- removed: `ingress_queue` was dropped in migration 28 because no runtime writer or reader used it

## 8.2 Why not one generic jobs table

A single table sounds simple but mixes incompatible concerns:
- very different retention and purge policies,
- different dedupe keys and lease semantics,
- harder indexing and worse observability.

Separate queue tables stay simpler operationally.

## 8.3 Worker stages

1. `ingest receiver path` (current runtime): QUIC frame -> ingest channel -> transactional canonical insert -> record by tenant -> enqueue project.
2. `project worker`: claim row -> project path (`valid`/`block`/`reject`) -> dequeue.
3. `egress worker`: dequeue by `connection_id` -> send frame -> mark `sent_at`/retry.
4. `cleanup worker`: purge sent egress rows, reclaim expired leases, TTL-purge old endpoint observations.

Queue DRY requirement:
- implement generic queue helper traits/functions once (`claim_batch`, `renew_lease`, `mark_done`, `mark_retry/backoff`).
- reuse them for both `project_queue` and `egress_queue` to avoid diverging retry/lease semantics.

## 8.4 Egress queue creation (matching working Topo shape)

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

Do not add in-memory dedup sets in front of `INSERT OR IGNORE` writers:
- pre-writer dedup causes data loss if the writer transaction rolls back (event marked "seen" but never persisted; peer retransmissions silently dropped),
- the set grows without bound in long-running daemons,
- redundant `INSERT OR IGNORE` from concurrent sessions is cheap and self-correcting.

---

## 9. Phase 10: Special Cases That Stay Explicit

These should not be forced into generic auto-write behavior.

1. `message_deletion` and cascade/tombstone semantics.
2. deterministic emitted-event flows where projection emits another event.
   - these flows still obey emitted-event rule and are unsigned by schema policy for determinism.

Deletion is special and should remain explicit.

---

## 10. Phase 11: Performance + Operational Hardening

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
- do not keep full trust/key sets in memory in low-memory mode.
- use SQL canonical trust/key tables with indexed point lookups and a bounded hot cache only.
- degrade throughput before violating memory ceiling (memory safety over speed).
- validate at scale (`>= 1_000_000` canonical events on disk) with stable memory.
- include large-identity-set validation (for example `>= 100_000` peer trust keys) while preserving memory ceiling.

Recommended initial size policy:
- `EVENT_MAX_BLOB_BYTES = 1_048_576` (1 MiB soft cap)
- `FILE_SLICE_TARGET_BYTES = 262_144` (256 KiB)
- `FILE_SLICE_MAX_BYTES = 1_048_430` (`EVENT_MAX_BLOB_BYTES(1_048_576) - wire_overhead(146)`)

`file_slice` events can be much larger than legacy simulator limits and are signed/verified like other events.
The `FILE_SLICE_MAX_BYTES` constant is derived so that the maximum encoded `file_slice` event
(ciphertext + type byte + timestamps + file_id + slice_number + signer trailer) fits within
`EVENT_MAX_BLOB_BYTES`.

### 10.1 File attachment event types

Two new event types (migration 13):
- `message_attachment` (type 24, signed): Descriptor linking a file to a message.
  Deps: `message_id`, `key_event_id`, `signed_by`. Fields include `blob_bytes`, `total_slices`, `slice_bytes`,
  `root_hash`, `filename`, `mime_type`.
- `file_slice` (type 25, signed): Individual encrypted chunk of a file.
  Dep: `signed_by`. Fields include `file_id`, `slice_number`, `ciphertext`.

Primary key for `file_slices`: `(recorded_by, file_id, slice_number)` — optimized for
sequential IO locality when reassembling files.

### 10.2 Metadata validation

`message_attachment` events are validated at parse time:
- `blob_bytes > 0` requires `total_slices > 0`
- `total_slices > 0` requires `slice_bytes > 0`
- `total_slices` must equal `ceil(blob_bytes / slice_bytes)`
- Zero-byte files (`blob_bytes == 0, total_slices == 0, slice_bytes == 0`) are valid.
- Signer metadata (`signed_by`, `signer_type`, `signature`) is required and then validated by the shared signer pipeline after dependency resolution.

### 10.3 Duplicate slice conflict handling

`file_slice` projection uses `INSERT OR IGNORE` with post-insert conflict detection:
- If insert succeeds (rows > 0): `Valid`
- If insert is ignored: check existing row's `event_id`
  - Same `event_id`: idempotent replay → `Valid`
  - Different `event_id`: conflict → `Reject` with durable rejection record

### 10.4 Future Work: Integrity and Conflict Resolution

1. **Merkle-proof extension**: Attachment carries `merkle_root`, each `file_slice` carries proof path,
   projector verifies proof against descriptor root. Overhead ~`log2(N) * 32` bytes per slice proof.
2. **Full DAG encoding**: Deferred unless needed. Too heavy for current phase.

### 10.5 Multi-source download

Multi-source download allows a sink to pull events from N sources concurrently.

A naive approach — running N independent negentropy sessions, each with its own
`batch_writer` — fails at scale: N writers contend on SQLite WAL locks, overlapping
need_ids cause redundant downloads, and a slow source blocks its events until timeout.

Required changes from the 1:1 sync model:

1. **Shared batch_writer.** One writer thread with all sessions feeding a single `mpsc`
   channel. Eliminates SQLite write contention entirely. Duplicate filtering is handled
   solely by `INSERT OR IGNORE` — see section 8.8 for why in-memory dedup sets must not
   be placed before the writer.
2. **Thread-per-connection.** Each connection spawns a `std::thread` with a dedicated
   single-threaded tokio runtime. Isolates connection failures and allows sharing the
   `mpsc::Sender` to the batch_writer across connections.
3. **Coordinator thread for pull assignment.** After negentropy reconciliation, each peer
   reports its discovered need_ids to a coordinator that assigns each event to the
   least-loaded peer that has it (greedy load balancing, unique-events-first ordering).
4. **Push uncoordinated, pull coordinated.** Have_ids (outbound) stream immediately — no
   coordinator involvement. Only need_ids (inbound) go through assignment. Push runs at
   full speed during the coordination window.
5. **Round-based reassignment.** Assignments are discarded after each round. Undelivered
   events re-appear as need_ids next round and get reassigned to a different peer.
6. **Short collection window (~20ms).** Coordinator waits briefly after the first peer
   reports. Stragglers report next round. Prevents convoy effects from slow reconciliation.
7. **Incremental egress enqueue.** Have_ids buffered and drained in batches per main loop
   iteration so event streaming is not starved by large reconciliation results.
8. **Negentropy snapshot ordering.** `BEGIN` must precede `rebuild_blocks()` so the storage
   sees a consistent read snapshot while concurrent writes proceed in the batch_writer.

Test families (in `sync_graph_test.rs`):
- **Family A (chain):** N-peer chain propagation (tail convergence, per-hop latency).
- **Family B (multi-source):** 1–8 concurrent sources with varying event counts.
  B0 = serialized baseline, B1 = coordinator-assigned, B2/B3 = variants.

---

## 11. Phase 12: Minimal Identity Layer + Crude Sender-Subjective Encryption

This is a final functional phase after the core projection/queue path is stable.
Prerequisite: Phase 6 signer substrate is complete before identity projector implementation begins.

## 11.1 Phase gate: TLA+ causal model first

Before writing identity/removal/encryption projectors in Rust:
1. Confirm signer pipeline from Phase 6 is active:
   - missing `signed_by` dependency blocks,
   - unblocked signer enables signature verification,
   - invalid signature rejects (not block).
2. Build/update a TLA+ model of causal relationships and guards for this phase.
3. Model split invite types (`user_invite`, `device_invite`) and trust-anchor semantics.
4. **Model workspace binding**: workspace events must be parameterized by workspace id, and the trust anchor must bind to a specific workspace. The model must prove that foreign workspace events (for workspaces the peer did not accept an invite for) can never become valid. Without this, the model cannot distinguish between valid and invalid workspace events, making it insufficiently expressive for multi-workspace scenarios. See `InvWorkspaceAnchor`, `InvSingleWorkspace`, `InvForeignWorkspaceExcluded` invariants.
5. **Model invite-derived trust anchor binding**: the trust anchor must bind deterministically to the workspace referenced by the invite, not by a free nondeterministic choice at `invite_accepted` time. The model captures which workspace an invite references when the first invite is recorded (`inviteCarriedWorkspace` variable); `invite_accepted` then reads `inviteCarriedWorkspace` to set the trust anchor. This ensures the binding mechanism is faithful to the real protocol where the invite blob carries a `workspace_id`. See `InvTrustAnchorMatchesCarried` invariant.
6. **Model guard placement explicitly (poc-6 parity)**:
   - trust-anchor guard applies to root workspace events,
   - `invite_accepted` is local anchor binding from carried `workspace_id` (no invite-presence dep gate),
   - downstream identity admission (`user`/`device`/`peer`) still requires signer/dependency chain validity in the same peer scope.
7. Verify bootstrap/self-invite, join, device-link, and removal safety invariants.
8. Freeze a projector-spec mapping table: each projector predicate/check maps to a named TLA guard.
9. Record TLA scope boundary for this phase:
   - current identity-causality models may abstract away transport TLS credential/session-key lifecycle.
   - this abstraction must be tracked explicitly and followed by a transport-key model extension milestone before final identity/transport convergence sign-off.

Projector implementations should mirror TLA conditions as directly as possible.

## 11.2 Minimal identity scope

Only include identity and policy needed for:
- trust-anchor bootstrap/join cascade
- self-invite bootstrap flow
- device linking
- removal enforcement
- recipient selection for encrypted message key wraps
- transport mTLS trust policy derived from identity-backed SQL trust state
  (PeerShared-derived SPKIs + accepted-invite bootstrap trust), not static CLI/file pin sources

## 11.3 Split invite event types (no mode switch)

Use separate types:
- `user_invite` (invites a user identity)
- `device_invite` (invites/links a peer device to a user)
- `invite_accepted` (records trust-anchor binding; local SQL also stores accepted invite-link bootstrap metadata)

Do not use one `invite` type with `mode=user|peer`.

Implementation requirement:
- keep one shared invite projector helper with per-type policy tables (signer/dependency checks).
- this keeps logical separation for TLA/model checking while avoiding duplicated Rust control flow.

## 11.4 Trust-anchor cascade requirements (from `poc-6`/TLA model)

Required behavior:
- `invite_accepted` records trust anchor intent for `workspace_id` (per `recorded_by` peer scope).
- `invite_accepted` is a local binding step from event-carried `workspace_id` (no invite-presence dep gate).
- if a different trust anchor already exists for that peer scope, `invite_accepted` is rejected.
- downstream identity events (`user_boot`, `device_invite`, `peer_shared`) remain dependency/signer-gated in peer scope.
- root `workspace` events are not valid until corresponding trust anchor exists and matches the root id.
- trust-anchor binding must come from validated projector input fields, not pre-projection capture tables.
- invites are never force-valid; they validate only through signer/dependency chain.
- accepted invite links store bootstrap transport trust tuples in SQL:
  - inviter address from invite link,
  - inviter SPKI fingerprint for that address,
  - looked up by sync on each connection/handshake (no in-memory-only trust authority).

Self-invite bootstrap sequence must stay explicit:
1. create `workspace` event (integrity self-sign only).
2. create bootstrap `user_invite` signed by workspace authority.
3. accept invite locally -> `invite_accepted(workspace_id=...)`.
4. normal cascade unblocks: `workspace -> user_invite -> user -> device_invite -> peer_shared`.

## 11.4.1 Poc-6-aligned high-level bootstrap migration plan

Use `poc-6` as reference behavior for end-to-end test setup:
1. Alice creates workspace + identity chain via high-level bootstrap API.
2. Alice creates invite link (contains bootstrap address + inviter SPKI fingerprint + invite event ID + invite private key + workspace ID). Wrapped content-key material is delivered via `secret_shared` events during bootstrap sync, not embedded in the invite link payload.
3. Bob accepts invite link via high-level accept API:
   - records local `invite_accepted`,
   - writes trust anchor binding (`workspace_id`),
   - stores accepted-invite bootstrap transport trust tuple in SQL,
   - unwraps bootstrap content-key material using invite private key and inviter public key,
   - materializes local `secret_key` events with deterministic event IDs (matching inviter's key IDs).
4. Sync bootstrap trust is read from SQL at connection creation (no in-memory-only trust authority).
5. Encrypted events received during bootstrap sync block until local key materialization (step 3) completes, then unblock via normal cascade.
6. Connection state follows `poc-6` ordering:
   - invite-auth request (`connReq`) -> ack (`connAck`) ->
   - invite-labeled connection (`connInvite`) ->
   - peer-labeled upgraded connection (`connPeer`).
7. Tests migrate to this flow:
   - remove direct SPKI pin setup from test harnesses,
   - remove synthetic low-level bootstrap stubs where high-level APIs exist,
   - require invite-link acceptance path for multi-peer bootstrap.
8. Keep low-level tests only for explicit adversarial/property coverage, not baseline bootstrap.

## 11.5 Crude sender-keys model (phase-1 style, no key history yet)

Use the sender-subjective O(n) baseline from `docs/group-encryption-design-aspects.md`
("Maximally simple.../Phase 4: baseline correctness and healing with O(n) key broadcast"):
- sender creates a fresh local-only `secret` key event per message,
- sender emits one `secret_shared` key-wrap event per perceived eligible recipient peer pubkey,
- encrypted content event references the key event id through normal dependency fields,
- each sender wraps to all perceived eligible members for each message (intentionally crude).

Bootstrap and runtime wrapping share the same `secret_shared` event type and wrap/unwrap projector path. Bootstrap wraps target the invite public key (X25519-derived from Ed25519 invite signing key); runtime wraps target PeerShared public keys. Recipients materialize local `secret_key` events with deterministic event IDs derived from key bytes (BLAKE2b hash → `created_at_ms`), ensuring inviter and joiner agree on `key_event_id` values.

Key modeling requirements for this phase:
- All protocol-level key material that projectors depend on must be represented as events and resolved by event-id dependencies (for example sender `secret` keys and recipient key-wrap events). Do not introduce out-of-band key stores for event-graph key dependencies.
- This requirement also applies to transport TLS keying in end-state: cert/public-key trust mapping and local TLS private key material are event-backed state with dependency ordering.
- Runtime file artifacts for TLS keys/certs are optional cache/materialization outputs only; they are not authoritative policy state.
- For fanout to many recipients, produce one canonical encrypted content event and many recipient-specific key-wrap events for the same key/decrypt target; recipients that are eligible and have key material must decrypt to the same plaintext event bytes (deterministic materialization target across recipients).

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

## 11.8 TLA transport-credential lifecycle (gap closed)

**Status:** Closed. `docs/tla/TransportCredentialLifecycle.tla` models the runtime transport credential and trust-store layer.

Previous gap: TLA models were identity/event-causality models that did not encode mTLS credential lifecycle (SPKI generation/rotation/revocation, projected trust-set state transitions).

**What is now modeled** (TransportCredentialLifecycle.tla):
- Local credential lifecycle: single credential per peer (no rotation/revocation in POC).
- Three-source trust store: PeerShared-derived SPKIs, invite_bootstrap_trust, pending_invite_bootstrap_trust.
- Supersession: AddPeerSharedTrust automatically removes matching bootstrap/pending entries.
- TTL expiry of bootstrap trust sources.
- Trust removal (peer_removed cascading, user_removed transitive denial via `peers_shared.user_event_id`).
- 6 invariants verified by TLC, mapped to Rust checks in `docs/tla/projector_spec.md`.

**What remains abstract** (by design):
- TLS handshake and session-key derivation.
- CLI pin trust source (modeled only in Rust, not in TLA+).
- Event-graph causality for trust-source inputs (nondeterministic in this module; covered by EventGraphSchema.tla).

Config files: `transport_credential_lifecycle_fast.cfg` (2 peers, 3 SPKIs), `transport_credential_lifecycle.cfg` (2 peers, 4 SPKIs).

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

1. Finish Phase `1`, `2`, `4`, and `5` with a small event set.
2. Complete Phase 6 signer substrate.
3. Add Phase 8 encrypted wrapper with PSK test harness for one core content path.
4. Add minimal Phase 9 queues.
5. Add deletion special-case behavior after baseline sync is stable.
6. Add final Phase 12 identity + invite cascade + sender-subjective key wraps.

---

## 15. Assistant Execution Playbook (High-detail)

Use this section as the implementation contract. If code conflicts with this section, update code to match this section unless user overrides.

## 15.1 Cross-phase non-negotiables

1. No alternate projection path:
   - all projection must converge on `project_one(recorded_by,event_id)`.
   - `project_one_step` (internal, non-cascading) is used only within the cascade worklist as a performance optimization; it shares all projection stages with `project_one`.
2. No alternate dependency resolver:
   - dependency refs come from schema metadata only.
3. No insecure transport default:
   - pinned mTLS required unless explicitly running dedicated test mode.
4. No fixed global event blob size after Phase 4.
5. No queue-specific retry logic duplication:
   - shared claim/lease/retry/backoff helpers only.
6. No per-tenant table fanout:
   - shared projection tables with tenant-scoped keys/indices only.
7. No cross-table direct projection for emitted events:
   - emitted events must project via their own event projector/autowrite path.
8. No alternate signer pipeline:
   - all signed event types use the same dependency-then-signature-verification ordering.

## 15.2 Phase 1 implementation checklist (CLI + daemon)

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

## 15.3 Phase 2 implementation checklist (mTLS baseline)

Must implement:
1. persistent cert identity per profile.
2. pinned-cert verifier on both client and server.
3. Transitional allowlist source in completed Phase 2 is CLI/profile supplied cert SPKI pins, not socket address.
4. session context binds:
   - local `recorded_by` from local cert profile identity.
   - remote `via_peer_id` from verified cert SPKI mapping (identity-backed once Phase 12 lands).
5. unit/integration tests for allowed and denied peers.
6. migration note implemented:
   - Phase 12 switches allowlist source to projected identity events (`peer_id -> cert SPKI`).
7. TODO (mandatory retrofit before final Phase 12 sign-off):
   - remove CLI/file pin authority and run transport trust solely from projected identity graph state.
   - represent local TLS cert/private key material as event-backed state; file artifacts remain cache only.

Common mistakes:
- using generated ephemeral cert each restart in daemon mode.
- leaving permissive cert verifier as default behavior.

Definition of done:
- unpinned peer connection fails at handshake,
- pinned invited peer sync succeeds repeatedly across daemon restarts.

## 15.4 Phase 4 implementation checklist (schema + wire + recording)

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

## 15.5 Phase 5 implementation checklist (projector + blocked deps)

Must implement:
1. `project_one(recorded_by,event_id)` entrypoint.
2. dependency persistence tables (`blocked_event_deps` + `blocked_events` header).
3. counter-based Kahn cascade unblock (`deps_remaining` decrement path + post-cascade dep-row cleanup).
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

## 15.5A Phase 6 implementation checklist (signer substrate)

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

## 15.6 Phase 8 implementation checklist (encrypted adapter)

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

## 15.7 Phase 9 implementation checklist (durable queues/workers)

Must implement:
1. queue tables (`project`, `egress`) with transactional boundaries.
2. shared queue helper functions for claim/lease/retry.
3. egress creation from reconciliation and request-list producers.
4. queue cleanup + TTL maintenance jobs.
5. ingest path writes canonical rows + `project_queue` enqueue atomically before projection drain.

Common mistakes:
- using one generic jobs table for all queues.
- mixing canonical durable rows and operational queue rows in one table.

Definition of done:
- crash/restart recovers and completes pending work,
- retries/backoff and lease recovery are observable and deterministic.

## 15.8 Phase 10 implementation checklist (special projectors)

Must implement:
1. explicit deletion/tombstone/cascade projector.
2. explicit deterministic emitted-event handling.

Common mistakes:
- forcing deletion into generic auto-write logic.

Definition of done:
- deletion-before-target and target-before-deletion converge identically.

## 15.9 Phase 11 implementation checklist (hardening)

Must implement:
1. batch/index tuning driven by measurements.
2. queue health metrics (`age`, `attempts`, blocked counts).
3. endpoint observation TTL purging.
4. `low_mem_ios` mode with explicit knobs (SQLite cache, channel/batch limits, worker concurrency caps).
5. long-run memory test at million-event scale showing `<= 24 MiB` steady-state RSS target in low-memory mode.
6. low-memory trust lookup path that avoids full in-memory keyset loading (SQL indexed lookup + bounded hot cache).
7. large-identity-set memory test (for example `>= 100_000` peer trust keys) within low-memory ceiling.

Common mistakes:
- premature micro-optimizations before invariant/test stability.
- optimizing throughput in low-memory mode at the cost of memory bound violations.

Definition of done:
- long-running sync remains stable and bounded in memory/storage.
- low-memory mode is reliable and repeatable under iOS NSE-style memory limits.

## 15.10 Phase 12 implementation checklist (TLA-first identity)

Must implement:
1. TLA model updated first for split invites and trust-anchor guards.
2. projector predicate mapping table from TLA guards.
3. split invite events (`user_invite`, `device_invite`) with shared helper core.
4. sender-subjective O(n) key wrapping baseline (no key history yet).
5. removal excludes removed peers from subsequent wraps.
6. preserve Phase 6 signer pipeline (do not add identity-specific signature fast paths).
7. transport mTLS trust source switched to projected identity graph policy (retrofit completed; no CLI/file pin authority in steady state).
8. local TLS cert/public/private key material modeled as events and materialized from projected local event state.
9. guard placement correction:
   - `invite_accepted` is local trust-anchor binding from carried `workspace_id` (no invite-presence dep gate) per peer scope.
   - trust-anchor guard applies on root workspace events only.
10. remove/avoid pre-projection trust-binding capture paths (for example raw-blob `invite_workspace_bindings` capture) as authority.
11. TLA transport-credential scope extension plan exists and is linked (credential/trust transitions modeled; handshake/session keys may remain abstract).

Common mistakes:
- implementing projector rules before guard/model freeze.
- re-introducing multimodal invite event (`mode=*`).
- adding a separate invite-presence gate to `invite_accepted` instead of enforcing identity admission through normal signer/dependency chain checks.
- forgetting to track the transport-credential TLA scope gap explicitly.

Definition of done:
- TLA invariants pass for bootstrap, join, device-link, and removal flows,
- Rust behavior matches TLA guard mapping in tests.
- transport-credential modeling gap is either closed in TLA or explicitly tracked as open with linked follow-up artifact.

## 15.11 PR slicing guidance (to reduce assistant mistakes)

Recommended PR sequence:
1. transport mTLS hardening only.
2. wire framing + schema registry scaffolding.
3. projector entrypoint + dependency resolver + blocked deps.
4. create_sync API contract and tests.
5. signer substrate (Phase 6): signer dep blocking + signature ordering tests.
6. encrypted adapter + PSK tests.
7. queue/worker architecture and shared queue helper extraction.
8. deletion special-case projector.
9. TLA model update + identity phase implementation.

Rule:
- each PR must include at least one failing test made to pass by that PR.

---

## 16. NAT Traversal and Hole Punch (Transport Extension)

This section documents the hole-punch implementation on the `quic-holepunch` branch and guidance for future builders.

### 16.1 Current implementation status

Implemented and tested:
1. `IntroOffer` wire message (88 bytes fixed, type `0x30`) on uni-directional QUIC streams.
2. Endpoint observation recording in `peer_endpoint_observations` from accept/connect loops and successful punched connections.
3. One-shot intro dispatch via the `intro` CLI command (no background intro worker in daemon).
4. Punch handler with paced QUIC dial, identity verification, and sync-on-success.
5. `intro_attempts` table tracking full lifecycle (`received -> dialing -> connected | failed | expired | rejected`).
6. CLI surface: `sync`, `intro` (one-shot), and `intro-attempts` (diagnostic).
7. Linux netns/NAT integration test (`tests/netns_nat_test.sh`) with cone and symmetric modes.

### 16.2 Architecture decisions

1. **Shared endpoint**: Intro offer handling and punch dialing run on the same QUIC endpoint as sync. This is required for NAT compatibility because punch packets must originate from the same UDP socket/port that the NAT has already mapped.

2. **spawn_local for punch handlers**: Punch attempts use `tokio::task::spawn_local` on a `LocalSet` instead of `tokio::spawn` or `spawn_blocking`. This is because:
   - Quinn endpoints are tied to a specific runtime's I/O driver.
   - Rusqlite connections are `!Send`.
   - `spawn_local` satisfies both constraints by running on the same runtime/thread.

3. **No canonical intro events**: IntroOffers and punch attempts are runtime protocol state, not canonical events. They are recorded in operational tables (`peer_endpoint_observations`, `intro_attempts`) with TTL-based cleanup.

4. **Introducer is a role, not a node type**: Any trusted peer with endpoint observations for two peers can issue an explicit intro call. There is no dedicated relay/TURN server in the current design.

5. **Concurrent accept_loop**: The accept loop spawns each connection handler as a `spawn_local` task so the introducer can serve multiple peers simultaneously rather than blocking on one connection's sync session.

### 16.3 NAT compatibility requirements

The current implementation works with EIM (Endpoint-Independent Mapping) NATs, which are the most common home router type:

1. **Port preservation**: The NAT must use the same external port for all destinations from a given internal `(ip, port)`. This is the defining property of EIM.
2. **Simultaneous open**: Both peers must send packets to each other within a short window so that each creates an outgoing NAT mapping before the other's packets arrive.
3. **No phantom conntrack entries**: On Linux, unsolicited incoming packets can create conntrack entries that interfere with port-preserving masquerade. The netns test uses `raw` table `notrack` + `INPUT` chain drops to prevent this. Real routers vary in whether they exhibit this behavior.

NAT types that will NOT work:
- Symmetric/port-dependent NATs (different external port per destination).
- NATs with very short UDP timeout (< attempt window).
- CGN (Carrier-Grade NAT) with unpredictable mapping behavior.

### 16.4 Explicit intro flow

The current intro flow is intentionally minimal:
1. An operator/controller calls `topo intro --peer-a <fpA> --peer-b <fpB>`.
2. The introducer resolves freshest non-expired endpoint observations for both peers.
3. It sends one `IntroOffer` to each peer over uni-directional QUIC streams.
4. Receivers validate trust/expiry/dedup, then run paced dial attempts inside `attempt_window_ms`.
5. On success, peers record `connected` in `intro_attempts`, persist observed endpoint metadata, and run direct sync.

There is no built-in pair selection scheduler in the daemon. Selection policy and retry cadence belong in a higher-level connection job.

### 16.5 How to test

Run from repo root:
1. `cargo test --test holepunch_test`
2. `cargo test test_record_endpoint_observation`
3. `cargo build --release`
4. `sudo tests/netns_nat_test.sh --cone` (expected: PASS)
5. `sudo tests/netns_nat_test.sh --symmetric` (expected: FAIL, by design)
6. `sudo tests/netns_nat_test.sh --cleanup`

Notes:
1. The netns script requires `ip`, `nft`, and root privileges.
2. In cone mode, script success means at least one peer reports `intro_attempts` status `connected`.
3. In symmetric mode, failure is the expected result and validates NAT-type sensitivity.
4. On unexpected mismatch, the script dumps nft rulesets, conntrack state (if present), and recent daemon logs.

### 16.6 Key implementation files

- `src/sync/punch.rs`: IntroOffer receiver, punch dial loop, identity verification, sync-on-punched-connection, punched-peer endpoint observation persistence.
- `src/sync/intro.rs`: one-shot intro send and endpoint lookup.
- `src/sync/engine.rs`: `accept_loop_inner` and `connect_loop_inner` with LocalSet, endpoint observation recording, `spawn_intro_listener` call sites.
- `src/main.rs`: CLI commands (`Intro`, `IntroAttempts`) and `sync` command wiring.
- `src/db/intro.rs`: `intro_attempts` table operations (insert, update status, query, dedup check) and freshest endpoint query.
- `src/db/health.rs`: `record_endpoint_observation`, `purge_expired_endpoints`.
- `tests/netns_nat_test.sh`: Linux netns NAT integration test (requires root/sudo).
- `tests/holepunch_test.rs`: localhost integration tests for trust/expiry/happy-path intro and punch behavior.

### 16.7 Future work for builders

1. **Connection job for intro scheduling**: Add an external or embedded scheduler that decides who to intro and when (rate limits, retry backoff, target degree, freshness thresholds).
2. **STUN integration**: Add STUN client discovery to improve mapped endpoint freshness and reduce stale-observation failures.
3. **TURN fallback**: For symmetric NATs where hole punch cannot work, relay traffic through an introducer/TURN role.
4. **Connection quality tracking**: Track latency/stability of direct paths and prefer direct links over relay links when healthy.
5. **Multi-path sync**: Use relay and direct paths together for redundancy and throughput.
6. **IPv6 traversal coverage**: Expand test coverage for IPv6 intro and direct dialing.
7. **Intro protocol hardening**: Optionally sign IntroOffers so trust is portable beyond the authenticated transport channel.

### 16.8 Common pitfalls for builders

1. **Cross-runtime endpoint I/O**: Quinn endpoints are bound to a specific tokio runtime's I/O driver. If you `spawn_blocking` with a new runtime and try to `endpoint.connect()`, the QUIC handshake will never complete because the UDP I/O is driven by the original runtime. Use `spawn_local` on the same `LocalSet` instead.

2. **Phantom conntrack on Linux**: When testing with nftables masquerade, unsolicited incoming UDP packets create conntrack entries even if they're dropped by the forward/input filter. These phantom entries cause masquerade to remap source ports, breaking EIM. Prevent with `raw` table `notrack` for new WAN-incoming packets and `INPUT` chain drops before conntrack confirm.

3. **QUIC endpoint must be dual-mode**: The same endpoint must be both client and server (via `create_dual_endpoint`) so that when A dials B and B dials A simultaneously, both sides can accept the other's connection.

4. **Intro timing matters**: Both peers must receive IntroOffers and start dialing within each other's attempt windows. A controller may need repeated one-shot `intro` calls when peers are unstable.

5. **LocalSet is required**: Both `accept_loop` and `connect_loop` wrap their inner logic in a `LocalSet::run_until()` to provide the context needed by `spawn_local` in `spawn_intro_listener`. Forgetting this causes a panic at runtime.

---

## 17. Phase 13: Functional Multitenancy

### Status: COMPLETE

One node hosting N local tenant identities in a shared SQLite DB with one shared QUIC endpoint, tenant-scoped workspace binding, and tenant-scoped trust policy. The DB itself is the tenant registry — no explicit registration step. Tenants are discovered by joining `trust_anchors` with `local_transport_creds`.

### Key insight

The DB already IS the tenant registry. `trust_anchors(peer_id, workspace_id)` contains every local identity that has accepted an invite (populated by `invite_accepted`, which is local-only). All projection tables scope by `(recorded_by, event_id)`. The only missing pieces were: (a) storing TLS cert/key material per tenant in the DB, and (b) a node daemon that reads this state and runs one shared QUIC endpoint with tenant-scoped cert selection/routing.

---

## 17.1 DB-Only TLS Credential Storage

Cert/key DER blobs live exclusively in SQLite. No `.cert.der` / `.key.der` files on disk. Transport credentials are derived from PeerShared signing keys during identity bootstrap (workspace creation or invite acceptance) and stored in the DB.

### 17.1.1 Migration 26: `local_transport_creds`

```sql
CREATE TABLE local_transport_creds (
    peer_id TEXT PRIMARY KEY,
    cert_der BLOB NOT NULL,
    key_der BLOB NOT NULL,
    created_at INTEGER NOT NULL
);
```

Populated during identity bootstrap: PeerShared-derived cert/key is installed by `install_peer_key_transport_identity`, or invite-derived cert/key by `install_invite_bootstrap_transport_identity`. Added in `src/db/migrations.rs`.

### 17.1.2 `src/db/transport_creds.rs`

CRUD operations for the `local_transport_creds` table:

```rust
pub fn store_local_creds(conn, peer_id, cert_der, key_der) -> Result<()>
pub fn load_local_creds(conn, peer_id) -> Result<Option<(Vec<u8>, Vec<u8>)>>
pub fn load_sole_local_creds(conn) -> Result<Option<(String, Vec<u8>, Vec<u8>)>>
pub fn list_local_peers(conn) -> Result<Vec<String>>
pub fn discover_local_tenants(conn) -> Result<Vec<TenantInfo>>
```

`TenantInfo` carries `peer_id`, `workspace_id`, `cert_der`, `key_der`.

`load_sole_local_creds` returns the single local credential when exactly one exists; errors if multiple exist. Used by single-tenant CLI mode to avoid ambiguity.

`discover_local_tenants` is the core multi-tenant query:

```sql
SELECT t.peer_id, t.workspace_id, c.cert_der, c.key_der
FROM trust_anchors t
JOIN local_transport_creds c ON t.peer_id = c.peer_id
```

This returns every local identity that has (a) accepted an invite and (b) has TLS material. No registration needed.

### 17.1.3 Filesystem cert elimination

**Removed:**
- `transport_cert_paths_from_db()` — file path derivation
- `write_cert_and_key()` — file writes
- `load_or_generate_cert()` — file-based load/generate
- `atomic_write()` and `set_owner_only_permissions()` — dead code
- File-based tests in `cert.rs`

**Kept:**
- `generate_self_signed_cert()` — generates in memory
- `generate_self_signed_cert_from_signing_key()` — deterministic generation for invites
- `extract_spki_fingerprint()` — computes BLAKE2b-256 of SPKI
- `validate_cert_key_match()` — validates cert/key consistency

### 17.1.4 Refactored `src/transport_identity.rs`

All functions switched from file I/O to DB queries. Functions take `&Connection` instead of `db_path: &str` at the core, with convenience wrappers that open connections:

```rust
// Core (take &Connection):
pub fn load_transport_peer_id(conn) -> Result<String>
pub fn ensure_transport_peer_id(conn) -> Result<String>
pub fn ensure_transport_cert(conn) -> Result<(String, CertificateDer, PrivatePkcs8KeyDer)>
pub fn load_transport_cert(conn, peer_id) -> Result<(CertificateDer, PrivatePkcs8KeyDer)>

// Convenience (open connection from db_path):
pub fn load_transport_peer_id_from_db(db_path) -> Result<String>
pub fn ensure_transport_peer_id_from_db(db_path) -> Result<String>
pub fn ensure_transport_cert_from_db(db_path) -> Result<(String, CertificateDer, PrivatePkcs8KeyDer)>

// Invite bootstrap (deterministic cert from invite key):
pub fn expected_invite_bootstrap_spki_from_invite_key(invite_key) -> [u8; 32]
pub fn install_invite_bootstrap_transport_identity(db_path, invite_key) -> Result<String>

// TransportKey event creation (removed — no longer created during bootstrap):
// ensure_transport_key_event has been removed; PeerShared-derived SPKIs serve as trust source
```

TransportKey event creation has been removed from the identity bootstrap flow. PeerShared-derived SPKIs now serve as the sole steady-state transport trust source.

### 17.1.5 Caller updates

All cert-loading sites across the codebase were updated from file-based to DB-based:

| File | Sites | Change |
|------|-------|--------|
| `src/main.rs` | 4 | `load_or_generate_cert` → `ensure_transport_cert_from_db` |
| `src/service.rs` | 4 | same, conn already available in service context |
| `src/identity_ops.rs` | 1 | `std::fs::read(cert_path)` → DB query |
| `src/testutil.rs` | ~15 | all Peer methods use `ensure_transport_cert` |
| `src/transport/mod.rs` | exports | removed file-based, added DB-based |

### Exit criteria (Phase 17.1)

`cargo test` passes. Zero cert files on disk. All cert material in `local_transport_creds` table. `discover_local_tenants` returns the right peers.

---

## 17.2 Production Identity Flows

Manual identity chain construction in test helpers was replaced with production `identity_ops` functions. This ensures tests exercise the same code paths as the real daemon.

### 17.2.1 `src/identity_ops.rs`

Three high-level flows:

**Bootstrap (creator):**
```rust
pub fn bootstrap_workspace(conn, recorded_by) -> Result<IdentityChain>
```
Creates: Workspace → UserInviteBoot → InviteAccepted (trust anchor) → UserBoot → DeviceInviteFirst → PeerSharedFirst → AdminBoot (7 identity events + content key events).

**Invite (admin):**
```rust
pub fn create_user_invite(conn, recorded_by, workspace_key, workspace_id) -> Result<InviteData>
```
Creates UserInviteBoot event signed by workspace key. Returns `InviteData { invite_event_id, invite_key, workspace_id, invite_type }`.

**Accept (joiner):**
```rust
pub fn accept_user_invite(conn, recorded_by, invite_key, invite_event_id, workspace_id) -> Result<JoinChain>
```
Creates: InviteAccepted → UserBoot → DeviceInviteFirst → PeerSharedFirst. Joiner must pre-copy Workspace + UserInviteBoot events into their DB before calling this.

**Device link:**
```rust
pub fn create_device_link_invite(conn, recorded_by, user_key, user_event_id, workspace_id) -> Result<InviteData>
pub fn accept_device_link(conn, recorded_by, device_invite_key, device_invite_event_id, workspace_id) -> Result<LinkChain>
```

All functions take `&Connection` and `recorded_by`, enabling multi-tenant operation on shared DBs.

### 17.2.2 Result types

```rust
pub struct IdentityChain {
    pub workspace_id: [u8; 32],
    pub workspace_key: SigningKey,
    pub peer_shared_event_id: [u8; 32],
    pub peer_shared_key: SigningKey,
    // ... plus all intermediate event IDs and keys
}

pub struct JoinChain {
    pub peer_shared_event_id: [u8; 32],
    pub peer_shared_key: SigningKey,
    pub invite_accepted_event_id: [u8; 32],
    // ... plus intermediate keys
}
```

---

## 17.3 Multi-Tenant Batch Writer

The sync engine's ingest channel was changed from a 2-tuple to a 3-tuple carrying the tenant identity.

### 17.3.1 `IngestItem` type

```rust
pub type IngestItem = (EventId, Vec<u8>, String);  // (event_id, blob, recorded_by)
```

### 17.3.2 `batch_writer` signature

```rust
pub fn batch_writer(
    db_path: String,
    mut rx: mpsc::Receiver<IngestItem>,
    events_received: Arc<AtomicU64>,
)
```

The `recorded_by: String` parameter was removed. Per-item `recorded_by` is extracted from each `IngestItem` for:
- `recorded_events` INSERT
- `project_queue` enqueue
- Per-tenant projection drain

Drain phase groups items by tenant and drains per tenant:
```rust
let tenants: HashSet<String> = batch.iter().map(|(_, _, rb)| rb.clone()).collect();
for rb in &tenants {
    pq.drain_with_limit(rb, batch_sz, |conn, eid_b64| { ... });
}
```

### 17.3.3 `spawn_data_receiver`

```rust
pub fn spawn_data_receiver<R>(
    data_recv: R,
    ingest_tx: Sender<IngestItem>,
    bytes_received: Arc<AtomicU64>,
    recorded_by: String,
)
```

Tags every received event with `recorded_by` before sending to the shared ingest channel. This ensures no event enters the shared writer without tenant identification.

### 17.3.4 `accept_loop_with_ingest`

```rust
pub async fn accept_loop_with_ingest(
    db_path: &str,
    recorded_by: &str,
    endpoint: Endpoint,
    allowed_peers: Option<AllowedPeers>,
    shared_ingest_tx: Sender<IngestItem>,
) -> Result<()>
```

Extracted from `accept_loop` to accept an external shared ingest channel. The existing `accept_loop` becomes a wrapper that spawns a local `batch_writer` and delegates.

---

## 17.4 Node Daemon

### 17.4.1 `src/node.rs`

```rust
pub async fn run_node(
    db_path: &str,
    bind_ip: IpAddr,
) -> Result<(), Box<dyn Error + Send + Sync>>
```

Flow:
1. Open shared DB, `create_tables()`.
2. `discover_local_tenants(&db)` — JOIN `trust_anchors` with `local_transport_creds`.
3. Fail if empty: "No local identities found."
4. Spawn ONE shared `batch_writer` thread.
5. Per tenant:
   - Deserialize cert/key DER into rustls types.
   - Verify SPKI fingerprint matches `peer_id`.
   - Create QUIC endpoint via `create_dual_endpoint_dynamic` on `(bind_ip, 0)` (auto-assign port).
   - Build per-tenant dynamic trust closure scoped to that `recorded_by`.
   - Spawn `accept_loop_with_ingest` with shared ingest channel.
   - Log actual bound port.
6. Ctrl-C → close all endpoints.

### 17.4.2 Per-tenant dynamic trust

Each tenant's QUIC endpoint gets a closure that checks transport trust in real-time:

```rust
let is_allowed = move |peer_fp: &str| -> bool {
    is_peer_allowed(&db_path, &recorded_by, peer_fp, &allowed_peers)
};
```

This queries `trust_anchors` and PeerShared-derived SPKIs for that specific `recorded_by`, enabling isolated trust policies per tenant within the same process.

### 17.4.3 `PeerDispatcher`

Tracks discovered peer addresses and manages connection lifecycle:

```rust
pub struct PeerDispatcher {
    known: HashMap<String, (SocketAddr, watch::Sender<()>)>,
}
```

`DiscoveryAction` enum routes decisions: `Skip` (already connected at same address), `Connect` (new peer), `Reconnect` (address changed — cancel old `connect_loop` via `watch` channel, spawn new one).

### 17.4.4 CLI integration

`src/main.rs` always calls `node::run_node()` for sync (single-tenant and multi-tenant handled uniformly). RPC server still runs alongside for queries.

---

## 17.5 mDNS/DNS-SD Discovery

### 17.5.1 `src/discovery.rs` (feature-gated: `discovery`)

```toml
# Cargo.toml
mdns-sd = { version = "0.11", optional = true }

[features]
default = ["discovery"]
discovery = ["mdns-sd"]
```

### 17.5.2 `TenantDiscovery`

```rust
pub struct TenantDiscovery {
    peer_id: String,
    daemon: ServiceDaemon,
    local_peer_ids: HashSet<String>,
}

impl TenantDiscovery {
    pub fn new(peer_id, port, local_peer_ids) -> Result<Self>
    pub fn browse(&self) -> Result<Receiver<DiscoveredPeer>>
}
```

Each tenant advertises under `_topo._udp.local.` with:
- Instance name: `p7-{peer_id_truncated_to_59_chars}` (DNS labels max 63 bytes).
- TXT property: `peer_id={full_64_hex_chars}` for exact matching.
- Explicit local non-loopback IPv4 address (discovered via UDP socket connect to 8.8.8.8).

`local_peer_ids` (the full set of all tenants on this node) filters out self-discoveries and other local tenants. This prevents unnecessary local connections.

### 17.5.3 Integration in `node.rs`

After creating the shared endpoint and learning its bound port, node creates `TenantDiscovery` per tenant using that shared port. On trusted discovery, `PeerDispatcher` routes to tenant-specific `connect_loop`. Feature-gated with `#[cfg(feature = "discovery")]`.

### 17.5.4 DNS label truncation

Peer IDs are 64 hex chars. With the `p7-` prefix (3 chars), using all 64 would produce a 67-char label exceeding the 63-byte DNS limit. The instance name truncates to 59 chars of the peer ID (62 total with prefix). The full peer ID is always available in the TXT property for exact matching.

---

## 17.6 Test Infrastructure

### 17.6.1 `SharedDbNode` test helper

```rust
pub struct SharedDbNode {
    pub db_path: String,
    pub tenants: Vec<Peer>,
    _tempdir: TempDir,
}
```

Creates N tenants in one shared DB. Each tenant gets:
- Unique self-signed cert (stored via `store_local_creds`).
- Full identity chain via `bootstrap_identity_chain()`.
- Own `workspace_id`, `peer_shared_event_id`, `peer_shared_signing_key`.

```rust
impl SharedDbNode {
    pub fn new(n: usize) -> Self           // N independent-workspace tenants
    pub fn add_tenant_in_workspace(        // join existing tenant's workspace
        &mut self, name: &str, creator_index: usize,
    )
    pub fn verify_all_invariants(&self)    // cross-tenant leakage check
}
```

`add_tenant_in_workspace` uses the production invite flow:
1. Generate distinct cert for new tenant, store in shared DB.
2. Creator issues invite via `create_user_invite`.
3. Copy prerequisite events (Workspace + UserInviteBoot) from creator to joiner.
4. Joiner accepts via `accept_user_invite` → full identity chain (no TransportKey — PeerShared-derived).

### 17.6.2 `Peer` construction

Three constructors matching different test needs:

| Constructor | Identity | Workspace | Use case |
|-------------|----------|-----------|----------|
| `Peer::new(name)` | Transport only | None | Manual identity tests |
| `Peer::new_with_identity(name)` | Full bootstrap | Own | Independent peer tests |
| `Peer::new_in_workspace(name, creator)` | Join flow (async) | Creator's | Same-workspace tests |

`new_with_identity` calls `bootstrap_workspace` (production flow). `new_in_workspace` (async) creates a real invite, starts a temp QUIC sync endpoint for the creator, and calls `svc_accept_invite` which performs bootstrap sync + identity chain creation — no direct DB-to-DB event copying.

### 17.6.3 Closure-based `sync_until_converged`

```rust
pub async fn sync_until_converged<F: Fn() -> bool>(
    peer_a: &Peer,
    peer_b: &Peer,
    check: F,
    timeout: Duration,
) -> SyncMetrics
```

Replaced the old `expected_count: i64` parameter with a generic closure. Metrics (events transferred, throughput) are computed from before/after `store_count()` internally.

### 17.6.4 Application-level convergence pattern

Tests use `has_event()` on specific event IDs for convergence detection, and meaningful projection counts for assertions:

```rust
// Convergence: sample a specific event, wait for it to arrive
let sample = alice.sample_event_ids(1)[0].clone();
let metrics = sync_until_converged(
    &alice, &bob,
    || bob.has_event(&sample),
    Duration::from_secs(120),
).await;

// Assertion: application-level data, not raw event counts
assert_eq!(alice.message_count(), 5_000);
assert_eq!(bob.message_count(), 5_000);
```

This pattern is resilient to identity chain size changes (6 events → 8 events → future changes). Tests never assert on `store_count()`, `recorded_events_count()`, or `neg_items_count()`.

For bidirectional zero-loss verification, sample multiple events from both sides:
```rust
let alice_samples = alice.sample_event_ids(50);
let bob_samples = bob.sample_event_ids(50);
sync_until_converged(&alice, &bob,
    || alice_samples.iter().all(|s| bob.has_event(s))
        && bob_samples.iter().all(|s| alice.has_event(s)),
    Duration::from_secs(120),
).await;
```

### 17.6.5 Cross-tenant leakage detection

```rust
pub fn assert_no_cross_tenant_leakage(
    db_path: &str,
    tenant_workspaces: &[(String, [u8; 32])],
)
```

Checks:
1. `recorded_events` and `valid_events` are pairwise disjoint for tenants in different workspaces.
2. No unexpected `recorded_by` values in projection tables (messages, reactions, signed_memos, secret_keys).
3. Overlaps expected for same-workspace tenants (after sync).

Wired into `SharedDbNode::verify_all_invariants()` and run after every multi-tenant scenario test.

---

## 17.7 Scenario Tests

Tests in `tests/scenario_test.rs`:

| Test | Topology | Verifies |
|------|----------|----------|
| `test_shared_db_same_workspace_two_tenants` | 2 tenants, same workspace, 1 DB | Messages project for both tenants |
| `test_shared_db_two_tenants_different_workspaces` | 2 tenants, different workspaces, 1 DB | Zero cross-workspace event overlap |
| `test_shared_db_no_cross_tenant_leakage` | 2 tenants, shared DB | Projection table isolation |
| `test_shared_db_sync_with_external_peer` | 1 node tenant + 1 standalone peer | Node tenant syncs with external peer |
| `test_shared_db_tenant_discovery` | 2+ tenants, shared DB | `discover_local_tenants` returns correct set |
| `test_cross_tenant_dep_scoping_after_sync` | 2 tenants, shared DB, sync | Dependency blocking scoped by recorded_by |
| `test_svc_node_status` | 2 tenants | `svc_node_status` returns correct tenant list |
| `test_mdns_two_peers_discover_and_sync` | 2 standalone peers | mDNS advertise/browse/sync |
| `test_mdns_multitenant_self_filtering_and_sync` | Node with 2 tenants + external peer | Self-filtering, external peer sync |

Tests in `tests/mdns_smoke.rs`:
| Test | Verifies |
|------|----------|
| `mdns_advertise_and_browse` | Basic mDNS register/resolve round-trip |

---

## 17.8 Implementation Files

| File | Action | Phase |
|------|--------|-------|
| `src/db/migrations.rs` | Migration 26: `local_transport_creds` | 17.1 |
| `src/db/transport_creds.rs` | **New** — store/load/list/discover creds from DB | 17.1 |
| `src/db/mod.rs` | Export `transport_creds` | 17.1 |
| `src/transport/cert.rs` | Remove file I/O, keep generation + fingerprint | 17.1 |
| `src/transport/mod.rs` | Update re-exports | 17.1 |
| `src/transport_identity.rs` | Rewrite: `&Connection` instead of file paths, DB-only | 17.1 |
| `src/identity_ops.rs` | Add `bootstrap_workspace`, `create_user_invite`, `accept_user_invite`, `create_device_link_invite`, `accept_device_link` | 17.2 |
| `src/main.rs` | Update 4 cert-loading sites | 17.1 |
| `src/service.rs` | Update 4 cert-loading sites, add `svc_node_status` | 17.1, 17.4 |
| `src/sync/engine.rs` | `IngestItem` 3-tuple, `accept_loop_with_ingest`, `PeerDispatcher` | 17.3 |
| `src/node.rs` | **New** — `run_node` multi-tenant daemon | 17.4 |
| `src/discovery.rs` | **New** — mDNS per-tenant discovery | 17.5 |
| `src/lib.rs` | Export `node`, `discovery` | 17.4, 17.5 |
| `Cargo.toml` | `mdns-sd` dep + `discovery` feature | 17.5 |
| `src/testutil.rs` | `SharedDbNode`, closure-based `sync_until_converged`, `new_in_workspace`, `add_tenant_in_workspace`, leakage checks | 17.6 |
| `tests/scenario_test.rs` | Multi-tenant + mDNS scenario tests, application-level assertions | 17.7 |
| `tests/mdns_smoke.rs` | **New** — mDNS integration test | 17.7 |
| `tests/perf_test.rs` | Closure-based convergence, application-level assertions | 17.6 |
| `tests/low_mem_test.rs` | Same | 17.6 |
| `tests/sync_graph_test.rs` | Same | 17.6 |

---

## 17.9 Assistant Execution Playbook (Phase 13)

### Must implement

1. `local_transport_creds` table with store/load/list/discover operations.
2. `discover_local_tenants` query joining `trust_anchors` with `local_transport_creds`.
3. All cert operations via DB, zero filesystem cert paths.
4. `IngestItem` 3-tuple `(event_id, blob, recorded_by)` everywhere in sync engine.
5. `accept_loop_with_ingest` accepting external shared ingest channel.
6. `run_node` single shared QUIC endpoint with `WorkspaceCertResolver`, tenant-scoped routing, and shared batch writer.
7. Per-tenant dynamic trust closure from `trust_anchors`/PeerShared-derived SPKIs.
8. mDNS per-tenant advertise + browse with self-filtering.
9. `SharedDbNode` test helper using production identity flows.
10. Application-level test assertions (never `store_count`, always `message_count`/`has_event`/etc.).

### Common mistakes

- **Filesystem cert remnants**: Do not read or write `.cert.der` / `.key.der` files. All cert material lives in `local_transport_creds`.
- **Hardcoded event counts in tests**: Identity chain size may change. Test convergence with `has_event()` on specific event IDs, assert with `message_count()` / `peer_shared_count()` / etc.
- **Single-sample convergence for large syncs**: A single `has_event` sample may pass after only partial transfer. For zero-loss or high-volume tests, sample 50+ events from both sides.
- **Global neg_items**: All tenants share one `neg_items` table. A remote peer connecting to the shared endpoint (routed as tenant A) will see event IDs from all tenants during negentropy. This is acceptable for single-operator nodes.
- **DNS label overflow**: Peer IDs are 64 hex chars. Instance names must stay under 63 bytes. Truncate peer ID in instance name; use TXT property for full ID.
- **Self-discovery in mDNS**: Pass the full set of local tenant peer IDs to `TenantDiscovery::new` so it can filter them all out, not just its own.
- **Forgetting per-tenant drain**: `batch_writer` must group ingested items by `recorded_by` and drain `project_queue` per tenant. A single drain call with one `recorded_by` misses events from other tenants in the same batch.

### Definition of done

- `topo start` discovers tenants from DB, starts QUIC endpoint with multi-workspace cert resolver, syncs with external peers.
- Two tenants on same node in different workspaces have zero event overlap after sync.
- Two tenants on same node in same workspace both project synced messages.
- mDNS self-filtering prevents local-only connections; external peers discovered and synced.
- Cross-tenant leakage check passes after every multi-tenant scenario test.
- All test files use application-level convergence and assertions (no `store_count`).

---

## 18. Cheat-Proof Realism Tests (`cheat-proof-tests` branch)

Goal: establish a test suite where successful P2P bootstrap and sync cannot be faked by local process shortcuts, shared filesystem state, or manual operator dials.

### 18.1 Realism contract

1. Out-of-band input is limited to invite links (`quiet://...`) with standard bootstrap data.
2. Nodes run in non-interactive daemon mode (`topo start`) and are asserted through CLI command results (`topo assert-*`).
3. Desired steady-state connectivity is invite/discovery-driven autodial, not manual `--connect`.
4. Multi-network topologies are required (local discovery + internet bootstrap-address mode).

### 18.2 Execution strategy

1. Add executable realism contract tests under `tests/cheat_proof_realism_test.rs`.
2. Include a passing baseline that proves invite bootstrap + daemon autodial transport path works, so failures are scoped to realism gaps, not broken transport.
3. Include strict contract tests for desired behavior:
   - invite-only daemon autodial after invite acceptance,
   - daemon CLI invite lifecycle surface (`topo create-invite` / `topo accept-invite`).
4. Keep these tests as non-negotiable regression guards for future refactors.

### 18.3 Minimal implementation required to make these tests pass

1. **Placeholder** startup autodial manager in `node.rs` that consumes persisted invite/bootstrap address rows first.
   - Must be explicitly labeled in code/logs as placeholder (for example `PLACEHOLDER AUTODIAL`) so it is not mistaken for end-state design.
2. Keep daemon startup invite/discovery-driven only (manual `--connect` removed).
3. Daemon CLI parity for invite lifecycle and tenant-targeted operations (so realism tests can stay daemon-first).
   - Scope note: in this branch, daemon-first operation requires at least one local tenant.
     Fresh DB first-invite acceptance is still a pre-daemon bootstrap step.
4. For realism in this POC, a naive autodialer is the critical requirement.
   - Full peer connection management (address scoring/prioritization, lifecycle policy, and advanced dial orchestration) is explicitly out of scope for this POC.

### 18.4 Follow-on topology expansion

1. Add segmented multi-network harness (container or netns) with at least 3 networks and overlapping peers.
2. Exercise all three behaviors in one scenario:
   - multitenancy overlap,
   - local mDNS discovery on shared LAN segments,
   - invite-link bootstrap address dialing across non-LAN segments.

### 18.5 Netns-first vs containers

1. Start with netns harness for fast iteration on network realism:
   - three LAN segments,
   - routed bootstrap reachability,
   - daemon-only assertions.
2. Treat netns harness as **insufficient** for strict anti-cheat filesystem isolation:
   - netns isolates network stack, not host filesystem visibility.
3. Container phase is required for strict "no filesystem/shared-memory cheat path" guarantees:
   - one container per peer,
   - no shared writable volumes,
   - isolated IPC/PID namespaces,
   - capability drop + no-new-privileges.
4. Current branch uses netns as a stepping stone and keeps this limitation explicit.
5. Netns realism caveat observed in practice: multiple peers can share the same OS hostname, which can alias mDNS host records and mis-map peer IDs to wrong IPs.
   - Mitigation in this branch: advertise per-tenant mDNS host labels (peer-id-derived), not `/etc/hostname`.

### 18.6 UPnP note for real-life multi-user testing

1. UPnP port mapping + external IP discovery were added as a pragmatic POC feature to make real-life testing with multiple users on different home networks easier.
2. This can be considered outside strict protocol scope: protocol correctness does not depend on UPnP, and explicit `--bootstrap <host:port>` remains supported.
3. Reason for inclusion anyway: it reduces manual router/NAT setup friction during realism testing and makes invite bootstrap trials faster to run.
4. Current behavior is intentionally best-effort/manual (`topo upnp`); there is no long-running lease-refresh manager in daemon scope.
5. Expected limitation: some networks (for example CGNAT or non-UPnP routers) still require manual bootstrap endpoints even with this feature.

## 19. Event-module locality (Options 1+2+4+5)

### 19.1 Motivation

`service.rs` previously embedded event-specific SQL queries, event construction logic, and response type definitions for all event types. This scattered event-specific concerns: message SQL lived far from `MessageEvent` schema, reaction queries were disconnected from `ReactionEvent`, etc.

Similarly, projector logic for all event types lived in two central files (`projection/projectors.rs` for content events, `projection/identity.rs` for identity events) with a large match statement in `apply.rs` routing to them. This violated locality — to understand message projection you had to jump to a different module.

### 19.2 Approach (Options 1+2)

Moved event-specific command (create), query helpers, and **projector functions** into event-owned modules, making `service.rs` a thin orchestrator and `apply.rs` an orchestration-only pipeline.

**Event modules gained:**
- `CreateXxxCmd` structs — input params for creating events
- `create()` — builds `ParsedEvent`, calls `create_signed_event_sync`, returns `EventId`
- `query_list()`, `query_count()`, `resolve_by_number()`, `resolve_selector()` — SQL against projection tables
- `project_pure()` — pure projector function registered in `EventTypeMeta.projector`

**Registry-driven projector dispatch:**
- `EventTypeMeta` gained a `projector` field: `fn(&str, &str, &ParsedEvent, &ContextSnapshot) -> ProjectorResult`
- `dispatch_pure_projector` in `apply.rs` uses registry lookup — no central match statement
- Deleted: `src/projection/projectors.rs` (content event splay) and `src/projection/identity.rs` (identity event splay)

**New dispatch layer:**
- `src/event_modules/dispatch.rs` — `EventCommand` enum + `execute_command()` for typed command routing

**Shared utilities added to `src/crypto/mod.rs`:**
- `event_id_from_hex()` — parse hex event ID
- `b64_to_hex()` — base64 to hex conversion

### 19.3 Service-to-event-module locality (Option 5)

Moved response types and conn-level service functions into event modules, making service.rs orchestration-only for event domains.

**Event modules gained (Option 5):**
- Response types (`MessageItem`, `MessagesResponse`, `SendResponse`, `ReactResponse`, `ReactionItem`) — owned by event modules, re-exported by service.rs
- High-level conn-level helpers (`send_conn`, `react_conn`, `delete_message_conn`, `remove_user_conn`, `messages_conn`, `reactions_conn`) — combine event creation/query with response assembly

**Module split pattern applied:**
- `message` module converted from flat file to directory (`message/{mod,wire,commands,queries}.rs`) as the pilot for the split pattern
- Split rule: when a module exceeds ~300-400 LOC or mixes 3+ concerns, split into `wire.rs`, `commands.rs`, `queries.rs`, `projector.rs`

### 19.4 Service.rs delegation table

| service.rs function | Delegates to |
|---|---|
| `svc_send_conn` | `message::send_conn` |
| `svc_messages_conn` | `message::messages_conn` |
| `svc_react_conn` | `reaction::react_conn` |
| `svc_reactions_conn` | `reaction::reactions_conn` |
| `svc_reactions_for_message_conn` | `reaction::query_for_message` |
| `svc_delete_message_conn` | `message_deletion::delete_message_conn` |
| `svc_deleted_message_ids_conn` | `message_deletion::query_deleted_ids` |
| `svc_remove_user_conn` | `user_removed::remove_user_conn` |
| `svc_message_event_id_by_num_conn` | `message::resolve_by_number` |
| `resolve_message_selector` | `message::resolve_selector` |
| `svc_status_conn` message/reaction counts | `message::query_count` + `reaction::query_count` |
| `query_field` message/reaction counts | `message::query_count` + `reaction::query_count` |
| `svc_users_conn` | `user::query_list` |
| `svc_keys_conn` counts | `peer_shared::query_count` + `admin::query_count` + `transport_key::query_count` |
| `svc_workspaces_conn` | `workspace::query_list` |

### 19.5 What service.rs retains

- DB open/close (`open_db_load`, `open_db_for_peer`)
- Auth (key loading, `require_local_peer_signer`)
- Cross-module orchestration (`svc_view_conn` combines messages, reactions, users)
- Shared response types (`DeleteResponse`, `StatusResponse`, `ViewResponse`, etc.)
- Identity bootstrap, invite flows, predicate/assert system
- Service-level helpers (`current_timestamp_ms`, `parse_workspace_hex`)

### 19.5 What apply.rs retains (orchestration-only)

- Dependency presence check + block row writes
- Dependency type enforcement
- Signer verification (uniform, not event-type-specific)
- Context snapshot construction
- Registry-driven projector dispatch
- Write-op execution and emit-command handling
- **No event-type-specific projection logic** — that lives in event modules

### 19.6 Boundary rules (normative)

1. Event-specific commands, queries, response types, and projectors belong in event modules.
2. `service.rs` is orchestration glue: DB context, auth, cross-module joins, error mapping.
3. `apply.rs` is pipeline orchestration: dependency checks, signer verification, registry dispatch.
4. Long event modules must split into `wire/commands/queries` structure (see DESIGN §14.3).
5. Wire layout constants (wire sizes, offsets) are owned by the event module — not in a global monolith. Shared cross-event primitives live in `src/event_modules/layout/common.rs` (see DESIGN §14.4).
