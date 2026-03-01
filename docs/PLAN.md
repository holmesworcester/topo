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
- Phase 13 depends on Phase 12 identity flows (`create_workspace`, `join_workspace_as_new_user`, `add_device_to_workspace`) being stable.

## 1.1 Historical gap audit note

The earlier `codex-simplified` gap audit served bootstrapping and is now historical.
For active work:
- use this PLAN for build order, scope cuts, and phase exit criteria,
- use [DESIGN.md](./DESIGN.md) for normative behavior and invariants,
- use git history/PR notes for resolved-gap chronology.

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
11. Identity pre-derive.
   - `create_workspace`, `accept_invite`, and `accept_device_link` pre-derive the PeerShared key and write events under the final `recorded_by` from first write — no `finalize_identity`.
   - invite acceptance / device link may install invite-derived bootstrap transport certs first, but tenant scope key remains final and projection later installs PeerShared-derived transport identity.
   - connect loop resolves identity once per QUIC connection, not per session (identity transitions only happen during discrete CLI commands).
   - `create_workspace` is strictly tenant-scoped once local creds exist: `recorded_by` must match a known local tenant peer ID in `local_transport_creds`; unscoped aliases are rejected. Fresh DB bootstrap (no local creds) remains allowed.
12. Transport fingerprint bridge.
   - `peer_shared` projection materializes deterministic `peers_shared.transport_fingerprint` and indexes `(recorded_by, transport_fingerprint)`.
   - trust/removal lookup paths use projected `transport_fingerprint` rows and do not fallback to runtime scan+derive over `peers_shared.public_key`.

## 2.2 CLI Architecture Principle

Every CLI instance is a real peer-to-peer device. All user-facing commands go through daemon RPC to the service layer:

1. **One service layer**: business logic lives in event modules (`src/event_modules/`) for event-specific concerns and `src/runtime/control/service.rs` for orchestration. CLI subcommands are thin UI adapters that call daemon RPC, which dispatches to service functions.
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
- `start`, `send`, `messages`, `status`, `generate` CLI commands work.
- `assert-now` and `assert-eventually` commands enable deterministic scripting.
- CLI integration tests use assert commands (no ad-hoc wait helpers).
- JSON output is not required; human-readable output is sufficient.

### Required RPC and selector contract

Phase 1 CLI/daemon shape must preserve:

1. versioned request/response envelopes and bounded frame size (`<= 16 MiB`) over length-prefixed JSON RPC framing,
2. bounded concurrent RPC connection handling in daemon,
3. selector-registry behavior (`~/.topo/db_registry.json` / `TOPO_REGISTRY_DIR`) with resolution order:
   - existing path -> alias -> numeric index -> passthrough path.

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

## 4.1 Transport status and source of truth

Phase 2 transport hardening is implemented and should be maintained as strict mTLS + QUIC with pinned peer identity checks.

Normative transport requirements now live in [DESIGN.md](./DESIGN.md):
- transport/auth model: §2.1-§2.5,
- trust-source lifecycle: §9.5,
- multitenant runtime integration: §3.2.1-§3.2.3.

## 4.2 Implementation focus for ongoing work

When touching transport in future phases:
1. preserve strict pinning and reject-any-untrusted behavior on both client and server,
2. keep transport trust SQL-backed and projection-owned (no ad-hoc authority path),
3. keep session identity mapping explicit (`recorded_by`, `via_peer_id`),
4. keep cert/key materialization behind the established transport-identity contract boundary.

### Sync session completion protocol (required)

Sync sessions use explicit completion frames and must not rely on stream-close timing:

1. `Done` (initiator control stream) means initiator is outbound-complete for the round.
2. `DataDone` (data stream, either direction) means no more data frames from that sender.
3. `DoneAck` (responder control stream) is sent only after responder drain and both `DataDone` observations.

Initiator completion is `DoneAck`-gated.

## 4.3 Transport regression checklist

For any transport-affecting PR, require:
1. positive/negative handshake tests,
2. reconnect/retry tests across daemon restarts,
3. removal-policy tests (new handshakes denied; active sessions torn down).

## 4.4 Anti-regression constraints

- No permissive verifier in production paths.
- No socket-address-based trust decisions.
- No separate transport identity authority outside projected trust state.

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
- It uses the active transport trust policy from [DESIGN.md](./DESIGN.md) §2.1-§2.2 and does not introduce a parallel trust path.
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

Frame safety bounds (required):
- enforce a global max frame payload length before allocation/decode,
- enforce per-frame-type max lengths,
- reject any frame where declared `payload_len` exceeds either bound.

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
    source TEXT NOT NULL,              -- local_create | emitted | import | quic_recv:<peer_id>@<ip:port>
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
1. Schema creation uses deterministic owner `ensure_schema(conn)` calls (no migration history playback in this POC).
2. Core tables are created by core owner modules (`state/db/*`); event projection tables are created by event-module owner `ensure_schema` functions.
3. Startup runs deterministic schema bootstrap plus registry/schema consistency checks and fails fast on mismatch.
4. Prototype schema epoch is explicit (`schema_epoch`) and checked at startup.
5. No backward compatibility is provided across prototype epochs: if an old DB is detected (legacy `schema_migrations` without current epoch marker), startup fails with a clear "recreate DB" error.

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
    RetryWorkspaceEvent { workspace_id },
    RetryFileSliceGuards { file_id },
    RecordFileSliceGuardBlock { file_id, event_id },
    WritePendingBootstrapTrust { invite_event_id, workspace_id, expected_bootstrap_spki_fingerprint },
    WriteAcceptedBootstrapTrust { invite_accepted_event_id, invite_event_id, workspace_id, bootstrap_addr, bootstrap_spki_fingerprint },
    SupersedeBootstrapTrust { peer_shared_public_key },
}
```

Entry-point requirement:
- `local_create`, `wire_receive`, `replay`, and unblock retries must all invoke `project_one`.
- no alternate projection code paths for specific ingestion sources.
- Internal cascade optimization: `project_one_step` (the 7-step algorithm without cascade) is used by the Kahn cascade worklist to avoid redundant recursive cascade. `apply_projection` executes `emit_commands` (which handles guard retries), so the cascade only manages Kahn dependency unblocking. All projection stages are shared; the split is a performance optimization, not an alternate path.

Apply engine execution stages:
1. Pipeline resolves `EventTypeMeta` and calls the event-module-owned `context_loader(conn, recorded_by, event_id_b64, parsed)` to build `ContextSnapshot`.
2. Pipeline calls pure projector → receives `ProjectorResult`.
3. Pipeline executes `write_ops` transactionally (only on Valid/AlreadyProcessed).
4. Pipeline executes `emit_commands` via explicit handlers (only on Valid).
5. Pipeline handles guard-block commands on Block decisions (e.g., file_slice guard blocks).

DRY split (required):
- Shared projection pipeline code owns:
  1. canonical event load/decode dispatch,
  2. dependency extraction + missing-dependency block writes,
  3. signer resolution + signature verification ordering (Phase 6),
  4. orchestrating context loading via `EventTypeMeta.context_loader` (no projector-specific SQL in pipeline files),
  5. executing `write_ops` and `emit_commands`,
  6. terminal state writes (`valid`/`block`/`reject`) + queue transitions.
- Per-event projector code owns only:
  1. event-specific predicate/policy checks,
  2. returning `ProjectorResult` with deterministic `write_ops` and `emit_commands`.
- Event modules own projector-specific SQL context queries through module-local context loaders (`queries.rs` or projector-local helpers).
- Per-event projector functions (`project_pure`) must not access the database, implement their own dependency walker, signer verifier, queue handling, or terminal-state writer.

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
- identity-specific exceptions (`invite_accepted` trust-anchor binding via `RetryWorkspaceEvent { workspace_id }` command, removal enforcement, bootstrap trust materialization via `WritePendingBootstrapTrust`/`WriteAcceptedBootstrapTrust` commands, supersession via `SupersedeBootstrapTrust` command) implemented via EmitCommand handlers.

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
- `create_event_synchronous(...) -> event_id`
- `create_events_batch(events, project_now: bool) -> Vec<EventId>`

`create_event_synchronous` should inline projection until terminal (`valid`, `blocked`, or `rejected`) so command chains can immediately use prior event ids.

Imperative orchestration contract (poc-6 style ergonomics):
- default `create_event_synchronous` must return success only when the created event is `valid` for `recorded_by`.
- if terminal state is `blocked` or `rejected`, return an error containing `event_id` + terminal reason.
- this guarantees call-site sequencing:
  - `a = create_event_synchronous(...)`
  - `b = create_event_synchronous(depends_on=a, ...)`

Implementation note:
- even synchronous create uses the same internal pipeline:
  - `persist_and_enqueue` -> `project_one` loop (same code as worker mode)
- do not add a separate "local fast-path" projector.

### Two-API design decision (investigated and confirmed)

The codebase provides two create-and-project entry points reflecting distinct caller needs:

1. **`create_event_synchronous`** (strict, PLAN-normative): returns `Ok(event_id)` only when projection reaches `Valid` or `AlreadyProcessed`. Returns `Err(Blocked { event_id, missing })` or `Err(Rejected { event_id, reason })` otherwise. All user-facing service commands (`svc_send`, `svc_react`, `svc_delete_message`, `svc_generate`) use this API.

2. **`create_event_staged`** (lenient, bootstrap-only): wraps `Blocked` errors into `Ok(event_id)` via `event_id_or_blocked`. Used in identity bootstrap command paths (for example `create_workspace`, `join_workspace_as_new_user`, `add_device_to_workspace`) where events like `Workspace` can be created before their trust-anchor dependency exists and are expected to block until the anchor arrives.

This split is intentional and correct: it preserves the strict contract for user-facing orchestration while allowing bootstrap chains to store pre-dependency events without aborting.

Test index for this contract:
- `test_create_signed_event_synchronous_returns_blocked_error` — strict API blocked→Err
- `test_create_signed_event_staged_returns_ok_on_blocked` — staged API blocked→Ok
- `test_create_reaction_before_target` — blocked event DB state
- `test_react_errors_on_blocked` — service layer propagation
- `test_delete_of_missing_target_writes_intent` — service-layer delete behavior
- `test_send_succeeds_on_valid` — valid→Ok
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

### 10.0 Profiling-first tail regression workflow

When investigating sync performance degradation at high cardinality (e.g. 500k+ events):

1. **Baseline capture**: run serial perf suite (`scripts/run_perf_serial.sh core`) and the target tail benchmark in isolation with `--test-threads=1`. Record wall time, msgs/s, peak RSS, and environment details (filesystem type, hardware).
2. **Tail profiling**: add per-batch timing instrumentation to `batch_writer` (persist_ms, commit+effects_ms, epoch_10k_ms via `WRITER_PROFILE` log lines). Identify whether tail slowdown is writer-side (persist/drain) or protocol-side (negentropy reconciliation stalls causing data starvation).
3. **Root-cause ranking**: rank bottlenecks by measured contribution. Common patterns:
   - Negentropy round latency scaling super-linearly with item count (protocol-level, deep fix).
   - Autocommit overhead in projection drain (transaction batching fix).
   - SQLite page cache pressure when dataset exceeds `cache_size` (tuning knob).
4. **Fix one bottleneck**: apply only the top-ranked implementable fix. Verify no regression on core suite before measuring tail improvement.
5. **Evidence artifact**: document baseline, profiling data, root-cause ranking, fix rationale, and post-fix comparison in `docs/planning/` for auditability.

Operational constraint: serial perf measurements (`--test-threads=1`) must be used for tail profiling to avoid cross-test interference. Stale test processes (e.g. from timed-out `sync_graph_test`) must be killed before re-running, as they hold tmpfs resources and cause spurious failures.

### 10.0.1 Implemented: batch dequeue + deferred WAL checkpoint

The projection drain path (`drain_project_queue_on_connection` + `drain_with_limit`) applies two optimizations to reduce per-batch overhead:

1. **Batch dequeue**: `drain_with_limit` collects successfully-projected event IDs and dequeues them via `mark_done_batch` (one `BEGIN`/`COMMIT` per claim cycle) instead of individual `mark_done` DELETEs per event. Reduces ~1000 autocommit DELETEs per writer batch to ~10 batch transactions.

2. **Deferred WAL checkpoint**: `drain_project_queue_on_connection` sets `PRAGMA wal_autocheckpoint = 0` during the drain, restoring to 1000 after. This prevents WAL checkpoint stalls between autocommit projection writes.

- Projection writes remain autocommit (each `project_one` call commits independently), preserving cascade-unblock correctness.
- On projection failure, events are retried with exponential backoff via `mark_retry`.
- Crash safety: `project_queue` provides recovery; interrupted drains leave events in the queue for re-projection.
- Operational note: WAL grows during drain proportional to pending event count. Disk space must accommodate this. The next persist-phase COMMIT triggers a checkpoint that processes accumulated WAL pages.

Profiling evidence: 500k one-way sync improved from 170.93s (2,925 msgs/s) to 106.75s (4,684 msgs/s) — 37.5% wall time reduction, 60% throughput improvement. Core suite (10k, 50k) showed no regressions.

Note: wrapping all projection writes in a single transaction was attempted first but abandoned — it caused ~0.06% of events to be left unprojected at 500k scale due to cascade_unblocked bulk cleanup interacting with the transaction scope.

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
3. **Coordinator thread for pull rebalancing.** After negentropy reconciliation, each peer
   reports its discovered need_ids to a coordinator that assigns each event to the
   least-loaded peer that has it (greedy load balancing, unique-events-first ordering).
   For single-peer, the coordinator is pass-through (all events already streamed).
4. **Push uncoordinated, pull streams then coordinates.** Have_ids (outbound) stream
   immediately. Need_ids (inbound) are dispatched as HaveList during reconciliation
   rounds (streaming pull — events flow immediately) AND reported to the coordinator
   after reconciliation for multi-peer rebalancing. The `wanted` table deduplicates.
   **Do not defer HaveList until after reconciliation** — this creates a pipeline stall
   that serializes ~1s of overhead on the critical path.
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
- **Family C (multi-source large-file):** all non-sink sources seeded with identical
  file-slice sets; sink asserts exact file-slice ID set and substantial per-source
  ingest share from `recorded_events.source` attribution.

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
- accepted invite links produce bootstrap transport trust tuples in SQL via projection:
  - service layer writes local `bootstrap_context` rows (inviter address + SPKI fingerprint from invite link),
  - invite projectors read `bootstrap_context` and emit `WritePendingBootstrapTrust` / `WriteAcceptedBootstrapTrust` commands,
  - trust rows are looked up by sync on each connection/handshake (no in-memory-only trust authority).
  - this follows the same poc-6 cascade pattern where `invite_accepted` projection drives trust-anchor establishment and workspace event unblocking.

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

Use the sender-subjective O(n) baseline ("maximally simple phase-1/phase-4 style key broadcast"):
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

- Keep model alignment with `docs/tla/EventGraphSchema.tla` (including `event_graph_schema_bootstrap.cfg`), `docs/tla/TransportCredentialLifecycle.tla`, and `docs/tla/UnifiedBridge.tla`.
- Treat `BootstrapGraph.tla` as retired/deleted in this epoch; do not add new checks there.
- Extend/adjust model events for split invites (`user_invite`, `device_invite`).
- For each identity-phase projector, include a referenced guard list in comments/docs.
- Treat divergence between projector logic and TLA guards as a spec bug that must be resolved before adding behavior.

### Conformance gating (CI-enforced)

Four CI gate scripts enforce bidirectional coverage between TLA+ guards and runtime checks:

1. **`scripts/check_projector_tla_conformance.py`** — every `spec_id` in the conformance matrix has at least one linked test; guard-level `spec_id`s have both pass and break polarity; every `check_id` exists in the catalog; every `spec_id` maps to at least one `check_id`.
2. **`scripts/check_projector_tla_bijection.py`** — every TLA guard in `projector_spec.md` maps to at least one `check_id` in the runtime check catalog; every `check_id` maps to a `tla_guard_id` or explicit `NON_MODELED::` waiver; every `check_id` has at least one linked test row.
3. **`scripts/check_bridge_conformance.py`** — every `CHK_BRIDGE_*` check in the runtime catalog has non-waiver pass coverage and (except liveness checks) non-waiver break coverage; disallows bridge regressions to TLC-only waivers.
4. **`scripts/check_tcl_conformance.py`** — every `CHK_TCL_*` check in the runtime catalog has non-waiver pass+break coverage and disallows TCL regressions to integration-effect-only waivers.

Artifacts: `docs/tla/runtime_check_catalog.md` (check_id → guard mapping), `docs/tla/projector_conformance_matrix.md` (spec_id → check_id → test_id with polarity). Waivers (`NON_MODELED::`) require inline rationale and are reviewed as spec debt.

## 11.8 TLA transport-credential and bridge layers (gaps closed)

**Status:** Closed. `docs/tla/TransportCredentialLifecycle.tla` models the runtime transport credential/trust-store layer, and `docs/tla/UnifiedBridge.tla` models the cross-layer trust-to-connection invariants and progress properties.

Previous gap: TLA models were identity/event-causality models that did not encode mTLS credential lifecycle (SPKI generation/rotation/revocation, projected trust-set state transitions).

**What is now modeled** (TransportCredentialLifecycle.tla):
- Local credential lifecycle: single credential per peer (no rotation/revocation in POC).
- Three-source trust store: PeerShared-derived SPKIs, invite_bootstrap_trust, pending_invite_bootstrap_trust.
- PeerShared trust source is represented as projected `peers_shared.transport_fingerprint` values (indexed by `(recorded_by, transport_fingerprint)`), matching runtime lookup shape.
- Supersession: PeerShared projector emits `SupersedeBootstrapTrust` command at projection time, which removes matching bootstrap/pending entries. Trust check reads are pure (no write side-effects).
- TTL expiry of bootstrap trust sources.
- Trust removal (peer_removed cascading, user_removed transitive denial via `peers_shared.user_event_id`).
- Invite ownership: `inviteCreator` variable tracks which peer created each invite SPKI. The `CreateInvite` action establishes ownership; `AddPendingBootstrapTrust` is guarded by `inviteCreator[s] = p` so only the invite creator can materialize pending trust.
- 7 invariants verified by TLC (11.5M states, 771K distinct at 2-peer/3-SPKI), mapped to Rust checks in `docs/tla/projector_spec.md`. The `InvPendingTrustOnlyOnInviter` invariant catches the joiner-side pending trust emission bug (verified: buggy model violates in 5 steps).

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
- `create_event_synchronous` chaining works for imperative orchestration:
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

## 15. Assistant Execution Playbook (Condensed)

Use this section as an execution-process checklist only.
Normative protocol/runtime behavior is defined in [DESIGN.md](./DESIGN.md).

## 15.1 Cross-phase execution rules

1. Build in the phase order from §1 unless explicitly overridden.
2. Treat phase exit criteria in this PLAN as release gates.
3. Use DESIGN as the normative source for protocol semantics and invariants.
4. Keep one projection path, one dependency engine, one signer pipeline, and tenant-scoped shared tables (see DESIGN §4-§5, §14).
5. For transport work, preserve strict mTLS and SQL-backed trust evaluation (see DESIGN §2, §9.5).

## 15.2 PR slicing guidance

Recommended sequence:
1. transport-only changes,
2. schema/wire changes,
3. projection and dependency changes,
4. signer substrate,
5. encrypted adapter,
6. queue/worker changes,
7. identity/TLA changes.

Rule:
- each PR must include failing tests made to pass by that PR.

## 15.3 Required evidence for phase completion

1. tests cover the new behavior and key regressions,
2. replay/reorder/reproject invariants still pass,
3. tenant-isolation checks still pass,
4. DESIGN references are updated if semantics change.

---

## 16. NAT Traversal and Hole Punch (Transport Extension)

Normative NAT/hole-punch behavior is defined in [DESIGN.md](./DESIGN.md) §2.4.
This PLAN keeps only execution-level expectations:

1. keep intro/hole-punch runtime-only (non-canonical),
2. keep explicit one-shot intro API and no hidden auto-pair scheduler in core runtime,
3. keep endpoint observation TTL + cleanup behavior,
4. preserve coverage with integration + netns NAT tests.

---

## 17. Phase 13: Functional Multitenancy

### Status: COMPLETE

One node can host N tenant identities in one DB with one shared QUIC endpoint and tenant-scoped routing/trust.
Detailed architecture and invariants are documented in [DESIGN.md](./DESIGN.md) §3.2.1-§3.2.3, §2.5, §8, and §14.

## 17.1 Completed outcomes

1. transport credentials are DB-resident and tenant-discoverable,
2. runtime supports shared endpoint + tenant routing + dynamic trust checks,
3. shared ingest/batch writer supports tenant-tagged ingest items,
4. mDNS supports per-tenant discovery with self-filtering.

## 17.2 Ongoing regression guards

1. no filesystem cert authority regression,
2. no cross-tenant projection/query leakage regression,
3. no reintroduction of event-count-based convergence assertions,
4. no bypass of workspace command ownership boundaries.

## 17.3 Validation suite expectations

1. multi-tenant shared-DB scenario coverage,
2. mDNS/discovery smoke coverage,
3. cross-tenant leakage checks in scenario tests,
4. application-level convergence/assertion style in tests.

## 17.4 Same-host loopback normalization rule

1. loopback-bound daemons may advertise non-loopback IPs for mDNS reachability,
2. browse-side must normalize discovered non-loopback addresses back to loopback when local daemon is loopback-bound,
3. advertised IP must be explicit runtime input, not inferred implicitly by discovery internals.

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

UPnP response contract:
1. `topo upnp` reports status `success | failed | not_attempted`,
2. output includes mapped external port/IP plus optional gateway/error fields,
3. loopback-bound listeners return `not_attempted`,
4. when mapping succeeds but external IP is not publicly routable, report `double_nat = true` and warn.

## 19. Event-module locality

Normative locality/layering rules are defined in [DESIGN.md](./DESIGN.md) §14.
Plan-level enforcement remains:

1. event-type-specific commands/queries/projectors stay in event modules,
2. `src/runtime/control/service.rs` remains orchestration-only,
3. projection pipeline remains orchestration-only,
4. module boundary checks stay automated in CI where available.
