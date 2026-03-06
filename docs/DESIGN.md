# Topo Protocol Design (Post-PLAN End State)

> **Status: Active** — Topo target protocol design describing the post-PLAN end state.

Topo is a draft protocol design for building full-featured local-first, peer-to-peer, end-to-end encrypted communication and collaboration tools.

This draft design focuses on the minimal necessary feature set to prove the protocol's suitability for building a viable secure replacement for Slack.

Terminology note:
`Topo` is the project and runtime name used throughout this repository.
`workspace` is the term for the logical peer set and shared protocol context; "network" refers only to transport/networking concerns.

## Requirements

1. **Encryption & Auth** - it should be straightforward to implement and validate modern, scalable, high-usability group encryption schemes with user removal (DCKGA, TreeKEM, etc.) from the ground up, so they can be tailored to product needs
1. **Deletion & Disappearing Messages** - deletion and disappearing messages should be straightforward (lots of p2p and local-first protocols make deletion hard 🤦)
1. **P2P Networking** - peer discovery, STUN-like connection across NATs, and TURN-like relay should be straightforward without additional dependencies, and adaptable to product needs
1. **Files** - multi-source file downloads (for images and attachments) should be performant (network-bound) and flexible
1. **Performance** - workspace state (messages, etc.) and files should sync quickly, up to 10GB of messages and attachments (we assume groups are using some global retention limit for security and that each workspace's data is bounded, or that users will resort to cloud hosting for long-term storage)
1. **Multi-tenancy** - It should be trivial to support many workspaces in the main client, join the same workspaces with multiple accounts in the same client, or host thousands of workspaces in a cloud node
1. **Cloud / Client Isomorphism** - Cloud nodes should not require a separate implementation.
1. **NSE / Client Isomorphism** - iOS background notification fetch (memory-constrained) should not require a separate implementation, so it should run in less than 24MB of RAM as required by iOS Notification Service Extensions (NSE's). 
1. **Local networking** - The protocol should be capable of zeroconf discovering and networking over LANs.
1. **Testing & Simulation** - It should be trivial to test interactions between multiple accounts on the same machine, with a toy interface that mimics the requirements of a production Slack Electron or React Native app, and to test robustness against concurrency and reordering. It should also be low-cost for an LLM to "self-QA" its work.
1. **Ergonomic Feature Development** - once complex features like auth, deletion, encryption, and forward secrecy are in place, it should be possible to build user-facing, Slack-like features (reactions, channels, threads, user profiles, etc.) with minimal friction
1. **Boring API for Frontends** - the backend should fully contain the complexity of the p2p stack and provide a boring API that keeps frontend development highly conventional (e.g., letting frontends fetch a paginated message list with attachments, reactions, usernames, and avatars should be easy)

## Motivation

A p2p, FOSS Slack alternative would be huge for user privacy, freedom of expression, and online community resilience / independence. But building one is too hard. We know because we've been trying (see: [Quiet](https://tryquiet.org)).

We think there is a simpler way, one that doesn't:

* lock developers into unrealistically-limited feature sets 
* require they assemble a bricolage of bleeding-edge tools like libp2p, Automerge, MLS, etc.
* handle some of the p2p parts but leave developers on their own for middleware, notifications, etc.
* lead to a nightmare of hard-to-reason-about concurrency problems

This PoC exists to prove the practicality of a principled approach that uses [event sourcing](https://martinfowler.com/eaaDev/EventSourcing.html), [range-based set reconciliation](https://aljoscha-meyer.de/assets/landing/rbsr.pdf),  [topological sort](https://en.wikipedia.org/wiki/Topological_sorting), and [materialization](https://en.wikipedia.org/wiki/Materialized_view) or "projection" of p2p-synced, decrypted events into SQLite tables that can be easily queried by an API.

### What it seeks to prove practical

* **SQLite for everything** - You can simplify state management by using SQLite for everything, even file slices, for GBs of messages/files.
* **Everything can be an event** - You can model all data, even file slices, as events, encrypt them, and store them all in SQLite.
* **DAG for auth, invites, multi-device, historical key provision** - Complex relationships such as team auth, admin promotion, multi-use Signal-like invite links, signed events, multi-device support, and group key agreement with removal and history-provision can be modeled as events that depend on prior events. (MLS-like TreeKEM schemes can be too, as a complexity-costly enhancement if needed.)
* **Negentropy sync is fast enough for everything** - You can use range-based set reconcilation ("Negentropy") for syncing all events, whether files, messages, auth, whatever. Large event sets sync fast enough. File downloads are likely network-bound, not IO or CPU-bound.
* **Topological sort makes order not matter** - We can receive data in any order we want because topological sort over large amounts of SQLite events is fast enough that we can block events with missing dependencies and unblock events when their dependencies come in. 
* **Dependency and blocking can fit product needs** - The dependency graph can be whatever it needs to, to fit features like "don't display messages until you know their username" or "display messages immediately with a placeholder username". Dependency is **NOT** hard-wired into the syncing protocol or document store, as with OrtbitDB or Automerge.
* **Complex, secure deletion** - It is straightforward to reliably implement things like "delete this message, its attachments, and reactions" or the kind of key purging you'd need for data-layer forward secrecy. 
* **It works in an iOS NSE** - At least, it works on Linux under the same 24MB memory limit imposed by iOS on background-wakeup Notification Service Extensions. TODO: real proof on iOS.
* **We can use conventional networking primitives** - We can control standard QUIC libraries (e.g. quinn in Rust) sufficiently to initiate mTLS sessions based on peer identity established by our event graph, and route to different workspaces on the same endpoint. We can even do mDNS local discovery and holepunching!
* **No separate STUN/TURN required** - If we need to for product reasons (unclear still, as it may make more sense to rely on cloud nodes or user-community-furnished high availability non-NAT nodes) we can holepunch by aiming QUIC attempts at each other after an in-band introduction signal from a mutually available peer, as opposed to using separate protocols/infra for ICE/STUN/TURN.
* **Multitenancy can be built-in** - We can use event sourcing and workspace differentiation via mTLS to make multitenancy a first-class thing, serve many Slack-like workspaces at the same cloud endpoint, and offer multi-account UIs out-of-the-box. Tenant creation and removal is event-based and deterministic like everything else.
* **Regular (fixed-length) wire formats** - [Langsec](https://langsec.org/) counsels that parsers can be made much more secure when data type complexity is limited, with regular (fixed-length-field) wire formats being the most tractable for secure parsing and formal verification. We keep our wire formats fixed-length.
* **Keys can just be dependencies** - There are no special queues for events with missing signer or decryption keys: these are just declared dependencies (key material is stored in events with id's) and block/unblock accordingly.
* **Canonical event naming** - For local/shared pairs, use `*_secret` / `*_shared` names (`peer_secret`/`peer_shared`, `invite_secret` + invite shared events, `key_secret`/`key_shared`). Avoid ad-hoc aliases.
* **Project-to-own-table rule** - Event projectors write to their own event table. They may read dependency-event tables as projection context, but cross-event side effects must flow through emitted events (or explicit runtime intents), not direct ad-hoc writes into other event tables. (Operational non-event tables, such as bootstrap trust bridges, are separate.)
* **Realistic testing** - We can run realistic tests locally with deterministic simulation of the event pipeline. Tests can check that for all relevant scenarios, reverse or adversarial reorderings of events and duplicated event replays all will yield the same state.

## Design Goal

The design goal is to keep protocol behavior auditable while still supporting real-time chat behavior and agent-friendly automation:

1. canonical data stays event-sourced and replayable,
2. transport and sync are real (QUIC + mTLS), not simulator paths,
3. projection logic is deterministic and convergent,
4. CLI workflows remain synchronous enough for imperative command chains.

## How it Works (Narrative Overview)

### Daemon Start

Every participant begins by starting a daemon (`topo ... start`) with a local database and bind address. That daemon owns the long-running machinery: projection workers, dial/accept peering loops, and sync session handling. Every step that follows is processed by the same runtime process.

### Workspace Creation And First User Creation

A workspace creator starts from an empty store. The create workspace command emits the initial auth event graph (`workspace`, bootstrap `user_invite_shared`, `invite_accepted`, `user`, `peer_invite_shared`, `peer_shared`) plus local signer/key material. Tenant identity (`recorded_by`) is pre-derived from the final PeerShared identity before writes begin, so bootstrap rows are already in the same scope used later for normal operation. (There is no "temporary tenant identity" that must be migrated later.)

### Creation And Projection Share One Path

Local event creation is synchronous at the command boundary, and every event still goes through the same projection pipeline used for replay and wire ingest. So even during initial setup, events are validated, dependency-checked, signer-checked, and materialized by the same projector logic used everywhere else. Their event id is returned to the caller once projected, which is useful for chaining commands. If a dependency is missing, the event blocks; when the dependency appears, the same unblock cascade continues projection. Exceptions to this flow (especially in initial workspace bootstrap or user joining) are highly discouraged.

### Inviting And Joining

After workspace creation, an admin creates a `user_invite_shared` event (which is synced to all existing members, if any) and shares invite data. The joiner accepts via `invite_accepted` and writes the follow-on identity chain (including a signed proof of invitation which all existing members can verify) for that joiner's user/device/peer identity. Normal sync brings missing canonical events, and the blocked rows unblock through the same dependency mechanism. If join prerequisites (such as prior auth events) are not yet present locally, the join path does not fork into ad-hoc recovery logic.

### Auth Event Graph Drives Join-Window Connection Policy

To avoid a chicken/egg problem, peers need to establish sessions before full steady-state PeerShared trust is present. The design handles this with projection-owned bootstrap trust rows fed by invite bootstrap context. Concretely: `invite_accepted` projection does write accepted bootstrap trust (`invite_bootstrap_trust`) when bootstrap context is present and that SPKI is not already superseded by projected PeerShared trust; inviter-side pending bootstrap trust (`pending_invite_bootstrap_trust`) is written by `user_invite_shared`/`peer_invite_shared` projectors on local invite creation. This lets first-contact handshakes happen under strict control of the auth event graph and tenant-scoped trust checks, rather than ad-hoc transport exceptions. Then, once `peer_shared` is projected, matching bootstrap trust is deterministically consumed and removed, and ongoing peering decisions remain on steady-state trust only, based on device/peer public keys, not invite public keys.

### Device Linking Uses The Same Story

Linking a second device follows the invite pattern with `peer_invite_shared` and acceptance, but extends an existing user instead of creating a new one. The runtime behavior is intentionally isomorphic to user join: bootstrap trust can bridge first contact, sync fills any missing canonical history, and PeerShared-derived trust becomes the long-term authority. Because this reuses the same event/projection/sync loop, multi-device behavior does not require a separate architecture: every subsequent device is recorded and validated in the same way as the first device.

### Peer Discovery Provides Candidates, Not Authority

Local networking uses mDNS/DNS-SD to discover candidate endpoints per tenant. Those advertisements are treated as unauthenticated hints. They can influence "who to try dialing" but never "who is trusted." Actual authority remains event-sourced and projection-backed: after QUIC+mTLS handshake identifies the remote transport identity, tenant trust checks decide whether the session is allowed to proceed. We rely on a `public-addr` CLI parameter to discover remote peers; in production we expect always-on cloud or non-NAT nodes to be the discoverable peers.

### Connection Establishment And Endpoint Behavior

Transport runs over QUIC with mTLS, while canonical event authenticity comes from event signatures and dependency validation. We intentionally force cloud-style multitenancy into the core runtime model: one daemon, one UDP port, many local tenants, each with its own workspace binding and trust state. That same mechanism is what enables a Slack/Discord-like local client to host many accounts/workspaces without spinning up one endpoint per account.

At daemon startup, local tenants are discovered from event-projected identity/trust state plus local transport creds. The runtime then builds a single endpoint with a workspace-aware cert resolver: inbound handshakes use SNI derived from `workspace_id`, and the resolver selects a cert from the local tenant set for that workspace. Outbound dials use tenant-specific client configs, so each local tenant still presents its own transport identity when it initiates sessions.

Handshake admission is union-based and tenant-scoped at the same time. The endpoint allows an incoming peer only if that peer fingerprint is trusted by at least one local tenant (`is_peer_allowed` over PeerShared trust plus bootstrap trust sources). After handshake, the runtime resolves a concrete `recorded_by` tenant for the connection and routes ingest/session processing under that tenant scope. This is the key boundary: one shared socket and one shared accept loop, but tenant-specific trust checks, routing, projection, and query visibility.

This also covers the hard case where multiple local identities on the same endpoint belong to the same workspace. Tenant trust sets may overlap in value, so the same remote peer can be valid for more than one local tenant. A given accepted connection is routed to one tenant scope, but the shared endpoint can concurrently host sessions for many tenant scopes, including multiple identities in the same workspace, without collapsing their state into one identity.

### Sync And Convergence

Once connected, peers reconcile their events over a set reconciliation algorithm that guarantees all peers will eventually have the same event set and (due to deterministic projection of events) the same convergent state for all shared data. Control and data are sent on separate QUIC streams for simplicity and reliability. Data streams carry events; control streams carry completion semantics (`Done`, `DataDone`, `DoneAck`) so each side can tell exactly when a round is complete. 

Negentropy reconciliation exchanges compact set summaries (`NegOpen`/`NegMsg`) over workspace-scoped, time-based `(ts, event_id)` membership and yields `need_ids` without walking the dependency graph directly. Unlike sync algorithms used by OrbitDB, Git, etc., it is important for our design to chose one that does not care about the shape of our data and is ideal for event sets that are always growing. In this way, set reconcilation / syncing can be decoupled from the content of events.

We use the Rust [`negentropy` library](https://crates.io/crates/negentropy) (`negentropy = "0.5"` in this repo), and this is the concrete engine behind our range-based set reconciliation approach ([Aljoscha Meyer, "Range-Based Set Reconciliation"](https://aljoscha-meyer.de/assets/landing/rbsr.pdf)). We modified our Negentropy integration to use a SQLite-backed store (`neg_items` + per-session `session_blocks`) instead of unbounded in-memory item sets, so reconciliation remains memory-bounded at large history sizes. (This is important for doing background sync in a memory-limited context on iOS). 

We also modified the session flow for multi-source catchup: each source runs Negentropy independently, `need_ids` are deterministically split with fallback reassignment for source-unique/small sets, and all sources feed one shared batch writer to avoid duplicate pull storms and SQLite write contention. Inbound events are ingested through the same `project_one` path used by local creation and replay, which is why the system can enforce one convergence contract across source types: `local_create`, `wire_receive`, and replay all converge to the same projected state.

### Steady-State Repeats The Same Loop

After creation/join/linking settles, day-to-day behavior is not a new phase. Peers create events, project them, discover targets, connect where policy allows, reconcile missing sets, and project incoming events. This is how the design gets both operational flexibility (local discovery, hole punch, multi-tenant endpoints) and strict correctness properties (deterministic projection, replay/reorder invariance, auth-gated connectivity) without maintaining multiple competing lifecycles and incurring the resulting state explosion.

### Frontend Ergonomic API

Our daemon provides a placeholder RPC API that is capable of serving whatever queries are desired, and accepting commands with the minimal convenient set of parameters needed to execute them. For example, the CLI can request a message list that includes not just message content but user information, reactions, file attachments, download progress, etc, with limits and ranges for lazy loading. Developers benefit from event-module locality: when adding functionality to, say, messages or reactions, everything they need to modify is in the same content-thematic cluster of create, project, and query functions. Queries and commands are strictly scoped by peer, to avoid accidental intermingling of local data in development or testing. Unlike most p2p or local-first frameworks, you aren't on your own to build complex state management layer and deal with state duplication and concurrency problems; there is no middleware and frontends can be maximally simple. Because our "server" is local and only serves one client, frequent polling is a simple-but-effective way to keep frontend and backend state in constant sync.

For instant optimistic feedback, write commands (`Send`, `React`, `SendFile`) accept an optional `client_op_id` that the frontend generates locally. The daemon stores a local mapping from `client_op_id` to the resulting `event_id`, and annotates view responses with these IDs. The frontend shows an optimistic row immediately on send, then drops it when the polled view contains a canonical item with the matching `client_op_id`. This gives Slack-like latency with no client-side state machine — just a key match on each poll.

For reactive data flows, the daemon provides a local subscription engine. Frontends create subscriptions filtered by event type (e.g. "message", "reaction") with optional field-level filter clauses. As events are projected, matching items are appended to a per-subscription feed table. Frontends poll feed items with `SubPoll` (sequential, ack-based cursor), check pending counts with `SubState`, and acknowledge consumed items with `SubAck`. Three delivery modes control feed granularity: `full` (render-ready payload), `id` (identifiers only), and `has_changed` (dirty flag + count, no per-item rows). Subscriptions are local to each peer and do not replicate — they are a projection-layer convenience for frontend reactivity, not protocol state. Ownership split: lifecycle/storage/feed mechanics live in `src/state/subscriptions/*`, while event-specific filter semantics and payload shaping live in each event module via `subscription_filter.rs` (or `subscription_filters.rs`).

## Adding Event-Layer Functionality

This is the concrete workflow for adding a user-facing feature as event-layer functionality, using a new multi-valued message attachment type (`message_unfurl`) as the example. The same flow applies to `message_reply` (or any other "many per message" relation): one canonical event per attachment item, all keyed by `message_id`.

### Example Feature: Multi-Valued `message_unfurl`

Goal: each message can have zero, one, or many unfurls.

Data shape: store one `message_unfurl` event per unfurl.  
Store metadata (`url`, `title`, optional `image_url`) in the unfurl event.  
Do not mutate the `message` row in place to add unfurls.

### 1. Create The Event Module

Add a new module directory:

```text
src/event_modules/message_unfurl/
  mod.rs
  wire.rs
  projector.rs
  queries.rs
```

Model and wire format in [wire.rs](/home/holmes/poc-7/src/event_modules/message_attachment/wire.rs)-style:

```rust
pub struct MessageUnfurlEvent {
    pub created_at_ms: u64,
    pub message_id: [u8; 32],   // dep: message
    pub url: String,            // fixed-size text slot
    pub title: String,          // fixed-size text slot
    pub image_url: String,      // fixed-size text slot, "" when absent
    pub signed_by: [u8; 32],    // dep: signer
    pub signer_type: u8,
    pub signature: [u8; 64],
}

pub static MESSAGE_UNFURL_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_MESSAGE_UNFURL,
    type_name: "message_unfurl",
    projection_table: "message_unfurls",
    share_scope: ShareScope::Shared,
    dep_fields: &["message_id", "signed_by"],
    dep_field_type_codes: &[&[1], &[]], // message, signer-resolved
    signer_required: true,
    signature_byte_len: 64,
    encryptable: true,
    parse: parse_message_unfurl,
    encode: encode_message_unfurl,
    projector: super::projector::project_pure,
    context_loader: crate::event_modules::registry::load_empty_context,
};
```

### 2. Add Projection Table + Projector

In `message_unfurl/mod.rs`, define schema with tenant scope and message fanout index:

```sql
CREATE TABLE IF NOT EXISTS message_unfurls (
  recorded_by TEXT NOT NULL,
  event_id TEXT NOT NULL,
  message_id TEXT NOT NULL,
  url TEXT NOT NULL,
  title TEXT NOT NULL,
  image_url TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  signer_event_id TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (recorded_by, event_id)
);
CREATE INDEX IF NOT EXISTS idx_msg_unfurls_message
  ON message_unfurls(recorded_by, message_id);
```

In `message_unfurl/projector.rs`, emit `InsertOrIgnore` into `message_unfurls`.  
This is what makes "many unfurls per message" natural: multiple events with same `message_id`, different `event_id`.

### 3. Register The Type In Core Event Registry

Update [mod.rs](/home/holmes/poc-7/src/event_modules/mod.rs):

1. `pub mod message_unfurl;`
2. `pub use message_unfurl::MessageUnfurlEvent;`
3. Allocate a new `EVENT_TYPE_MESSAGE_UNFURL` code.
4. Add `message_unfurl::ensure_schema(conn)?` to `ensure_schema`.
5. Add `ParsedEvent::MessageUnfurl(...)`.
6. Add entries in `dep_field_values`, `event_type_code`, and `signer_fields`.
7. Add `&message_unfurl::MESSAGE_UNFURL_META` to `registry()`.

If encryptable, also add wire size mapping in [common.rs](/home/holmes/poc-7/src/event_modules/layout/common.rs) `encrypted_inner_wire_size(...)`.

### 4. Add Queries And Include In Message View

Create `message_unfurl::queries::list_for_message(...)` (same pattern as [queries.rs](/home/holmes/poc-7/src/event_modules/message_attachment/queries.rs)).

Then update [queries.rs](/home/holmes/poc-7/src/event_modules/message/queries.rs):

1. import `message_unfurl`,
2. fetch unfurls alongside reactions/attachments,
3. add `unfurls: Vec<UnfurlSummary>` to [mod.rs](/home/holmes/poc-7/src/event_modules/message/mod.rs) `MessageItem`, where each `UnfurlSummary` carries `url`, `title`, and `image_url`.

This is the only place the "messages API shape" changes; canonical history remains event-sourced.

### 5. Add Command Path

Add a command entrypoint where user-facing sends are already implemented:

1. either in [commands.rs](/home/holmes/poc-7/src/event_modules/message/commands.rs),
2. or a focused `message_unfurl/commands.rs`.

Use `create_signed_event_synchronous(...)` to emit one `message_unfurl` event per unfurl.  
If the message does not exist yet, the unfurl event blocks and later unblocks via normal cascade.

### 6. Wire RPC/CLI To The New Command

If this feature is externally callable:

1. add RPC method variant in [protocol.rs](/home/holmes/poc-7/src/runtime/control/rpc/protocol.rs),
2. add catalog entry in [catalog.rs](/home/holmes/poc-7/src/runtime/control/rpc/catalog.rs),
3. add dispatch handler in [server.rs](/home/holmes/poc-7/src/runtime/control/rpc/server.rs),
4. add CLI handler in [main.rs](/home/holmes/poc-7/src/runtime/control/main.rs) using `rpc_require_daemon()`.

The CLI must always go through RPC — never open the database directly for workspace queries. No event logic belongs in RPC/service routing; those layers orchestrate only.

### 7. Tests You Add In The Same Change

1. Roundtrip/meta tests in [mod.rs](/home/holmes/poc-7/src/event_modules/mod.rs) (parse/encode, dep fields, signer fields, registry lookup).
2. Projector tests in `tests/projectors/` for valid insert + dep/signer blocking behavior.
3. Pipeline integration tests in `src/state/projection/apply/tests/` for unblock/cascade behavior.
4. Scenario/API test proving messages can return multiple unfurls for one message.

### `message_reply` Variant

If you implement reply references instead of unfurls, use the same flow with:

1. `message_reply` event fields: `message_id`, `target_message_id`, signer fields,
2. deps: `["message_id", "target_message_id", "signed_by"]`,
3. projection table keyed by `(recorded_by, event_id)` with index on `(recorded_by, message_id)`.

You still get "multiple replies attached to one message" by emitting multiple `message_reply` events with the same `message_id`.

---

## Documentation scope policy

1. Main sections describe protocol semantics and runtime invariants in language-agnostic terms.
2. Rust file/module paths are included only when they materially reduce ambiguity for implementers.
3. Dense implementation maps and file ownership details belong in appendices.
4. When both appear, conceptual text comes first and implementation references are cross-linked.
5. Runtime/topology visuals are maintained in [DESIGN_DIAGRAMS.md](./DESIGN_DIAGRAMS.md); this file links to those diagrams where flow shape matters.

---

Note: the following section is written with coding agents in mind and emphasizes some aspects that might be obvious to a human reader, to avoid common agent mistakes. 

# 1. Protocol Model

## 1.1 Event classes

1. Canonical shared events:
   - durable and shareable across peers.
2. Canonical local-only events:
   - durable and replayable, but never shared.
3. Runtime protocol messages:
   - non-canonical transport/sync frames only.

Shareability is event-type policy, not a separate storage system.

Blocked-event normalcy rule:
1. blocked events are still canonical/shareable facts in the log,
2. some events are expected to remain blocked for a tenant (for example encrypted content or key-share events where that tenant is not a recipient),
3. post-sync blocked presence must be interpreted with policy context, not as automatic failure; policy-appropriate blocked rows after sync can be normal operation.

## 1.2 Event format

Events are flat and schema-defined.

Rules:
1. no universal `deps` field,
2. no universal `payload` envelope,
3. any schema field marked as `event_id` reference is a dependency source.

More details:

1. Field kinds are schema-driven (`fixed_bytes`, integers), and each event type has deterministic field order and fixed total wire size.
2. No canonical event field uses a length prefix to determine body boundaries.
3. Text slots use fixed-size UTF-8 with mandatory zero-padding: unused bytes after the canonical text content must be zero, and no non-zero bytes may appear after the text terminator.
4. Encrypted event wire size is deterministic by `inner_type_code` (inner types are fixed-size).
5. File slice events use a canonical fixed ciphertext size; final plaintext chunks are padded before encryption.
6. Retired event type 4 is rejected as an unknown type by runtime dispatch; it is not part of the active parser/projector surface.
7. `bench_dep` events (type 26) are fixed-size shared benchmark events for dependency/cascade performance testing; they are non-encryptable and project no domain rows beyond validity state.

## 1.3 Event identity and signatures

1. canonical event bytes are content-addressed (`event_id` from canonical bytes),
2. signed events carry canonical signer fields:
   - `signed_by` (event-id reference),
   - `signer_type` (`workspace | user_invite_shared | peer_invite_shared | user | peer_shared`),
   - `signature`,
3. signature verification resolves signer key by (`signer_type`, `signed_by`) after dependency resolution,
4. transport security is separate and complementary to event signatures.

Deterministic emitted-event exception:
1. deterministic emitted event types are canonical but unsigned for deterministic bytes/ids,
2. those types omit `signed_by`, `signer_type`, and `signature` by schema,
3. they are validated by deterministic-derivation checks instead of signature checks.

No per-event transit wrapper is used; transit encryption is handled by QUIC/mTLS.

## 1.4 Sync frame header (`payload_len`) rationale

Sync frames include a `payload_len` in the frame header.

Why:
1. QUIC streams are byte streams; receiver needs explicit frame boundaries.
2. Non-event frame types also exist (reconciliation/control), so delimiters are needed for mixed frame streams.
3. Length-delimited framing allows safe skip/reject behavior for unknown/future frame types.

Safety rule:
1. `payload_len` is an untrusted framing delimiter, not semantic authority.
2. enforce global and per-frame-type max lengths.
3. all canonical event types have fixed wire sizes; `payload_len` must exactly match the schema-defined size for the event type (or, for encrypted events, the size determined by `inner_type_code`).
4. any mismatch rejects the frame.

## 1.5 Dual-stream sync completion protocol

Sync sessions use one control stream and one data stream.

Why split streams:
1. keeps large event transfer (`Event` frames) from head-of-line blocking control semantics (`Done`, `DoneAck`),
2. makes completion semantics explicit (data completion vs control completion),
3. improves practical throughput and observability by separating reconciliation/control chatter from bulk payload flow.

Completion frames:
1. `Done` (control stream, initiator -> responder): initiator has finished producing outbound work for this round.
2. `DataDone` (data stream, either direction): sender has no more `Event` frames on the data stream.
3. `DoneAck` (control stream, responder -> initiator): responder confirms terminal completion.

Completion invariants:
1. responder sends `DoneAck` only after its egress is drained, it has sent its own `DataDone`, and it has observed peer `DataDone` on inbound data.
2. initiator treats the session as complete only after `DoneAck`.
3. this handshake gives explicit end-of-data semantics without relying on transport stream close timing.

---

# 2. Transport and Session Identity

Transport identity is derived from event-layer peer identity:

1. **Transport identity** (mTLS scope): cert/key material, SPKI fingerprints, `peer_id` derived from BLAKE2b-256 of X.509 SPKI. Managed by `src/runtime/transport/identity.rs` via `src/runtime/transport/identity_adapter.rs`.
2. **Event-graph identity** (identity layer scope): Ed25519 keys, signer chains, accepted workspace bindings (`invites_accepted`), and identity events (types 8-22). Owned by event modules (for example `src/event_modules/workspace/*`, `src/event_modules/invite_accepted.rs`, `src/event_modules/peer_shared/*`, `src/event_modules/peer_secret.rs`) and executed through the generic projection pipeline (`src/state/projection/apply/*`).

Transport certs are deterministically derived from PeerShared Ed25519 signing keys, so the two identity scopes are unified. All transport trust is derived from PeerShared Ed25519 public keys via `spki_fingerprint_from_ed25519_pubkey()`.

## 2.1 QUIC + mTLS

All peer transport uses QUIC with strict pinned mTLS.

Rules:
1. each daemon profile has persistent cert/private key material,
2. peer allow/deny policy is based on SQL trust state:
   - PeerShared-derived transport fingerprints from projected `peers_shared.transport_fingerprint` rows (deterministically computed from PeerShared public key at projection time),
   - `invite_bootstrap_trust` rows produced by projection from `InviteAccepted` events + local `bootstrap_context`,
   - `pending_invite_bootstrap_trust` rows produced by projection from invite events (UserInvite, DeviceInvite) + local `bootstrap_context`,
   - trust rows are projection-owned state; the service layer writes `bootstrap_context` rows only, not trust rows directly,
3. no permissive verifier in production mode.

## 2.2 Transport identity binding

Transport peer identity is SPKI-derived:

1. `peer_id = hex(BLAKE2b-256(cert_SPKI))`,
2. `peer_shared` projection materializes `peers_shared.transport_fingerprint` as that deterministic SPKI fingerprint and indexes `(recorded_by, transport_fingerprint)`,
3. the `peer_transport_bindings` table is observation telemetry keyed by `(recorded_by, peer_id)`, where `recorded_by` is the local tenant key and `peer_id` is the remote transport fingerprint; `spki_fingerprint` stores the raw 32-byte SPKI for lookup/diagnostics,
4. `invite_bootstrap_trust` stores accepted invite-link bootstrap tuples
   (`bootstrap_addr`, inviter SPKI) used before PeerShared-derived trust appears,
5. `pending_invite_bootstrap_trust` stores inviter-side expected invitee SPKI
   until PeerShared-derived trust consumes it,
6. accepted/pending bootstrap rows are time-bounded and consumed at projection time
   (PeerShared projector issues deterministic `Delete` write-ops for matching SPKIs)
   when steady-state PeerShared-derived trust appears. Trust check reads are pure
   (no write side-effects).
7. trust/removal lookups use projected `transport_fingerprint` rows and do not scan/derive fallback from `peers_shared.public_key`.

Runtime rule: handshake verification queries SQL trust state per connection creation; projected peer keys are not treated as in-memory authority.

Why this is SQL-first:
1. restart-safe: no trust bootstrap gap after process restart,
2. low-memory friendly: avoids unbounded in-memory trust sets,
3. multi-tenant safe: one node can host many tenants with tenant-scoped indexed lookups.

Conceptually:
`TrustedPeerSet = PeerShared_SPKIs ∪ invite_bootstrap_trust ∪ pending_invite_bootstrap_trust`.

### Transport identity materialization boundary

Transport cert/key materialization is isolated behind a typed contract:

- **`TransportIdentityIntent`** (enum): describes *what* identity change is needed (`InstallBootstrapIdentityFromInviteKey` or `InstallPeerSharedIdentityFromSigner`).
- **`TransportIdentityAdapter`** (trait): executes the intent against the DB. The sole concrete implementation (`ConcreteTransportIdentityAdapter` in `src/runtime/transport/identity_adapter.rs`) is the **only** code that calls raw install functions (`install_invite_bootstrap_transport_identity`, `install_peer_key_transport_identity`).
- **Workspace command layer** (`accept_invite` / `accept_device_link`) installs invite-derived bootstrap identity via the adapter intent path (not raw transport calls).
- **Event modules** emit `ApplyTransportIdentityIntent` commands (e.g., `peer_secret` projector for PeerShared signers).
- **Projection pipeline** (`write_exec.rs`) routes intents through the adapter.
- **Downgrade guard**: bootstrap install is rejected once a PeerShared-derived identity has been installed (`BootstrapAfterPeerSharedDenied`), enforcing one-way transition.
- **Credential source tracking**: `local_transport_creds.source` records `random | bootstrap | peershared` for runtime guard checks and diagnostics.
- **Boundary enforcement**: layered controls enforce this boundary:
  1. typed intent contract (`TransportIdentityIntent`),
  2. single adapter implementation (`ConcreteTransportIdentityAdapter`),
  3. static import guard (`scripts/check_boundary_imports.sh`),
  4. contract tests (`tests/identity_transport_contract_tests/*`).

## 2.3 Event-graph identity binding

Identity is event-defined; transport identity must use event-layer identity as its source of truth:

1. identity state maintains signer chains from workspace root to peer,
2. identity state directly determines transport trust — transport certs are derived from PeerShared signing keys,
3. projected identity determines which peers are allowed to sync.
4. identity and signatures determine what events are valid (who can do what)

### 2.3.1 Display names (POC placeholder)

Encrypting workspace and event names is straightforward given group key agreement (see: poc-6), but it adds complexity and is out of the scope of this proof-of-concept design.

As a placeholder, workspace, user, and device events carry a 64-byte cleartext name text slot.

### 2.3.2 Author dependency

Content events (Message, Reaction, MessageDeletion) declare `author_id` as a dependency field pointing to User events (type 14). The dependency system blocks projection until the referenced User event exists, and the projector verifies that the signer's peer_shared `user_event_id` matches the claimed `author_id`. This enables direct `messages.author_id = users.event_id` JOINs for display name resolution.

## 2.4 NAT traversal and hole punch

Direct peer-to-peer connectivity through NAT is a transport optimization, not a canonical protocol concern.

Principles:
1. Hole punch is opportunistic — sync via normal-operation set reconciliation and an intermediary peer is always the fallback.
2. Introduction data (endpoint observations, IntroOffers) is runtime protocol state, not canonical events.
3. The introducer role is a behavior of any peer that has active connections to multiple other peers — it is not a special node type.
4. Punch success depends on NAT behavior (EIM = endpoint-independent mapping). Symmetric/port-dependent NATs will not work with the current approach.

### Endpoint observations

When a peer accepts or establishes a QUIC connection, it records the remote peer's observed `(ip, port)` in the `peer_endpoint_observations` table with a TTL.
After a successful hole-punched connection, it also records the punched peer's observed endpoint so that peer can be introduced to others later.

Rules:
1. Observations are append-only with `INSERT OR IGNORE`.
2. Freshness is determined by `MAX(observed_at)` query, not in-place update.
3. Observations expire via `expires_at` and are periodically purged.
4. Observations are scoped by `recorded_by` (the observer) and `via_peer_id` (the observed peer).

### Introduction protocol

An introducer sends `IntroOffer` messages to two peers so they can attempt a direct connection:

1. The introducer looks up the freshest non-expired endpoint observation for each peer.
2. It sends each peer an `IntroOffer` containing the other peer's `(peer_id, ip, port, observed_at, expires_at, attempt_window_ms)`.
3. IntroOffers are sent on uni-directional QUIC streams (not bi-directional sync streams).
4. IntroOffers are 88 bytes fixed-size and contain a 16-byte random `intro_id` for deduplication.

Receiver validation:
1. Expired offers are dropped and recorded as `expired`.
2. Offers for untrusted peers (not in `AllowedPeers`) are rejected.
3. Duplicate `intro_id` values are silently skipped per `(recorded_by, intro_id)`.
4. `intro_attempts` rows currently have no TTL purge; dedupe horizon is DB-retention lifetime in this POC.

### Hole punch dial protocol

After receiving a valid IntroOffer, the peer attempts paced QUIC connections to the introduced peer's observed address:

1. Dial attempts are paced at 200ms intervals within the `attempt_window_ms` (default 4s). The 200ms pace is the current implementation default and can be promoted to a tuning knob if field data requires it.
2. Each attempt uses `endpoint.connect()` on the same QUIC endpoint (sharing the UDP socket and local port).
3. On successful connection, the peer verifies the remote peer's identity matches the expected `other_peer_id`.
4. On identity match, a normal sync session runs on the punched connection.
5. The attempt lifecycle is recorded in `intro_attempts` with status transitions: `received → dialing → connected | failed | expired | rejected`.

NAT traversal relies on simultaneous open: both peers dial each other at roughly the same time, creating outgoing NAT mappings that allow the other's packets through.

Timing uses local monotonic timers for pacing and local wall-clock checks for offer expiry. The protocol does not require GPS-grade or globally synchronized clocks; skew mainly affects whether a borderline-stale offer is attempted vs dropped.

### Explicit intro API

Introductions are explicit and one-shot:

1. An operator (or external job) calls `topo intro --peer-a <fpA> --peer-b <fpB>`.
2. The command looks up freshest non-expired endpoint observations for both peers.
3. It sends IntroOffers to both peers on the same QUIC endpoint socket.
4. The daemon does not run background peer-pair selection or automatic intro scheduling

Selection logic ("who to intro, when to retry") is intentionally out of scope for the proof-of-concept; application developers can tailor solutions to their needs.

### UPnP port mapping (operator-invoked)

UPnP/IGD mapping is an optional transport reachability aid, separate from canonical protocol state.

Rules:
1. mapping is invoked explicitly via `topo upnp` (daemon RPC `Upnp`) using the daemon's actual bound QUIC listen address.
2. result is a structured status report: `success | failed | not_attempted` with mapped external port/IP and optional gateway/error fields.
3. loopback-bound listeners produce `not_attempted`; routable mapping requires non-loopback bind (`0.0.0.0` or explicit LAN IP).
4. if mapping succeeds but the external IP is not publicly routable, runtime flags `double_nat = true` and warns.
5. UPnP outcome is informational runtime metadata (`NodeRuntimeNetInfo.upnp`) and does not modify trust/projection/signature semantics.

### Testing

Test the feature with both local integration tests and Linux netns NAT simulation:

1. `cargo test --test holepunch_test`
2. `cargo test test_record_endpoint_observation`
3. `cargo build --release`
4. `sudo tests/netns_nat_test.sh --cone` (expected pass)
5. `sudo tests/netns_nat_test.sh --symmetric` (expected fail)
6. `sudo tests/netns_nat_test.sh --cleanup`

Netns runbook notes:
1. The script creates five namespaces (`hp_i`, `hp_na`, `hp_nb`, `hp_a`, `hp_b`) and a public bridge.
2. `--cone` mode configures endpoint-independent mapping and should permit successful hole punch.
3. `--symmetric` mode configures randomized source-port NAT and should fail direct hole punch.
4. On success, temp logs are removed; on failure, logs are preserved under `/tmp/hp_nat_test.*` for diagnosis.
5. Always run `--cleanup` after interrupted runs to remove namespaces and bridge state.

## 2.4.1 Identity bootstrap operations

High-level identity operations are owned by event-module commands (`event_modules/workspace/commands.rs`). They compose low-level event creation primitives (from `event_modules/workspace/identity_ops.rs`) into correct sequences.

**Bootstrap** (`workspace::commands::create_workspace`): creates the identity chain for a new workspace owner:
Workspace → InviteAccepted (accepted workspace binding) → UserInvite → User → DeviceInvite → PeerShared + PeerSecret (`peer_shared` signer) + content key seed.
The `peer_secret` event for the local `peer_shared` signer triggers `ApplyTransportIdentityIntent` on projection, installing a PeerShared-derived transport identity.
Scope rule: `create_workspace` is tenant-scoped. If local transport credentials already exist, `recorded_by` must match a known local tenant peer ID in `local_transport_creds`; unscoped aliases (for example `"bootstrap"`) are rejected. Fresh DB bootstrap (no local creds) is still allowed.

**Invite** (`workspace::commands::create_user_invite`): admin creates a UserInvite event and returns portable invite data (event ID + signing key + workspace ID). Wraps content key for invitee if sender keys are available.

**Accept** (`workspace::commands::join_workspace_as_new_user`): joiner consumes invite data and creates:
InviteAccepted (accepted workspace binding) → User → DeviceInvite → PeerShared.
Prerequisite: the joiner's DB must already contain the Workspace and UserInvite events (copied from the inviter before or during sync).
The acceptance path also unwraps bootstrap content-key material received via `key_shared` events (wrapped to the invite public key at creation time) and materializes local `key_secret` events so that encrypted content received during bootstrap sync can be decrypted.
Signer secrets (PeerSecret events) are NOT emitted here; `persist_join_peer_secret` is called separately after push-back sync completes.

**Device link** (`workspace::commands::create_device_link_invite` / `add_device_to_workspace`): similar to user invite but creates a shorter chain (PeerShared only, skipping user/peer_invite_shared creation).

**Retry** (`workspace::commands::retry_pending_invite_content_key_unwraps`): retries content-key unwrap for invites where `key_shared` prerequisites arrived late. Triggered via `event_modules::post_drain_hooks` from `state/pipeline/effects.rs` after each projection drain.

Identity pre-derive:

All three creation paths pre-derive `recorded_by` from the PeerShared key
(`derived_peer_id = hex(spki_fingerprint(pubkey))`) before writing any events,
so all events are written under the final peer_id from the start.

- **Workspace creation** (`create_workspace`): pre-derives PeerShared key,
  installs PeerShared-derived transport cert directly. No bootstrap sync needed.
- **Invite acceptance / device link** (`accept_invite`, `accept_device_link`):
  pre-derives PeerShared key for `recorded_by`, but installs an invite-derived
  bootstrap transport cert (needed for the initial QUIC handshake — the inviter
  expects the invite-derived SPKI). The PeerShared-derived transport identity
  replaces it later via projection cascade
  (`ApplyTransportIdentityIntent::InstallPeerSharedIdentityFromSigner`).
- **Connect loop**: identity is resolved once per QUIC connection (not per
  session). Identity transitions only happen during discrete CLI commands,
  never during active sync, so per-session re-lookup is unnecessary overhead.

Pre-derive implication:
1. because `recorded_by` is final before any event write, bootstrap does not need a special remap/finalize pass,
2. dependency blocking/unblocking behaves identically to steady-state sync,
3. replay naturally converges through normal dependency resolution for the same tenant key.

Concrete bootstrap-replay example (why pre-derive matters):
1. joiner pre-derives final `recorded_by = P` from its `peer_shared` public key,
2. joiner writes `invite_accepted` and follow-on identity events under `P`,
3. if `workspace`/`user_invite_shared` prerequisites arrive later via sync, those rows are also recorded under `P`,
4. blocked dependents unblock through the standard cascade under the same tenant key `P`,
5. no identity remap/finalize phase is required during replay.

### Identity ownership boundary

Conceptual ownership:
1. **Event commands own workflows** (workspace creation, invite creation/acceptance, device linking, retry paths).
2. **Crypto modules own cryptographic primitives** (`shared/crypto/*`, `projection/encrypted.rs` for wrap/unwrap, hash/sign/verify operations).
3. **Identity helpers own event-domain composition** (`event_modules/workspace/identity_ops.rs`: deterministic key-event materialization, invite helper assembly, bootstrap helper data shaping) and call crypto primitives rather than redefining them.
4. **Transport adapter owns cert/key/SPKI materialization** and is invoked via typed intents, not direct calls from event modules.
5. **Projection pipeline owns deterministic decision-conditioned apply order** (`Valid`: `write_ops` then `emit_commands`; `Block`: `emit_commands` only) and post-drain hooks.
6. **Service/RPC layer owns orchestration only** (routing, db open/close, error mapping), not identity policy logic.
7. **Boundary checks are automated** (import guard script + contract tests).

Concrete Rust file mapping is in Appendix A (implementation map).

All functions take `&Connection` and `recorded_by`, enabling multi-tenant operation where multiple identities share a single database.

## 2.5 Recording identity semantics

1. `signed_by`: canonical signer event reference used for signature/policy checks.
2. `signer_type`: signer keyspace discriminator (`workspace | user_invite_shared | peer_invite_shared | user | peer_shared`).
3. `recorded_by`: local tenant scope key that recorded/projected the event; in the current implementation this key is the local transport peer fingerprint selected during bootstrap.
4. `via_peer_id`: authenticated remote transport peer for ingress metadata.

`recorded_by` is derived from authenticated local daemon/profile transport identity, not from event payload claims.
Legacy naming note: some tenant-scoped tables still use the column name `peer_id` for this same local scope key domain (for example `recorded_events.peer_id`). In this document, `recorded_by` is the canonical term.
Naming rule: `peer_id` means a transport identity fingerprint (local or remote by context). `event_id` means a canonical event hash; these domains are never interchangeable.

---

# 3. Durable Storage Model

## 3.1 Canonical and state tables

Core durable tables:

1. `events(event_id, event_type, blob, share_scope, created_at, inserted_at)`.
2. `recorded_events(peer_id, event_id, recorded_at, source)` as receive/create journal.
3. `valid_events(peer_id, event_id)`.
4. `rejected_events(peer_id, event_id, reason, rejected_at)`.
5. projection tables owned by event modules.

Operational metadata table:

1. `peer_endpoint_observations(recorded_by, via_peer_id, origin_ip, origin_port, observed_at, expires_at)` (append-only + TTL).

## 3.2 Multitenancy model

Shared physical tables are used across peers.

Rules:
1. no per-tenant table fanout,
2. subjective rows include tenant scope using the same local tenant-key domain (column name is `recorded_by` in newer tables and legacy `peer_id` in older ones),
3. composite identity/index shape is tenant-first, typically `(peer_id, event_id)`,
4. query APIs are tenant-bound wrappers rather than raw unrestricted DB handles.

This preserves scoped reads/writes while keeping the schema ergonomic.

**Known limitation:** `neg_items` is one shared physical table. Negentropy reads are workspace-scoped (`workspace_id = ? OR workspace_id = ''`), so tenants do not enumerate other tenants' non-empty workspace buckets. Remaining leakage risk is limited to rows with empty `workspace_id` during bootstrap/pre-anchor windows. In this document, **pseudonym isolation** means preventing any cross-tenant metadata correlation at the node level; full pseudonym isolation still requires separate node instances on separate network paths.

## 3.2.1 Functional multitenancy: one node, N tenants

A single node process can host N tenant identities in one shared SQLite database, with one shared QUIC endpoint plus tenant-scoped workspace binding and trust policy.

The DB is the tenant registry. No explicit tenant registration step is required. The node discovers its tenants by joining two tables:

```sql
SELECT i.recorded_by, i.workspace_id, c.cert_der, c.key_der
FROM invites_accepted i
JOIN local_transport_creds c ON i.recorded_by = c.peer_id
``` 

`invites_accepted` is populated by `invite_accepted` (local-only, part of the identity bootstrap). `local_transport_creds` is populated during identity bootstrap: invite acceptance may install an invite-derived bootstrap cert first, then projection installs the PeerShared-derived cert.

Why certs are part of discovery:
1. event-layer identity establishes who the tenant is,
2. transport credentials establish that the tenant can actually terminate mTLS handshakes,
3. the daemon needs both to start accept/dial loops safely (identity without certs cannot serve transport; certs without anchor cannot map to workspace scope).

### Node daemon architecture

The node daemon (`run_node`) operates as follows:

1. Discover all local tenants from the DB.
2. Create a **single** QUIC endpoint with `WorkspaceCertResolver` for SNI-based cert selection across all tenants.
3. Create one shared `batch_writer` thread that all tenants feed into.
4. Run a single `accept_loop_with_ingest` with a union dynamic trust closure that checks across all tenants. Post-handshake, the peer's SPKI fingerprint is checked per-tenant to determine `recorded_by` routing.
5. Optionally: per-tenant mDNS advertisement and peer discovery.

### Single-port multi-tenant endpoint

All tenants on a device share a single UDP port. The server uses `WorkspaceCertResolver` to select the correct TLS cert based on the client's SNI hostname (`workspace_sni()` maps workspace_id to a DNS-safe hex label). Outbound connections use `workspace_client_config()` for per-workspace cert presentation.

### Per-tenant dynamic trust

The single QUIC endpoint uses a union trust closure that accepts connections trusted by **any** local tenant. Post-handshake, `resolve_tenant_for_peer` checks `is_peer_allowed` for each tenant to determine routing. The trust closure queries three trust sources for each tenant's `recorded_by`:
- **PeerShared-derived transport fingerprints** (primary steady-state; from projected `peers_shared.transport_fingerprint`),
- `invite_bootstrap_trust` rows (accepted invite-link bootstrap, TTL-bounded),
- `pending_invite_bootstrap_trust` rows (inviter-side pre-handshake, TTL-bounded).

Trust checks are **tenant-scoped** (`recorded_by`-partitioned). Value-level trust-set overlap is allowed (the same SPKI may appear in multiple tenants' trust rows), and the union closure permits the shared endpoint to accept connections for any local tenant. `invites_accepted` is read during startup tenant discovery (to enumerate local tenant/workspace bindings), but per-connection authorization uses `is_peer_allowed` over PeerShared/bootstrap trust tables, not `invites_accepted`.

### Removal-driven session teardown

When a `PeerRemoved` event is projected, trust lookups and removal-watch checks use indexed `(recorded_by, transport_fingerprint)` projection rows plus `removed_entities` predicates to deny the removed peer. When a `UserRemoved` event is projected, all peers linked to that user via `peers_shared.user_event_id` are transitively denied. Additionally:
- New TLS handshakes are denied: `is_peer_allowed` returns false for removed peers and for peers whose owning user has been removed.
- Active sessions are torn down: between sync sessions, both `accept_loop` and `connect_loop` check `is_peer_removed` for the connected peer's SPKI. If the peer has been directly removed or its user has been removed, the QUIC connection is closed with error code 2 ("peer removed").

### Shared batch writer with tenant routing

All tenants share a single `batch_writer` thread to avoid SQLite write contention.
Each ingested event carries `recorded_by` and source attribution
(`IngestItem = (event_id, blob, recorded_by, source_tag)`), so one writer can
safely persist mixed-tenant ingress without cross-tenant state confusion while
retaining per-peer ingest provenance in `recorded_events.source`.

Per batch:
1. collect ingress tuples from concurrent sessions,
2. persist canonical rows once (`events`) and tenant receipt rows (`recorded_events`) in one transaction,
3. enqueue tenant-scoped projection work (`project_queue`),
4. commit,
5. run post-commit effects (queue drain, health logging, post-drain hooks).

The batch writer runs two explicit phases:

1. Persist phase (`state/pipeline/phases.rs`): inserts into `events`, `recorded_events`, and `neg_items`, and enqueues `project_queue` rows in one transaction.
2. Effects phase (`state/pipeline/effects.rs`): executes side effects directly from `PersistPhaseOutput` through the executor boundary (wanted removal, queue drain/projection, queue health logging, post-drain hooks).

The projection drain (`project_queue::drain_with_limit`) runs each projection in autocommit mode and batches dequeue DELETEs via `mark_done_batch` (one `BEGIN`/`COMMIT` per claim cycle). Individual projection failures are retried with exponential backoff via `mark_retry`. During the drain (outside low_mem mode), `drain_project_queue_on_connection` defers WAL autocheckpointing (`PRAGMA wal_autocheckpoint = 0`) to avoid checkpoint stalls between autocommit writes, restoring the default after drain completes. In low_mem mode this is skipped to keep WAL growth bounded. Crash safety is provided by the queue: interrupted drains leave events in `project_queue` for re-projection on the next cycle.

Ownership statement: persist owns ingest SQL writes, planner owns deterministic command mapping, effects owns side-effect execution, and `batch_writer` in `state/pipeline/mod.rs` owns sequencing/retry policy.

This eliminates write contention while preserving per-tenant projection isolation.

### TLS credential storage

Transport cert/key **DER** (ASN.1 Distinguished Encoding Rules) blobs live exclusively in the `local_transport_creds` SQLite table (with `source` marker: `random | bootstrap | peershared`). No cert files exist on disk. Credentials are stored during identity bootstrap and loaded at endpoint creation time. Bootstrap identity install is one-way gated: after a PeerShared install, bootstrap install is denied. This keeps all node state in one database file.

## 3.2.2 LAN peer discovery (mDNS/DNS-SD)

Multi-tenant nodes advertise each tenant on the local network under the `_topo._udp.local.` service type. Each tenant registers a separate mDNS service instance with its actual bound port and full transport `peer_id` (SPKI-derived fingerprint) in a TXT property.

Discovery rules:
1. **Self-filtering**: the browser receives the full set of local tenant transport peer IDs and filters them out, preventing unnecessary local connections.
2. **Trust gating**: discovered peers are only dialed if they pass the tenant's dynamic trust check.
3. **Address churn**: when a previously-discovered peer re-advertises at a different address, the old `connect_loop` is cancelled via a `watch` channel and a new one is spawned.

mDNS authenticity model (POC):
1. mDNS advertisements are treated as unauthenticated discovery hints (address + claimed peer_id),
2. an attacker can spoof mDNS TXT records and cause extra dial attempts,
3. spoofed advertisements cannot bypass identity/auth: session acceptance still requires mTLS identity and tenant-scoped `is_peer_allowed` trust checks,
4. authoritative peer identity for the session is the TLS/SPKI-derived peer fingerprint observed at handshake, not the mDNS TXT claim.

Out-of-scope note (current POC):
1. same-instance communication between two local tenants in the same workspace is not implemented as a special intra-daemon delivery path,
2. because self-filtering excludes local peer IDs, local tenants do not discover/connect to each other through mDNS,
3. adding explicit intra-instance delivery may be desirable future work, but it is out of scope for the current design baseline.

DNS label constraint: peer IDs (64 hex chars) are truncated to 59 chars in the mDNS instance name (62 total with `p7-` prefix, under the 63-byte DNS label limit). The full peer ID is always in the TXT property for exact matching.

Same-host daemon discovery: when two daemons run on the same machine bound to `127.0.0.1`, they advertise a routable (non-loopback) IP via mDNS because multicast DNS does not discover services advertised on loopback addresses. The browse side compensates with `normalize_discovered_addr_for_local_bind`, which rewrites discovered non-loopback addresses back to loopback when the local daemon is bound to loopback. The advertise IP is always provided explicitly by the caller (`run_node`); discovery internals perform no implicit address inference.

## 3.2.3 Peering runtime loop model

Runtime flow reference: [DESIGN_DIAGRAMS.md](./DESIGN_DIAGRAMS.md) sections `1` (unified ingest), `2` (sync session control/data), `3` (high-level boundaries), and `4` (runtime topology).

The production peering runtime follows a single conceptual loop:

1. **Projected SQLite state**: invite_bootstrap_trust rows, PeerShared-derived trust, endpoint observations.
2. **Target planner** (`runtime::peering::engine::target_planner`): single-owner module for all dial target planning. Collects bootstrap trust targets from SQL and mDNS discovery candidates. Routes both through `PeerDispatcher` for deduplication and reconnect management.
3. **Supervisor layer**: startup preflight + loop orchestration live in the peering supervisor.
4. **Dial/accept loops**: `connect_loop` (outbound) and `accept_loop` (inbound) are separate long-running loops coordinated by shared projected state and cancellation/watch channels. QUIC dial/accept + peer identity extraction flows through `transport::connection_lifecycle`, and stream wiring flows through `transport::session_factory`.
5. **Sync session runner** (`SyncSessionHandler`): protocol-agnostic session handler invoked via the `SessionHandler` contract.
6. **Ingest writer** (`batch_writer`): single shared thread consuming `IngestItem` tuples from all concurrent sessions.
7. **Projected SQLite state**: projection cascade updates trust rows, completing the loop.

### Module ownership

- **Target planning**: `src/runtime/peering/engine/target_planner.rs` — the single source of truth for dial target decisions. Bootstrap autodial and mDNS discovery both route through this module.
- **Transport connection lifecycle**: `src/runtime/transport/connection_lifecycle.rs` — sole owner of QUIC `connect/accept` and TLS peer identity extraction for peering paths (`dial_peer`, `accept_peer`).
- **Transport session factory**: `src/runtime/transport/session_factory.rs` — sole owner of QUIC stream opening and `DualConnection` / `QuicTransportSessionIo` construction. Provides `open_session_io()` and `accept_session_io()` that return `(session_id, Box<dyn TransportSessionIo>)`.
- **Transport session I/O adapter**: `src/runtime/transport/transport_session_io.rs` — sole owner of frame boundary validation (`parse_frame` exact-consumption), max-frame-size enforcement, and mapping between QUIC stream errors and `TransportSessionIoError`.
- **Peering orchestration seam**: `src/runtime/peering/loops/mod.rs::run_session` — wires session metadata, peer-removal cancellation, and the session handler together. Receives pre-built `TransportSessionIo` from the transport session factory.
- **Bootstrap test helpers**: `src/testutil/bootstrap.rs` — test-only. Production runtime never depends on these; bootstrap progression is driven by the autodial loop polling projected SQL state.

### Event-sourced authority boundary (peering)

Durable trust/identity authority transitions are event-sourced (InviteAccepted, PeerShared, PeerRemoved). Transport runtime mechanics are not canonical facts: retry cadence, discovery timing, session lifecycle, and endpoint observations are ephemeral operational state managed by the peering runtime directly.

## 3.3 Table lifecycle and naming

1. schema creation runs through deterministic owner `ensure_schema` calls (no migration history playback in this POC),
2. no `schema_migrations` table or versioned migration runner is required in active startup/operation,
3. each owner module defines its own idempotent `ensure_schema(conn)` (event projection tables in `event_modules/*`, queue/infra tables in `state/db/*`),
4. central bootstrap calls owner `ensure_schema` in deterministic order,
5. prototype schema epoch is explicit (`schema_epoch`) and enforced at startup,
6. legacy DB layouts from prior prototype epochs are intentionally rejected (no backward migration; recreate DB),
7. each event module declares explicit `event_type` and `projection_table`; no inferred naming heuristics.

---

# 4. Projection Model

## 4.1 Single projector entrypoint

All ingest paths converge on:

`project_one(recorded_by, event_id) -> ProjectionDecision`

This applies to:
1. local create,
2. wire receive,
3. replay/reproject,
4. unblock retries.

No alternate projection path is allowed.

Internal two-layer model: `project_one` is the sole public entrypoint.
Internally it delegates to `project_one_step` (the 7-step single-event algorithm without cascade), then runs cascade-unblock if the result is `Valid`. The Kahn cascade worklist calls `project_one_step` directly to avoid redundant recursive cascade; Phase 2 guard retries call back into `project_one` for proper recursive cascade. This split isolates "single-event apply logic" from "cascade orchestration" for readability and testability while keeping one canonical ingest path. It is a cascade optimization, not an alternate projection path — all projection stages
(dep check, type check, signer verify, projector dispatch) are shared.

## 4.2 Pure functional projector contract

Projectors are **pure functions** over `(ParsedEvent, ContextSnapshot)` that return
a deterministic `ProjectorResult`. They do not execute SQL or any other side effects
directly. The apply engine executes the returned operations.

### ProjectorResult

```
ProjectorResult {
    decision: ProjectionDecision,  // Valid | Block | Reject | AlreadyProcessed
    write_ops: Vec<WriteOp>,       // deterministic state mutations
    emit_commands: Vec<EmitCommand> // follow-on actions for the command executor
}
```

- `write_ops` are applied only when `decision` is `Valid`.
- `emit_commands` are executed on:
  - `Valid` (normal post-write follow-ons),
  - `Block` (block-side effects such as file-slice guard row recording).

### WriteOp types

1. `InsertOrIgnore { table, columns, values }` — immutable, idempotent materialization.
2. `Delete { table, where_clause }` — explicit row removal (tombstone cascades).

### EmitCommand types

1. `RetryWorkspaceEvent { workspace_id }` — re-project the specific workspace event after accepted-workspace binding is written by `invite_accepted`.
2. `RetryFileSliceGuards { file_id }` — re-project file_slice events after descriptor arrives.
3. `RecordFileSliceGuardBlock { file_id, event_id }` — record guard-block for pending file_slices; consumed by `RetryFileSliceGuards` after descriptor projection (see section 12.2 file attachment flow and section 5.2 cascade lifecycle).
4. `ApplyTransportIdentityIntent { intent }` — apply typed transport identity transitions through the `TransportIdentityAdapter` boundary.

Bootstrap trust materialization uses projector `WriteOp`s (not `EmitCommand`s):
1. `user_invite_shared`/`peer_invite_shared` projectors write pending bootstrap trust rows when `is_local_create` and `bootstrap_context` are present,
2. `invite_accepted` projector writes accepted bootstrap trust rows when `bootstrap_context` is present,
3. `peer_shared` projector consumes matching bootstrap trust rows using deterministic `Delete` write-ops,
4. trust-check functions (`is_peer_allowed`, `allowed_peers_from_db`) remain read-only.

### ContextSnapshot

Read-model snapshot populated before calling the pure projector.
Projectors must not access the database directly. `ContextSnapshot` carries
query-derived read facts for projector predicates; it does not carry a generic
dependency list. Dependency IDs are extracted from parsed event fields via
schema metadata on each projection attempt.

Context ownership rule:
1. projector-specific context queries are owned by the event module via
   `EventTypeMeta.context_loader`,
2. shared pipeline code invokes the module-owned loader and remains free of
   projector-specific SQL branches.

Fields include:

- `accepted_workspace_id` — accepted workspace binding for this tenant
- `target_message_author` / `target_tombstone_author` — for deletion auth
- `deletion_intents` — pre-existing deletion intents (for delete-before-create convergence)
- `target_message_deleted` — for reaction skip-on-delete
- `recipient_removed` — for `key_shared` removal exclusion
- `file_descriptors` / `existing_file_slice` — for FileSlice authorization
- `bootstrap_context` — local bootstrap context (addr + SPKI) for invite trust materialization
- `is_local_create` — whether the event was locally created (from `recorded_events.source`); gates pending bootstrap trust `InsertOrIgnore` writes so only the invite creator materializes pending trust

Encrypted key resolution/decryption is handled in the encrypted-wrapper stage (`projection/encrypted.rs`), not via `ContextSnapshot`.

### Command/effect execution stage semantics

After `write_ops` are applied transactionally, `emit_commands` are executed in order
by explicit handlers in the pipeline. Commands may call `project_one` recursively
(e.g., to retry guard-blocked events), which is safe because each re-projection goes
through the same pure projector → apply engine path. Command identities are derived
from event identity for idempotence — re-running the command executor does not mutate
final state.

### Pipeline/projector split (DRY contract)

1. shared pipeline code handles:
   - event load/decode dispatch,
   - dependency extraction and blocking,
   - signer resolution and signature verification ordering,
   - invoking `EventTypeMeta.context_loader` to build `ContextSnapshot`,
   - executing `write_ops` and `emit_commands`,
   - queue/state transitions and terminal status writes.
2. per-event projector code handles:
   - event-specific predicate/policy logic,
   - returning `ProjectorResult` with deterministic `write_ops` and `emit_commands`.
3. projector-specific SQL context queries live in event modules (`queries.rs` or
   projector-local helpers), not in shared pipeline files.
4. per-event projector functions do not access the database, implement custom
   dependency resolution, signature pipeline, or queue/terminal-write paths.

### Default write policy

1. immutable and idempotent materialization uses `InsertOrIgnore`,
2. avoid `INSERT OR REPLACE`,
3. deletions are explicit `Delete` WriteOps (never hidden side effects).

Endpoint observation policy:
1. observations (runtime endpoint observations from section 2.4 "Endpoint observations") are append-only rows with TTL (`observed_at`, `expires_at`),
2. ingest uses `INSERT OR IGNORE` (no in-place refresh),
3. derive `first_seen`/`last_seen` via `MIN(observed_at)`/`MAX(observed_at)` queries when needed.

## 4.3 Emitted-event rule

If projector `A` emits event `B`:

1. emit canonical `B` only (normal persistence/queue path),
2. allow `B` to project through `B`'s own projector/autowrite table.

`autowrite` means the projector's default deterministic write path: `InsertOrIgnore` materialization into its owned projection table with no cross-module side effects.

Projectors should not directly write into another event type's projection table except rare, explicitly documented operational exceptions.

Deterministic emitted-event rule detail:
1. deterministic emitted event types still use the same emitted-event flow (`emit -> persist -> self-project`),
2. they use schema-marked unsigned mode for determinism (no signer fields),
3. shared pipeline applies deterministic derivation checks for those types in place of signer checks.

## 4.4 Explicit special cases

Some behavior stays explicit by design:

1. deletion/tombstone cascades (`message_deletion` and related checks),
2. accepted-workspace binding handling in `invite_accepted` (`invites_accepted` write + explicit `RetryWorkspaceEvent` replay trigger),
3. identity/removal policy checks from TLA guards.

### Deletion intent + tombstone lifecycle

Deletion uses a two-stage model so deletes stay deterministic when events arrive out of order. 

**Stage 1: deletion_intent write.**
The `MessageDeletion` projector always emits an idempotent `deletion_intent` write keyed
by `(recorded_by, target_kind="message", target_id)`. This records the intent to delete
regardless of whether the target message exists yet.

**Stage 2: tombstone + cascade.**
- If the target message exists in projected state, the projector also emits tombstone
  (`deleted_messages`) write ops and cascade deletes (`messages`, `reactions`) in the same
  apply batch.
- If the target does not exist yet, only the intent is recorded. No imperative retries.

**Delete-before-create convergence:**
Target-creation projectors (`project_message_pure`) check for matching `deletion_intent`
rows in their context snapshot and immediately tombstone on first materialization. The
tombstone row uses the original deletion event's ID and author from the intent, ensuring
identical final state regardless of arrival order.

**Monotonic deletion state:**
- `active → tombstoned` is allowed.
- `tombstoned → active` is never allowed by replay.
- Physical row removal is a separate compaction concern; projector semantics prefer tombstones.

**Cleanup fanout:**
Reaction cleanup on message delete is represented as explicit deterministic `Delete` WriteOps
in the `ProjectorResult`, not hidden side effects. Reactions arriving after their target
message is deleted (or has a deletion intent) are structurally valid but produce no row.

### Replay/reorder/idempotence deletion invariants

These invariants are enforced by tests (`test_deletion_invariant_*`):

1. **Duplicate replay:** Re-projecting a deletion event leaves state unchanged after first application.
2. **Order convergence:** Delete-before-create produces identical tombstone rows as create-before-delete.
3. **Replay invariance:** Full forward replay from event log reproduces identical tombstone state.
4. **Auth determinism:** Authorization failure paths are deterministic from projected context snapshot.
5. **Cleanup completeness:** No live reactions remain for tombstoned messages; no query can surface deleted entities.
6. **Command idempotence:** `deletion_intent` identities are stable (derived from event identity); re-running does not mutate final state.
7. **Monotonicity:** Once tombstoned, a message cannot revert to active state.

---

# 5. Dependency Blocking and Unblocking

## 5.1 Blocked dependency persistence

Blocked state uses two projection tables:

1. `blocked_event_deps(peer_id, event_id, blocker_event_id)`:
   - unique blocker edges per blocked event.
2. `blocked_events(peer_id, event_id, deps_remaining)`:
   - small header row with unresolved unique blocker count.

Rules:
1. missing deps are deduped before write,
2. blocker edges are persisted in `blocked_event_deps`,
3. `deps_remaining` is written from that deduped blocker set,
4. `blocked_event_deps` stays the canonical "currently blocked?" source for queue admission checks; `blocked_events` is a performance header for cascade scheduling.

We do not persist a global transitive dependency graph as an always-updated materialized structure. Instead, we persist only currently-blocked edges needed for unblock scheduling (`blocked_event_deps`) plus per-event blocked headers (`blocked_events`).

Dependencies are extracted per projection attempt from schema metadata for the current event type. Example: projecting a `Reaction` reads its declared dependency fields (`target_event_id`, `author_id`, `signed_by`) from the parsed event, checks presence in `valid_events`, and writes block rows only for missing deps.

## 5.2 Counter-based Kahn cascade unblock

Unblocking uses a counter-driven Kahn-style cascade:

1. when blocker `X` becomes valid, read candidates from `blocked_event_deps` by (`peer_id`, `blocker_event_id`),
2. decrement `blocked_events.deps_remaining` for each candidate,
3. when a candidate reaches zero remaining deps, delete its `blocked_events` header row and project it through the same canonical projection entrypoint,
4. if that candidate becomes valid, treat it as the next blocker and continue the cascade.

Implementation detail:
1. `blocked_event_deps` is read-only during per-step cascade work,
2. stale rows are bulk-cleaned only after cascade transitions occur (valid/rejected terminal rows); this cleanup runs in the same projection transaction boundary as terminal-state writes so readers do not observe partial unblock state,
3. guard retries run after this dep cleanup so guard queries see current state. 

Design note:
1. a SQL-only cascade (`DELETE ... RETURNING` + zero-row checks) is simpler,
2. local benchmark runs during refactor showed the counter path materially faster in `tests/topo_cascade_test.rs` workloads (exact multiplier environment-dependent), so counter-based cascade is the default.

## 5.3 Event creation API

Three creation entry points exist:

1. `create_event_synchronous(...) -> event_id` (current Rust symbol: `create_event_synchronous`),
2. `create_signed_event_synchronous(...) -> event_id` (current Rust symbol: `create_signed_event_synchronous`),
3. `create_encrypted_event_synchronous(...) -> event_id` (current Rust symbol: `create_encrypted_event_synchronous`).

The `_sync` suffix in current symbols means "synchronous/blocking creation"
(not sync/reconciliation protocol semantics). The canonical semantics are
`*_synchronous`.

`create_event_synchronous` uses the same internal path as workers and returns
success only when terminal state is `valid` for the target `recorded_by`.
This preserves imperative orchestration ergonomics:

1. create event A synchronously,
2. create dependent event B in the next line with no ad-hoc waits.

## 5.4 Signer pipeline

Signer refs (`signed_by` + `signer_type`) are dependency metadata using the same blocking mechanism as other event references. Missing signer dependency writes blocker rows in `blocked_event_deps`, updates `blocked_events.deps_remaining`, and returns `Block`, identical to any other missing dep.

Ordering:
1. signer key is resolved only after all required deps (including the signer dep itself) are available,
2. signature verification runs after signer key resolution succeeds,
3. invalid signature → `Reject`, never `Block`.

One shared signer helper handles all signed event families. There is no identity-specific signer verification path; every signed event type uses the same resolve-by-(`signer_type`, `signed_by`) pipeline.

Schema-marked unsigned exemption:
1. deterministic emitted event types are schema-marked `signer_required=false`,
2. the pipeline skips signer dependency extraction and signature verification for those types,
3. validation uses deterministic-derivation checks from dependencies/context instead.

Tenant-scoped signer behavior: signer resolution and verification are scoped to the projecting tenant's `recorded_by`. Missing or invalid signer state in tenant A does not leak effects into tenant B.

---

# 6. Encrypted Events (Same Model, No Fork)

## 6.1 Wrapper integration

Encrypted wrapper is a normal event type in the same registry.
It uses flat fields such as `key_event_id`, mandatory `inner_type_code`, `ciphertext`, and auth metadata.

Wrapper field rule:
1. `inner_type_code` is mandatory (fixed-width).
2. ciphertext size is deterministic: derived from `inner_type_code` because all inner plaintext types have fixed wire sizes.
3. no `ciphertext_len` field exists in the canonical wire format; the parser computes expected ciphertext size from `inner_type_code`.
4. if we later adopt padded/opaque envelopes, this can be revisited deliberately.

## 6.2 Projection adapter stage

Projection flow:

1. parse outer encrypted wrapper,
2. resolve outer deps (including key dependency),
3. if missing deps: block through normal dependency path (`blocked_event_deps` + `blocked_events`),
4. verify envelope signature/auth,
5. decrypt,
6. decode inner event using normal registry,
7. verify `inner_type_code` matches decoded inner event type (mismatch -> reject),
8. reject nested encrypted wrapper,
9. resolve inner deps via same schema dependency engine (presence check uses the same blocker tables and outer-event anchoring),
10. skip inner dep type-code enforcement for decrypted inners because inner deps may legitimately target encrypted wrapper events that carry admissible plaintext,
11. run normal inner signer + projector stages,
12. mark outer event valid only if inner projection succeeds.

Decryption is an adapter stage inside the same projection pipeline, not a second projection system.

## 6.3 Plaintext policy

1. default: no persisted plaintext queue,
2. plaintext exists in memory during projection only,
3. optional short-lived cache can be added later for performance.

Current canonical plaintext families:
1. identity/auth chain events (`workspace`, `invite_accepted`, `user_invite_shared`, `peer_invite_shared`, `user`, `peer_shared`, `admin`, removals),
2. local identity/support events (`peer_secret`, `key_secret`, bootstrap helper events),
3. content metadata events that are intentionally cleartext in this POC (`message_attachment`, `file_slice`, `reaction`, `message_deletion`, `bench_dep`).

Encrypted wrapper events remain canonical but carry ciphertext payloads whose inner event type is validated by `inner_type_code` before inner projection.

---

# 7. Durable Queue and Worker Model

## 7.1 Queue tables

Operational queues:

1. `project_queue(peer_id, event_id, available_at, attempts, lease_until)`,
2. `egress_queue(connection_id, frame_type, event_id, payload, attempts, lease_until, sent_at, dedupe_key)`.

Canonical tables and queue tables stay separate.

## 7.2 Workers

Current runtime ingest/worker shape:
1. sync ingest receiver path:
   - receive `Frame::Event` blobs,
   - decode + canonical insert (`events`, `neg_items`, `recorded_events`) + `project_queue` enqueue in one transaction,
   - commit, then drain `project_queue`.
2. project worker/drain:
   - claim batch, project each event in autocommit (`valid|block|reject`), batch-dequeue successes, mark retry on failure. WAL autocheckpoint deferred during drain (skipped in low_mem mode).
3. egress worker:
   - claim per connection, send frame, mark sent or retry.
4. cleanup worker:
   - reclaim expired leases, purge stale/sent operational rows, TTL endpoint cleanup.

Queue claim/lease/retry/backoff logic is DRY and shared across `project_queue` and `egress_queue`.

## 7.3 Egress production

Egress rows are produced by:

1. negentropy reconciliation decisions (`runtime/sync_engine/session/control_plane.rs`),
2. incoming `HaveList` responses and need buffering (`runtime/sync_engine/session/initiator.rs`),
3. control protocol producers (`Frame::NegOpen`, `Frame::NegMsg`, `Frame::HaveList`, `Frame::Done`, `Frame::DataDone`, `Frame::DoneAck`, `Frame::IntroOffer`) in `shared/protocol.rs`,
4. optional proactive send pathways (future optimization hooks in this queue model).

For canonical event transfer, egress rows carry `event_id`; canonical blob is read at send time.

## 7.4 Dedupe and purge

1. `project_queue` is transient and purged on terminal decision (`Valid`, `Reject`, or `AlreadyProcessed` for the `(peer_id, event_id)` projection target),
2. enqueue uses dedupe guards and skips terminal/blocked states,
3. duplicate enqueue races are safe via `INSERT OR IGNORE` plus terminal fast-drop checks,
4. `attempts` is retry bookkeeping (backoff, lease recovery, alert thresholds), not business truth.

## 7.5 Atomicity boundaries

Must be atomic:

1. canonical event insert + recorded insert + project enqueue,
2. projection state transition + project dequeue,
3. unblock update + project requeue.

Can be eventual:

1. transport send,
2. queue cleanup/purge,
3. metrics/logging.

## 7.6 Multi-source download coordination

Multi-source download uses deterministic per-event ownership to split work
across concurrent sessions without a central coordinator barrier:

1. **Discovery**: each session runs negentropy with its source, discovering
   need_ids (events the sink needs). Push (have_ids) proceeds immediately.
2. **Streaming ownership dispatch**: as need_ids are discovered during
   reconciliation, each is routed through an ownership predicate:
   `hash(event_id[0..8]) % total_peers == peer_idx`. Owned events get
   HaveList immediately (pipelining data transfer with reconciliation).
   Non-owned events are buffered for fallback.
3. **Threshold-based claim-all**: when need_ids count is small (below
   `total_peers * 20`), the session claims ALL need_ids regardless of
   ownership. This handles source-unique events (identity chains, markers)
   that only exist at one source and cannot be downloaded by their
   deterministic "owner" peer which connects to a different source.
4. **Fallback discard**: after reconciliation, buffered non-owned events
   are discarded. Their deterministic owners handle them from their
   respective sources (or the threshold rule claims them when counts are
   small enough).

**Critical invariant — streaming pull dispatch.** HaveList frames MUST be sent
during reconciliation rounds, not deferred until after reconciliation completes.
The `wanted` table provides natural dedup so streaming dispatch is safe.

Key properties:
- Single-peer degenerates naturally: `total_peers <= 1` means all events owned.
- Work division is deterministic — no coordinator barrier, no collection window.
- Source-unique events handled by threshold fallback without cross-source state.
- Undelivered events re-appear as need_ids in the next session cycle.
- Push path (egress streaming) runs independently during pull dispatch.
- Sink-side transfer accounting can be audited via `recorded_events.source`
  tags (`quic_recv:<peer_id>@<ip:port>`) and grouped by source peer.

### Pre-registration of peers

All `PeerCoord` handles must be registered before spawning connect loop threads.
This ensures `total_peers` is correct from the first session. Without
pre-registration, early threads see `total_peers=1` and claim all events,
defeating the ownership split.

### Implementation decisions

A naive negentropy implementation runs one session per peer pair: each session
has its own `batch_writer` thread for persistence, and after reconciliation it
sends HaveList for all need_ids and streams all have_ids directly. This works
for 1:1 sync but breaks down when a sink pulls from N sources concurrently:

1. N independent `batch_writer` threads all write to the same SQLite DB,
   causing WAL contention and lock timeouts.
2. Multiple sources discover the same need_ids. Without coordination each
   source sends the full set, wasting bandwidth proportional to overlap.
3. If one source is slow, its events are delayed until its session completes.
   No other source can pick up the slack.

The multi-source design addresses each of these:

**Shared batch_writer.** All concurrent sessions feed events into a single
shared `mpsc` channel consumed by one `batch_writer` thread. This eliminates
write contention entirely — only one thread ever holds the SQLite write lock.
Do not add an in-memory dedup set in front of the shared writer:
- Pre-writer dedup causes data loss if the writer transaction rolls back
  (event marked "seen" but never persisted; peer retransmissions silently dropped).
- A global in-memory "seen set" grows without bound for long-running daemons (~90 bytes per EventId), which conflicts with low-memory goals.
- `INSERT OR IGNORE` in `batch_writer` handles duplicates correctly and cheaply.

**Deterministic ownership for pull splitting.** Each peer pushes all have_ids
without coordination — the push path runs at full speed. The pull path uses
`hash(event_id) % total_peers` to split need_ids across sessions, so each
source sends roughly `1/N` of the shared events. For single-peer sync,
ownership degenerates naturally (all events owned).

**Session-cycle reassignment.** Each session starts fresh with a new negentropy
snapshot. If a peer fails to deliver its owned events (slow, disconnected),
those events re-appear as need_ids in the next session cycle and get claimed
by the next session connecting to a source that has them.

**Thread-per-connection.** Each incoming connection spawns a `std::thread`
with a dedicated single-threaded tokio runtime. This isolates connection
failures, avoids `!Send` constraints from `rusqlite` leaking into the async
task graph, and allows each connection to share the `mpsc::Sender` to the
shared batch_writer.

**Incremental egress enqueue.** Have_ids from reconciliation are buffered and
drained incrementally per main loop iteration rather than enqueued in one burst.
This interleaves egress enqueue with event streaming so the data stream is not
starved while processing large reconciliation results.

**Negentropy snapshot ordering.** `BEGIN` must precede `rebuild_blocks()` so
the negentropy storage sees a consistent read snapshot of the events table.
Without this, concurrent writes from the batch_writer can produce an
inconsistent view during block rebuilding.

## 7.7 Negentropy implementation notes

Baseline implementation:
1. `neg_items` stores shared-event membership tuples (`workspace_id`, timestamp, event id bytes).
2. Per-session block indexes are rebuilt into `session_blocks` for reconciliation rounds.
3. Control-plane reconciliation uses `NegOpen` and `NegMsg` frames; results drive `HaveList`.
4. Data-plane transfer streams `Event` frames while reconciliation can continue in parallel.
5. Multi-source coordination does not replace negentropy; it consumes per-peer `need_ids` discovered by negentropy.

Primary code references:
1. `src/runtime/sync_engine/negentropy_sqlite.rs`
2. `src/runtime/sync_engine/session/control_plane.rs`
3. `src/shared/protocol.rs`

---

# 8. CLI and Daemon Contract

The CLI/daemon operational shape is primarily for operability, testing, and demo workflows in this POC; it is not itself part of canonical protocol semantics.

## 8.1 Operational shape

1. one daemon per profile/peer (`topo start`),
2. local RPC control socket,
3. unified CLI (`topo`) with subcommands that route through RPC to the daemon.

### CLI-to-RPC principle

All CLI commands that read or mutate workspace state **must** go through RPC to the running daemon. The CLI binary should never open the database directly for queries or operations that the daemon can serve. This ensures:

1. workspace scoping is always applied consistently (via the daemon's active tenant/peer),
2. the daemon can coordinate side effects (runtime restarts, invite refs, connection management),
3. there is a single authority for session-local state (active peer, invite aliases).

Exceptions where direct DB access is acceptable:
- **daemon startup** (`topo start`): the daemon itself opens the DB to initialize schema and discover tenants,
- **DB registry management** (`topo db add/list/remove`): operates on a local JSON config file, not the SQLite DB,
- **shell completions** (`topo completions`): pure CLI metadata, no DB involved.

When adding a new CLI command, always add a corresponding `RpcMethod` variant, catalog entry, and server dispatch handler. The CLI handler should call `rpc_require_daemon()` and format the response for display.

RPC and locality flow reference: [DESIGN_DIAGRAMS.md](./DESIGN_DIAGRAMS.md) section `0` ("RPC Dispatch And Event Locality").

### RPC wire contract

1. local RPC uses a versioned envelope (`RpcRequest.version`, `RpcResponse.version`),
2. transport framing is `u32` big-endian length-prefixed JSON,
3. server rejects oversized RPC frames (>16 MiB),
4. daemon enforces a bounded concurrent RPC connection cap.

### Daemon session-local state

Daemon RPC state owns local UX/session aliases that are intentionally non-canonical:
1. active peer selection for multi-tenant DBs,
2. invite-link numeric references (session-local aliases to full `topo://...` links),
3. channel aliases + active-channel selection per peer.

These are operator ergonomics, not protocol facts; they do not project into canonical event state.

### Local-echo reconciliation (`client_op_id`)

Frontends need instant optimistic feedback on user actions (send, react, attach file) even while the backend is busy with sync or projection. The `client_op_id` mechanism provides this:

1. Frontend generates a unique `client_op_id` string and passes it with the write RPC (`Send`, `React`, `SendFile`).
2. Frontend immediately shows an optimistic row keyed by `client_op_id` — no server round-trip needed for display.
3. Daemon creates the event normally and stores a local mapping: `client_op_id → event_id` in the `local_client_ops` table (not replicated).
4. When building `View` or `Messages` responses, the daemon annotates canonical projected items with their `client_op_id` (via LEFT JOIN on the mapping table).
5. Frontend polls the view and sees a canonical message tagged with `client_op_id: "abc"` — drops the optimistic row. Done.

The frontend reconciliation is a single selector: `visible = canonical ∪ {o ∈ optimistic | o.client_op_id ∉ canonical.client_op_ids}`. No status machine, no async state tracking, no merge logic. The `client_op_id` is purely optional and backward compatible — commands without it work exactly as before.

The `local_client_ops` table is pruned periodically (entries older than 24h). It is local UX state only.

### DB registry selector contract

CLI database selection supports a local registry (`~/.topo/db_registry.json`, overridable by `TOPO_REGISTRY_DIR`) with:
1. alias names,
2. 1-based numeric selectors,
3. default DB selection for the implicit `--db topo.db` case.

Selectors resolve in priority order: existing path -> alias -> index -> passthrough path.

## 8.2 Testing and agent ergonomics

Assertion-first commands are first-class:

1. `assert-now`,
2. `assert-eventually`,
3. low-memory realism/perf harnesses: `scripts/run_lowmem_proxy.sh`, `scripts/run_perf_serial.sh lowmem` (Linux-only).

`assert-eventually` is preferred over ad-hoc sleeps for both deterministic tests and agent self-play loops.

Low-memory Linux-only note:
1. proxy/regimen harnesses sample `/proc/<pid>/status` and `/proc/<pid>/smaps`,
2. hard-ceiling validation uses cgroup v2 (`memory.max`, `memory.events`),
3. RSS-sampling tests in `tests/low_mem_test.rs` are sanity checks (ignored by default for budget assertions),
4. non-Linux platforms should use functional low-memory tests and device-native profiling instead of the Linux proxy gate.

### Multi-source large-file catchup perf methodology

The dedicated large-file catchup harness in `sync_graph_test.rs` validates both correctness and source-distribution behavior:
1. seed source `S0` with signed `message_attachment + file_slice` events,
2. clone that exact dataset to all non-sink sources,
3. run sink-driven multi-source catchup,
4. assert sink `file_slice` event-id set exactly equals the seeded set,
5. attribute each received file slice by source from `recorded_events.source` (`quic_recv:<peer_id>@<ip:port>`),
6. assert each source contributes a minimum fair-share fraction, not merely `>0`.

Current smoke fairness floor uses `min_fair_share_fraction = 10%` of `(total_slices / source_count)`.

### Low-memory perf methodology

Low-memory coverage is split into two lanes:
1. **Functional lane** (`tests/low_mem_test.rs`) for fast correctness checks in low-memory mode.
2. **Realism lane** (`scripts/run_lowmem_proxy.sh`) for process-isolated Linux memory accounting and optional cgroup hard caps.

Functional lane defaults:
1. runs by default: `low_mem_ios_functional_smoke_2k`,
2. RSS-sampling budget tests are ignored by default: `low_mem_ios_budget_smoke_10k`, `low_mem_ios_budget_soak_million`.

Realism lane defaults:
1. driven through `scripts/run_perf_serial.sh lowmem`,
2. default scenarios: `50k+10k` message delta and `50k+20x1MiB` file delta,
3. default enforcement: `LOWMEM_PROXY_CGROUP_ENFORCE=1`, `LOWMEM_PROXY_CGROUP_LIMIT_KB=22528`.

Optional low-memory hardening scenarios:
1. enable with `PERF_LOWMEM_POC_ENABLE=1`,
2. optionally add `PERF_LOWMEM_RUN_LARGE_TARGET=1` and `PERF_LOWMEM_RUN_SMALL_BRACKET=1`,
3. available scenarios include `1M+10k` messages, `500k+100x1MiB` realism files, and `0+10k x1MiB` extreme files.

Low-memory proxy output fields used by perf reporting:
1. `LOWMEM_BUDGET_KB` and `PASS_UNDER_24MB`,
2. `CGROUP_ENFORCED`, `CGROUP_LIMIT_KB`, `CGROUP_OOM`, `CGROUP_OOM_KILL`,
3. `MAX_BOB_TOTAL_KB` (receiver working-set peak from smaps categories).

Linux hard-cap policy:
1. receiver daemon is moved into a dedicated cgroup v2 with `memory.max=22 MiB` and `memory.swap.max=0`,
2. run fails if `memory.events:oom_kill > 0`,
3. `22 MiB` Linux cap is used as margin against iOS `24 MiB` Jetsam-accounting differences.

---

# 9. Identity, Auth, Invites, Trust Anchor, and Removal

A secure Slack alternative requires a clear notion of team membership, Signal/Slack-like invite links, end-to-end encryption, and message history provision.

For reliability reasons we bias toward making key agreement a layer on top of the auth CRDT, not the same as the auth CRDT or necessary to read the auth CRDT. (Though it should be possible to build either such design with this protocol.)

We explore a simple placeholder model of this "plaintext signed auth graph as basis for group key agreement" type here.

## 9.1 TLA-first requirement

Identity phase projector predicates are derived from an explicit TLA causal model.
Rust projector guards map 1:1 to named model guards.

Required invariants (TLC-checked):
1. `InvWorkspaceAnchor`: workspace validity requires a matching accepted workspace binding,
2. `InvSingleWorkspace`: at most one workspace row per peer in the workspaces table,
3. `InvForeignWorkspaceExcluded`: a foreign workspace event can never become valid,
4. `InvTrustAnchorMatchesCarried`: accepted workspace winner always matches an event-carried `workspace_id`.

Workspace binding proof: the invite determines which workspace a peer accepts; only that workspace can project. The guard mechanism checks that a workspace event's id matches the binding, structurally excluding foreign workspace events.

Invite-workspace binding: `invite_accepted` writes `invites_accepted` rows directly from its own `workspace_id` field. Winner selection is read-time deterministic (`ORDER BY created_at, event_id LIMIT 1`). No pre-projection capture authority.

Projector-spec mapping: each Rust projector predicate maps to a named TLA guard. The full mapping is maintained in `docs/tla/projector_spec.md`. Any divergence between projector logic and TLA guards is treated as a spec bug that must be resolved before adding new behavior.

### TLA conformance cadence

1. Per change (required): when modifying event schemas, projector predicates, dependency extraction, signer rules, or emitted-command semantics, run `scripts/check_projector_tla_conformance.py` and `scripts/check_projector_tla_bijection.py`.
2. Nightly/periodic full pass: run the expanded TLC configs (`docs/tla/event_graph_schema_expanded.cfg`, `docs/tla/event_graph_schema_expanded_single_peer.cfg`) and record drift.
3. Pre-merge gate for identity/trust/bootstrap changes: run full conformance + expanded TLC before merge.
4. If behavior changes, update `docs/tla/projector_spec.md` and `docs/tla/projector_conformance_matrix.md` in the same change.
5. Before release and perf-baseline cuts, rerun the same conformance checks so design+code+mapping stay aligned.

### Layered conformance model

Tests are organized into three layers, each exercising a different scope of the TLA+ conformance contract:

1. **Projector unit** (`tests/projectors/*_projector_tests.rs`) — pure function contract. Each test calls `project_pure(event, ctx)` directly with a hand-built `ContextSnapshot` and asserts decision, write_ops, and emit_commands. Covers event-local predicates (accepted workspace binding, signer mismatch, deletion author, bootstrap trust emission, file slice auth).
2. **Pipeline integration** (`src/state/projection/apply/tests/`) — shared pipeline stages. Tests exercise `project_one_step` end-to-end through dep presence, dep type checks, signer resolution, encrypted wrapper decrypt/dispatch, and cascade unblock. Uses a real SQLite DB with the full projection pipeline.
3. **Replay/order conformance** (`src/state/projection/apply/tests/`) — model-critical convergence properties. Source-isomorphism tests replay the same events in different orderings and assert identical terminal state. Covers out-of-order convergence, idempotent replay, stable terminal state, and deletion two-stage convergence.

Coverage is tracked in `docs/tla/projector_conformance_matrix.md` (spec_id → check_id → test_id with pass/break polarity) and enforced by CI gate scripts (`scripts/check_projector_tla_conformance.py`, `scripts/check_projector_tla_bijection.py`).

## 9.2 Invite model

Use split invite event types:

1. `user_invite_shared`,
2. `peer_invite_shared`,
3. `invite_accepted`.

We do not use multimodal `invite(mode=...)` type (even though it would be DRY) because it complicates the TLA model.

Implementation uses shared invite helper logic with per-type policy tables.
Interactive CLI keeps real invite links (`topo://invite/...`, `topo://link/...`) in frontend state; session-local invite numbers are aliases to those links.

### Invite link wire format (v3, plaintext)

Invite links use a plaintext, slash-delimited, hex-encoded format. All fields are labeled for readability and the link contains no spaces or characters that break URL selection (continuously linkifiable). This is intentional for debugging — all data (addresses, workspace ID, keys, SPKI fingerprint) is visible in the link itself.

User invite:
```
topo://invite/v3/user/eid.<hex64>/key.<hex64>/wid.<hex64>/spki.<hex64>/addr.<a1>,<a2>
```

Device-link invite:
```
topo://link/v3/device_link/eid.<hex64>/key.<hex64>/wid.<hex64>/uid.<hex64>/spki.<hex64>/addr.<a1>,<a2>
```

Field labels: `eid` = invite event ID, `key` = invite private key, `wid` = workspace ID, `uid` = user event ID (device-link only), `spki` = bootstrap SPKI fingerprint. All ID/key fields are 32-byte hex (64 hex chars). Address tokens use the same display format as `to_bootstrap_addr_string` (port omitted when default 4433, IPv6 bracketed), comma-separated.

## 9.3 Accepted-workspace cascade

`invite_accepted` records accepted-workspace binding rows for `workspace_id` in tenant scope (`invites_accepted`).

Required semantics:
1. workspace is not valid until an accepted-workspace binding exists,
2. invite events and invites are not forced-valid,
3. normal signer/dependency chain still governs validity,
4. bootstrap transport trust rows (`invite_bootstrap_trust`, `pending_invite_bootstrap_trust`) are projection-owned state, produced by concrete event projectors:
   - `user_invite_shared` projector writes pending bootstrap trust rows (boot variant, local-create gated),
   - `peer_invite_shared` projector writes pending bootstrap trust rows (first variant, local-create gated),
   - `invite_accepted` projector writes accepted bootstrap trust rows using local `bootstrap_context`,
   - `peer_shared` projector deletes matching bootstrap trust rows when steady-state trust appears.
   Projectors read local `bootstrap_context`; the service layer writes `bootstrap_context` rows only, never trust rows directly.
   Invite command paths do not write pending bootstrap trust directly; local invite events are projected and materialize pending trust through this command path.
   This follows the same poc-6 cascade pattern where `invite_accepted` projection drives trust establishment.

Self-invite bootstrap stays explicit:

1. create `workspace`,
2. locally self-bind with `invite_accepted(workspace_id = workspace_event_id)`,
3. create bootstrap `user_invite_shared`,
4. cascade unblocks `workspace -> user_invite_shared -> user -> peer_invite_shared -> peer_shared`.

Guard placement rules:
1. accepted-workspace guard applies to root workspace events only; foreign root ids must not become valid,
2. `invite_accepted` is a local accepted-workspace binding event (no invite-presence dependency gate). It writes its own binding row from carried `workspace_id`; winner selection is deterministic at read time (`created_at,event_id`),
3. new user/device/peer identities are still gated by normal signer/dependency validation in the same peer scope (for example `user -> user_invite_shared`, `peer_shared -> peer_invite_shared`),
4. bootstrap transport trust is persisted in SQL and queried at connection creation time; projected peer keys are not treated as in-memory-only authority.

This approach makes first-user creation and device linking isomorphic to subsequent-user additions and device linking. Auth graph logic is easy to get wrong, so this simplification is valuable. 

### 9.3.1 Bootstrap-to-steady-state trust walkthrough

1. Inviter projects `user_invite_shared`/`peer_invite_shared` and writes pending bootstrap trust rows from local `bootstrap_context`.
2. Joiner accepts invite (`invite_accepted`) and writes accepted bootstrap trust rows for its scoped tenant.
3. Initial sync sessions may authenticate via bootstrap trust rows while full identity events are still converging.
4. `peer_shared` projection consumes matching bootstrap trust rows with deterministic `Delete` write-ops once steady-state PeerShared trust is present.
5. Ongoing dial/accept checks then use SQL trust queries (`is_peer_allowed`) with no trust writes in read paths.

## 9.4 Sender-subjective encryption proof-of-concept

The proof-of-concept requires that we show that modern group key agreement schemes are possible with this approach, but we do not seek to build one, instead opting for a simple placeholder.  

For each encrypted message in the prototype:

1. sender creates a fresh local key event,
2. sender emits one key-wrap event per currently eligible recipient peer pubkey,
3. encrypted content references key dependency via normal event refs.

After observing `user_removed` or `peer_removed`, sender excludes removed recipients from subsequent wraps.
Historical re-encryption or key history request/response mechanism is out of scope for the proof-of-concept.

### 9.4.1 Bootstrap key distribution via invite-key wrap/unwrap

Bootstrap key acquisition uses the same `key_shared` event type and wrap/unwrap logic as runtime sender-keys. The only difference is the recipient: at invite creation the inviter wraps content-key material to the invite public key (X25519-derived from the Ed25519 invite signing key), rather than to a peer's PeerShared public key.

(In this way we demonstrate that the auth graph is compatible with the goal of sharing key history (access to existing messages) with new users and devices, a potential requirement of a Slack-like workplace messenger.)

Flow:
1. At invite creation, the inviter wraps current content key(s) to the invite key via `key_shared` events (delivered during bootstrap sync, not embedded in the invite link payload).
2. At invite acceptance, the joiner unwraps using the invite private key (carried in the link) and the inviter's public key (from the `key_shared` event's signer).
3. The joiner materializes local `key_secret` events with deterministic event IDs (BLAKE2b hash of key bytes → `created_at_ms`), ensuring both inviter and joiner derive identical `key_event_id` values.
4. Encrypted events that depend on those key IDs can then be projected normally through the standard block/unblock cascade.

All key acquisition flows through the same event-backed wrap/unwrap path.

## 9.5 Transport credential lifecycle model

This section covers the lifecycle state machine for the three trust sources: PeerShared-derived SPKIs (steady-state), `invite_bootstrap_trust`, and `pending_invite_bootstrap_trust`.

Credential transition model: invite acceptance may install a bootstrap transport cert first; projection later installs the PeerShared-derived cert. Runtime enforces one-way transition (no bootstrap-after-PeerShared downgrade).

Consumption: when a PeerShared event is projected, the PeerShared projector deletes matching `invite_bootstrap_trust` and `pending_invite_bootstrap_trust` entries for that SPKI in the same projection apply transaction. This happens at projection time, not on trust check reads — trust check reads (`is_peer_allowed`, `allowed_peers_from_db`) are pure queries with no write side-effects.

Lookup shape: trust and removal queries resolve peers via projected `peers_shared.transport_fingerprint` (indexed by `(recorded_by, transport_fingerprint)`), not by runtime fallback scans over `peers_shared.public_key`.

TTL expiry: bootstrap trust rows are time-bounded. Unconsumed entries expire and are purged.

Removal cascade: `peer_removed` cascades trust removal across all three sources for the affected peer.

Invite ownership: `inviteCreator` tracks which peer created each invite SPKI. Only the invite creator (inviter) may materialize pending bootstrap trust — the joiner must not write pending bootstrap trust when syncing the invite event. This is enforced by the `is_local_create` flag in `ContextSnapshot`, populated from `recorded_events.source`. The TLA+ model captures this via the `inviteCreator[s] = p` guard on `AddPendingBootstrapTrust` and the `InvPendingTrustOnlyOnInviter` invariant.

TLC-verified invariants (from `TransportCredentialLifecycle.tla`, mapped to Rust checks in `docs/tla/projector_spec.md`):
1. `InvSPKIUniqueness` — no two peers share an active SPKI,
2. `InvBootstrapConsumedByPeerShared` — bootstrap trust disjoint from PeerShared trust,
3. `InvPendingConsumedByPeerShared` — pending trust disjoint from PeerShared trust,
4. `InvTrustSetIsExactUnion` — trust set is exact union of three sources,
5. `InvTrustSourcesWellFormed` — all trust sets contain valid SPKIs,
6. `InvMutualAuthSymmetry` — mutual auth requires both peers have credentials,
7. `InvPendingTrustOnlyOnInviter` — pending trust exists only on invite creator's store,
8. `InvCredentialSourceConsistency` — credential presence and source are consistent across bootstrap→PeerShared transition.

Abstract boundary: TLS handshake and session-key derivation remain unmodeled. The TLA spec covers trust-source state transitions but not the cryptographic session establishment that consumes them.

---

# 10. Convergence and Test Invariants

The system is accepted only if these invariants hold:

1. replay invariance:
   - replaying canonical events yields the same projected state.
2. replay idempotency:
   - replaying the same canonical set a second time (2x replay) yields no additional state changes.
3. reverse-order replay invariance:
   - replaying canonical events in reverse order yields the same projected state.
4. reproject invariance:
   - dropping projections and reprojection yields the same state.
5. reorder invariance:
   - out-of-order ingest converges to the same state.
6. source isomorphism:
   - `local_create`, `wire_receive`, and replay converge through the same `project_one` path.
7. tenant isolation:
   - no cross-tenant leakage under scoped queries.

Operational queue rows are excluded from end-state equality fingerprints.

Harness policy:
1. replay invariants (`once`, `twice`, `reverse-order`, shuffled reorder, reproject-no-clear idempotency) are standard checks in the scenario harness.
2. they run after scenario tests that mutate canonical event-store rows.
3. checks are computed from deterministic table-state fingerprints over event-store-derived state.
4. implementation references: `src/testutil/mod.rs` (`verify_projection_invariants`) and scenario coverage in `tests/scenario_test.rs`.

## 10.1 Application-level test assertions

Sync tests assert on application-meaningful data, never on raw event counts.

Why: the identity bootstrap chain produces a variable number of events (workspace/identity events plus local signer/content-key materialization). This count has changed across development and may change again. Tests that hardcode `store_count() == K + N` break silently when bootstrap composition changes.

Rules:
1. **Convergence detection** uses `has_event(event_id)` on a specific known event, not `store_count >= N`.
2. **Assertions** use projection-level counts: `message_count()`, `reaction_count()`, `peer_shared_count()`, `user_count()`, etc.
3. **Never assert** on `store_count()`, `recorded_events_count()`, or `neg_items_count()` — these include identity overhead that varies.
4. **High-volume convergence** samples multiple events (50+) from both sides to avoid premature convergence (a single sample can pass after only partial transfer).
5. **Performance benchmarks** use the same pattern: sample event IDs from the sender, check arrival at the receiver via `has_event()`.

The `sync_until_converged` helper takes a closure for convergence detection:

```rust
sync_until_converged(&alice, &bob, || bob.has_event(&sample), timeout).await;
```

This makes tests resilient to identity chain structure changes while still verifying that the application-level data (messages, reactions, identities) converged correctly.

## 10.2 Lifecycle narrative reference

The end-to-end narrative now lives in [How it Works](#how-it-works), including workspace creation, first-user bootstrap, device linking, joining, discovery, and steady-state sync.
Section 10 stays focused on convergence/test invariants derived from that lifecycle.

---

# 11. Performance and Operational Defaults

1. use SQLite WAL mode and prepared statements,
2. batch worker operations with measured sizing,
3. keep queue purge policies explicit and predictable,
4. monitor blocked counts, queue age, retries, lease churn,
5. provide `low_mem_ios` mode with a target of `<= 24 MiB` steady-state RSS for constrained runtimes (including iOS NSE),
6. in `low_mem_ios`, enforce strict in-flight bounds and prefer reduced throughput over memory spikes,
7. use serial perf measurement (`--test-threads=1`, `scripts/run_perf_serial.sh`) for tail profiling to avoid cross-test interference; profile before tuning,
8. projection drain uses batch dequeue (`mark_done_batch`) and deferred WAL autocheckpoint to reduce per-batch overhead at high cardinality.

Operational payload caps for this prototype (wire-format specifics in section 1.2 and file-flow details in section 12.2):

1. `EVENT_MAX_BLOB_BYTES = 1 MiB` soft cap,
2. `FILE_SLICE_TARGET_BYTES = 256 KiB`,
3. `FILE_SLICE_CIPHERTEXT_BYTES = 262_144` (fixed canonical ciphertext payload per file-slice event).

`file_slice` events (type 25, signed) are signed and validated like other canonical events.
`message_attachment` events (type 24, signed) are file descriptors with deps on `message_id`, `key_event_id`, and `signed_by`.
Retired event type 4 is rejected by unknown-type dispatch in this epoch.

### Low-memory strategy (`low_mem_ios`)

Trust and key sets use SQL indexed point lookups, not full in-memory loading. The projection tables (`invites_accepted`, identity chain tables, bootstrap trust tables) are queried on demand with indexed `(recorded_by, ...)` keys.

There is no dedicated unbounded in-memory trust/key hot cache; low-memory behavior relies on indexed SQL lookups plus statement caching (`prepare_cached`).

Canonical event/trust datasets can grow large on disk; low-memory mode bounds in-memory working set (queues, buffers, caches), not total persisted history.

Runtime low-memory mode is enabled by env var `LOW_MEM_IOS` (truthy except `0`/`false`). Queue/runtime tuning values are centralized in `src/shared/tuning.rs`, including:
1. projection drain/write batch sizing,
2. shared ingest channel caps,
3. session ingest caps,
4. transport receive-buffer limits.

Validation scale requirements: the low-memory path must remain stable at >= 1,000,000 canonical events on disk and >= 100,000 peer trust keys, for sync deltas > 10,000 events or files while targeting a 24 MiB steady-state RSS envelope on representative constrained devices. Throughput may degrade to preserve bounded memory. For very large message histories and trust sets, the design favors bounded memory (smaller in-flight windows and SQL point lookups) over peak throughput.

Caveat: `24 MiB` is an operational target validated by representative low-memory tests and tuning profiles, not a universal guarantee across all kernels/devices/workloads.

Validation harness platform scope:
1. low-memory proxy/regimen perf gates are Linux-only (`/proc` + cgroup v2),
2. Linux proof runs use a stricter receiver hard cap (`22 MiB`) as margin against iOS `24 MiB` operational target differences in memory accounting.
3. default serial lowmem perf lane is fast (`50k+10k` message delta + moderate file delta) and cgroup-enforced,
4. 1M-scale and extreme file-volume lowmem scenarios remain available but opt-in for hardening cycles.

---

# 12. Extensibility Path

The completed prototype is deliberately minimal but extension-friendly.

## 12.1 Richer content surface

Current baseline already includes reactions, message deletion, attachments, and file slices. Additional families (for example edits, richer thread semantics, moderation signals) can be added by:

1. declaring schema + projection table metadata,
2. using default **autowrite** where possible (projector returns deterministic `InsertOrIgnore` writes only, no emitted commands),
3. introducing explicit special projector logic only when policy semantics require it (for example accepted-workspace retries, bootstrap trust supersession, deletion intent/tombstone coupling, or guard-block retry flows).

## 12.2 File attachments and large payload flows

Attachments and slice streaming fit naturally:

1. large payload events remain canonical typed events with fixed wire sizes,
2. file slices use a canonical fixed ciphertext size; final plaintext chunks are zero-padded before encryption,
3. deps and signatures continue to gate integrity and ordering (wire/layout details in section 1.2; queue transfer behavior in section 7.6).

## 12.3 Proactive 1-hop gossip on send

Beyond pull/reconcile sync, send-time proactive push can be layered as an egress producer: 

1. on local canonical event creation, enqueue one-hop egress to currently connected peers,
2. keep dedupe by `(connection_id, event_id)` and existing lease/retry rules,
3. preserve canonical/projector semantics unchanged (transport optimization only).

## 12.4 Subjective encryption with history provision

The baseline sender-subjective O(n) wrap model can incrementally evolve toward a future group-encryption design note (not yet committed in this repository):

1. introduce update-path style shared key structure for better asymptotics,
2. add key request/response healing for inactive peers,
3. add explicit history-availability policy and provisioning events for newly linked devices/users (baseline already has invite bootstrap key distribution and pending-unwrap retry, but not full long-horizon history policy controls),
4. eventually optimize recipient-cover selection (e.g. TreeKEM) while preserving the same canonical dependency/projection model.

This extension path is intentionally additive: it does not require a new storage or projection architecture.

---

# 13. Summary

After completing all phases in `PLAN.md`, the system is:

1. real transport and real daemon operations (no simulator dependency),
2. one canonical event model with strict replayability,
3. one projection/dependency engine for cleartext and encrypted events,
4. queue-driven operational control with explicit atomic boundaries,
5. tenant-scoped shared tables,
6. accepted-workspace and identity behavior grounded in TLA guard mappings.
7. multitenant

The result is a small protocol core with clear upgrade paths instead of a stack of exceptions.

# 14. Event-Module Locality

For developer ergonomics it will be helpful to have event-related logic in the most important event modules, rather than spread across the codebase.

## 14.1 Enforceable locality contract

These rules are mandatory. Violations must be fixed before merge.

1. **Event-module locality rule**: Event modules (`src/event_modules/<type>/`) own all event-type-specific behavior: wire format, projector, commands, queries, and response types. No event-type-specific SQL or logic may live in `src/runtime/control/service.rs` or the projection pipeline.

2. **Service orchestration-only rule**: `src/runtime/control/service.rs` is a thin orchestrator. It handles DB open/close, auth/key loading, cross-module composition, non-event-specific logic (identity bootstrap, invite flows, predicate/assert), and error mapping. It must not contain event-type-specific SQL — it calls event-module APIs.

3. **Direct module routing rule**: Service routes event-local operations directly to event-module command/query APIs (for example: `message::send`, `reaction::list`, `workspace::name`). There is no central `EventCommand`/`EventQuery` service dispatcher.

4. **Workflow-command locality rule**: Multi-step event-domain workflows are still commands and belong in the owning event module `commands.rs` (or `commands/` when split), not in `src/runtime/control/service.rs`. Example: workspace onboarding workflows (`create_workspace`, `join_workspace_as_new_user`, `add_device_to_workspace`) live in `workspace::commands`.

5. **Module split rule**: When an event module exceeds ~300-400 LOC or mixes 3+ concerns, split into a directory module (see 14.4).

6. **Local reactive infra boundary rule**: Local-only subscription lifecycle/feed state is not an event type and lives in `src/state/subscriptions/*`. Event modules only own event-specific subscription filter semantics (`subscription_filter` / `subscription_filters`), not subscription CRUD/feed storage.

## 14.2 Layering convention

Event modules (`src/event_modules/<type>/`) own five concerns. During migration,
some event types may remain single-file under `src/event_modules/<type>.rs`.

1. **Wire** — struct definition, parse/encode, wire layout, `EventTypeMeta`.
2. **Projector** — `project_pure()` function: the pure projector for this event type. Takes `(recorded_by, event_id_b64, &ParsedEvent, &ContextSnapshot)` and returns `ProjectorResult`. Registered in `EventTypeMeta.projector` so the pipeline dispatches via registry lookup with no central match statement.
3. **Projector context loader** — `build_projector_context(...)` (location: `queries.rs` or projector-local helper) performs projector-specific SQL reads and returns `ContextSnapshot`. Registered in `EventTypeMeta.context_loader`.
4. **Commands** — `CreateXxxCmd` struct + `create()` function that builds the `ParsedEvent`, calls `create_signed_event_synchronous`, and returns `EventId`. High-level command helpers callable from service/RPC routes (for example `send`, `react`) and multi-step workflows (for example workspace onboarding) are first-class command APIs in this layer.
5. **Queries** — `list()`, `count()`, `resolve()`, `list_for_message_with_authors()`, etc. — SQL against projection tables scoped by `recorded_by`. All event-specific SQL lives here.
6. **Response types** — serializable structs for the event domain (e.g. `MessageItem`, `MessagesResponse`, `SendResponse`). Owned by the event module, re-exported by `src/runtime/control/service.rs` for external callers.

The projection pipeline (`src/state/projection/apply/`) is orchestration-only:

- Dependency presence check + block row writes
- Dependency type enforcement
- Signer verification (uniform across all signed events)
- Context loading orchestration via `EventTypeMeta.context_loader`
- Registry-driven projector dispatch: `(meta.projector)(recorded_by, event_id_b64, parsed, ctx)`
- Write-op execution and emit-command handling

The service layer (`src/runtime/control/service.rs`) is a thin orchestrator:

- DB open/close and connection management
- Auth/key helpers (`load_local_peer_signer_pub`, `load_local_user_key`)
- Cross-module composition is routed through RPC handlers and event-module queries (for example `workspace::view` combines workspace/message/reaction/user projections)
- Non-event-specific logic (identity bootstrap, invite flows, predicate/assert system)
- Error mapping from module results to `ServiceError`

## 14.3 Routing pattern

### Projector dispatch

`EventTypeMeta` includes:
1. a `projector` function pointer with the uniform signature:

```rust
fn(&str, &str, &ParsedEvent, &ContextSnapshot) -> ProjectorResult
```
2. a `context_loader` function pointer with the uniform signature:

```rust
fn(&Connection, &str, &str, &ParsedEvent) -> Result<ContextSnapshot, Box<dyn Error>>
```

### Service command routing

RPC command handlers (`src/runtime/control/rpc/server.rs`) call owner-module command APIs directly. Example flows:

- `RpcMethod::Send` -> `message::send_for_peer`
- `RpcMethod::React` -> `reaction::react_for_peer`
- `RpcMethod::DeleteMessage` -> `message::delete_message_for_peer`
- `RpcMethod::Ban` -> `user::ban_for_peer`
- `RpcMethod::CreateWorkspace` -> `workspace::commands::create_workspace_for_db`
- `RpcMethod::AcceptInvite` -> `workspace::commands::accept_invite`
- `RpcMethod::AcceptLink` -> `workspace::commands::accept_device_link`
- `RpcMethod::CreateInvite` -> `workspace::commands::create_invite_for_db` / `workspace::commands::create_invite_with_spki`
- `RpcMethod::CreateDeviceLink` -> `workspace::commands::create_device_link_for_peer`
- `RpcMethod::SubCreate` / `SubEnable` / `SubDisable` -> `state::subscriptions::*` (local infra API)

### Service query routing

RPC query handlers (`src/runtime/control/rpc/server.rs`) call owner-module query APIs directly. Example flows:

- `RpcMethod::Messages` -> `message::list`
- `RpcMethod::Reactions` -> `reaction::list`
- `RpcMethod::Users` -> `user::list_items`
- `RpcMethod::Workspaces` -> `workspace::list_items`
- `RpcMethod::Keys` -> `workspace::keys` (which aggregates `user`, `peer_shared`, and `admin` counts)
- `RpcMethod::SubList` / `SubPoll` / `SubState` / `SubAck` -> `state::subscriptions::*`

## 14.4 Module split rule

When an event module exceeds roughly 300-400 LOC or mixes 3+ concerns (wire + commands + queries + projector), split it into a directory module:

```
src/event_modules/<name>/
    mod.rs          — re-exports stable public API
    wire.rs         — event struct, parse, encode, EventTypeMeta, project_pure
    projector.rs    — project_pure + projector-local helpers (if separated from wire)
    commands.rs     — CreateXxxCmd, create(), high-level command helpers
    queries.rs      — query_list, query_count, resolve_*, response assembly
```

`mod.rs` re-exports all public items so callers continue to import from `event_modules::<name>`.

If `commands.rs` becomes long because of multiple workflows, split commands into a directory while keeping `event_modules::<name>::commands::*` stable:

```
src/event_modules/workspace/
    mod.rs
    wire.rs
    projector.rs
    queries.rs
    commands/
        mod.rs
        create_workspace.rs
        join_workspace_as_new_user.rs
        add_device_to_workspace.rs
```

This keeps workflow locality (all workspace lifecycle commands under workspace) without forcing one very large `commands.rs`.

## 14.5 Layout locality rule 

Wire layout constants (wire sizes, text-slot budgets, field offset modules) are owned by the event module that defines the event type:

1. **Single-file events** (`foo.rs`): layout constants live inline in `foo.rs`.
2. **Directory-scoped events** (`foo/`): layout constants live in `foo/layout.rs`.
3. **Shared cross-event primitives** (`COMMON_HEADER_BYTES`, `SIGNATURE_TRAILER_BYTES`, text-slot helpers, encrypted envelope helpers) live in `src/event_modules/layout/common.rs`.
4. **Event modules must not import another event module's layout constants.** Cross-event wire math (e.g. `encrypted_inner_wire_size`) belongs in `layout/common.rs` and imports the needed per-event wire sizes.

Do not reintroduce a global layout monolith. When adding a new event type, define its wire size and offsets in the owning module.

## 14.6 Explicit workspace guard retry

The `invite_accepted` projector emits `RetryWorkspaceEvent { workspace_id }` after writing `invites_accepted`. This explicitly targets the known workspace event for re-projection, flowing through normal `project_one` + cascade. The workspace projector guard-blocks when no accepted-workspace binding exists and unblocks when retried after the binding is written by `invite_accepted`.

## 14.7 Adding a new event type

`dispatch_pure_projector` in `apply/dispatch.rs` looks up the event's type code in the registry and calls the registered projector. No central match statement is required. Each event module owns its complete projection semantics.

When adding a new event type:

1. Define the event struct, parse/encode, and `EventTypeMeta` in `src/event_modules/<type>/wire.rs` (or in `src/event_modules/<type>.rs` for legacy single-file modules).
2. **Add `project_pure()`** — the pure projector function. Set `EventTypeMeta.projector = project_pure`. This is where all projection semantics for this event type live.
3. Add `CreateXxxCmd` + `create()` for command paths.
4. Add `query_*()` functions for any projection-table queries.
5. Add response types and service/RPC-facing convenience helpers in the event module.
6. Add `RpcMethod` variant in `protocol.rs`, catalog entry in `catalog.rs`, and dispatch handler in `server.rs`.
7. Wire `src/runtime/control/service.rs` to call the event module functions, mapping errors to `ServiceError`.
8. Add CLI handler in `main.rs` using `rpc_require_daemon()` — never open the DB directly from CLI.

**Rule**: Event projection semantics MUST live in event modules, not in central projector files. The pipeline must not contain event-type-specific SQL logic; it only orchestrates module-owned context loaders.

---

# 15. Appendix: Implementation Map

This appendix holds concrete Rust file/module references so conceptual sections stay readable.

## 15.1 Projection pipeline map

1. Canonical entrypoint: `src/state/projection/apply/project_one.rs`
2. Dependency and signer stages: `src/state/projection/apply/stages.rs`
3. Module-owned context loaders: `src/event_modules/*/(queries.rs|projector.rs)` via `EventTypeMeta.context_loader`
4. Write/emit executor: `src/state/projection/apply/write_exec.rs`
5. Cascade scheduler: `src/state/projection/apply/cascade.rs`
6. Batch writer orchestration: `src/state/pipeline/mod.rs`
7. Pipeline persist/effects: `src/state/pipeline/phases.rs`, `src/state/pipeline/effects.rs`

## 15.2 Peering/runtime map

1. Runtime task-graph supervisor: `src/runtime/peering/engine/supervisor.rs`
2. Dial loop: `src/runtime/peering/loops/connect.rs`
3. Accept loop: `src/runtime/peering/loops/accept.rs`
4. Session runner seam: `src/runtime/peering/loops/mod.rs`
5. Target planning: `src/runtime/peering/engine/target_planner.rs`
6. QUIC dial/accept lifecycle: `src/runtime/transport/connection_lifecycle.rs`
7. Session I/O construction: `src/runtime/transport/session_factory.rs`
8. Session I/O adapter: `src/runtime/transport/transport_session_io.rs`

## 15.3 Identity and transport boundary map

1. Workspace identity workflows: `src/event_modules/workspace/commands.rs`
2. Identity helper primitives: `src/event_modules/workspace/identity_ops.rs`
3. Invite link codec: `src/event_modules/workspace/invite_link.rs`
4. Transport identity adapter contract: `src/shared/contracts/transport_identity_contract.rs`
5. Transport identity adapter implementation: `src/runtime/transport/identity_adapter.rs`
6. Transport cert/key install/load helpers: `src/runtime/transport/identity.rs`
7. Trust SQL tables + helpers: `src/state/db/transport_trust.rs`
8. Boundary guard script: `scripts/check_boundary_imports.sh`
