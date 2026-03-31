# Topo Protocol Design (Post-PLAN End State)

> **Status: Active** — Topo target protocol design describing the post-PLAN end state.

Topo is a draft protocol design for building full-featured local-first, peer-to-peer, end-to-end encrypted communication and collaboration tools.

This draft design focuses on the minimal necessary feature set to prove the protocol's suitability for building a viable secure replacement for Slack.

Terminology note:
`Topo` is the project and runtime name used throughout this repository.
`workspace` is the term for the logical peer set and shared protocol context; "network" refers only to transport/networking concerns.

## Requirements

1. **Encryption & Auth** - it should be straightforward to implement and validate modern, scalable, high-usability group encryption schemes (DCKGA, TreeKEM, etc.) from the ground up, so they can be tailored to product needs
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

Out-of-scope note: user removal / banning is not implemented in this PoC. Safe removal requires coordinated group key agreement and key rotation, which this prototype intentionally does not attempt yet.

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
* **DAG for auth, invites, multi-device, historical key provision** - Complex relationships such as team auth, admin promotion, multi-use Signal-like invite links, signed events, multi-device support, and group key agreement with history-provision can be modeled as events that depend on prior events. (MLS-like TreeKEM schemes can be too, as a complexity-costly enhancement if needed.)
* **Negentropy sync is fast enough for everything** - You can use range-based set reconcilation ("Negentropy") for syncing all events, whether files, messages, auth, whatever. Large event sets sync fast enough. File downloads are likely network-bound, not IO or CPU-bound.
* **Topological sort makes order not matter** - We can receive data in any order we want because topological sort over large amounts of SQLite events is fast enough that we can block events with missing dependencies and unblock events when their dependencies come in. 
* **Dependency and blocking can fit product needs** - The dependency graph can be whatever it needs to, to fit features like "don't display messages until you know their username" or "display messages immediately with a placeholder username". Dependency is **NOT** hard-wired into the syncing protocol or document store, as with OrtbitDB or Automerge.
* **Complex, secure deletion** - It is straightforward to reliably implement things like "delete this message, its attachments, and reactions" or the kind of key purging you'd need for data-layer forward secrecy. 
* **It works in an iOS NSE** - At least, it works on Linux under the same 24MB memory limit imposed by iOS on background-wakeup Notification Service Extensions. TODO: real proof on iOS.
* **We can use conventional networking primitives** - We can use a daemon-scoped QUIC runtime (`iroh`) to authenticate remote daemons, route different workspaces over one shared connection, and get local mDNS discovery plus NAT/path management without keeping bespoke glue.
* **No separate STUN/TURN required** - relay-backed `iroh` provides rendezvous, NAT traversal, and fallback transport directly, so we do not need a bespoke `topo` intro/hole-punch protocol on top.
* **Multitenancy can be built-in** - We can use event sourcing and workspace differentiation via daemon-scoped transport plus workspace-scoped routed sessions to make multitenancy a first-class thing, serve many Slack-like workspaces at the same cloud endpoint, and offer multi-account UIs out-of-the-box. Tenant creation and lifecycle management are event-based and deterministic like everything else.
* **Regular (fixed-length) wire formats** - [Langsec](https://langsec.org/) counsels that parsers can be made much more secure when data type complexity is limited, with regular (fixed-length-field) wire formats being the most tractable for secure parsing and formal verification. We keep our wire formats fixed-length.
* **Keys can just be dependencies** - There are no special queues for events with missing signer or decryption keys: these are just declared dependencies (key material is stored in events with id's) and block/unblock accordingly.
* **Canonical event naming** - For local/shared pairs, use `*_secret` / `*_shared` names (`peer_secret`/`peer_shared`, `invite_secret` + invite shared events, `key_secret`/`key_shared`). Avoid ad-hoc aliases.
* **Terminology migration** - The design now uses `account` for the workspace-scoped app principal and `endpoint` for the daemon-scoped transport principal. The current wire/schema event name remains `peer_shared` for compatibility, but conceptually it is today's `account_shared`.
* **Project-to-own-table rule** - Event projectors write to their own event table. They may read dependency-event tables as projection context, but cross-event side effects must flow through emitted events (or explicit runtime intents), not direct ad-hoc writes into other event tables. (Operational non-event tables, such as bootstrap trust bridges, are separate.)
* **Realistic testing** - We can run realistic tests locally with deterministic simulation of the event pipeline. Tests can check that for all relevant scenarios, reverse or adversarial reorderings of events and duplicated event replays all will yield the same state.

## Design Goal

The design goal is to keep protocol behavior auditable while still supporting real-time chat behavior and agent-friendly automation:

1. canonical data stays event-sourced and replayable,
2. transport and sync are real (daemon-scoped `iroh` QUIC), not simulator paths,
3. projection logic is deterministic and convergent,
4. CLI workflows remain synchronous enough for imperative command chains.

## How it Works (Narrative Overview)

### Daemon Start

Every participant begins by starting a daemon (`topo ... start`) with a local database and bind address. That daemon owns the long-running machinery: projection workers, dial/accept peering loops, and long-lived sync connection handling. Every step that follows is processed by the same runtime process.

### Workspace Creation And First User Creation

A workspace creator can start from an empty store or from a DB that already hosts other local tenants. The create workspace command always emits a fresh auth event graph (`workspace`, bootstrap `user_invite_shared`, `invite_accepted`, `user`, `peer_invite_shared`, `peer_shared`) plus local signer/key material for a new tenant/workspace binding; it never reuses the daemon's currently active tenant. Tenant identity (`recorded_by`) is pre-derived from the final PeerShared identity before writes begin, so bootstrap rows are already in the same scope used later for normal operation. (There is no "temporary tenant identity" that must be migrated later.)

### Creation And Projection Share One Path

Local event creation is synchronous at the command boundary, and every event still goes through the same projection pipeline used for replay and wire ingest. So even during initial setup, events are validated, dependency-checked, signer-checked, and materialized by the same projector logic used everywhere else. Their event id is returned to the caller once projected, which is useful for chaining commands. If a dependency is missing, the event blocks; when the dependency appears, the same unblock cascade continues projection. Exceptions to this flow (especially in initial workspace bootstrap or user joining) are highly discouraged.

### Inviting And Joining

After workspace creation, an admin creates a `user_invite_shared` event (which is synced to all existing members, if any) and shares invite data. The joiner accepts via `invite_accepted` and writes the follow-on identity chain (including a signed proof of invitation which all existing members can verify) for that joiner's user/device/peer identity. Accepting a workspace invite follows the same control-plane boundary as `create-workspace`: it creates a fresh local tenant bound to the invited workspace instead of reusing whichever tenant is currently active in the daemon. Normal sync brings missing canonical events, and the blocked rows unblock through the same dependency mechanism. If join prerequisites (such as prior auth events) are not yet present locally, the join path does not fork into ad-hoc recovery logic.

### Auth Event Graph Drives Join-Window Connection Policy

To avoid a chicken/egg problem, peers need to establish sessions before full steady-state PeerShared trust is present. The design handles this with projection-owned bootstrap trust rows fed by invite bootstrap context. Concretely: `invite_accepted` projection does write accepted bootstrap trust (`invite_bootstrap_trust`) when bootstrap context is present and that SPKI is not already superseded by projected PeerShared trust; inviter-side pending bootstrap trust (`pending_invite_bootstrap_trust`) is written by `user_invite_shared`/`peer_invite_shared` projectors on local invite creation. This lets first-contact handshakes happen under strict control of the auth event graph and tenant-scoped trust checks, rather than ad-hoc transport exceptions. Then, once `peer_shared` is projected, matching bootstrap trust is deterministically consumed and removed, and ongoing peering decisions remain on steady-state trust only, based on device/peer public keys, not invite public keys.

### Build Order Rule: Identity Before Transport Hardening

Transport security is a consumer of the auth event graph, not a bootstrap substitute for it. Future implementers should build the canonical event path first:

1. accepted-workspace binding (`invite_accepted`),
2. invite creation/acceptance flow,
3. `peer_shared` projection and deterministic `transport_fingerprint` materialization,
4. bootstrap trust rows (`invite_bootstrap_trust`, `pending_invite_bootstrap_trust`) as projection-owned state.

Only after those exist should strict daemon transport auth be added. Do not introduce placeholder manual pinning, file allowlists, or test-only trust seeding as a temporary transport authority. If the identity chain and projected trust graph are not present yet, transport hardening is not ready to start.

### Device Linking Uses The Same Story

Linking a second device follows the invite pattern with `peer_invite_shared` and acceptance, but extends an existing user instead of creating a new one. Any already-linked device may create a device-link invite for its own user identity; device-link creation is not admin-only, but it is still user-scoped and cannot target another user. Unlike workspace creation or workspace-invite acceptance, device-link accept is scoped to an existing workspace/account lineage carried by the link; it must not create a second workspace binding or reinterpret the daemon's active tenant as a different workspace. The runtime behavior is intentionally isomorphic to user join: bootstrap trust can bridge first contact, sync fills any missing canonical history, and PeerShared-derived trust becomes the long-term authority. Because this reuses the same event/projection/sync loop, multi-device behavior does not require a separate architecture: every subsequent device is recorded and validated in the same way as the first device.

### Peer Discovery Provides Candidates, Not Authority

Local networking uses daemon-scoped `iroh` mDNS to discover candidate endpoints. Those advertisements are treated as unauthenticated hints. They can influence "who to try dialing" but never "who is trusted." Actual authority remains event-sourced and projection-backed: after the daemon handshake identifies the remote transport identity, tenant trust checks decide whether the session is allowed to proceed. We rely on invite/bootstrap addresses, optional local mDNS discovery, and `iroh`'s relay-backed rendezvous/path management rather than a custom intro protocol.

For simplicity, discovery is allowed to remain narrower than steady-state direct trust during bootstrap. In particular, a bootstrap-mode node may only have connectivity to the inviter (or whatever peer supplied the invite bootstrap transport identity) until steady-state transport fingerprints converge through sync; this is an acceptable tradeoff if it keeps transport targeting and authorization strictly fingerprint-based rather than introducing broader workspace-wide admission.

### Connection Establishment And Endpoint Behavior

Transport runs over daemon-scoped `iroh` QUIC, while canonical event authenticity comes from event signatures and dependency validation. We intentionally force cloud-style multitenancy into the core runtime model: one daemon, one UDP port, many local tenants, each with its own workspace binding and trust state. That same mechanism is what enables a Slack/Discord-like local client to host many accounts/workspaces without spinning up one endpoint per account.

At daemon startup, local tenants are still discovered from event-projected identity/trust state plus replay-derived tenant session-auth state, but the live QUIC endpoint is now daemon-scoped. The runtime ensures one local `endpoint_secret` root event under `recorded_by = endpoint_id`, replays that `iroh::SecretKey`, and builds one shared `iroh::Endpoint` from it. This endpoint root may exist before any workspace is created or any invite is accepted. Outbound dials use daemon `EndpointId` plus explicit/bootstrap/observed addresses; no tenant or workspace identity appears in handshake metadata.

Invite creation follows the daemon-scoped rule. If a user or device-link invite does not override `public_spki`, the invite link embeds the daemon transport fingerprint, not the tenant's current local peer/device fingerprint. Bootstrap targeting is therefore "dial daemon D and redeem invite I", not "dial exact tenant session-auth identity T".

Handshake verification is split into two layers, but only one of them is currently authoritative. First, `iroh` authenticates the remote daemon `EndpointId` and establishes the encrypted daemon connection. We do not currently require a pre-handshake secret gate. Instead, the connection is quarantined until the first logical session proves either an admitted `OpenSessionRoute { source_peer_id, target_tenant_id }` or a valid `OpenSessionAuthInvite`. If that proof does not arrive quickly, or it resolves to anything other than one exact authorized tenant/workspace scope, the daemon connection is closed before any sync work starts.

The stricter target for the next auth cleanup is narrower than the current transitional runtime:

1. `endpoint_secret` stays the replay root for the daemon-scoped `iroh` endpoint and may exist before any workspace.
2. `endpoint_shared` is now a self-signed shared event in endpoint scope (`recorded_by = endpoint_id`), published from that replay root and identifying the daemon transport principal by its public `EndpointId`.
3. `invite_accepted` is the local accepted-workspace binding that breaks the bootstrap cycle.
4. Unknown endpoints must not be admitted because of any node-global bootstrap window or because some unrelated peer is still unbound.
5. Instead, bootstrap admission should accept only one exact proof scope: `(invite, local account/workspace, remote account, actual remote endpoint)`.
6. Steady-state sessions are already `OpenSessionRoute` only. Bootstrap or new-workspace admission uses `OpenSessionAuthInvite` until `account` events (currently `peer_shared`) depend on `endpoint_shared` directly.

This target is captured in the focused TLA safety model [`EndpointBootstrapRoute.tla`](./tla/EndpointBootstrapRoute.tla). That model checks the exact bootstrap and route safety properties before we remove the current bridge code.

This also covers the hard case where multiple local identities on the same endpoint belong to the same workspace. One daemon-to-daemon QUIC connection can carry multiple tenant/workspace sessions over time, and tenant trust sets may overlap in value, but session admission remains tenant-scoped because each logical session names the exact tenant/workspace scope to bind. Range sync and dependency repair are separate session classes on that shared daemon connection, so recent-history control traffic can stay responsive without paying for a second QUIC congestion controller to the same daemon.

### Why Not Fully Sessionless Signed Control

We considered an alternative where there are no daemon-to-daemon logical sessions and every control message is individually signed and verified before being acted on, with ingest routing by signer/workspace mapping.

The attraction is real: connection sharing becomes simpler, and there is less explicit session-open state. But for the active negentropy/dependency design it is not actually stateless. We still need round correlation, replay protection, response matching, and prioritized control/data handling. Putting asymmetric verification on every control message would move more crypto onto the hot path while still leaving per-round state in the sync engine. The current design therefore keeps one daemon-scoped QUIC connection and uses one routed session-open per logical session, with signatures only when bootstrap or new-scope admission is required.

### Sync And Convergence

Once connected, peers reconcile explicit time ranges instead of planning per-event pull work. A range session loads the local `(ts, event_id)` membership for one selected range from `shared_event_index`, seals it into an in-memory `NegentropyStorageVector`, exchanges `NegOpen` / `NegMsg`, and then both sides stream all missing blobs for that range as raw length-delimited records. The receiver appends those blobs to a `ReceiveLog`, stamps `first_received_at` / `first_stored_at` in the file as each blob is appended, finalizes the spool file, and then lets canonical ingest continue in the background.

Negentropy remains the set-reconciliation engine because it is agnostic to event content and naturally fits an ever-growing event set. The active range path uses the Rust [`negentropy` library](https://crates.io/crates/negentropy) over one selected range at a time. The current scheduler intentionally stays simple and round-robins:

1. `last day`
2. `last week`
3. `last twelve weeks`
4. `full history`

When multiple peers are connected, the scheduler uses the same simple rule every round:

1. `last day` is duplicated across all live peers to minimize time-to-project for recent history,
2. `last week`, `last twelve weeks`, and `full history` are partitioned across the current live peer set by sorted peer rank,
3. the partition is recomputed on every new range session from the live connection set.

This is intentionally the simplest robust strategy. There is no durable ownership table, no per-event planner, and no sticky assignment state to repair after a peer disappears. If a peer drops mid-download, the next round sees a smaller live peer set and the remaining peers automatically widen their assigned historical slices. While a hot `LastDay` receive is active for a DB, background receive-log ingest stays paused so download/store remains the priority path.

Dependency repair is a separate fast path. Projection blocking emits direct dependency requests keyed by source peer, and dependency replies are ingested immediately through the same canonical/projector path used by local creation and replay. This preserves one convergence contract across source types while keeping bulk transfer durable-first and blocker repair latency-first.

Legacy `forward_on_have` controls are no longer part of the active range-owned sync design. The tested path is range sessions plus immediate dependency repair; bulk sync no longer uses durable `wanted` rows, `ResponseCredit`, or a shared ingest channel to keep the wire busy.

For same-workspace sibling tenants sharing one DB, there is one extra local step after canonical persistence: shared events created locally or ingested from the network are fanned out to sibling tenant scopes with the same `workspace_id`, then projected through those tenants' normal queue/drain path. This is not a transport shortcut and it does not bypass projectors; it is local fanout of already-canonical shared blobs so one shared DB converges the same way multiple separate daemons would.

### Steady-State Repeats The Same Loop

After creation/join/linking settles, day-to-day behavior is not a new phase. Peers create events, project them, discover targets, connect where policy allows, reconcile missing sets, and project incoming events. This is how the design gets both operational flexibility (local discovery, hole punch, multi-tenant endpoints) and strict correctness properties (deterministic projection, replay/reorder invariance, auth-gated connectivity) without maintaining multiple competing lifecycles and incurring the resulting state explosion.

### Frontend Ergonomic API

Our daemon provides a placeholder RPC API that is capable of serving whatever queries are desired, and accepting commands with the minimal convenient set of parameters needed to execute them. For example, the CLI can request a message list that includes not just message content but user information, reactions, file attachments, download progress, etc, with limits and ranges for lazy loading. Developers benefit from event-module locality: when adding functionality to, say, messages or reactions, everything they need to modify is in the same content-thematic cluster of create, project, and query functions. Queries and commands are strictly scoped by peer, to avoid accidental intermingling of local data in development or testing. Unlike most p2p or local-first frameworks, you aren't on your own to build complex state management layer and deal with state duplication and concurrency problems; there is no middleware and frontends can be maximally simple. Because our "server" is local and only serves one client, frequent polling is a simple-but-effective way to keep frontend and backend state in constant sync. For perf/testing, `generate` accepts a `history_span` and spreads synthetic message timestamps evenly across `[now - history_span, now]`; the default span is 3 years.

### Tenant Readiness Surface

Tenant/workspace readiness is intentionally minimal and query-driven:

1. CLI surfaces (`view`, `status`) do not read SQL directly. They render query/RPC responses owned by event modules, primarily `workspace::view` and `workspace::status`, with runtime-only fields composed in the RPC layer when needed.
2. The only public readiness bit is `ready: bool`.
3. Tenant visibility already implies invite acceptance, because top-level tenant discovery is derived from `invites_accepted`. We do not expose a second public `accepted` readiness field.
4. `ready` means only: this tenant is writable on this device right now. It is derived from the same authoring-precondition helper used by write commands (`Send`, `React`, `SendFile`), so the UI and command behavior share one source of truth.
5. `ready` does not mean "history complete", "caught up", or "no blocked rows". Sync debt and history completeness are separate concerns.
6. Human-facing `view` stays compact and preserves the existing multi-tenant layout. It appends `[still joining]` only for visible tenants whose `ready == false`; ready tenants show no extra label.
7. `status` may show the same tenant-level `[still joining]` tag or equivalent prose, but machine surfaces should keep the underlying boolean.

This keeps the user-facing state model narrow:
- visible tenant + `ready == false`: accepted locally but still joining on this device,
- visible tenant + `ready == true`: writable now.

For instant optimistic feedback, write commands (`Send`, `React`, `SendFile`) accept an optional `client_op_id` that the frontend generates locally. The daemon stores a local mapping from `client_op_id` to the resulting `event_id`, and annotates view responses with these IDs. The frontend shows an optimistic row immediately on send, then drops it when the polled view contains a canonical item with the matching `client_op_id`. This gives Slack-like latency with no client-side state machine — just a key match on each poll.

For reactive data flows, the daemon provides a local subscription engine. Frontends create subscriptions filtered by event type (e.g. "message", "reaction") with optional field-level filter clauses. As events are projected, matching items are appended to a per-subscription feed table. Frontends poll feed items with `SubPoll` (sequential, ack-based cursor), check pending counts with `SubState`, and acknowledge consumed items with `SubAck`. CLI shape is nested under `topo sub ...` (for example `topo sub create`, `topo sub list`, `topo sub poll`), and selectors accept subscription id, exact name, or list index (`N` / `#N`), with default-to-only-subscription behavior for poll/state/ack/enable/disable. Three delivery modes control feed granularity: `full` (render-ready payload), `id` (identifiers only), and `has_changed` (dirty flag + count, no per-item rows). Subscriptions are local to each peer and do not replicate — they are a projection-layer convenience for frontend reactivity, not protocol state. Ownership split: lifecycle/storage/feed mechanics live in `src/state/subscriptions/*`, while event-specific filter semantics and payload shaping live in each event module via `subscription_filter.rs` (or `subscription_filters.rs`). Subscription match tracing is emitted at `INFO`, so default `topo start` (WARN) does not print those lines unless `RUST_LOG=info` (or higher verbosity) is set.

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

Model and wire format in [wire.rs](/home/holmes/poc-7/src/event_modules/file/wire.rs)-style:

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

Create `message_unfurl::queries::list_for_message(...)` (same pattern as [queries.rs](/home/holmes/poc-7/src/event_modules/file/queries.rs)).

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

No per-event transit wrapper is used; transit encryption is handled by the daemon-scoped QUIC transport.

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

## 1.5 Sync session classes and stream separation

One authenticated daemon connection can host two sync session classes:

1. `Range` sessions for bulk catchup,
2. `Dependency` sessions for targeted blocker repair.

Why keep control and data separate inside a session:
1. large `Event` blobs do not head-of-line block reconciliation or dependency requests,
2. control remains readable and bounded while data transfer stays bulk-oriented,
3. dependency replies can stay latency-first without sharing the same hot path as range bulk transfer.

Current shape:
1. a `Range` session uses one control stream plus one data stream and runs in two strict phases:
   - negentropy reconcile for one explicit range,
   - bulk event transfer for that same range,
2. a `Dependency` session uses one control stream for `RequestIds` and one data stream for dependency `Event` replies,
3. bulk range transfer does not use `ResponseCredit`, durable `wanted`, or a per-event request scheduler,
4. the receiver writes bulk data to a `ReceiveLog`; dependency replies ingest immediately through the normal canonical path.

---

# 2. Transport and Session Identity

Transport identity is split from event-layer peer identity:

1. **Transport identity** (daemon transport scope): daemon-scoped `iroh::SecretKey` material replayed from the local `endpoint_secret` event, plus replay-derived tenant session-routing/auth state in `local_transport_creds` / `local_transport_targets`. Both use SPKI-derived `peer_id` fingerprints, but only the daemon endpoint identity authenticates daemon-to-daemon QUIC connections.
2. **Event-graph identity** (identity layer scope): Ed25519 keys, signer chains, accepted workspace bindings (`invites_accepted`), and identity events (types 8-22). Owned by event modules (for example `src/event_modules/workspace/*`, `src/event_modules/invite_accepted.rs`, `src/event_modules/peer_shared/*`, `src/event_modules/peer_secret.rs`) and executed through the generic projection pipeline (`src/state/projection/apply/*`).

Tenant-scoped peer/device fingerprints remain deterministically derived from PeerShared Ed25519 signing keys via `spki_fingerprint_from_ed25519_pubkey()`. Legacy schema/table names still say `transport_fingerprint` / `local_transport_*`, but in the current design those rows are tenant session-routing/auth identity state, not the live daemon handshake identity. The live transport identity is a daemon-scoped `iroh` endpoint id replayed from `endpoint_secret`; the stored self-signed cert remains compatibility state, not tenant identity on the wire.

## 2.1 Iroh + QUIC

All peer transport uses one daemon-scoped `iroh` endpoint plus tenant-scoped routed sessions, both driven by projected trust rows.

Rules:
1. each daemon profile has persistent daemon transport identity material replayed from `endpoint_secret`,
2. peer allow/deny policy is based on SQL trust state:
   - PeerShared-derived transport fingerprints from projected `peers_shared.transport_fingerprint` rows (deterministically computed from PeerShared public key at projection time),
   - `invite_bootstrap_trust` rows produced by projection from `InviteAccepted` events + local `bootstrap_context`,
   - `pending_invite_bootstrap_trust` rows produced by projection from invite events (UserInvite, DeviceInvite) + local `bootstrap_context`,
   - trust rows are projection-owned state; the service layer writes `bootstrap_context` rows only, not trust rows directly,
3. no permissive verifier in production mode.

## 2.2 Transport identity binding

Transport peer identity is split:

1. `daemon_peer_id = endpoint_id = hex(iroh_secret.public())`, where `iroh_secret` comes from the local `endpoint_secret` event and that event is scoped under `recorded_by = endpoint_id`,
2. `peer_shared` projection materializes `peers_shared.transport_fingerprint` as the deterministic tenant/peer transport fingerprint and indexes `(recorded_by, transport_fingerprint)`,
3. the `peer_transport_bindings` table is observation telemetry keyed by `(recorded_by, peer_id)`, where `recorded_by` is the local tenant key and `peer_id` is the remote tenant/peer transport fingerprint; `spki_fingerprint` stores the remote daemon fingerprint observed on the authenticated daemon channel,
4. `invite_bootstrap_trust` stores accepted invite-link bootstrap tuples
   (`bootstrap_addr`, daemon SPKI) used before steady-state peer bindings appear,
5. `pending_invite_bootstrap_trust` stores inviter-side expected invitee SPKI
   until PeerShared-derived trust consumes it,
6. accepted/pending bootstrap rows are time-bounded and consumed at projection time
   (PeerShared projector issues deterministic `Delete` write-ops for matching SPKIs)
   when steady-state PeerShared-derived trust appears. Trust check reads are pure
   (no write side-effects).
7. trust lookups use projected `transport_fingerprint` rows and do not scan/derive fallback from `peers_shared.public_key`.

Runtime rule: handshake verification queries SQL trust state per connection creation; projected peer keys are not treated as in-memory authority.

Why this is SQL-first:
1. restart-safe: no trust bootstrap gap after process restart,
2. low-memory friendly: avoids unbounded in-memory trust sets,
3. multi-tenant safe: one node can host many tenants with tenant-scoped indexed lookups.

Conceptually:
`TrustedPeerSet = PeerShared_SPKIs ∪ invite_bootstrap_trust ∪ pending_invite_bootstrap_trust`.

This union is still the current transitional implementation. The stricter target is different:

- bootstrap proof is a narrow connection-scoped admission path, not a broad node-wide trust source,
- `endpoint_shared` becomes the steady-state transport authority in the auth graph,
- route admission depends on exact `(remote account, remote endpoint)` graph state,
- eventual convergence comes from retries after projection catches up, not permissive trust widening.

### Transport identity materialization boundary

Transport cert/key materialization is isolated behind a typed contract:

- **`TransportIdentityIntent`** (enum): describes *what* identity change is needed (`InstallBootstrapIdentityFromInviteSecret` or `InstallPeerSharedIdentityFromSigner`).
- **`TransportIdentityAdapter`** (trait): executes the intent against the DB. The sole concrete implementation (`ConcreteTransportIdentityAdapter` in `src/runtime/transport/identity_adapter.rs`) is the **only** code that calls raw install functions (`install_invite_bootstrap_transport_identity`, `install_peer_key_transport_identity`).
- **Workspace command layer** (`accept_invite` / `accept_device_link`) still installs invite-derived tenant bootstrap identity via the adapter intent path (not raw transport calls), but that identity no longer terminates the live QUIC handshake.
- **Event modules** emit `ApplyTransportIdentityIntent` commands (e.g., `peer_secret` projector for PeerShared signers).
- **Projection pipeline** (`write_exec.rs`) routes intents through the adapter.
- **Downgrade guard**: bootstrap install is rejected once a PeerShared-derived identity has been installed (`BootstrapAfterPeerSharedDenied`), enforcing one-way transition.
- **Credential source tracking**: `local_transport_creds.source` records `random | bootstrap | peershared` for tenant identity/trust diagnostics, while the live daemon QUIC identity is stored separately in the projected `endpoint_secrets` table.
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
1. NAT traversal and rendezvous are transport concerns owned by `iroh`, not by a bespoke Topo protocol.
2. Runtime observations (endpoint observations, peer→daemon bindings) are local orchestration state, not canonical events.
3. Direct-connect success is opportunistic. Relay-backed connectivity and ordinary set reconciliation are always valid fallbacks.
4. The runtime may still record observed addresses and daemon bindings for reconnect efficiency, but it does not run an explicit introduction API or maintain a parallel punch protocol.

### Endpoint observations

When a peer accepts or establishes a daemon connection, it records the remote peer's observed `(ip, port)` in the `peer_endpoint_observations` table with a TTL. Those rows are reconnect hints and observability data only; they do not authorize trust.

Rules:
1. Observations are append-only with `INSERT OR IGNORE`.
2. Freshness is determined by `MAX(observed_at)` query, not in-place update.
3. Observations expire via `expires_at` and are periodically purged.
4. Observations are scoped by `recorded_by` (the observer) and `via_peer_id` (the observed peer).

### Relay-backed connectivity

The daemon runtime relies on `iroh` for:

1. relay registration and relay-assisted rendezvous,
2. hole-punch timing and NAT traversal when relays are available,
3. direct-path upgrade and path maintenance after the daemon connection exists,
4. stream multiplexing for range/dependency/control work on the shared daemon connection.

There is no longer a `topo intro` command or `IntroOffer` wire frame in the target runtime. If two peers can reach each other only through a relay, sync still proceeds on the same daemon-scoped `iroh` connection surface; if a direct path becomes possible later, `iroh` upgrades the connection itself.

### Transport-owned port mapping

Best-effort port mapping is now transport-owned through `iroh`'s portmapper, not a bespoke `topo upnp` control surface.

Rules:
1. mapping is opportunistic transport runtime behavior, not canonical protocol state,
2. explicit bootstrap addresses remain valid even when mapping fails or is unavailable,
3. mapping outcome must never modify trust/projection/signature semantics.

### Testing

Test the feature with both local integration tests and Linux netns NAT simulation:

1. `cargo test --test cli_test -- --test-threads=1`
2. `cargo test --test cli_observability_test test_parallel_device_links_converge -- --test-threads=1`
3. `cargo test test_record_endpoint_observation`
4. `cargo build --release`
5. `sudo tests/netns_nat_test.sh --cone` (expected pass)
6. `sudo tests/netns_nat_test.sh --symmetric` (expected pass via relay fallback)
7. `sudo tests/netns_nat_test.sh --cleanup`

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
The `peer_secret` event for the local `peer_shared` signer triggers `ApplyTransportIdentityIntent` on projection, installing a PeerShared-derived tenant session-auth identity under a legacy transport-named adapter boundary.
Scope rule: `create_workspace` is tenant-agnostic at the CLI/RPC boundary. It always mints a fresh local tenant/workspace binding, even when the DB already has active tenants or transport credentials. Direct command internals may still pass an explicit `recorded_by` for tests or low-level idempotence, but operator-facing `topo create-workspace` must never collapse onto the active tenant.

**Invite** (`workspace::commands::create_user_invite`): admin creates a UserInvite event and returns portable invite data (event ID + signing key + workspace ID). Wraps content key for invitee if sender keys are available.

**Accept** (`workspace::commands::join_workspace_as_new_user`): joiner consumes invite data and creates:
InviteAccepted (accepted workspace binding) → User → DeviceInvite → PeerShared.
Prerequisite: the joiner's DB must already contain the Workspace and UserInvite events (copied from the inviter before or during sync).
Scope rule: workspace invite acceptance is also tenant-agnostic at the CLI/RPC boundary. It creates a new local tenant bound to the invited workspace instead of reusing the active tenant.
The acceptance path also unwraps bootstrap content-key material received via `key_shared` events (wrapped to the invite public key at creation time) and materializes local `key_secret` events so that encrypted content received during bootstrap sync can be decrypted.
On shared-DB multi-tenant nodes, acceptance also replays already-present shared events for the accepted workspace into the new tenant scope. Canonical blobs may already exist globally in `events` / `shared_event_index`, and negentropy will not refetch them just because a new local tenant accepted the workspace. That replay is therefore part of the correctness contract for same-DB joins, not just an optimization.
Signer secrets (PeerSecret events) are NOT emitted here; `persist_join_peer_secret` is called separately after push-back sync completes.

**Device link** (`workspace::commands::create_device_link_invite` / `add_device_to_workspace`): similar to user invite but creates a shorter chain (PeerShared only, skipping user/peer_invite_shared creation). Authorization rule: any linked device may issue a device-link invite for its own user identity; adding new users remains admin-only through `create_user_invite`.
Scope rule: device-link commands remain workspace-scoped. They extend an existing workspace/account lineage and do not create a new workspace binding.
The same replay rule applies to device linking: when a new local device joins a workspace whose shared history already exists in the DB, that history must be seeded into the new tenant scope immediately.

**Retry** (`workspace::commands::retry_pending_invite_content_key_unwraps`): retries content-key unwrap for invites where `key_shared` prerequisites arrived late. Triggered via `event_modules::post_drain_hooks` from `state/pipeline/effects.rs` after each projection drain.

Identity pre-derive:

All three creation paths pre-derive `recorded_by` from the PeerShared key
(`derived_peer_id = hex(spki_fingerprint(pubkey))`) before writing any events,
so all events are written under the final peer_id from the start.

- **Workspace creation** (`create_workspace`): pre-derives PeerShared key,
  installs PeerShared-derived tenant session-auth cert directly. No bootstrap sync needed.
- **Invite acceptance / device link** (`accept_invite`, `accept_device_link`):
  pre-derives PeerShared key for `recorded_by` and still materializes
  invite-derived tenant bootstrap session-auth creds in replay state, but the
  initial QUIC handshake now uses the daemon transport identity. Bootstrap
  authorization moves to the first encrypted `OpenSessionAuthInvite` frame,
  and the PeerShared-derived tenant session-auth identity replaces the
  bootstrap tenant identity later via projection cascade
  (`ApplyTransportIdentityIntent::InstallPeerSharedIdentityFromSigner`).
- **Connect loop**: daemon connection ownership is resolved once per QUIC
  connection, but outbound session auth is resolved per logical session.
  That lets bootstrap-derived auth naturally converge to steady-state
  `PeerShared` auth on the next session open without forcing a second raw
  connection.

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

**Known limitation:** `shared_event_index` is one shared physical table keyed by `workspace_id`, not by tenant. Negentropy reads one explicit workspace bucket at a time. Production create/ingest paths only index shared events when they have an explicit workspace binding, so empty workspace buckets are not part of the runtime design. In this document, **pseudonym isolation** means preventing any cross-tenant metadata correlation at the node level; full pseudonym isolation still requires separate node instances on separate network paths.

## 3.2.1 Functional multitenancy: one node, N tenants

A single node process can host N tenant identities in one shared SQLite database, with one shared QUIC endpoint plus tenant-scoped workspace binding and trust policy.

The DB is the tenant registry. No explicit tenant registration step is required. The runtime currently discovers its tenants by joining the accepted-workspace binding with the tenant's current local peer/device fingerprint mapping:

```sql
SELECT t.tenant_id, i.workspace_id, t.transport_peer_id
FROM local_transport_targets t
JOIN local_transport_creds c ON c.peer_id = t.transport_peer_id
JOIN invites_accepted i ON i.recorded_by = t.tenant_id
``` 

`invites_accepted` is populated by `invite_accepted` (local-only, part of the identity bootstrap). `local_transport_targets` maps a tenant to its current local peer/device fingerprint, and `local_transport_creds` stores the corresponding local session-auth key material under a legacy table name. Invite acceptance may install invite-derived bootstrap state first, then projection installs the PeerShared-derived steady-state state.

Why this state is part of discovery:
1. event-layer identity establishes who the tenant is,
2. local session-auth state establishes which peer/device fingerprint the tenant can currently authenticate as,
3. the daemon needs both to start tenant-scoped routing safely (workspace binding without session-auth state is incomplete; session-auth state without workspace binding cannot map to tenant scope).

### Node daemon architecture

The node daemon (`run_node`) operates as follows:

1. Discover all local tenants from the DB.
2. Ensure one persistent daemon transport identity and create a **single** `iroh::Endpoint` from that daemon key.
3. Run one accept loop over that shared endpoint; each accepted daemon connection claims or reuses one daemon-scoped live slot keyed by remote daemon id.
4. Each live daemon connection runs one inbound session supervisor that accepts logical sessions, reads `OpenSessionRoute` or bootstrap/fallback proof, resolves the tenant from local SQL state, and lets only that tenant authorize the authenticated remote peer.
5. Tenant work does not own the raw QUIC connection. Outbound range/dependency work reuses the live daemon connection for that remote daemon and opens routed logical sessions inside it; bootstrap/new-workspace admission pays the signed proof only when extending scope.
6. Optional local discovery is daemon-scoped `iroh` mDNS. `topo discover` subscribes to that stream. The current branch also accepts n0 relays for wide-area rendezvous and hole-punch timing instead of running a custom intro protocol.

### Single-port multi-tenant endpoint

All tenants on a device share a single UDP port and one daemon endpoint id. Outbound dials use explicit/bootstrap/observed addresses, local `iroh` mDNS lookup, and relay-backed `iroh` connectivity. Tenant routing is no longer a handshake concern; it happens in the first control frame of each logical session. Same-workspace sibling tenants and reused bootstrap/device-link sessions should therefore share the same daemon connection whenever they are talking to the same remote daemon.

### Per-tenant dynamic trust

The single daemon endpoint no longer uses a pre-handshake tenant trust gate. Any remote daemon that speaks the `iroh/topo` ALPN can complete the daemon handshake, but the connection is not admitted for application work until the first logical session proves one exact tenant/workspace scope. That proof is either:
- `OpenSessionRoute`, which is accepted only if local projected state already binds `(tenant_id, remote_account_id)` to the actual connected daemon, or
- `OpenSessionAuthInvite`, which is accepted only if the invite proof validates and the projected bootstrap trust rows resolve to exactly one tenant for the actual connected daemon.

Trust checks remain **tenant-scoped** (`recorded_by`-partitioned). Value-level trust-set overlap is allowed on the remote side, but session admission still requires one unique tenant binding from the routed/bootstrap preface. Another tenant's trust must never satisfy that frame. This remains transitional until endpoint identity is first-class event-graph state; the current branch removes the permissive handshake shortcuts first and keeps bootstrap proof as the only way an unknown daemon can become useful.

`local_transport_targets` is not a new authority source. It remains replay-derived tenant identity state for projected trust, discovery, and bootstrap lineage: local event projection emits transport identity intents, the transport adapter materializes tenant session-auth identity state, and that successful apply updates the tenant's current peer/device fingerprint. Replaying local event state rebuilds both `local_transport_creds` and `local_transport_targets`, but the live daemon endpoint uses `endpoint_secret` rather than those tenant rows.

Discovery-only invite acceptance may still persist an empty `bootstrap_addr` marker row so the bootstrap SPKI remains available in projected state. That row is a projection marker only; it must never create an autodial target or be treated like a concrete bootstrap endpoint.

### User removal is out of scope

This PoC does not implement `PeerRemoved`, `UserRemoved`, or a `ban` command. Safe user/device removal requires coordinated group key agreement plus key rotation so future ciphertext is no longer available to the removed member. When removal is added back, it must revoke any admitted `(tenant_id, remote_peer_id)` routes on live daemon connections and close the daemon connection entirely if no tenant scopes remain; we must not rely on ingest rejection alone. We intentionally defer that work here and keep transport trust/session logic limited to invite/bootstrap trust and steady-state `PeerShared` trust.

### Receive logs and immediate ingest

The active network ingest model has two boundaries:

1. **Range bulk receive** writes blobs to a per-session `ReceiveLog`.
2. **Dependency replies** call `ingest_now` immediately.

Range bulk path:
1. append each blob to the `ReceiveLog`,
2. stamp first-store timing as the append succeeds,
3. finalize on connection close or idle timeout,
4. replay the log into canonical ingest,
5. recover leftover logs on startup and delete them after successful replay.

Dependency path:
1. receive one or more dependency `Event` replies,
2. opportunistically drain what is already buffered now,
3. call `ingest_now`,
4. let normal `project_queue` / `project_one` logic unblock dependents.

This keeps the bulk hot path free of per-event SQLite work while still using
the same canonical/projector pipeline after the durable handoff point.

### Session-auth credential storage

Tenant peer/device cert/key **DER** (ASN.1 Distinguished Encoding Rules) blobs live exclusively in the legacy-named `local_transport_creds` SQLite table (with `source` marker: `random | bootstrap | peershared`). No cert files exist on disk. These rows are stored during identity bootstrap as tenant session-routing/auth identity state; they do not create the shared daemon endpoint. The live endpoint is built from replayed `endpoint_secret`, while `local_transport_creds` and `local_transport_targets` track which peer/device fingerprint a tenant can route as when opening steady-state `OpenSessionRoute` sessions or bootstrap `OpenSessionAuth*` sessions. Bootstrap identity install is one-way gated: after a PeerShared install, bootstrap install is denied. This keeps all node state in one database file.

## 3.2.2 LAN peer discovery (`iroh` mDNS)

Local discovery now uses `iroh`'s daemon-scoped mDNS lookup. One daemon advertises one daemon endpoint id plus its current reachable socket addresses on the local network, and `topo discover` subscribes to the same `iroh` mDNS stream the runtime uses for discovery hints.

Discovery rules:
1. **Self-filtering**: the browser filters out the local daemon endpoint id, preventing unnecessary self-connects.
2. **Trust gating**: discovered daemons are candidate addresses only; actual admission still requires daemon auth plus tenant-scoped routed/bootstrap session checks.
3. **Address churn**: when a previously-discovered daemon re-advertises at a different address, `iroh` updates the candidate address set and the runtime reuses the same daemon-scoped live slot keyed by remote daemon id.
4. **Current branch uses n0 relays for rendezvous**: local discovery still works without them, but the direct-connect timing/hole-punch job is delegated to `iroh` relay-backed transport rather than a custom intro protocol.

mDNS authenticity model (POC):
1. mDNS advertisements are treated as unauthenticated discovery hints (address + claimed daemon endpoint id),
2. an attacker can spoof mDNS data and cause extra dial attempts,
3. spoofed advertisements cannot bypass identity/auth: session acceptance still requires authenticated daemon identity and tenant-scoped `is_authorized_for_tenant` + route checks,
4. authoritative identity for the session is the authenticated remote daemon id observed at handshake, not the mDNS advertisement claim.

Out-of-scope note (current POC):
1. there is still no transport/session-level intra-daemon peering path for two local tenants in the same workspace,
2. same-workspace tenants that share one DB instead converge through projection-layer replay/fanout of shared canonical events,
3. adding explicit intra-instance transport delivery may still be desirable future work, but it is not required for the current design baseline.

## 3.2.3 Peering runtime loop model

Runtime flow reference: [DESIGN_DIAGRAMS.md](./DESIGN_DIAGRAMS.md) sections `1` (unified ingest), `2` (sync connection control/data), `3` (high-level boundaries), and `4` (runtime topology).

The production peering runtime follows a single conceptual loop:

1. **Projected SQLite state**: invite_bootstrap_trust rows, PeerShared-derived trust, endpoint observations.
2. **Target planner** (`runtime::peering::engine::target_planner`): single-owner module for all dial target planning. Bootstrap trust rows now surface the authenticated bootstrap transport fingerprint, so bootstrap, observed endpoints, and `iroh` mDNS discovery all collapse onto one exact transport-target dispatch key per `(tenant_id, target_transport_fingerprint)`. Relay-backed `iroh` connectivity sits under that planner; there is no separate intro path.
3. **Supervisor layer**: startup preflight + loop orchestration live in the peering supervisor. Connectivity inputs are hints to `ensure_connected(peer)`, not independent long-lived owners.
4. **Dial/accept loops**: `connect_loop` (outbound tenant work) and `accept_loop` (raw inbound daemon connections) are separate long-running loops coordinated by shared projected state and cancellation/watch channels. `iroh` dial/accept + daemon identity extraction flows through `transport::connection_lifecycle`, and stream wiring flows through `transport::session_factory`.
5. **Live daemon slot**: after daemon identity extraction, the runtime claims at most one local live daemon connection slot per `(db_path, remote_daemon_peer_id)`. Duplicates are closed instead of starting overlapping sync ownership. If both directions appear, the deterministic preferred direction is the lexicographically lower daemon id dialing outbound and the higher daemon id retaining inbound; a preferred-direction connection replaces a non-preferred one.
6. **Logical session auth and runners**: tenant work reuses the live daemon connection and opens logical range/dependency sessions. Steady-state sessions begin with `OpenSessionRoute`; bootstrap or new-workspace sessions use `OpenSessionAuthInvite`, then run through `SyncConnectionHandler` or the dependency fast path.

Known drawback: because there is no pre-handshake secret gate today, anyone who learns the daemon's `iroh` address or relay-reachable endpoint can touch the unauthenticated `iroh/topo` surface. They still cannot authenticate into a workspace without a valid route or invite proof, but they can force the first-session timeout path and probe for bugs in `iroh` itself or in our own session/bootstrap parsing and admission logic. This is an intentional simplicity tradeoff in the current design, not a claim that the exposed pre-proof surface is zero.
7. **Ingest boundary**: range sessions write `ReceiveLog` files and dependency sessions call `ingest_now`; both converge through the same canonical/projector path.
8. **Projected SQLite state**: projection cascade updates trust rows, completing the loop.

### Module ownership

- **Target planning**: `src/runtime/peering/engine/target_planner.rs` — the single source of truth for dial target decisions. Bootstrap autodial, observed endpoints, and mDNS discovery all route through this module.
- **Transport connection lifecycle**: `src/runtime/transport/connection_lifecycle.rs` — sole owner of `iroh` `connect/accept` and daemon identity extraction for peering paths (`dial_daemon`, `accept_daemon`).
- **Transport session factory**: `src/runtime/transport/session_factory.rs` — sole owner of stream opening and `TransportSessionIo` construction over `iroh` bi streams. Provides `open_session_io()` and `accept_session_io()` that return `(session_id, Box<dyn TransportSessionIo>)`.
- **Transport session I/O adapter**: `src/runtime/transport/transport_session_io.rs` — sole owner of frame boundary validation (`parse_frame` exact-consumption), max-frame-size enforcement, and mapping between QUIC stream errors and `TransportSessionIoError`.
- **Live connection ownership**: `src/runtime/peering/loops/mod.rs` — owns the per-daemon live connection slot registry and deterministic preferred-direction rule used by both outbound and inbound loops.
- **Peering orchestration seam**: `src/runtime/peering/loops/mod.rs::run_session` — wires session metadata, peer-removal cancellation, and the session handler together. Receives pre-built `TransportSessionIo` from the transport session factory.

### Event-sourced authority boundary (peering)

Durable trust/identity authority transitions are event-sourced (InviteAccepted, PeerShared). Transport runtime mechanics are not canonical facts: retry cadence, discovery timing, session lifecycle, and endpoint observations are ephemeral operational state managed by the peering runtime directly.

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
4. trust-check functions (`is_authorized_for_tenant`, `authorized_fingerprints_from_db`) remain read-only.

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
- `target_message_deleted` — for reaction/file skip-on-delete
- `deleted_file_message_id` — root deleted-message id for late `file_slice` arrivals after descriptor purge
- `file_descriptors` / `existing_file_slice` / `current_transport_key_event_id` — for FileSlice authorization, duplicate detection, and wrapper-key matching
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
3. identity/auth policy checks from TLA guards.

### Deletion intent + tombstone lifecycle

Deletion uses a two-stage model so deletes stay deterministic when events arrive out of order. 

**Stage 1: deletion_intent write.**
The `MessageDeletion` projector always emits an idempotent `deletion_intent` write keyed
by `(recorded_by, target_kind="message", target_id)`. This records the intent to delete
regardless of whether the target message exists yet.

**Stage 2: tombstone + hard purge.**
- If the target message exists in projected state, the projector also emits tombstone
  (`deleted_messages`) write ops, live-view cleanup (`messages`, `reactions`), and a
  `HardPurgeMessageGraph` follow-up in the same projection transaction.
- If the target does not exist yet, only the intent is recorded. No imperative retries.

**Delete-before-create convergence:**
Target-creation projectors (`project_message_pure`) check for matching `deletion_intent`
rows in their context snapshot and immediately tombstone on first materialization. The
tombstone row uses the original deletion event's ID and author from the intent, ensuring
identical final state regardless of arrival order.

**Monotonic deletion state:**
- `active → tombstoned` is allowed.
- `tombstoned → active` is never allowed by replay.
- Minimal tombstones remain (`deletion_intents`, `deleted_messages`, and `deleted_files`).
- Deleted event material does not remain in `events`, tenant-scoped event tables, or live projections after a successful purge.

**Cleanup fanout:**
Reaction cleanup on message delete is represented as explicit deterministic `Delete` WriteOps
in the `ProjectorResult`, not hidden side effects. The hard-purge follow-up then removes the
deleted message graph from event storage and dependent projection rows (`reactions`, `files`,
`file_slices`, queue rows, blocked rows, subscription feed rows, fanout rows, and orphaned
global event blobs when no tenant still references them).

**Late dependent arrivals:**
- `message` after prior intent: tombstones immediately, then purges itself.
- `reaction` / `file` after prior tombstone: dependency checks treat the deleted message as
  satisfied for the message-target edge, the projector emits `HardPurgeMessageGraph`, and the
  event purges itself in the current transaction.
- `file_slice` after descriptor purge: purge persists a minimal `deleted_files(file_id -> message_id)`
  map, so the `file_slice` projector can recognize the deleted graph even when the original
  descriptor row is already gone and purge the slice immediately.

**Atomicity + retry:**
`project_one` owns the transaction boundary for the projector writes, emitted purge command,
terminal `valid_events` insert, and cascade. If any purge deletion or postcondition check fails,
the whole transaction rolls back and the normal `project_queue` retry path runs later.

### Replay/reorder/idempotence deletion invariants

These invariants are enforced by tests (`test_deletion_invariant_*`):

1. **Duplicate replay:** Re-projecting a deletion event leaves state unchanged after first application.
2. **Order convergence:** Delete-before-create produces identical tombstone rows as create-before-delete.
3. **Replay invariance:** Full forward replay from event log reproduces identical tombstone state.
4. **Auth determinism:** Authorization failure paths are deterministic from projected context snapshot.
5. **Cleanup completeness:** No live reactions, file descriptors, or file slices remain for tombstoned messages; no query can surface deleted entities.
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

Three synchronous creation entry points exist:

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

Rare bootstrap-context flows use one explicit second mode:

1. store the canonical event so the event id is known,
2. write event-id-dependent context,
3. project in the same transaction,
4. return only after that projection outcome commits.

Local create does not rely on create-side origin `project_queue` rows for crash
safety. The durable recovery path for blocked local create is the blocked-state
tables, while the ordinary synchronous path commits canonical store and first
projection attempt together.

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
9. resolve inner deps via the same schema dependency engine (presence uses tenant-scoped `valid_events` and semantic dep typing reads tenant-scoped `valid_events.semantic_type_code`),
10. run normal inner signer + projector stages, passing the outer wrapper `key_event_id` into projector context when a projector needs transport-level authorization checks,
11. mark outer event valid only if inner projection succeeds.

Decryption is an adapter stage inside the same projection pipeline, not a second projection system.

## 6.3 Plaintext policy

1. default: no persisted plaintext queue,
2. plaintext exists in memory during projection only,
3. optional short-lived cache can be added later for performance.

Current canonical plaintext families:
1. identity/auth chain events (`workspace`, `invite_accepted`, `user_invite_shared`, `peer_invite_shared`, `user`, `peer_shared`, `admin`),
2. local identity/support events (`peer_secret`, `key_secret`, bootstrap helper events),
3. test/support-only content such as `bench_dep` when intentionally left outside normal privacy policy.

Normal user content families (`message`, `reaction`, `message_deletion`, `file`, `file_slice`) are required-encrypted. Canonical persisted rows for those events therefore normally have outer type `encrypted`, while `valid_events.semantic_type_code` records the inner semantic type for dep checking and projector dispatch.

Encrypted wrapper events remain canonical but carry ciphertext payloads whose inner event type is validated by `inner_type_code` before inner projection.

---

# 7. Durable Queue and Worker Model

## 7.1 Queue tables

Operational queues:

1. `project_queue(peer_id, event_id, available_at, attempts, lease_until, priority_lane, priority_ts)`.

Canonical tables and queue tables stay separate.

## 7.2 Workers

Peer runtime worker shape:
1. `RangeSession`:
   - choose one explicit range,
   - reconcile that range with negentropy on the control stream,
   - exchange missing blobs on the data stream as raw length-delimited records,
   - append received blobs to a `ReceiveLog`,
   - finish the spool file before local canonical ingest continues in the background.
2. dependency session:
   - receive direct dependency requests on the control stream,
   - send dependency replies on the data stream,
   - ingest replies immediately through `ingest_now`.
3. project worker/drain:
   - claim `project_queue`,
   - run `project_one` in autocommit,
   - dequeue successes in batches and retry failures with backoff.
4. cleanup worker:
   - recover leftover receive logs,
   - reclaim expired leases,
   - purge stale operational rows and expired endpoint observations.

## 7.3 Sync Transfer Production

Bulk transfer is range-owned.

1. the scheduler picks one range from the current ladder:
   - `last day`
   - `last week`
   - `last twelve weeks`
   - `full history`
2. the initiator opens a `Range` session and sends the concrete window bounds in the initial `NegOpen`,
3. both sides load that range from `shared_event_index` into an in-memory `NegentropyStorageVector`,
4. negentropy computes `have_ids` / `need_ids` for that explicit range,
5. both sides stream all missing blobs for that range as raw `[u32 len][blob]` records,
6. the receiver appends those records to a `ReceiveLog`, stamping `first_received_at` and `first_stored_at` in the file,
7. on close or idle timeout, the log is finalized with `flush + sync_all`, the range session ends, and the log is queued for background canonical ingest,
8. while a hot `LastDay` receive is active for a DB, bulk receive-log replay stays paused so download/store remains the priority path.

Dependency repair is separate:

1. projection blocking records the missing dep and source peer,
2. the runtime publishes that dep to the live dependency session for the source peer,
3. the peer replies with `Event` blobs,
4. replies ingest immediately and may unblock waiting events.

## 7.4 Dedupe and recovery

1. `project_queue` is transient and purged on terminal decision for the `(peer_id, event_id)` projection target.
2. enqueue uses dedupe guards and skips terminal or already-blocked states.
3. duplicate enqueue races are safe via `INSERT OR IGNORE` plus terminal fast-drop checks.
4. `ReceiveLog` replay parses valid records to EOF and ignores a truncated tail.
5. leftover receive logs are ingested on startup; interrupted bulk ranges are not discarded.
6. dependency-session routing state is bounded in-memory state keyed by `(db_path, tenant_id, peer_id)`.

## 7.5 Atomicity boundaries

Must be atomic:

1. append one blob to the `ReceiveLog`,
2. canonical event insert + recorded insert + `project_queue` enqueue,
3. projection state transition + project dequeue,
4. unblock update + project requeue.

Can be eventual:

1. range retry after timeout or connection loss,
2. dependency request retry,
3. queue cleanup and metrics/logging.

## 7.6 Multi-source coordination

The active implementation keeps coordination intentionally simple.

1. there is one authenticated QUIC connection per peer,
2. each peer can host multiple range sessions plus one dependency session,
3. bulk scheduling is range-based, not event-based,
4. newer ranges are favored by the fixed ladder order,
5. true arbitrary-range splitting and cross-peer range balancing are future work.

This means the current branch optimizes for:

1. minimum time to first durable store for recent data,
2. minimum latency to unblock projection for missing deps,
3. a small, readable scheduler rather than a global per-event allocator.

### Connection idempotency

All connectivity producers are allowed to be "hungry" and keep emitting dial
hints, but the runtime remains peer-idempotent after authentication:

1. bootstrap rows, observed endpoints, and discovery advertisements are all
   inputs to `ensure_connected(tenant, peer)`,
2. once the remote daemon fingerprint is known, all such inputs share the
   same daemon-scoped dispatch key,
3. locally there is at most one live QUIC daemon connection owner per
   `(db_path, remote_daemon_peer_id)`, while tenant/workspace work reuses that
   connection by opening logical sessions inside it,
4. a preferred-direction connection replaces a non-preferred duplicate, while
   equal-or-worse duplicates are closed immediately.

This keeps bootstrap as an ongoing process instead of a brittle state machine
while preventing the dual-session/double-send failure mode caused by redundant
live connections to the same peer.

### Implementation decisions

The active branch chooses simpler boundaries over a global per-event planner:

1. **Range-owned bulk transfer.** One range session owns one explicit range and
   one `ReceiveLog`.
2. **Immediate dependency repair.** Blockers go to a separate dependency
   session and reply ingestion does not wait behind bulk files.
3. **Daemon-connection-scoped ownership.** Sessions belong to one authenticated
   daemon connection lifetime, and duplicate raw connections are still collapsed
   by the live daemon-connection slot rule.
4. **Simple scheduler first.** The current scheduler round-robins the fixed
   range ladder before growing into arbitrary coordinator-chosen ranges.
5. **Use stock negentropy directly.** The active path builds an in-memory
   vector from `shared_event_index` for the selected range instead of routing bulk sync
   through a bespoke request-credit scheduler.

## 7.7 Negentropy implementation notes

Baseline implementation:
1. `shared_event_index` stores shared-event membership tuples (`workspace_id`, timestamp, event id bytes).
2. `RangeSession` queries `shared_event_index` for one explicit range and loads that slice into an in-memory `NegentropyStorageVector`.
3. Control-plane reconciliation uses `NegOpen` and `NegMsg`; the first `NegOpen` may carry a `P7SW` window envelope selecting one of:
   - `LastDay`
   - `LastWeek`
   - `LastTwelveWeeks`
   - `Full`
4. Outbound scheduling currently round-robins those windows per `(db_path, peer_id)`.
5. Range data transfer streams raw length-delimited blob records (`[u32 len][blob]`) after reconciliation for that range.
6. Multi-source coordination does not replace negentropy; future smarter range balancing will still consume range-local membership discovered by negentropy.
7. The current range path uses only the in-memory vector-backed storage built directly from `shared_event_index`; the older SQLite-backed storage path has been removed.

Primary code references:
1. `src/runtime/sync_engine/session/range_session.rs`
2. `src/runtime/sync_engine/session/windowing.rs`
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

1. workspace scoping is applied consistently: workspace-facing RPCs use the daemon's active tenant, while workspace-creating RPCs (`CreateWorkspace`, `AcceptInvite`) are tenant-agnostic control-plane operations that mint fresh tenants,
2. the daemon can coordinate side effects (runtime restarts, invite refs, connection management),
3. there is a single authority for session-local state (active peer, invite aliases).

Exceptions where direct DB access is acceptable:
- **daemon startup** (`topo start`): the daemon itself opens the DB to initialize schema and discover tenants,
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

Tenant-scoping rule:
1. `Status`, `View`, `Messages`, `Users`, `Peers`, `Keys`, and similar workspace-facing RPCs are scoped to the active tenant,
2. `CreateWorkspace` and `AcceptInvite` are tenant-agnostic control-plane RPCs: they always create a fresh local tenant/workspace binding and must not reuse the active tenant,
3. `CreateInvite`, `CreateDeviceLink`, `AcceptLink`, and similar existing-workspace operations stay scoped to an already bound tenant/workspace lineage,
4. on a multi-tenant DB with no selected tenant, workspace-facing RPCs should return `no active tenant` instead of misleading aggregate zeros,
5. daemon readiness/liveness probes therefore need tenant-agnostic control-plane RPCs such as `ActiveTenant` or `Tenants`, not `Status`.

### Local-echo reconciliation (`client_op_id`)

Frontends need instant optimistic feedback on user actions (send, react, attach file) even while the backend is busy with sync or projection. The `client_op_id` mechanism provides this:

1. Frontend generates a unique `client_op_id` string and passes it with the write RPC (`Send`, `React`, `SendFile`).
2. Frontend immediately shows an optimistic row keyed by `client_op_id` — no server round-trip needed for display.
3. Daemon creates the event normally and stores a local mapping: `client_op_id → event_id` in the `local_client_ops` table (not replicated).
4. When building `View` or `Messages` responses, the daemon annotates canonical projected items with their `client_op_id` (via LEFT JOIN on the mapping table).
5. Frontend polls the view and sees a canonical message tagged with `client_op_id: "abc"` — drops the optimistic row. Done.

The frontend reconciliation is a single selector: `visible = canonical ∪ {o ∈ optimistic | o.client_op_id ∉ canonical.client_op_ids}`. No status machine, no async state tracking, no merge logic. The `client_op_id` is purely optional and backward compatible — commands without it work exactly as before.

The `local_client_ops` table is pruned periodically (entries older than 24h). It is local UX state only.

### DB selection

The `--db` flag takes a literal file path. Default: `topo.db` in the current directory. No aliases, indices, or global registry.

## 8.2 Testing and agent ergonomics

Assertion-first commands are first-class:

1. `assert-now`,
2. `assert-eventually`,
3. low-memory realism/perf harnesses: `scripts/run_lowmem.sh`, `scripts/run_perf_serial.sh lowmem` (Linux-only).

`assert-eventually` is preferred over ad-hoc sleeps for both deterministic tests and agent self-play loops.

Low-memory Linux-only note:
1. harness scripts sample `/proc/<pid>/status` and `/proc/<pid>/smaps`,
2. hard-ceiling validation uses cgroup v2 (`memory.max`, `memory.events`),
3. RSS-sampling tests in `tests/low_mem_test.rs` are sanity checks (ignored by default for budget assertions),
4. non-Linux platforms should use functional low-memory tests and device-native profiling instead of the Linux harness gate.

### Multi-source large-file catchup perf methodology

The dedicated large-file catchup harness in `sync_graph_test.rs` validates both correctness and source-distribution behavior:
1. seed source `S0` with encrypted `file` descriptor + `file_slice` events,
2. clone that exact dataset to all non-sink sources,
3. run sink-driven multi-source catchup,
4. assert sink `file_slice` event-id set exactly equals the seeded set,
5. attribute each received file slice by source from `recorded_events.source` (`quic_recv:<peer_id>@<ip:port>`),
6. assert each source contributes a minimum fair-share fraction, not merely `>0`.

Current smoke fairness floor uses `min_fair_share_fraction = 10%` of `(total_slices / source_count)`.

### Low-memory perf methodology

Low-memory coverage is split into two lanes:
1. **Functional lane** (`tests/low_mem_test.rs`) for fast correctness checks in low-memory mode.
2. **Realism lane** (`scripts/run_lowmem.sh`) for process-isolated Linux memory accounting and optional cgroup hard caps.

Functional lane defaults:
1. runs by default: `low_mem_ios_functional_smoke_2k`,
2. RSS-sampling budget tests are ignored by default: `low_mem_ios_budget_smoke_10k`, `low_mem_ios_budget_soak_million`.

Realism lane defaults:
1. driven through `scripts/run_perf_serial.sh lowmem`,
2. default scenarios: `50k+10k` message delta and `50k+20x1MiB` file delta,
3. default enforcement: `LOWMEM_CGROUP_ENFORCE=1`, `LOWMEM_CGROUP_LIMIT_KB=22528`.

Optional low-memory hardening scenarios:
1. enable with `PERF_LOWMEM_POC_ENABLE=1`,
2. optionally add `PERF_LOWMEM_RUN_LARGE_TARGET=1` and `PERF_LOWMEM_RUN_SMALL_BRACKET=1`,
3. available scenarios include `1M+10k` messages, `500k+100x1MiB` realism files, and `0+10k x1MiB` extreme files.

Low-memory harness output fields used by perf reporting:
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

Invites are **multi-use by design**. The same invite link can be accepted by multiple peers (or the same peer multiple times). Each acceptance creates a new local tenant with a fresh user+peer identity bound to the invited workspace. This is intentional — invite links are portable, shareable tokens analogous to Signal group invite links rather than single-use authorization codes.

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

Field labels: `eid` = invite event ID, `key` = invite private key, `wid` = workspace ID, `uid` = user event ID (device-link only), `spki` = daemon SPKI fingerprint. All ID/key fields are 32-byte hex (64 hex chars). Address tokens are comma-separated; port omitted when default 4433. IPv6 addresses are fully expanded as 8 dash-separated groups of 4 hex digits (no brackets) to avoid shell glob/escaping issues; non-default port uses `_port` suffix (e.g. `2601-0645-8881-1d40-0216-3eff-fe8c-0d03_7443`).

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
3. Initial sync connection runs may authenticate via bootstrap trust rows while full identity events are still converging.
4. `peer_shared` projection consumes matching bootstrap trust rows with deterministic `Delete` write-ops once steady-state PeerShared trust is present.
5. Ongoing dial/accept checks then use SQL trust queries (`is_authorized_for_tenant`) with no trust writes in read paths.

## 9.4 Sender-subjective encryption proof-of-concept

The proof-of-concept requires that we show that modern group key agreement schemes are possible with this approach, but we do not seek to build one, instead opting for a simple placeholder.  

For each encrypted message in the prototype:

1. sender creates a fresh local key event,
2. sender emits one key-wrap event per currently eligible recipient peer pubkey,
3. encrypted content references key dependency via normal event refs.

User removal is out of scope in this proof-of-concept, so sender key-wrap selection is based on the currently known peer set rather than a removal policy.
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

Credential transition model: tenant-scoped replay state may install a bootstrap session-auth cert first; projection later installs the PeerShared-derived tenant session-auth cert. The live QUIC endpoint continues to use the separate daemon transport identity throughout. Runtime enforces one-way transition for tenant creds (no bootstrap-after-PeerShared downgrade).

Consumption: when a PeerShared event is projected, the PeerShared projector deletes matching `invite_bootstrap_trust` and `pending_invite_bootstrap_trust` entries for that SPKI in the same projection apply transaction. This happens at projection time, not on trust check reads — trust check reads (`is_authorized_for_tenant`, `authorized_fingerprints_from_db`) are pure queries with no write side-effects.

Lookup shape: trust queries resolve peers via projected `peers_shared.transport_fingerprint` (indexed by `(recorded_by, transport_fingerprint)`), not by runtime fallback scans over `peers_shared.public_key`.

TTL expiry: bootstrap trust rows are time-bounded. Unconsumed entries expire and are purged.

User removal is out of scope in this transport model; trust derives only from bootstrap trust rows and steady-state `PeerShared` projection state.

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
3. **Never assert** on `store_count()`, `recorded_events_count()`, or `shared_event_index_count()` — these include identity overhead that varies.
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

`file_slice` events (type 25, signed) are signed and validated like other canonical events, but in normal operation they are carried inside `encrypted` wrappers whose `key_event_id` must match the parent file descriptor's `key_event_id`.
`file` events (type 24, signed) are encrypted file descriptors with deps on `message_id`, `key_event_id`, and `signed_by`.
Retired event type 4 is rejected by unknown-type dispatch in this epoch.

### Low-memory strategy (`low_mem_ios`)

Trust and key sets use SQL indexed point lookups, not full in-memory loading. The projection tables (`invites_accepted`, identity chain tables, bootstrap trust tables) are queried on demand with indexed `(recorded_by, ...)` keys.

There is no dedicated unbounded in-memory trust/key hot cache; low-memory behavior relies on indexed SQL lookups plus statement caching (`prepare_cached`).

Canonical event/trust datasets can grow large on disk; low-memory mode bounds in-memory working set (queues, buffers, caches), not total persisted history.

Runtime low-memory mode is enabled by env var `LOW_MEM_IOS` (truthy except `0`/`false`). Queue/runtime tuning values are centralized in `src/shared/tuning.rs`, including:
1. projection drain/write batch sizing,
2. shared ingest channel caps,
3. session ingest caps,
4. transport receive-buffer limits,
5. disabling file-slice receive-rate capture so `sync_run_rx_events` does not accumulate even event-id queue pressure in lowmem mode.

Validation scale requirements: the low-memory path must remain stable at >= 1,000,000 canonical events on disk and >= 100,000 peer trust keys, for sync deltas > 10,000 events or files while targeting a 24 MiB steady-state RSS envelope on representative constrained devices. Throughput may degrade to preserve bounded memory. For very large message histories and trust sets, the design favors bounded memory (smaller in-flight windows and SQL point lookups) over peak throughput.

Caveat: `24 MiB` is an operational target validated by representative low-memory tests and tuning profiles, not a universal guarantee across all kernels/devices/workloads.

Validation harness platform scope:
1. low-memory harness perf gates are Linux-only (`/proc` + cgroup v2),
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

1. `file` descriptors and `file_slice` payload events are normal content events and therefore travel inside `encrypted` wrappers in steady state,
2. `file.key_event_id` is the required wrapper/decryption key for every slice in that file; file-slice projection and `save-file` both reject wrapper-key mismatches,
3. file slices use a canonical fixed ciphertext size; final plaintext chunks are zero-padded before encryption,
4. `send-file` and synthetic file generation stream slices one at a time instead of reading the whole file into memory,
5. `save-file` streams decrypt/write into a temp file in the destination directory, truncates to the descriptor byte length, and atomically renames on success,
6. effective download rate is derived from synced `file_slice` events only; low-memory mode disables that capture so completed files may legitimately show no MiB/s there,
7. deps and signatures continue to gate integrity and ordering (wire/layout details in section 1.2; queue transfer behavior in section 7.6).

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

## 15.4 Formal verification (Verus)

Machine-checked proofs live in `verus-proofs/`. Run via `scripts/run_verus_proofs.sh`.

## 16. TODO: Automatic misbehavior detection and participant removal

### 16.1 Wrong-author deletion as detectable misbehavior

A `MessageDeletion` event contains `author_id` inside the encrypted wrapper (not
visible without the content key). The projector rejects deletions where
`del.author_id` does not match the target message's author. However, the
`deletion_intent` row is recorded before this check (intent-only path for
delete-before-create convergence), and wrong-author intents are never cleaned up.

Since `MessageDeletion` events are signed by `signed_by` (the sender's peer identity)
and encrypted, a wrong-author deletion can only be created by a workspace member
with a tampered or broken client. This is detectable misbehavior:

1. **Detection**: When a deletion projector sees `author_id != target_message_author`,
   record the misbehaving `signed_by` peer identity.
2. **Response**: Emit a `Removal` event targeting the misbehaving peer. This revokes
   their transport authorization via the `removed_entities` table.
3. **Cleanup**: Garbage-collect `deletion_intent` rows where the referenced deletion
   event has been rejected (wrong-author or wrong-type).

### 16.2 Other detectable misbehavior patterns

Future work should detect and respond to:

- Events with invalid signatures (already rejected, but the source peer could be flagged)
- Events with forged `signed_by` fields (peer claims to be someone else)
- Excessive event volume from a single peer (rate limiting / DoS protection)
- Events referencing non-existent or unauthorized workspace_ids
