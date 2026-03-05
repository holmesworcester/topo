# POC-7 Current Runtime Diagram

Code-accurate runtime and data-flow snapshot for `master` in `poc-7`.

Primary source modules:
- `src/main.rs`
- `src/rpc/server.rs`
- `src/node.rs`
- `src/service.rs`
- `src/event_modules/*/{commands.rs,queries.rs}`
- `src/peering/runtime/*`
- `src/peering/loops/*`
- `src/peering/workflows/*`
- `src/transport/{peering_boundary.rs,connection_lifecycle.rs,session_factory.rs,intro_io.rs}`
- `src/sync/session/*`
- `src/event_pipeline/{mod.rs,phases.rs,planner.rs,effects.rs,drain.rs}`
- `src/projection/apply/*`
- `src/projection/create.rs`
- `src/db/{project_queue.rs,egress_queue.rs,wanted.rs,transport_trust.rs}`

## 0) RPC Dispatch And Event Locality

```mermaid
flowchart TD
    CLI["CLI (topo)"] --> RPC["rpc/server dispatch"]
    RPC --> EM["event_modules commands + queries"]
    RPC --> SUB["state/subscriptions local infra"]
    RPC --> SVC["service.rs (thin helpers)"]

    EM --> SVC
    EM --> CREATE["create_*_event_synchronous / create_signed_event_synchronous"]
    SUB --> SVC
    CREATE --> PROJ["project_one + cascade"]
    PROJ --> READS["projection read tables"]

    SVC --> INFRA["open_db_* helpers / node status / intro transport helper"]
```

## 1) Unified Ingest to SQLite (Local + Wire Events)

```mermaid
flowchart TD
    LOCAL["Local create events"] --> INGEST["shared ingest + batch_writer"]
    OTHERS["Other peers"] -->|"sync sessions"| EP

    subgraph NET["Incoming Wire"]
      EP["QUIC endpoint"] --> LIFE["connection lifecycle"]
      LIFE --> FACT["session factory"]
      FACT --> SESS["sync session (data stream)"]
      SESS --> RECV["receiver task"]
      RECV --> INCOMING["incoming sync events"]
    end

    INCOMING --> INGEST
    INGEST --> STORE["events + recorded + sync state persist"]
    STORE --> QDB[("SQLite Queues")]
    QDB --> APPLY["project_one + cascade"]
    APPLY --> PDB[("SQLite Projections")]

    CTRL["Sync control stream (HaveList / need_ids)"] --> QDB
    PDB -->|trust rows| LIFE
```

## 2) One Sync Session (Control/Data Flow)

```mermaid
flowchart TD
    PEER["peering loop (connect/accept/download/punch)"] --> BOUND["transport::peering_boundary (dial/accept/session/intro helpers)"]
    BOUND --> LIFE["connection_lifecycle (connected peer + peer_id)"]
    BOUND --> FACT["session_factory (open/accept streams)"]
    FACT --> IO["TransportSessionIo + session_id"]
    IO --> HANDLER["SyncSessionHandler::on_session"]

    HANDLER --> SYNC_RECON["sync reconcile (control exchange)"]
    SYNC_RECON --> IDS["have_ids + need_ids"]

    IDS -->|peer needs my ids| ENQ["egress_queue.enqueue_events(peer_id, ids)"]
    IDS -->|I need peer ids| HAVE["wanted_events.insert(ids) + send HaveList(ids)"]

    ENQ --> CLAIM["egress_queue.claim_batch + mark_sent"]
    CLAIM --> OUT["data_send: Frame::Event(blob)"]
    OUT --> RX["peer receiver task"]
    RX --> IN["ingest channel"]

    IN --> WRITER["batch_writer"]
    WRITER --> P1["phase 1: persist + enqueue"]
    P1 --> P2["phase 2: plan post-commit commands"]
    P2 --> P3["phase 3: run effects executor"]
    P3 --> PROJ["project_one + cascade"]

    OUT --> DD["DataDone"]
    DD --> SHUT["Done / DoneAck shutdown protocol"]
```

## 3) High-Level Runtime Boundaries

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 320}} }%%
flowchart TD
    CTRL["Control"]
    BOOT["Setup"]
    RSUP["Supervisor"]
    TRANS["Transport"]
    SYNC["Sync Engine"]
    PIPE["Event Pipeline"]
    PSTATE["Projection State"]
    PEERS["Peers"]

    CTRL --> BOOT
    CTRL --> PIPE
    BOOT --> RSUP
    BOOT --> TRANS
    BOOT --> PIPE
    RSUP --> TRANS
    PEERS --> TRANS
    TRANS --> SYNC
    SYNC --> PIPE
    PIPE --> PSTATE
    PSTATE -->|trust rows| TRANS
```

## 4) Runtime Topology (Threads + Queues + DB, Reference)

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 340}} }%%
flowchart TD
    subgraph CTRL["Control Plane"]
      CLI["CLI (topo start)"] --> MAIN["main.rs"]
      MAIN --> RPC["RPC server thread (Unix socket)"]
      MAIN --> NODE["node::run_node"]
      MAIN --> SIG["Ctrl-C signal task"]
      SIG --> SHUT_N["shutdown_notify"]

      RPC --> DISPATCH["rpc/server dispatch"]
      DISPATCH --> SHUT_REQ["RpcMethod::Shutdown"]
      SHUT_REQ --> SHUT_N
      DISPATCH --> EMQ["event_modules commands + queries"]
      DISPATCH --> SUBQ["state/subscriptions local infra"]
      DISPATCH --> SVC["service.rs helpers"]
      EMQ --> SVC
      SUBQ --> SVC
      EMQ --> LOCAL["local create path / create_*_event_synchronous"]
    end

    START["setup_endpoint_and_tenants"]

    subgraph RUNTIME_SUP["Runtime Supervisor"]
      RSUP["Supervisor"]
      RSTATE["state machine: IdleNoTenants <-> Active"]
      RCANCEL["CancellationToken tree"]
      TARGET_Q["unified target ingress queue"]
      DISPATCHER["single target dispatcher"]
      ACCEPT_W["accept-loop worker"]
      CONNECT_W["connect-loop workers"]
      INGRESS_W["target ingress workers"]
      RSUP --> RSTATE
      RSUP --> RCANCEL
      RSUP --> ACCEPT_W
      RSUP --> INGRESS_W
      RSUP --> TARGET_Q
      TARGET_Q --> DISPATCHER
      DISPATCHER --> CONNECT_W
      INGRESS_W --> TARGET_Q
    end

    NODE --> START
    START --> RSUP

    subgraph PIPE["Event Pipeline"]
      LOCAL --> INGEST["shared ingest channel (mpsc)"]
      INGEST --> WRITER["batch_writer thread"]
      WRITER --> P1["Persist + enqueue"]
      P1 --> PROJ_Q["project_queue"]
      PROJ_Q --> P3
      P1 --> P2["phase 2: plan post-commit commands"]
      P2 --> P3["phase 3: execute effects boundary"]
      P3 --> PROJ["project_one + cascade"]
    end

    subgraph TRANS["Transport"]
      direction LR
      EP["single QUIC endpoint"]
      BOUND["peering_boundary (contract helpers)"]
      LIFE["connection lifecycle + trust read"]
      FACT["session factory"]
      IIO["intro io"]
    end

    START --> EP
    RSUP --> WRITER
    ACCEPT_W --> BOUND
    CONNECT_W --> BOUND
    BOUND --> LIFE
    BOUND --> FACT
    BOUND --> IIO

    subgraph SYNC_ENG["Sync Engine"]
      SYNC["SyncSessionHandler (on_session)"]
      CTRL_STREAM["Sync control"]
      DATA["Sync data"]
      WANT["wanted_events"]
      EGRESS["egress_queue"]
      SEND["Shared event send"]
      RECV["Receive + source tag"]

      SYNC --> CTRL_STREAM
      SYNC --> DATA
      CTRL_STREAM --> WANT
      CTRL_STREAM --> EGRESS
      EGRESS --> SEND
      DATA --> RECV
    end

    FACT --> SYNC
    RECV --> INGEST

    subgraph PSTATE["Projection State"]
      direction LR
      TRUST_DB["Transport trust tables"]
      VALID["valid_events"]
      BLOCKED["blocked_events + blocked_event_deps"]
      REJECTED["rejected_events"]
      READS["Projection tables"]
    end

    PROJ --> VALID
    PROJ --> BLOCKED
    PROJ --> REJECTED
    PROJ --> READS
    PROJ --> TRUST_DB

    TRUST_DB --> LIFE
    SHUT_N --> RSUP
    SHUT_N --> RPC
```

**Runtime Topology Legend**
- `runtime::supervisor::RuntimeSupervisor`: single owner for long-lived runtime workers (writer, accept loop, unified target dispatcher, target ingress workers).
- `service.rs helpers`: `open_db_*`, node status helpers, intro transport helper entry points.
- `Persist + enqueue`: phase 1 persists events/recorded/sync state and enqueues `project_queue`.
- `Sync control`: sync control stream messages including `HaveList` and `Done`.
- `Sync data`: sync data stream frames (`Event`, `DataDone`).
- `Shared event send`: `Store::get_shared(events) -> Frame::Event`.
- `Projection tables`: projected read models (`messages`, `users`, `peers`, `channels`).
- `Transport trust tables`: transport trust rows (`peer_shared`, invite bootstrap records).
- `connection lifecycle + trust read`: transport-owned tenant-scoped lookup via `db::transport_trust::is_peer_allowed` plus dial/accept identity handling.

## 5) Bootstrap Event DAG (Alice/Bob/Carol, Multi-device)

Main DAG uses two collapsed repeated blocks to keep repeated invite-accept patterns DRY:
- `JOIN(...)`: expanded in `5.1 User Join Subgraph`.
- `DEVICE_ADD(...)`: expanded in `5.2 Device Add Subgraph`.

```mermaid
flowchart LR
    subgraph A["Alice (inviter)"]
      A0["A0 Workspace"]
      A1["A1 InviteAccepted (self anchor)"]
      A2["A2 UserInvite (self)"]
      A3["A3 User (alice)"]
      A4["A4 DeviceInvite (alice-laptop)"]
      A5["A5 PeerShared (alice-laptop)"]
      A6["A6 DeviceInvite (link alice-phone)"]
      A7["A7 PeerShared (alice-phone)"]
      A8["A8 UserInvite (for Bob)"]
      A9["A9 UserInvite (for Carol)"]
      A10["A10 SecretShared (content key -> Bob invite)"]
      A11["A11 SecretShared (content key -> Carol invite)"]
    end

    A0 --> A1 --> A2 --> A3 --> A4 --> A5
    A3 --> A6 --> A7
    A3 --> A7
    A0 --> A8
    A0 --> A9
    A8 --> A10
    A9 --> A11
    A5 --> A10
    A5 --> A11

    BJ["JOIN(Bob)"]
    CJ["JOIN(Carol)"]
    A8 --> BJ
    A10 --> BJ
    A9 --> CJ
    A11 --> CJ

    BUSER["B.user (from JOIN)"]
    BPSL["B.peer_shared laptop (from JOIN)"]
    CUSER["C.user (from JOIN)"]
    CPSL["C.peer_shared laptop (from JOIN)"]
    BJ --> BUSER
    BJ --> BPSL
    CJ --> CUSER
    CJ --> CPSL

    BDI["B DeviceInvite (link bob-phone)"]
    CDI["C DeviceInvite (link carol-tablet)"]
    BUSER --> BDI
    CUSER --> CDI

    BADD["DEVICE_ADD(Bob phone)"]
    CADD["DEVICE_ADD(Carol tablet)"]
    BDI --> BADD
    CDI --> CADD
    BUSER --> BADD
    CUSER --> CADD

    BPSP["B.peer_shared phone"]
    CPST["C.peer_shared tablet"]
    BADD --> BPSP
    CADD --> CPST

    M1["M1 message (alice-phone: hi)"]
    M2["M2 message (bob-phone: hey)"]
    M3["M3 message (carol-laptop: ship it)"]

    A3 --> M1
    A7 --> M1
    BUSER --> M2
    BPSP --> M2
    CUSER --> M3
    CPSL --> M3
```

### 5.1 User Join Subgraph (expanded)

`workspace::commands::join_workspace_as_new_user` + `persist_join_signer_secrets`.

```mermaid
flowchart LR
    INV["UserInvite invite event"] --> IA["InviteAccepted (local accepted binding)"]
    INV --> UB["User (signed_by = invite_event_id)"]
    UB --> DIF["DeviceInvite (signed_by = user_event_id)"]
    DIF --> PSF["PeerShared (signed_by = device_invite_event_id)"]
    UB --> PSF

    INV --> SS["SecretShared (recipient_event_id = invite_event_id)"]
    SS -. optional timing .-> SK["SecretKey (unwrapped content key)"]

    PSF --> LSP["LocalSignerSecret (peer_shared)"]
    UB --> LSU["LocalSignerSecret (user)"]

    IA -. guard-unblock / retry .-> UB
    IA -. guard-unblock / retry .-> DIF
    IA -. guard-unblock / retry .-> PSF
```

### 5.2 Device Add Subgraph (expanded)

`workspace::commands::add_device_to_workspace` + `persist_link_signer_secrets`.

```mermaid
flowchart LR
    USER["Existing User"] --> DINV["DeviceInvite link invite"]
    DINV --> IA["InviteAccepted (local accepted binding)"]
    DINV --> PSF["PeerShared (new device)"]
    USER --> PSF
    PSF --> LSP["LocalSignerSecret (peer_shared)"]
    IA -. guard-unblock / retry .-> PSF
```

## 6) Subscriptions (Before vs After Refactor)

### 6.1 Pre-refactor Flow (historical)

```mermaid
flowchart TD
    subgraph CTRL["Control Path (RPC/CLI)"]
      CLI["CLI: sub-create/sub-enable/sub-disable/sub-poll/..."] --> RPC["rpc/server Sub* handlers"]
      RPC --> SUBMOD["event_modules/subscription::{create_subscription,set_enabled,poll_feed,ack_feed,get_state,list_subscriptions}"]
      SUBMOD --> SUBDB[("local_subscriptions + local_subscription_state + local_subscription_feed")]
    end

    subgraph PROJ["Projection Match Path"]
      INGEST["local create or wire receive"] --> PROJ1["project_one (Valid path)"]
      PROJ1 --> HOOK["event_modules/subscription::matcher::on_projected_event"]
      HOOK --> LOAD["load_active_subscriptions_for_type(recorded_by,event_type)"]
      LOAD --> MATCH["subscription matcher (currently centralized in matcher.rs)"]
      MATCH --> WRITE1["append_feed_item (full/id)"]
      MATCH --> WRITE2["mark_changed (has_changed)"]
      WRITE1 --> SUBDB
      WRITE2 --> SUBDB
    end
```

### 6.2 Current Refactored Flow (implemented)

```mermaid
flowchart TD
    subgraph CTRL2["Control Path (local-only subscription lifecycle)"]
      CLI2["CLI: SubCreate/SubEnable/SubDisable/SubPoll/..."] --> RPC2["rpc/server Sub* handlers"]
      RPC2 --> SUBCORE["state/subscriptions/* (engine + storage)"]
      SUBCORE --> SUBDB2[("local_subscriptions + local_subscription_state + local_subscription_feed")]
    end

    subgraph PROJ2["Projection Match Path (event-module-owned filters)"]
      INGEST2["local create or wire receive"] --> PROJ2A["project_one (Valid path)"]
      PROJ2A --> DISPATCH["subscriptions dispatcher (generic orchestration)"]
      DISPATCH --> SF_MSG["event_modules/message/subscription_filter.rs"]
      DISPATCH --> SF_RXN["event_modules/reaction/subscription_filter.rs"]
      DISPATCH --> SF_ATT["event_modules/message_attachment/subscription_filter.rs"]
      SF_MSG --> OUT_MSG["matches(spec, parsed) + feed_payload(mode)"]
      SF_RXN --> OUT_RXN["matches(spec, parsed) + feed_payload(mode)"]
      SF_ATT --> OUT_ATT["matches(spec, parsed) + feed_payload(mode)"]
      OUT_MSG --> SUBCORE
      OUT_RXN --> SUBCORE
      OUT_ATT --> SUBCORE
      SUBCORE --> SUBDB2
    end
```

Current ownership intent:
- Event modules own event-specific subscription filter semantics (`subscription_filter` or `subscription_filters` when multiple helpers are needed).
- Subscription lifecycle/storage/feed mechanics remain local infra (non-replicated), outside event-type modules.

## Current Data-Flow Facts

1. `egress_queue` is fed by sync control-plane `HaveList` messages, not by `batch_writer`.
2. `batch_writer` is the shared ingest sink for wire-received events and local-create events; it runs explicit phases: persist transaction, post-commit command planning, and effects execution.
3. RPC command/query dispatch routes to owner modules (event modules for event-domain operations, `state/subscriptions` for local subscription infra); `service.rs` is an infra helper layer (`open_db_*`, node status, intro transport helper).
4. Peering orchestration (`connect_loop`/`accept_loop`/workflows) now routes transport operations through `transport::peering_boundary`; peering no longer imports QUIC/trust internals directly.
5. QUIC dial/accept + peer identity extraction are transport-owned in `connection_lifecycle`.
6. QUIC stream wiring (`open_bi`/`accept_bi`, `DualConnection`, `QuicTransportSessionIo`) is transport-owned in `session_factory`.
7. Projection outputs both user-facing read tables and transport trust tables; trust rows feed both handshake allow/deny and bootstrap autodial.
8. `HaveList` IDs originate from sync reconciliation `need_ids`; runtime initiator sessions use coordinator-assigned subsets (autodial + mDNS), then land in `egress_queue`.
9. Foreground runtime is daemon-first (`topo start`): shutdown is coordinated by shared `shutdown_notify` (RPC `Shutdown` or Ctrl-C).
10. Runtime and helper initiator sessions both route pull assignment through the coordinator; there is no direct `need_ids -> HaveList(all)` bypass path.
11. Transport trust checks now read `db::transport_trust::is_peer_allowed` directly inside transport; the separate trust-oracle adapter layer is removed.
