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
    RPC --> SVC["service.rs (thin helpers)"]

    EM --> SVC
    EM --> CREATE["create_*_event_synchronous / create_signed_event_synchronous"]
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
      DISPATCH --> SVC["service.rs helpers"]
      EMQ --> SVC
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

## Current Data-Flow Facts

1. `egress_queue` is fed by sync control-plane `HaveList` messages, not by `batch_writer`.
2. `batch_writer` is the shared ingest sink for wire-received events and local-create events; it runs explicit phases: persist transaction, post-commit command planning, and effects execution.
3. RPC command/query dispatch is event-module owned; `service.rs` is now an infra helper layer (`open_db_*`, node status, intro transport helper).
4. Peering orchestration (`connect_loop`/`accept_loop`/workflows) now routes transport operations through `transport::peering_boundary`; peering no longer imports QUIC/trust internals directly.
5. QUIC dial/accept + peer identity extraction are transport-owned in `connection_lifecycle`.
6. QUIC stream wiring (`open_bi`/`accept_bi`, `DualConnection`, `QuicTransportSessionIo`) is transport-owned in `session_factory`.
7. Projection outputs both user-facing read tables and transport trust tables; trust rows feed both handshake allow/deny and bootstrap autodial.
8. `HaveList` IDs originate from sync reconciliation `need_ids`; runtime initiator sessions use coordinator-assigned subsets (autodial + mDNS), then land in `egress_queue`.
9. Foreground runtime is daemon-first (`topo start`): shutdown is coordinated by shared `shutdown_notify` (RPC `Shutdown` or Ctrl-C).
10. Runtime and helper initiator sessions both route pull assignment through the coordinator; there is no direct `need_ids -> HaveList(all)` bypass path.
11. Transport trust checks now read `db::transport_trust::is_peer_allowed` directly inside transport; the separate trust-oracle adapter layer is removed.
