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
- `src/event_pipeline.rs`
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
    EM --> CREATE["create_*_event_sync / create_signed_event_sync"]
    CREATE --> PROJ["project_one + cascade"]
    PROJ --> READS["projection read tables"]

    SVC --> INFRA["open_db_* helpers / node status / intro transport helper"]
```

## 1) Simplified SQLite View (Collapsed Local + Incoming Paths)

```mermaid
flowchart TD
    LOCAL["Local create events"] --> INGEST["shared ingest + batch_writer"]
    OTHERS["Other peers"] -->|"sync sessions"| EP

    subgraph NET["Incoming Wire Path"]
      EP["QUIC endpoint"] --> LIFE["connection_lifecycle / accept_peer / dial_peer"]
      LIFE --> FACT["session_factory"]
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
    PDB --> TRUST["transport trust decisions"]
    TRUST --> LIFE
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
    WRITER --> STORE["persist events/recorded/sync state + enqueue project_queue"]
    STORE --> PROJ["project_one + cascade"]

    OUT --> DD["DataDone"]
    DD --> SHUT["Done / DoneAck shutdown protocol"]
```

## 3) Runtime Topology (Threads + Queues + DB, Reference)

```mermaid
flowchart TD
    subgraph CTRL["Daemon Control Plane (CLI + RPC + node lifecycle)"]
      CLI["CLI (topo start)"] --> MAIN["main.rs"]
      MAIN --> RPC["RPC server thread (Unix socket)"]
      MAIN --> NODE["node::run_node"]
      MAIN --> SIG["Ctrl-C signal task"]
      SIG --> SHUT_N["shutdown_notify"]

      RPC --> DISPATCH["rpc/server dispatch"]
      DISPATCH --> SHUT_REQ["RpcMethod::Shutdown"]
      SHUT_REQ --> SHUT_N
      DISPATCH --> EMQ["event_modules commands + queries"]
      DISPATCH --> SVC["service.rs thin helpers (open_db_*, intro, node status)"]
      EMQ --> SVC
      EMQ --> LOCAL["local create path / create_*_event_sync"]
    end

    NODE --> START["setup_endpoint_and_tenants"]
    START --> EP["single QUIC endpoint"]
    START --> TRUST["SqliteTrustOracle (tenant-scoped allow/deny)"]

    subgraph PIPE["Event Pipeline (shared ingest -> projection)"]
      LOCAL --> INGEST["shared ingest channel (mpsc)"]
      INGEST --> WRITER["batch_writer thread"]
      WRITER --> STORE["events + recorded_events + sync state tables"]
      STORE --> PROJ_Q["project_queue enqueue + drain"]
      PROJ_Q --> PROJ["project_one + cascade"]
    end

    EP --> ACCEPT["accept_loop_with_ingest thread"]
    EP --> CONNECT["connect_loop_with_coordination threads (autodial / discovery)"]

    ACCEPT --> ORCH
    CONNECT --> ORCH

    subgraph ORCH["Peering Orchestration"]
      CYCLE["loop lifecycle (retry/backoff/cancel)"]
      INTRO["intro/punch workflows"]
    end

    subgraph TRANS["Transport Capsule"]
      BOUND["peering_boundary (contract helpers)"]
      LIFE["connection_lifecycle / accept_peer / dial_peer"]
      FACT["session_factory / accept/open_session_io"]
      IIO["intro_io / accept_and_read_intro"]
    end

    ORCH --> BOUND
    INTRO --> BOUND
    BOUND --> LIFE
    BOUND --> FACT
    BOUND --> IIO

    FACT --> SYNC["SyncSessionHandler (on_session)"]
    SYNC --> CTRL_STREAM["control stream / sync control messages / HaveList / Done"]
    SYNC --> DATA["data stream / Event / DataDone"]

    CTRL_STREAM --> WANT["wanted_events"]
    CTRL_STREAM --> EGRESS["egress_queue"]
    EGRESS --> SEND["Store::get_shared(events) -> Frame::Event send"]

    DATA --> RECV["receiver task / hash(blob) + tag recorded_by"]
    RECV --> INGEST

    PROJ --> VALID["valid_events"]
    PROJ --> BLOCKED["blocked_events + blocked_event_deps"]
    PROJ --> REJECTED["rejected_events"]
    PROJ --> READS["projection tables (messages, users, peers, channels)"]
    PROJ --> TRUST_DB["transport trust tables (peer_shared + invite bootstrap)"]

    TRUST_DB --> TRUST
    TRUST --> LIFE
    SHUT_N --> NODE
    SHUT_N --> RPC
```

## Current Data-Flow Facts

1. `egress_queue` is fed by sync control-plane `HaveList` messages, not by `batch_writer`.
2. `batch_writer` is the shared ingest sink for wire-received events and local-create events; it persists event blobs and drains `project_queue`.
3. RPC command/query dispatch is event-module owned; `service.rs` is now an infra helper layer (`open_db_*`, node status, intro transport helper).
4. Peering orchestration (`connect_loop`/`accept_loop`/workflows) now routes transport operations through `transport::peering_boundary`; peering no longer imports QUIC/trust internals directly.
5. QUIC dial/accept + peer identity extraction are transport-owned in `connection_lifecycle`.
6. QUIC stream wiring (`open_bi`/`accept_bi`, `DualConnection`, `QuicTransportSessionIo`) is transport-owned in `session_factory`.
7. Projection outputs both user-facing read tables and transport trust tables; trust rows feed both handshake allow/deny and bootstrap autodial.
8. `HaveList` IDs originate from sync reconciliation `need_ids`; in current runtime they are coordinator-assigned subsets by default (autodial + mDNS), then land in `egress_queue`.
9. Foreground runtime is daemon-first (`topo start`): shutdown is coordinated by shared `shutdown_notify` (RPC `Shutdown` or Ctrl-C).
10. Non-coordinated `need_ids -> HaveList(all)` behavior still exists in legacy helper/test paths (`download_from_sources` / direct `connect_loop`) and is no longer the primary runtime shape.
