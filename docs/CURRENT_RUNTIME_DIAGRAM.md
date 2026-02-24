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

    SVC --> INFRA["open_db_* helpers\nnode status\nintro transport helper"]
```

## 1) Runtime Topology (Threads + Queues + DB)

```mermaid
flowchart TD
    CLI["CLI (topo start)"] --> MAIN["main.rs"]
    MAIN --> RPC["RPC server thread (Unix socket)"]
    MAIN --> NODE["node::run_node"]
    MAIN --> SIG["Ctrl-C signal task"]
    SIG --> SHUT_N["shutdown_notify"]

    RPC --> DISPATCH["rpc/server dispatch"]
    DISPATCH --> SHUT_REQ["RpcMethod::Shutdown"]
    SHUT_REQ --> SHUT_N
    DISPATCH --> EMQ["event_modules commands + queries"]
    DISPATCH --> SVC["service.rs thin helpers\n(open_db_*, intro, node status)"]
    EMQ --> SVC

    EMQ --> LOCAL["local create path\ncreate_*_event_sync"]
    LOCAL --> INGEST["shared ingest channel (mpsc)"]

    NODE --> START["setup_endpoint_and_tenants"]
    START --> EP["single QUIC endpoint"]
    START --> TRUST["SqliteTrustOracle\n(tenant-scoped allow/deny)"]

    INGEST --> WRITER["batch_writer thread"]
    WRITER --> STORE["events + recorded_events + neg_items"]
    STORE --> PROJ_Q["project_queue enqueue + drain"]
    PROJ_Q --> PROJ["project_one + cascade"]

    EP --> ACCEPT["accept_loop_with_ingest thread"]
    EP --> CONNECT["connect_loop threads\n(autodial / discovery / manual)"]

    ACCEPT --> ORCH
    CONNECT --> ORCH

    subgraph ORCH["Peering Orchestration"]
      CYCLE["loop lifecycle\n(retry/backoff/cancel)"]
      INTRO["intro/punch workflows"]
    end

    subgraph TRANS["Transport Capsule"]
      BOUND["peering_boundary\n(contract helpers)"]
      LIFE["connection_lifecycle\naccept_peer / dial_peer"]
      FACT["session_factory\naccept/open_session_io"]
      IIO["intro_io\naccept_and_read_intro"]
    end

    ORCH --> BOUND
    INTRO --> BOUND
    BOUND --> LIFE
    BOUND --> FACT
    BOUND --> IIO

    FACT --> SYNC["SyncSessionHandler\n(on_session)"]
    SYNC --> CTRL_STREAM["control stream\nNegOpen / NegMsg / HaveList / Done"]
    SYNC --> DATA["data stream\nEvent / DataDone"]

    CTRL_STREAM --> WANT["wanted_events"]
    CTRL_STREAM --> EGRESS["egress_queue"]
    EGRESS --> SEND["Store::get_shared(events)\n-> Frame::Event send"]

    DATA --> RECV["receiver task\nhash(blob) + tag recorded_by"]
    RECV --> INGEST

    PROJ --> VALID["valid_events"]
    PROJ --> BLOCKED["blocked_events + blocked_event_deps"]
    PROJ --> REJECTED["rejected_events"]
    PROJ --> READS["projection tables\n(messages, users, peers, channels)"]
    PROJ --> TRUST_DB["transport trust tables\n(peer_shared + invite bootstrap)"]

    TRUST_DB --> TRUST
    TRUST --> LIFE
    SHUT_N --> NODE
    SHUT_N --> RPC
```

## 2) One Sync Session (Control/Data Flow)

```mermaid
flowchart TD
    PEER["peering loop\n(connect/accept/download/punch)"] --> BOUND["transport::peering_boundary\n(dial/accept/session/intro helpers)"]
    BOUND --> LIFE["connection_lifecycle\n(connected peer + peer_id)"]
    BOUND --> FACT["session_factory\n(open/accept streams)"]
    FACT --> IO["TransportSessionIo + session_id"]
    IO --> HANDLER["SyncSessionHandler::on_session"]

    HANDLER --> NEG["Negentropy reconcile\n(NegOpen/NegMsg)"]
    NEG --> IDS["have_ids + need_ids"]

    IDS -->|peer needs my ids| ENQ["egress_queue.enqueue_events(peer_id, ids)"]
    IDS -->|I need peer ids| HAVE["wanted_events.insert(ids)\n+ send HaveList(ids)"]

    ENQ --> CLAIM["egress_queue.claim_batch + mark_sent"]
    CLAIM --> OUT["data_send: Frame::Event(blob)"]
    OUT --> RX["peer receiver task"]
    RX --> IN["ingest channel"]

    IN --> WRITER["batch_writer"]
    WRITER --> STORE["persist events/recorded/neg\n+ enqueue project_queue"]
    STORE --> PROJ["project_one + cascade"]

    OUT --> DD["DataDone"]
    DD --> SHUT["Done / DoneAck shutdown protocol"]
```

## 3) Trust + Bootstrap Autodial Feedback Loop

```mermaid
flowchart TD
    INV["invite/device-link events\n+ bootstrap_context"] --> EMIT["projection emit_commands"]
    EMIT --> PEND["pending_invite_bootstrap_trust"]
    EMIT --> ACC["invite_bootstrap_trust"]

    PEER["PeerShared projection"] --> SUPER["SupersedeBootstrapTrust"]
    SUPER --> PEND
    SUPER --> ACC

    PEND --> ALLOW["SqliteTrustOracle\nallow/deny"]
    ACC --> ALLOW
    PEER --> ALLOW

    ALLOW --> LIFE["connection_lifecycle\n(handshake peer allow)"]

    ACC --> AUTODIAL["autodial refresher\nlist_active_invite_bootstrap_addrs"]
    AUTODIAL --> DIAL["spawn connect_loop_thread"]
    DIAL --> LIFE
    LIFE --> SYNC["sync sessions"]
    SYNC --> PEER
```

## 4) Simplified SQLite View (Collapsed Local + Incoming Paths)

```mermaid
flowchart TD
    LOCAL["Local create events"] --> INGEST["shared ingest + batch_writer"]

    subgraph NET["Incoming Wire Path"]
      EP["QUIC endpoint"] --> LIFE["connection_lifecycle\naccept_peer / dial_peer"]
      LIFE --> FACT["session_factory"]
      FACT --> SESS["sync session (data stream)"]
      SESS --> RECV["receiver task"]
      RECV --> INCOMING["incoming sync events"]
    end

    INCOMING --> INGEST
    INGEST --> STORE["events + recorded + neg persist"]
    STORE --> QDB[("SQLite Queues")]
    QDB --> APPLY["project_one + cascade"]
    APPLY --> PDB[("SQLite Projections")]

    CTRL["Sync control stream\n(HaveList / need_ids)"] --> QDB
    PDB --> TRUST["transport trust decisions"]
    TRUST --> LIFE
```

## 5) Draft: QUIC Endpoints Loop (Include Other Peers)

```mermaid
flowchart TD
    subgraph LOCAL["This node"]
      LEP["QUIC endpoint (local)"]
      LCOORD["CoordinationManager\n(tenant-scoped)"]
      LEP --> LCOORD
    end

    subgraph OTHERS["Other peers (same workspace)"]
      P1["Peer A QUIC endpoint"]
      P2["Peer B QUIC endpoint"]
      P3["Peer C QUIC endpoint"]
    end

    LEP -->|"sync sessions"| P1
    P1 -->|"sync sessions"| P2
    P2 -->|"sync sessions"| P3
    P3 -->|"sync sessions"| LEP

    LCOORD -->|"assign need_ids"| P1
    LCOORD -->|"assign need_ids"| P2
    LCOORD -->|"assign need_ids"| P3
```

## 6) Draft: Runtime-Coordinated Path + Peer Loop

```mermaid
flowchart TD
    AUTO["autodial + mDNS targets"] --> LOOP["connect_loop_with_coordination threads"]
    LOOP --> LEP["Local QUIC endpoint"]
    LOOP --> HANDLER["SyncSessionHandler::initiator_with_coordination"]
    HANDLER --> NEG["negentropy reconcile"]
    NEG --> CTRL["control stream HaveList/need_ids"]
    CTRL --> EQ["egress_queue"]
    EQ --> DATA["data stream Event/DataDone"]
    DATA --> INGEST["shared ingest + batch_writer"]
    INGEST --> DB[("SQLite Queues + Projections")]

    subgraph PEERS["Other peers"]
      P1["Peer A endpoint"]
      P2["Peer B endpoint"]
      P3["Peer C endpoint"]
    end

    LEP --> P1
    P1 --> P2
    P2 --> P3
    P3 --> LEP
```

## 7) Multi-Source Simplification Snapshot (Local `master`)

1. Runtime outbound sync (bootstrap autodial + mDNS discovery) now uses tenant-scoped `CoordinationManager` plus `connect_loop_with_coordination`.
2. Sink download benchmarks (`start_sink_download`) were moved onto the same coordinated connect-loop path.
3. Legacy helpers still exist (`download_from_sources`, `run_coordinator`) for compatibility/testing, so simplification is substantial but not yet a full single-path deletion.

## 8) Draft: Current Control-Plane Truth (Runtime Default Coordination)

```mermaid
flowchart TD
    NEG["sync session negentropy\n(need_ids)"] --> REPORT["report need_ids\n(to tenant CoordinationManager)"]
    REPORT --> COORD["CoordinationManager\n(runtime default path)"]
    COORD --> ASSIGN["assigned need_ids\nfor this connection"]
    ASSIGN --> HAVE["control stream HaveList(assigned ids)"]
    HAVE --> EQ["egress_queue"]
    EQ --> DATA["data stream Event/DataDone"]

    subgraph RUNTIME["Production runtime target sources"]
      AUTO["bootstrap autodial"] --> LOOP["connect_loop_with_coordination"]
      MDNS["mDNS discovery"] --> LOOP
    end

    LOOP --> NEG

    LEGACY["legacy/non-coordinated helper paths"] --> DIRECT["HaveList(all need_ids)"]
    DIRECT --> EQ
```

## Current Data-Flow Facts

1. `egress_queue` is fed by sync control-plane `HaveList` messages, not by `batch_writer`.
2. `batch_writer` is the shared ingest sink for wire-received events and local-create events; it persists event blobs and drains `project_queue`.
3. RPC command/query dispatch is event-module owned; `service.rs` is now an infra helper layer (`open_db_*`, node status, intro transport helper).
4. Peering orchestration (`connect_loop`/`accept_loop`/workflows) now routes transport operations through `transport::peering_boundary`; peering no longer imports QUIC/trust internals directly.
5. QUIC dial/accept + peer identity extraction are transport-owned in `connection_lifecycle`.
6. QUIC stream wiring (`open_bi`/`accept_bi`, `DualConnection`, `QuicTransportSessionIo`) is transport-owned in `session_factory`.
7. Projection outputs both user-facing read tables and transport trust tables; trust rows feed both handshake allow/deny and bootstrap autodial.
8. `HaveList` IDs originate from negentropy `need_ids`; in current runtime they are coordinator-assigned subsets by default (autodial + mDNS), then land in `egress_queue`.
9. Foreground runtime is daemon-first (`topo start`): shutdown is coordinated by shared `shutdown_notify` (RPC `Shutdown` or Ctrl-C).
10. Non-coordinated `need_ids -> HaveList(all)` behavior still exists in legacy helper/test paths (`download_from_sources` / direct `connect_loop`) and is no longer the primary runtime shape.
