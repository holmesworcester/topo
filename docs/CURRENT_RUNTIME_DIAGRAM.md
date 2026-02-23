# POC-7 Current Runtime Diagram

Code-accurate runtime and data-flow snapshot for `master` in `poc-7`.

Primary source modules:
- `src/main.rs`
- `src/node.rs`
- `src/peering/runtime/*`
- `src/peering/loops/*`
- `src/peering/workflows/*`
- `src/transport/{connection_lifecycle.rs,session_factory.rs,intro_io.rs}`
- `src/sync/session/*`
- `src/event_pipeline.rs`
- `src/projection/apply/*`
- `src/projection/create.rs`
- `src/db/{project_queue.rs,egress_queue.rs,wanted.rs,transport_trust.rs}`

## 1) Runtime Topology (Threads + Queues + DB)

```mermaid
flowchart TD
    CLI["CLI (topo)"] --> MAIN["main.rs"]
    MAIN --> RPC["RPC server thread (Unix socket)"]
    MAIN --> NODE["node::run_node"]

    RPC --> SVC["service + event_modules commands"]
    SVC --> LOCAL["local create path\ncreate_*_event_sync"]
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
      LIFE["connection_lifecycle\naccept_peer / dial_peer"]
      FACT["session_factory\naccept/open_session_io"]
      IIO["intro_io\naccept_and_read_intro"]
    end

    ORCH --> LIFE
    INTRO --> LIFE
    LIFE --> FACT
    INTRO --> IIO

    FACT --> SYNC["SyncSessionHandler\n(on_session)"]
    SYNC --> CTRL["control stream\nNegOpen / NegMsg / HaveList / Done"]
    SYNC --> DATA["data stream\nEvent / DataDone"]

    CTRL --> WANT["wanted_events"]
    CTRL --> EGRESS["egress_queue"]
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
```

## 2) One Sync Session (Control/Data Flow)

```mermaid
flowchart TD
    PEER["peering loop\n(connect/accept/download/punch)"] --> LIFE["connection_lifecycle\n(connected peer + peer_id)"]
    LIFE --> FACT["session_factory\n(open/accept streams)"]
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

## 4) Simplified SQLite View (Cylinders)

```mermaid
flowchart TD
    LOCAL["Local create events"] --> INGEST["shared ingest + batch_writer"]

    subgraph NET["Peering + Transport Capsule"]
      EP["QUIC endpoint"] --> LIFE["connection_lifecycle"]
      LIFE --> FACT["session_factory"]
      FACT --> SESS["sync sessions"]
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

## 5) Draft: Split Local Create vs Incoming Sync Events

```mermaid
flowchart TD
    LOCAL["Local create events"] --> INGEST["shared ingest + batch_writer"]

    subgraph WIRE["Incoming Wire Path"]
      QEP["QUIC endpoint"] --> LIFE["connection_lifecycle\naccept_peer / dial_peer"]
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

## 6) Draft: Prior Variant (Feedback + Explicit Control Inputs)

```mermaid
flowchart TD
    LOCAL["Local create events"] --> INGEST["shared ingest + batch_writer"]

    subgraph NET["Transport + Session"]
      QEP["QUIC endpoint"] --> LIFE["connection_lifecycle"]
      LIFE --> FACT["session_factory"]
      FACT --> SESS["sync session"]
      SESS --> RECV["receiver task"]
    end

    RECV --> INCOMING["incoming sync events"]
    INCOMING --> INGEST

    INGEST --> STORE["events + recorded + neg persist"]
    STORE --> QDB[("SQLite Queues")]
    QDB --> APPLY["project_one + cascade"]
    APPLY --> PDB[("SQLite Projections")]

    NEG["negentropy reconcile\n(need_ids)"] --> CTRL["Sync control stream\n(HaveList / need_ids)"]
    COORD["optional coordinator assignment\n(download mode)"] --> CTRL
    CTRL --> QDB

    PDB --> TRUST["transport trust decisions"]
    TRUST --> LIFE
```

## 7) Draft: Control Inputs Produced By Sync Session

```mermaid
flowchart TD
    LOCAL["Local create events"] --> INGEST["shared ingest + batch_writer"]

    QEP["QUIC endpoint"] --> LIFE["connection_lifecycle"]
    LIFE --> FACT["session_factory"]
    FACT --> SESS["sync session"]

    SESS --> RECV["receiver task (data stream)"]
    RECV --> INCOMING["incoming sync events"]
    INCOMING --> INGEST

    SESS --> NEG["session reconciliation\n(negentropy have/need sets)"]
    SESS --> COORD_IN["session gets coordinator assignment\n(optional download mode)"]
    NEG --> CTRL["Sync control stream\n(HaveList / need_ids)"]
    COORD_IN --> CTRL

    INGEST --> STORE["events + recorded + neg persist"]
    STORE --> QDB[("SQLite Queues")]
    CTRL --> QDB
    QDB --> APPLY["project_one + cascade"]
    APPLY --> PDB[("SQLite Projections")]

    PDB --> TRUST["transport trust decisions"]
    TRUST --> LIFE
```

## Current Data-Flow Facts

1. `egress_queue` is fed by sync control-plane `HaveList` messages, not by `batch_writer`.
2. `batch_writer` is the shared ingest sink for wire-received events and local-create events; it persists event blobs and drains `project_queue`.
3. Peering orchestration (`connect_loop`/`accept_loop`/workflows) no longer performs direct QUIC dial/accept or peer-id extraction; those are transport-owned in `connection_lifecycle`.
4. QUIC stream wiring (`open_bi`/`accept_bi`, `DualConnection`, `QuicTransportSessionIo`) is transport-owned in `session_factory`.
5. Projection outputs both user-facing read tables and transport trust tables; trust rows feed both handshake allow/deny and bootstrap autodial.
6. `HaveList` IDs originate from negentropy `need_ids` (and optionally coordinator-assigned subsets in download mode), then land in `egress_queue`.
