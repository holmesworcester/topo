# POC-7 Current Runtime Diagram

This is a code-accurate explainer of the runtime shape in `poc-7` today.
Source modules: `src/node.rs`, `src/peering/runtime/*`, `src/peering/loops/*`, `src/sync/*`, `src/event_pipeline/*`, `src/projection/*`, `src/rpc/*`, `src/db/*`.

## 1) Runtime topology (compact)

```mermaid
flowchart TD
    CLI["CLI (topo)"] --> MAIN["main.rs"]
    MAIN --> RPC["RPC server + DaemonState"]
    MAIN --> NODE["node::run_node"]

    RPC --> SVC["service::*"]
    SVC --> DB[(Shared SQLite)]

    NODE --> START["setup_endpoint_and_tenants"]
    START --> DB
    START --> CERT["WorkspaceCertResolver"]
    START --> TRUST["SqliteTrustOracle"]
    CERT --> EP["Single QUIC endpoint"]
    TRUST --> EP

    EP --> ACCEPT["accept_loop_with_ingest"]
    EP --> CONNECT["connect_loop threads"]
    ACCEPT --> INGEST["shared ingest channel"]
    CONNECT --> INGEST
    INGEST --> WRITER["batch_writer"]

    WRITER --> E1["events + recorded_events + neg_items"]
    WRITER --> E2["project_queue + egress_queue"]
    WRITER --> PROJ["project_one + cascade"]

    PROJ --> P1["valid/rejected/blocked"]
    PROJ --> P2["projection tables"]
    PROJ --> P3["transport trust tables"]
    P3 --> TRUST
```

## 1b) Runtime topology (SQLite-centered)

```mermaid
flowchart LR
    CLI["CLI (topo)"] --> MAIN["main.rs"]
    MAIN --> RPC["RPC server + DaemonState"]
    MAIN --> NODE["node::run_node"]

    RPC --> SVC["service::*"]

    NODE --> START["startup: tenants + cert resolver + endpoint config"]
    START --> EP["single QUIC endpoint"]
    EP --> LOOPS["accept/connect loops"]
    LOOPS --> INGEST["shared ingest channel"]
    INGEST --> WRITER["batch_writer"]
    WRITER --> PROJ["project_one + cascade"]

    DB[(SQLite DB)]

    SVC --> DB
    START --> DB
    WRITER --> DB
    PROJ --> DB

    DB --> TRUST["tenant-scoped trust lookup"]
    TRUST --> EP
```

## 1c) Runtime topology (SQLite box with internal queues)

```mermaid
flowchart LR
    CLI["CLI (topo)"] --> MAIN["main.rs"]
    MAIN --> RPC["RPC server + DaemonState"]
    MAIN --> NODE["node::run_node"]

    RPC --> SVC["service::*"]
    NODE --> START["startup (tenants + endpoint config)"]
    START --> EP["single QUIC endpoint"]
    EP --> LOOPS["accept/connect loops"]
    LOOPS --> INGEST["shared ingest channel"]
    INGEST --> WRITER["batch_writer"]
    WRITER --> PROJ["project_one + cascade"]

    subgraph SQLITE["SQLite DB (single file)"]
        direction TB
        Q1["project_queue"]
        Q2["egress_queue"]
        E1["events + recorded_events + neg_items"]
        E2["valid/rejected/blocked"]
        E3["projection tables"]
        E4["transport trust tables"]
    end

    SVC --> SQLITE
    START --> SQLITE
    WRITER --> Q1
    WRITER --> E1
    PROJ --> E2
    PROJ --> E3
    PROJ --> E4
    Q2 --> LOOPS
    E4 --> EP
```

## 2) One sync session (compact phases)

```mermaid
flowchart TD
    S1["1. QUIC+mTLS handshake<br/>+ tenant trust routing"] --> S2["2. Open 2 bi streams<br/>(control + data)"]
    S2 --> S3["3. Reconcile on control<br/>NegOpen / NegMsg / HaveList"]
    S3 --> S4["4. Data receiver task reads Event(blob)<br/>-> hashes -> IngestItem(recorded_by)"]
    S4 --> S5["5. batch_writer persists + drains project_queue"]
    S5 --> S6["6. project_one -> dep checks / signer verify / projector / cascade"]
    S6 --> S7["7. Session shutdown<br/>DataDone, Done, DoneAck"]
```

## 3) Event ingest + projection convergence (compact)

```mermaid
flowchart TD
    LOCAL["Local create<br/>(projection::create::*)"] --> LSTORE["Persist<br/>events + recorded_events + neg_items"]
    LSTORE --> P["project_one"]

    WIRE["Wire receive<br/>(sync receiver)"] --> BW["batch_writer"]
    BW --> QSTORE["Persist + enqueue<br/>events/recorded_events/neg_items/project_queue"]
    QSTORE --> DRAIN["drain project_queue"]
    DRAIN --> P

    P --> STEP["project_one_step<br/>parse + dep/type checks + signer verify + projector"]
    STEP -->|Valid| OK["valid_events + projection tables"]
    STEP -->|Block| BLK["blocked_events + blocked_event_deps"]
    STEP -->|Reject| REJ["rejected_events"]
    OK --> CAS["cascade_unblocked"]
    CAS --> OK
    CAS --> BLK
```

## Quick explanation script

1. `poc-7` runs one QUIC endpoint and one writer thread per node, even for multiple local tenants.
2. Trust is tenant-scoped in SQL but enforced dynamically during transport handshakes.
3. Both local creates and network receives converge on the same projection entrypoint (`project_one`).
4. Sync uses dual streams (control/data) with explicit shutdown (`DataDone`, `Done`, `DoneAck`).
