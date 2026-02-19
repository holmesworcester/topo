# POC-7 Current Runtime Diagram

This is a code-accurate explainer of the runtime shape in `poc-7` today.
Source modules: `src/node.rs`, `src/peering/runtime/*`, `src/peering/loops/*`, `src/sync/*`, `src/event_pipeline/*`, `src/projection/*`, `src/rpc/*`, `src/db/*`.

## 1) Runtime topology

```mermaid
flowchart TB
    subgraph CLI["Operator entry points"]
        U1["topo start"]
        U2["topo <daemon command>"]
        U3["topo create-workspace / accept-invite"]
    end

    subgraph DAEMON["Daemon process (from topo start)"]
        RPC["RPC server (Unix socket)"]
        DS["DaemonState"]
        NODE["node::run_node"]
        STARTUP["setup_endpoint_and_tenants"]
        EP["Single QUIC endpoint (single UDP port)"]
        CERT["WorkspaceCertResolver (SNI -> tenant cert)"]
        TRUST["SqliteTrustOracle (dynamic tenant trust)"]
        ACCEPT["accept_loop_with_ingest"]
        CONNECT["connect_loop threads (mDNS/autodial/intro)"]
        INGEST["shared ingest channel"]
        WRITER["batch_writer thread"]
        PROJECT["projection::apply::project_one + cascade"]
    end

    subgraph DB["Shared SQLite DB"]
        TDISC["trust_anchors + local_transport_creds"]
        TEVENTS["events + recorded_events + neg_items"]
        TQUEUE["project_queue + egress_queue + wanted_events"]
        TSTATE["valid_events + rejected_events + blocked_*"]
        TPROJ["projection tables (messages/users/peers_shared/...)"]
        TTRUST["transport trust tables (peer_shared SPKI + bootstrap trust)"]
    end

    U1 --> NODE
    U2 --> RPC
    U3 --> PROJECT

    RPC --> DS
    RPC --> PROJECT

    NODE --> STARTUP
    STARTUP --> TDISC
    STARTUP --> CERT
    STARTUP --> TRUST
    CERT --> EP
    TRUST --> EP

    EP --> ACCEPT
    EP --> CONNECT
    ACCEPT --> INGEST
    CONNECT --> INGEST
    INGEST --> WRITER

    WRITER --> TEVENTS
    WRITER --> TQUEUE
    WRITER --> PROJECT

    PROJECT --> TSTATE
    PROJECT --> TPROJ
    PROJECT --> TTRUST
    TTRUST --> TRUST
```

## 2) One sync session (dual stream protocol)

```mermaid
sequenceDiagram
    participant A as Initiator loop (connect_loop)
    participant B as Responder loop (accept_loop)
    participant H as ReplicationSessionHandler
    participant R as data receiver task
    participant W as batch_writer + projector

    A->>B: QUIC+mTLS handshake (SPKI trust check)
    A->>B: open bi stream #1 (control)
    A->>B: open bi stream #2 (data)
    A->>H: on_session Outbound
    B->>H: on_session Inbound
    H->>B: NegOpen/NegMsg/HaveList (control)
    H->>A: NegMsg/HaveList (control)
    H->>R: spawn_data_receiver(data stream)
    B-->>R: Event(blob) frames
    R->>W: enqueue (event_id, blob, recorded_by)
    A->>B: DataDone (data) + Done (control)
    B->>A: DataDone (data) + DoneAck (control)
```

## 3) Event ingest + projection convergence

```mermaid
flowchart LR
    LOCAL["Local create path (projection::create::*)"] --> LSTORE["insert events/recorded_events/neg_items"]
    LSTORE --> P["project_one"]

    WIRE["Wire receive path (sync receiver)"] --> BW["batch_writer"]
    BW --> BSTORE["insert events/recorded_events/neg_items"]
    BW --> PQ["enqueue project_queue"]
    PQ --> DRAIN["drain project_queue per tenant"]
    DRAIN --> P

    P --> STEP["project_one_step: parse -> dep/type checks -> signer verify -> projector dispatch"]
    STEP -->|Valid| OK["valid_events + projection tables"]
    STEP -->|Block| BLK["blocked_events + blocked_event_deps"]
    STEP -->|Reject| REJ["rejected_events"]
    OK --> CAS["cascade_unblocked (Kahn unblock + guard retries)"]
    CAS --> OK
    CAS --> BLK
```

## Quick explanation script

1. `poc-7` runs one QUIC endpoint and one writer thread per node, even for multiple local tenants.
2. Trust is tenant-scoped in SQL but enforced dynamically during transport handshakes.
3. Both local creates and network receives converge on the same projection entrypoint (`project_one`).
4. Sync uses dual streams (control/data) with explicit shutdown (`DataDone`, `Done`, `DoneAck`).
