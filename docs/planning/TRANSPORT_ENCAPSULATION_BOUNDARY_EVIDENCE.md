# Transport Encapsulation Boundary Evidence

Date: 2026-02-23
Branch: `exec/transport-encapsulation-boundary-plan`

## Success Criteria Evidence

### SC1: `src/peering/**` has no direct construction of `DualConnection` / `QuicTransportSessionIo`

```bash
$ rg -n "DualConnection::new|QuicTransportSessionIo::new" src/peering/
# No matches
```

Verified: `DualConnection::new` and `QuicTransportSessionIo::new` appear only in `src/transport/session_factory.rs` (and `src/transport/transport_session_io.rs` tests, `src/testutil/` test helpers).

### SC2: QUIC stream open/accept wiring is owned in `src/transport/**`

```bash
$ rg -n "open_bi\(|accept_bi\(" src/peering/ src/transport/
src/transport/session_factory.rs:33:        .open_bi()
src/transport/session_factory.rs:37:        .open_bi()
src/transport/session_factory.rs:52:        .accept_bi()
src/transport/session_factory.rs:56:        .accept_bi()
# No matches in src/peering/
```

Verified: all `open_bi()` and `accept_bi()` calls are in `src/transport/session_factory.rs`.

### SC3: Peering loop code reads as orchestration only

```bash
$ rg -n "quinn::SendStream|quinn::RecvStream" src/peering/
# No matches
```

Peering retains only `quinn::Connection` and `quinn::Endpoint` for orchestration-level use:
- `IntroSpawnerFn` type signature (connection lifecycle callback)
- `send_intro_offer`, `handle_intro_offer`, `spawn_intro_listener` (intro/punch orchestration)

No stream-level types leak into peering. Stream wiring flows:
1. Peering calls `transport::session_factory::open_session_io(&connection)` or `accept_session_io(&connection)`
2. Transport opens streams, builds `DualConnection` + `QuicTransportSessionIo`
3. Transport returns `(session_id, Box<dyn TransportSessionIo>)`
4. Peering passes to `run_session()` which wires metadata + cancellation + handler

### SC4: Runtime diagrams fit within the 3-diagram model

Rewritten `docs/CURRENT_RUNTIME_DIAGRAM.md` contains exactly 3 canonical diagrams:
- **L0 Runtime Loop** (5 boxes): planner → peering supervisor → transport capsule → sync session → ingest/projection
- **L1 Transport Boundary** (inside capsule): endpoint, trust oracle, session factory, cert resolver, intro listener
- **L2 Session Data Flow** (single session): ControlIo/DataSendIo/DataRecvIo contract types only

Diagram rules enforced:
- Contract names only across boundaries (no concrete Rust types in L0/L2)
- No arrows from peering to QUIC internals
- Solid = data, dashed = control/orchestration
- One level of detail per diagram

### SC5: Core tests and boundary script pass

```bash
$ cargo check
# Finished dev profile

$ cargo test --lib -q
# 409 passed; 0 failed

$ cargo test --test holepunch_test -q
# 4 passed; 0 failed

$ cargo test --test sync_contract_tests -q
# 21 passed; 0 failed

$ bash scripts/check_boundary_imports.sh
# All boundary checks passed.
```

## Files Changed

### New files
- `src/transport/session_factory.rs` — sole owner of stream wiring (`open_session_io`, `accept_session_io`, `accept_and_read_intro`)

### Modified files
- `src/transport/mod.rs` — registered `session_factory` module
- `src/peering/loops/mod.rs` — `run_session()` now takes `(session_id, Box<dyn TransportSessionIo>)` instead of raw `quinn::SendStream`/`RecvStream`; removed `DualConnection`/`QuicTransportSessionIo` imports
- `src/peering/loops/accept.rs` — calls `accept_session_io()` instead of `connection.accept_bi()` + manual wiring
- `src/peering/loops/connect.rs` — calls `open_session_io()` instead of `connection.open_bi()` + manual wiring
- `src/peering/loops/download.rs` — calls `open_session_io()` instead of inline `DualConnection::new` + `QuicTransportSessionIo::new`
- `src/peering/workflows/punch.rs` — `run_sync_on_punched_connection` calls `open_session_io()`; `spawn_intro_listener` calls `accept_and_read_intro()`; removed `DualConnection`/`QuicTransportSessionIo`/`quinn::RecvStream` imports
- `scripts/check_boundary_imports.sh` — added transport encapsulation forbidden edges + positive checks
- `docs/CURRENT_RUNTIME_DIAGRAM.md` — rewritten to 3-diagram canonical model (L0/L1/L2)
- `docs/DESIGN.md` — updated module ownership section for transport session factory

## Boundary Script Rules Added

Forbidden edges:
- `DualConnection::new` in `src/peering/`
- `QuicTransportSessionIo::new` in `src/peering/`
- `open_bi(` in `src/peering/`
- `accept_bi(` in `src/peering/`
- `quinn::SendStream` in `src/peering/`
- `quinn::RecvStream` in `src/peering/`

Positive checks:
- `open_session_io` in `src/transport/session_factory.rs`
- `accept_session_io` in `src/transport/session_factory.rs`
- `DualConnection::new` in `src/transport/session_factory.rs`
