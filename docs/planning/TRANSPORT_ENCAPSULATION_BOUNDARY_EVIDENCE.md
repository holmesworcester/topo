# Transport Encapsulation Boundary Evidence

Date: 2026-02-23
Branch: `exec/transport-capsule-step2`

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

### SC3: Peering loop/workflow code reads as orchestration only

```bash
$ rg -n "quinn::SendStream|quinn::RecvStream" src/peering/
# No matches

$ rg -n "endpoint\.connect_with\(|endpoint\.connect\(|endpoint\.accept\(|peer_identity_from_connection" src/peering/loops src/peering/workflows
# No matches
```

Peering retains `quinn::Connection`/`quinn::Endpoint` values for orchestration-level
ownership only, but dial/accept and peer-id extraction are now transport-owned:
- `transport::connection_lifecycle::dial_peer()`
- `transport::connection_lifecycle::accept_peer()`

No stream-level types leak into peering. Stream wiring flows:
1. Peering calls `transport::session_factory::open_session_io(&connection)` or `accept_session_io(&connection)`
2. Transport opens streams, builds `DualConnection` + `QuicTransportSessionIo`
3. Transport returns `(session_id, Box<dyn TransportSessionIo>)`
4. Peering passes to `run_session()` which wires metadata + cancellation + handler

### SC4: Runtime diagrams fit within the 3-diagram model

Diagram rewrite is intentionally deferred by request while diagrams are being
iterated on `master`. This branch keeps transport encapsulation changes and
tests only, without modifying `docs/CURRENT_RUNTIME_DIAGRAM.md`.

Current branch still preserves the code-side boundary required for diagram
simplification:
1. Stream wiring moved to `src/transport/session_factory.rs`.
2. Intro uni-stream parsing moved to `src/transport/intro_io.rs`.
3. QUIC dial/accept + peer identity extraction moved to `src/transport/connection_lifecycle.rs`.

### SC5: Core tests and boundary script pass

```bash
$ cargo check
# Finished dev profile

$ cargo test transport::connection_lifecycle::tests:: -- --nocapture
# 2 passed; 0 failed

$ cargo test --test holepunch_test -q
# 4 passed; 0 failed

$ cargo test --test sync_contract_tests -q
# 21 passed; 0 failed

$ bash scripts/check_boundary_imports.sh
# All boundary checks passed.
```

## Files Changed

### New files
- `src/transport/session_factory.rs` — sole owner of sync session stream wiring (`open_session_io`, `accept_session_io`)
- `src/transport/intro_io.rs` — intro uni-stream receive/parse helpers (`accept_and_read_intro`)
- `src/transport/connection_lifecycle.rs` — sole owner of QUIC dial/accept + peer identity extraction (`dial_peer`, `accept_peer`)

### Modified files
- `src/transport/mod.rs` — registered `connection_lifecycle`, `session_factory`, and `intro_io` modules
- `src/peering/loops/mod.rs` — `run_session()` now takes `(session_id, Box<dyn TransportSessionIo>)` instead of raw `quinn::SendStream`/`RecvStream`; removed `DualConnection`/`QuicTransportSessionIo` imports
- `src/peering/loops/accept.rs` — calls `accept_peer()` for endpoint accept + peer-id extraction, then `accept_session_io()`
- `src/peering/loops/connect.rs` — calls `dial_peer()` for outbound dial + peer-id extraction, then `open_session_io()`
- `src/peering/loops/download.rs` — calls `dial_peer()` for outbound dial + peer-id extraction, then `open_session_io()`
- `src/peering/workflows/intro.rs` — uses `dial_peer()` when sending IntroOffers
- `src/peering/workflows/punch.rs` — uses `dial_peer()` in paced punch attempts; `run_sync_on_punched_connection` calls `open_session_io()`; `spawn_intro_listener` calls `accept_and_read_intro()`
- `scripts/check_boundary_imports.sh` — added transport encapsulation forbidden edges + positive checks
- `docs/DESIGN.md` — updated module ownership section for transport connection lifecycle + session factory

## Boundary Script Rules Added

Forbidden edges:
- `DualConnection::new` in `src/peering/`
- `QuicTransportSessionIo::new` in `src/peering/`
- `open_bi(` in `src/peering/`
- `accept_bi(` in `src/peering/`
- `quinn::SendStream` in `src/peering/`
- `quinn::RecvStream` in `src/peering/`
- `peer_identity_from_connection` in `src/peering/`
- `endpoint.connect*` / `endpoint.accept` in `src/peering/loops/` and `src/peering/workflows/`

Positive checks:
- `open_session_io` in `src/transport/session_factory.rs`
- `accept_session_io` in `src/transport/session_factory.rs`
- `DualConnection::new` in `src/transport/session_factory.rs`
- `dial_peer` in `src/transport/connection_lifecycle.rs`
- `accept_peer` in `src/transport/connection_lifecycle.rs`
