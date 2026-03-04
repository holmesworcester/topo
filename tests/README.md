# Test Suite

## Running tests

Standard Rust integration tests:

```bash
cargo test              # all tests (excluding feature-gated)
cargo test --all-features  # include mDNS discovery tests
```

Individual test binaries:

```bash
cargo test --test cli_test
cargo test --test rpc_test
cargo test --test scenario_tests
cargo test --test projectors
```

## Test organization

### CLI/daemon tests (shared `cli_harness/`)

| File | Scope |
|------|-------|
| `cli_test.rs` | CLI binary black-box: multi-peer sync, command output formatting, workspace management |
| `rpc_test.rs` | RPC protocol roundtrips, daemon lifecycle/state transitions, per-method RPC correctness |
| `cheat_proof_realism_test.rs` | Invite-only autodial and daemon-first invite lifecycle (no manual connect, no restart) |
| `two_process_test.rs` | Full two-process QUIC sync with real separate daemon processes |

All four share helpers from `cli_harness/mod.rs`.

### Scenario tests (`scenario_tests/`)

Library-level integration tests using `Peer` + `ScenarioHarness` (no CLI binary):

| Module | Scope |
|--------|-------|
| `sync.rs` | Bidirectional sync, stress, isolation, reactions, ordering |
| `encryption.rs` | PSK/encrypted event sync, out-of-order key delivery |
| `queue.rs` | Project queue crash recovery, egress queue lifecycle |
| `deletion.rs` | Deletion sync, before-target, encrypted deletion |
| `identity.rs` | Identity chain bootstrap, key wrap/unwrap, trust anchors (pure, no network) |
| `identity_sync.rs` | Identity join/cascade/device-link via network sync |
| `shared_db.rs` | Multi-tenant shared DB isolation and sync |
| `mdns.rs` | mDNS peer discovery and sync (requires `discovery` feature) |
| `transport.rs` | TLS identity extraction, per-tenant cert presentation, outbound trust |

### Other test binaries

| File | Scope |
|------|-------|
| `canonical_wire_tests.rs` | Wire format golden bytes, truncation, malformed data rejection |
| `wire_no_length_fields_guard_test.rs` | Structural guards: no length fields, all types have fixed wire size |
| `projectors/` | Pure projector conformance tests (no I/O) |
| `sync_contract_tests/` | Sync protocol correctness via `FakeSessionIo` (no QUIC) |
| `identity_transport_contract_tests/` | Transport identity adapter conformance |
| `holepunch_test.rs` | QUIC holepunch intro flow |
| `perf_test.rs` | Sync throughput benchmarks |
| `sync_graph_test.rs` | Chain propagation performance |
| `topo_cascade_test.rs` | SQLite topo-sort cascade performance |
| `file_throughput_test.rs` | File-slice insertion throughput |
| `low_mem_test.rs` | RSS budget tests |
| `low_mem_large_trustset_test.rs` | Trust-set churn under memory constraints |
| `mdns_smoke_test.rs` | Library-level mDNS advertisement smoke tests |

## Shell tests (require sudo)

These tests use Linux network namespaces for real network segmentation
and are **not** runnable via `cargo test`. They require:

- Linux with network namespace support
- `sudo` privileges
- A release build: `cargo build --release`

### `netns_cheat_proof_realism_test.sh`

Real network segmentation with 3 LANs and overlapping multi-homed peers.
Tests invite bootstrap over routed paths and mDNS discovery after inviter
shutdown.

```bash
cargo build --release
sudo tests/netns_cheat_proof_realism_test.sh
```

### `netns_nat_test.sh`

QUIC holepunch through simulated NAT (cone and symmetric modes) using
network namespaces and iptables.

```bash
cargo build --release
sudo tests/netns_nat_test.sh              # cone NAT (expected PASS)
sudo tests/netns_nat_test.sh --symmetric  # symmetric NAT (expected FAIL)
sudo tests/netns_nat_test.sh --cleanup    # remove leftover namespaces
```
