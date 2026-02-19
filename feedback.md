# Feedback: exec/option-b-phase6-hardening

## Findings

1. **Medium — Workstream E is marked `Done`, but required harness capabilities are not all implemented yet**  
   The plan requires fragmentation, delayed delivery, out-of-order delivery, frame-size violations, and deterministic protocol-violation scenarios, but the current fake transport and tests only exercise ordering/cancellation/error flows on straightforward channel delivery. `FakeDataSendIo`/`FakeDataRecvIo` currently forward whole frames directly without delay/reordering/fragment controls.  
   References: `docs/OPTION_B_NETWORK_BOUNDARY_PHASE_6_HARDENING_PLAN.md:183`, `docs/OPTION_B_NETWORK_BOUNDARY_PHASE_6_HARDENING_PLAN.md:229`, `tests/replication_contract_tests/fake_session_io.rs:141`, `tests/replication_contract_tests/fake_session_io.rs:163`

2. **Medium — Event-runtime callback details leak through networking public APIs**  
   `run_node`, `accept_loop`, and `connect_loop` now require callers to pass `batch_writer_fn` and/or `drain_queue_fn`. This pushes event-runtime wiring concerns into every callsite (including tests/helpers), which widens the surface and reduces the encapsulation gains this phase is aiming for.  
   References: `src/network/runtime/mod.rs:53`, `src/network/loops/accept.rs:42`, `src/network/loops/connect.rs:39`, `src/testutil.rs:1408`, `tests/scenario_test.rs:3545`

3. **Low — SessionIo contract still contains legacy/deprecated surface after split migration**  
   The new `split()` path is in place, but `SessionIo` still exposes `into_any` plus direct frame methods (`recv_control`, `send_control`, etc.). Keeping both surfaces increases ambiguity and leaves bypass paths that the refactor was trying to remove.  
   References: `src/contracts/network_contract.rs:102`, `src/contracts/network_contract.rs:104`, `src/contracts/network_contract.rs:110`, `src/transport/session_io.rs:186`

## What I verified

1. Boundary gate and compile/test checks passed on this worktree state:
   - `bash scripts/check_boundary_imports.sh`
   - `cargo test --lib --no-run`
   - `cargo test --lib test_boundary_imports_enforced -q`
   - `cargo test --test replication_contract_tests -q`
   - `cargo test --test holepunch_test -q`
   - `cargo test --test scenario_test test_mdns_two_peers_discover_and_sync -q`
   - `cargo test --test scenario_test test_run_node_multitenant_outbound_isolation -q`
   - `cargo test --test scenario_test test_tenant_scoped_outbound_trust_rejects_untrusted_server -q`
2. Module split goals are materially achieved (network/replication files are now role-focused and mostly under 400 LOC).

## Summary

The refactor is directionally strong and appears behavior-safe on the exercised paths. Remaining issues are about boundary/API tightening and making the isolation harness satisfy the full realism contract before claiming Workstream E fully complete.
