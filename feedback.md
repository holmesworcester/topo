# Feedback: exec/option-b-phase6-hardening

## Findings

1. **Medium — Workstream E is still slightly over-claimed as `Done`**  
   The realism harness now covers delayed delivery, out-of-order data, frame-size enforcement, cancellation, and ordering checks, but two plan items still appear unimplemented: explicit fragmentation modeling and deterministic peer-protocol-violation scenarios. The current `FakeIoConfig` has delay/size/reorder knobs only.  
   References: `docs/OPTION_B_NETWORK_BOUNDARY_PHASE_6_HARDENING_PLAN.md:184`, `docs/OPTION_B_NETWORK_BOUNDARY_PHASE_6_HARDENING_PLAN.md:189`, `docs/OPTION_B_NETWORK_BOUNDARY_PHASE_6_HARDENING_PLAN.md:229`, `tests/replication_contract_tests/fake_session_io.rs:42`, `tests/replication_contract_tests/error_mapping.rs:161`

2. **Low — SessionIo contract surface is still broader than the new split-based model**  
   `into_any` is gone (good), but `SessionIo` still carries legacy direct-frame methods (`recv_control`, `send_control`, etc.) alongside `split()`. That leaves two contract styles and weakens the “one obvious path” boundary.  
   References: `src/contracts/network_contract.rs:107`, `src/contracts/network_contract.rs:112`, `src/transport/session_io.rs:209`

## What I verified

1. Worktree is clean (`git status -sb`).
2. Boundary checks and tests passed on current HEAD (`f937359`):
   - `bash scripts/check_boundary_imports.sh`
   - `cargo test --lib --no-run`
   - `cargo test --test replication_contract_tests -q`
   - `cargo test --test holepunch_test -q`
   - `cargo test --test scenario_test test_mdns_two_peers_discover_and_sync -q`
   - `cargo test --test scenario_test test_run_node_multitenant_outbound_isolation -q`
   - `cargo test --test scenario_test test_tenant_scoped_outbound_trust_rejects_untrusted_server -q`
3. Structural split and boundary extraction are materially improved versus pre-phase state.

## Summary

This is a strong pass overall: architecture, boundaries, and testability are all meaningfully better and currently green on the exercised gates. Remaining work is mainly finishing the last realism/hard-to-cheat details and tightening the SessionIo contract surface to one path.
