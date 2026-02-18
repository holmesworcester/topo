# Feedback: exec/option-b-network-boundary

## Findings

1. **Medium — plan doc still contains a Phase 4 status contradiction**  
   The plan marks Phase 4 complete in the status table, but still lists "(pending) - Phase 4" in the branch snapshot list.  
   References: `docs/OPTION_B_NETWORK_BOUNDARY_IMPLEMENTATION_PLAN.md:358`, `docs/OPTION_B_NETWORK_BOUNDARY_IMPLEMENTATION_PLAN.md:369`

2. **Medium — plan claims one boundary item is resolved, but code still depends on sync internals**  
   The plan states network-path dependency on sync internals is resolved, but `src/network/loops.rs` still imports and calls through `crate::sync::*` for session handling and intro listener wiring.  
   References: `docs/OPTION_B_NETWORK_BOUNDARY_IMPLEMENTATION_PLAN.md:717`, `src/network/loops.rs:34`, `src/network/loops.rs:35`, `src/network/loops.rs:295`, `src/network/loops.rs:545`

## What I verified

1. Before writing this feedback, `git status -sb` was clean.
2. Current structure matches the intended extraction shape:
   - `src/sync/engine.rs` is now a 19-line re-export shim.
   - `src/node.rs` is a 6-line re-export composition root.
   - `src/network/runtime.rs` and `src/network/loops.rs` contain the moved orchestration code.
3. Tests run and pass on current HEAD (`c9ae259`):
   - `cargo test --lib --no-run`
   - `cargo test --test two_process_test -q`
   - `cargo test --test holepunch_test -q`
   - `cargo test --test cli_test -q`
   - `cargo test --test rpc_test -q`
   - `cargo test --test scenario_test test_mdns_two_peers_discover_and_sync -q`
   - `cargo test --test scenario_test test_run_node_multitenant_outbound_isolation -q`
   - `cargo test --test scenario_test test_tenant_scoped_outbound_trust_rejects_untrusted_server -q`

## Summary

No blocking runtime regressions found in tested paths. Remaining work is mainly boundary-hardening/document-accuracy cleanup before Phase 5 enforcement.
