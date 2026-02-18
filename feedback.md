# Feedback: exec/option-b-network-boundary

## Findings

1. **Medium — implementation plan is internally inconsistent about phase status and next steps**  
   `docs/OPTION_B_NETWORK_BOUNDARY_IMPLEMENTATION_PLAN.md` marks Phase 2 and Phase 3 as complete in the status table, but later still says "Next Task (Phase 2 Completion)" and includes old "Phase 2 is in-progress" instructions. This will mislead the next assistant about what remains.  
   - References: `docs/OPTION_B_NETWORK_BOUNDARY_IMPLEMENTATION_PLAN.md:364`, `docs/OPTION_B_NETWORK_BOUNDARY_IMPLEMENTATION_PLAN.md:379`, `docs/OPTION_B_NETWORK_BOUNDARY_IMPLEMENTATION_PLAN.md:381`

2. **Low — replication module exports a wider public surface than currently needed**  
   `src/replication/mod.rs` re-exports `run_coordinator` and `spawn_data_receiver` publicly. These appear to be session-internal orchestration helpers (used via `sync/engine.rs`), and exposing them at `crate::replication::*` widens the API before Phase 4/5 boundary hardening.  
   - Reference: `src/replication/mod.rs:3`

## What I verified

- Build/test gates run locally on this branch:
  - `cargo test --lib --no-run`
  - `cargo test --test two_process_test -q`
  - `cargo test --test holepunch_test -q`
  - `cargo test --test rpc_test -q`
  - `cargo test --test cli_test -q`
  - `cargo test --test scenario_test --no-run`
  - `cargo test --test sync_graph_test multi_source_coordinated_2x_5k -q`
- All commands above passed.

## Summary

No blocking functional regressions found in the reviewed Phase 2/3 extraction path. The main follow-up is tightening documentation accuracy and optional API narrowing to keep boundary contracts explicit for the next implementation phases.
