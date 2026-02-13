# Feedback: Issue 6 - Daemon RPC CLI Contract

## Findings

1. Medium (integration risk): Service layer still references `event_id_or_blocked` directly (`src/service.rs:22`, `src/service.rs:328`, `src/service.rs:571`, `src/service.rs:738`, `src/service.rs:767`). If Issue 3 lands with helper visibility/API changes, this branch will conflict or fail until adapted to staged APIs.
2. Low: RPC server currently spawns an unbounded thread per accepted connection (`src/rpc/server.rs:40`), which is vulnerable to local connection-flood pressure.

## Evidence

- `cargo test --test rpc_test -- --nocapture` passed (13/13 tests).

## Summary

Core daemon/RPC/CLI split is in place and tests pass. Main concern is forward-compatibility with Issue 3 API changes and connection-level resource bounding.
