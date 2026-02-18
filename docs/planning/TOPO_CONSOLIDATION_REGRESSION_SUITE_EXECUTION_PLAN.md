# Topo Consolidation Regression Suite Execution Plan

Branch: `fix/topo-consolidation-regression-suite`
Worktree: `/home/holmes/poc-7-topo-regression-fixes`
Baseline: `5e7ae95` (`topo` consolidation)

## Objective
Fix the full regression set identified in review of `5e7ae95`:

1. `tests/netns_cheat_proof_realism_test.sh` invokes `"$BIN start"` and checks `-x "$BIN start"`.
2. Netns helper still depends on global `--socket`, but unified `topo` removed global `--socket`.
3. Custom socket routing regressed for daemon-preferred commands (`status/send/messages/...` hardcode default socket).
4. RPC shutdown path uses `std::process::exit(0)` from RPC thread instead of coordinated daemon shutdown.
5. Missing tests for `topo stop` behavior and custom-socket routing.

## Scope
In scope:

- `src/main.rs`
- `src/rpc/server.rs`
- `src/node.rs` (if needed for graceful shutdown signaling)
- `tests/rpc_test.rs`
- `tests/netns_cheat_proof_realism_test.sh`
- Any directly related helper/test files

Out of scope:

- Refactoring unrelated command architecture
- New features beyond restoring/locking intended behavior

## Required Behavior After Fix

1. `topo start --socket <path>` starts daemon on custom socket.
2. `topo --socket <path> status|send|messages|assert-*|...` talks to that daemon (no accidental default-socket fallback).
3. `topo --socket <path> stop` cleanly stops daemon.
4. RPC shutdown should not call `std::process::exit`; daemon should stop through normal control flow.
5. Netns realism script should invoke `topo` subcommands correctly and pass socket arguments in a way the CLI supports.

## Implementation Plan

## Phase 1: Restore global socket plumbing in unified CLI

Files:

- `src/main.rs`

Changes:

- Add back a global CLI socket option on root `Cli` (like old daemon CLI behavior):
  - `#[arg(long, global = true)] socket: Option<String>`
- Use a single derived socket value for command routing.
- Pass that socket to `try_rpc_or_direct` for all daemon-preferred commands.
- Ensure `start`/`stop` use the same global socket override.

Acceptance checks:

- `topo --help` shows global `--socket`.
- `topo --db <db> --socket <sock> status` no longer errors on unknown arg.

## Phase 2: Fix netns realism shell harness command wiring

Files:

- `tests/netns_cheat_proof_realism_test.sh`

Changes:

- Replace invalid executable checks and invocation patterns:
  - Remove `[[ -x "$BIN start" ]]`
  - Replace `"$BIN start" ...` with `"$BIN" start ...`
- Keep helper invocations consistent with unified CLI argument order.
- Ensure all helper calls that need custom RPC socket pass `--socket` in supported position.

Acceptance checks:

- `bash -n tests/netns_cheat_proof_realism_test.sh` passes.
- No `"$BIN start"` substring remains in script.

## Phase 3: Replace forced process exit with coordinated shutdown

Files:

- `src/rpc/server.rs`
- `src/main.rs`
- `src/node.rs` (if required)

Changes:

- Remove `std::process::exit(0)` from `RpcMethod::Shutdown` handler.
- Keep RPC behavior: set shutdown signal and return success response.
- Make `topo start` stop `node` and RPC server through shared shutdown signaling.
- Ensure socket cleanup still runs on shutdown path.

Recommended minimal design:

- Use a shared shutdown signal that both RPC server and node respect.
- In node runtime, support stopping on either Ctrl-C or daemon shutdown signal.

Acceptance checks:

- `topo stop` ends the daemon process without hard `process::exit`.
- Daemon socket is removed after stop.

## Phase 4: Add/strengthen tests for regressions

Files:

- `tests/rpc_test.rs`
- Optional: small additional integration test file if cleaner

Required test coverage:

1. **Stop flow test**
   - Start daemon (`topo start`) on temp db (with bootstrap identity), call `topo stop`, assert process exits and socket disappears.

2. **Custom socket routing test**
   - Start daemon on custom socket.
   - Run daemon-preferred command with `--socket <custom>` and assert success path goes through daemon.
   - Assert default-socket command does not incorrectly claim daemon is running on default path.

3. **Shutdown implementation guard**
   - Behavioral test that validates graceful stop semantics (not just enum serialization).

## Phase 5: Verification and regression gate

Run all required checks:

```bash
cargo fmt --all
cargo test -q --test rpc_test
cargo test -q --test cli_test
cargo test -q --test cheat_proof_realism_test
cargo test -q
bash -n tests/netns_cheat_proof_realism_test.sh
```

If environment allows privileged netns execution, additionally run:

```bash
sudo tests/netns_cheat_proof_realism_test.sh --cleanup
sudo tests/netns_cheat_proof_realism_test.sh --keep-logs
```

## Notes / Guardrails

- Do not reintroduce separate daemon/control binaries (all commands go through `topo`).
- Keep fallback semantics explicit and deterministic when daemon is unavailable.
- Prefer one socket-resolution path shared by all daemon-preferred commands.
- Avoid broad refactors while fixing this slice.

## Definition of Done

- All five identified issues are resolved.
- New behavioral tests prevent regression.
- Full test suite passes.
- Netns script parses and invokes unified `topo` correctly.
