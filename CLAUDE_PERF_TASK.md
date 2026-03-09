# Perf Follow-Up

Worktree: `/tmp/poc-7-claude-perf-followup`
Branch: `claude/perf-followup`

## Goal

Track down the current perf/regression issues, fix them, rerun the maintained perf suite, and refresh `docs/PERF.md` so it contains only current results for the maintained perf tests.

## User Requirements

1. `perf_test.rs` is the old in-process suite; do not treat its RSS/timing as authoritative.
2. `sync_graph_test.rs` should be moved to the CLI/daemon style.
3. Daemon perf numbers must measure steady-state sync, not setup/connect time.
4. Memory numbers must be per-daemon `VmHWM`, not shared process RSS.
5. Low-memory perf tests should work again.
6. `docs/PERF.md` should keep straight latest results only, not historical hand-written tables.

## Current Findings

1. A real two-daemon repro exists in `scripts/repro_generate_sync.sh`.
2. On the branch I was working in (`/tmp/poc-7-perf-suite-fixes`), `scripts/repro_generate_sync.sh 50000` initially failed with `alice_count=50001, bob_count=1`.
3. The most plausible current fix is to notify the runtime after successful local write RPCs (`send`, `generate`, `generate-files`, `send-file`, `react`, `delete`, `ban`). That change was made only in the other worktree, not here.
4. `scripts/run_lowmem_proxy.sh` still assumes `create-workspace` and `accept` auto-start daemons. That is no longer true and breaks the proxy perf paths.
5. `sync_graph_test.rs` in this worktree is still the old in-process `Peer` harness.
6. I ran a git bisect in another worktree with the external repro. It pointed at `7811a613f739b39fe58358ea303ac8354b8223e4` (`fix: don't drop pre-removal pending fanouts during recovery`) as the first bad commit, but confirmation around that boundary was noisy enough that you should treat it as a lead, not a final proof.

## Success Criteria

1. `scripts/repro_generate_sync.sh 50000` passes reliably on this branch.
Proof:
`scripts/repro_generate_sync.sh 50000`

2. `cargo +stable test --release --test daemon_perf_test perf_sync_50k -- --nocapture --ignored --test-threads=1` passes and emits a summary file.
Proof:
`cargo +stable test --release --test daemon_perf_test perf_sync_50k -- --nocapture --ignored --test-threads=1`

3. Low-memory proxy perf paths run successfully with the current daemon lifecycle.
Proof:
`env LOWMEM_PROXY_BASE_EVENTS=50000 LOWMEM_PROXY_DELTA_EVENTS=10000 LOWMEM_PROXY_LARGE_TIMEOUT_SECS=600 scripts/run_lowmem_proxy.sh delta10k`
`env LOWMEM_PROXY_BASE_EVENTS=50000 LOWMEM_PROXY_DELTA_FILES=20 LOWMEM_PROXY_DELTA_FILE_MIB=1 LOWMEM_PROXY_LARGE_TIMEOUT_SECS=600 scripts/run_lowmem_proxy.sh deltafiles`

4. `sync_graph_test.rs` is no longer using the old in-process methodology for the maintained perf cases.
Proof:
The maintained tests in `tests/sync_graph_test.rs` use daemon/CLI-style setup and per-daemon `VmHWM`, and at least one representative case passes.

5. `docs/PERF.md` contains only current latest results for the maintained perf tests.
Proof:
`python3 scripts/run_perf_serial.py full`
Inspect `docs/PERF.md`.

## End-to-End Validation

Run these after the fixes:

```bash
scripts/repro_generate_sync.sh 50000
cargo +stable test --release --test daemon_perf_test perf_sync_10k -- --nocapture --test-threads=1
cargo +stable test --release --test daemon_perf_test perf_continuous_10k -- --nocapture --test-threads=1
cargo +stable test --release --test daemon_perf_test perf_sync_50k -- --nocapture --ignored --test-threads=1
env LOWMEM_PROXY_BASE_EVENTS=50000 LOWMEM_PROXY_DELTA_EVENTS=10000 LOWMEM_PROXY_LARGE_TIMEOUT_SECS=600 scripts/run_lowmem_proxy.sh delta10k
env LOWMEM_PROXY_BASE_EVENTS=50000 LOWMEM_PROXY_DELTA_FILES=20 LOWMEM_PROXY_DELTA_FILE_MIB=1 LOWMEM_PROXY_LARGE_TIMEOUT_SECS=600 scripts/run_lowmem_proxy.sh deltafiles
python3 scripts/run_perf_serial.py full
```

If `sync_graph_test.rs` remains part of the maintained perf set, also run the representative daemonized cases you keep there and make sure their outputs land in `docs/PERF.md`.

## Suggested Attack Plan

1. Start with `scripts/repro_generate_sync.sh 50000`.
2. Inspect `src/runtime/control/rpc/server.rs` and any runtime wakeup path after successful local write RPCs.
3. Fix `scripts/run_lowmem_proxy.sh` to use the current daemon-first lifecycle consistently.
4. Convert the maintained `sync_graph_test.rs` cases to daemon/CLI methodology or replace them with a new daemon-based topology perf file if that is cleaner.
5. Refresh `scripts/run_perf_serial.py` if needed so it includes the maintained perf tests only.
6. Rerun the suite and update `docs/PERF.md`.

## Notes

The other worktree with in-progress edits is `/tmp/poc-7-perf-suite-fixes`. It has an uncommitted runtime-recheck patch and lowmem proxy edits if you want to inspect them, but this branch is intentionally clean so you can land a coherent fix here.
