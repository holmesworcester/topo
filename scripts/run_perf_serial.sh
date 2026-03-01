#!/usr/bin/env bash
set -euo pipefail

# Run perf integration tests in a strict serial order to avoid cross-test
# interference from concurrent endpoint binds and background sync sessions.
#
# Usage:
#   scripts/run_perf_serial.sh            # core suite
#   scripts/run_perf_serial.sh core
#   scripts/run_perf_serial.sh full

MODE="${1:-core}"

run() {
  echo
  echo ">>> $*"
  "$@"
}

case "$MODE" in
  core)
    run cargo +stable test --release --test perf_test -- --nocapture --test-threads=1
    run cargo +stable test --release --test file_throughput -- --nocapture --test-threads=1
    run cargo +stable test --release --test sync_graph_test ten_hop_chain_10k -- --nocapture --test-threads=1
    ;;
  full)
    run cargo +stable test --release --test perf_test -- --nocapture --include-ignored --test-threads=1
    run cargo +stable test --release --test file_throughput -- --nocapture --include-ignored --test-threads=1
    run cargo +stable test --release --test sync_graph_test -- --nocapture --include-ignored --test-threads=1
    run cargo +stable test --release --test low_mem_test -- --nocapture --include-ignored --test-threads=1
    ;;
  *)
    echo "unknown mode: $MODE"
    echo "usage: scripts/run_perf_serial.sh [core|full]"
    exit 2
    ;;
esac
