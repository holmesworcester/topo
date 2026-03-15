#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "[1/9] cargo test -q"
cargo test -q

echo "[2/9] cargo test -q --test sync_contract_tests"
cargo test -q --test sync_contract_tests -- --nocapture

echo "[3/9] cargo test -q --test double_send_test duplicate_sends_stay_below_regression_threshold"
cargo test -q --test double_send_test duplicate_sends_stay_below_regression_threshold -- --nocapture --test-threads=1

echo "[4/9] cargo test -q --test scenario_tests queue::test_egress_queue_lifecycle"
cargo test -q --test scenario_tests queue::test_egress_queue_lifecycle -- --nocapture

echo "[5/9] cargo +stable test --release --test sync_graph_test catchup_non_uniform_sources"
cargo +stable test --release --test sync_graph_test catchup_non_uniform_sources -- --nocapture --test-threads=1

echo "[6/9] cargo +stable test --release --test sync_graph_test catchup_dead_peer_dropout"
cargo +stable test --release --test sync_graph_test catchup_dead_peer_dropout -- --nocapture --test-threads=1

echo "[7/9] cargo +stable test --release --test daemon_perf_test perf_sync_10k"
cargo +stable test --release --test daemon_perf_test perf_sync_10k -- --nocapture --exact --test-threads=1

echo "[8/9] cargo +stable test --release --test daemon_perf_test perf_continuous_10k"
cargo +stable test --release --test daemon_perf_test perf_continuous_10k -- --nocapture --exact --test-threads=1

echo "[9/9] cargo +stable test --release --test daemon_perf_test perf_sync_50k"
cargo +stable test --release --test daemon_perf_test perf_sync_50k -- --nocapture --ignored --exact --test-threads=1

echo "All request-credit WIP checks passed."
