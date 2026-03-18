#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$ROOT/Cargo.toml"
TARGET_DIR_DEFAULT="/home/holmes/cargo-target-poc7"
TMPDIR_DEFAULT="/home/holmes/tmp"
RESULTS_DIR="$ROOT/target/perf-results"
mkdir -p "$RESULTS_DIR"
mkdir -p "$TMPDIR_DEFAULT"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$TARGET_DIR_DEFAULT}"
export TMPDIR="${TMPDIR:-$TMPDIR_DEFAULT}"

run_perf_case() {
  local label="$1"
  local test_name="$2"
  local claim="$3"
  local bulk="$4"
  local quantum="$5"
  local ignored="${6:-0}"
  local summary="$RESULTS_DIR/daemon_perf_test.${test_name}.summary"

  rm -f "$summary"
  if [[ "$claim" == "-" ]]; then
    unset TOPO_EGRESS_CLAIM_COUNT TOPO_BULK_EGRESS_CLAIM_COUNT TOPO_EGRESS_SEND_QUANTUM_BYTES
  else
    export TOPO_EGRESS_CLAIM_COUNT="$claim"
    export TOPO_BULK_EGRESS_CLAIM_COUNT="$bulk"
    export TOPO_EGRESS_SEND_QUANTUM_BYTES="$quantum"
  fi

  echo "== $label :: $test_name =="
  if [[ "$ignored" == "1" ]]; then
    cargo +stable test --release --manifest-path "$MANIFEST" \
      --test daemon_perf_test "$test_name" -- --ignored --nocapture --test-threads=1 \
      >/tmp/send-window-"$test_name".log
  else
    cargo +stable test --release --manifest-path "$MANIFEST" \
      --test daemon_perf_test "$test_name" -- --nocapture --test-threads=1 \
      >/tmp/send-window-"$test_name".log
  fi

  if [[ ! -f "$summary" ]]; then
    echo "missing summary: $summary" >&2
    cat /tmp/send-window-"$test_name".log >&2
    exit 1
  fi

  local wall msgs rss
  wall="$(awk -F': *' '/Wall time:/ {gsub(/^ +/, "", $2); print $2}' "$summary")"
  msgs="$(awk -F': *' '/Msgs\/s:/ {gsub(/^ +/, "", $2); print $2}' "$summary")"
  rss="$(awk -F': *' '/Peak RSS:/ {gsub(/^ +/, "", $2); print $2}' "$summary")"
  echo "wall=$wall msgs_per_s=$msgs peak_rss=$rss"
}

run_double_send_case() {
  local label="$1"
  local claim="$2"
  local bulk="$3"
  local quantum="$4"

  if [[ "$claim" == "-" ]]; then
    unset TOPO_EGRESS_CLAIM_COUNT TOPO_BULK_EGRESS_CLAIM_COUNT TOPO_EGRESS_SEND_QUANTUM_BYTES
  else
    export TOPO_EGRESS_CLAIM_COUNT="$claim"
    export TOPO_BULK_EGRESS_CLAIM_COUNT="$bulk"
    export TOPO_EGRESS_SEND_QUANTUM_BYTES="$quantum"
  fi

  echo "== $label :: double_send_test =="
  cargo test -q --manifest-path "$MANIFEST" \
    --test double_send_test duplicate_sends_stay_below_regression_threshold \
    -- --nocapture --test-threads=1
}

run_lowmem_smoke() {
  local label="$1"
  local claim="$2"
  local bulk="$3"
  local quantum="$4"

  export LOW_MEM_IOS=1
  if [[ "$claim" == "-" ]]; then
    unset TOPO_EGRESS_CLAIM_COUNT TOPO_BULK_EGRESS_CLAIM_COUNT TOPO_EGRESS_SEND_QUANTUM_BYTES
  else
    export TOPO_EGRESS_CLAIM_COUNT="$claim"
    export TOPO_BULK_EGRESS_CLAIM_COUNT="$bulk"
    export TOPO_EGRESS_SEND_QUANTUM_BYTES="$quantum"
  fi

  echo "== $label :: low_mem_ios_budget_smoke_10k =="
  cargo +stable test --release --manifest-path "$MANIFEST" \
    --test low_mem_test low_mem_ios_budget_smoke_10k -- --nocapture --test-threads=1
  unset LOW_MEM_IOS
}

MODE="${1:-full}"
CANDIDATE_LABEL="${CANDIDATE_LABEL:-candidate}"
CANDIDATE_CLAIM="${CANDIDATE_CLAIM:-64}"
CANDIDATE_BULK="${CANDIDATE_BULK:-8}"
CANDIDATE_QUANTUM="${CANDIDATE_QUANTUM:-2097152}"

case "$MODE" in
  matrix)
    echo "Running perf_sync_10k tuning matrix..."
    run_perf_case "default" perf_sync_10k - - -
    run_perf_case "64/8/1MiB" perf_sync_10k 64 8 1048576
    run_perf_case "64/8/2MiB" perf_sync_10k 64 8 2097152
    run_perf_case "128/16/2MiB" perf_sync_10k 128 16 2097152
    ;;
  candidate)
    echo "Running broader checks with ${CANDIDATE_LABEL}..."
    run_perf_case "$CANDIDATE_LABEL" perf_sync_10k "$CANDIDATE_CLAIM" "$CANDIDATE_BULK" "$CANDIDATE_QUANTUM"
    run_perf_case "$CANDIDATE_LABEL" perf_continuous_10k "$CANDIDATE_CLAIM" "$CANDIDATE_BULK" "$CANDIDATE_QUANTUM"
    run_perf_case "$CANDIDATE_LABEL" perf_sync_50k "$CANDIDATE_CLAIM" "$CANDIDATE_BULK" "$CANDIDATE_QUANTUM" 1
    run_double_send_case "$CANDIDATE_LABEL" "$CANDIDATE_CLAIM" "$CANDIDATE_BULK" "$CANDIDATE_QUANTUM"
    run_lowmem_smoke "$CANDIDATE_LABEL" "$CANDIDATE_CLAIM" "$CANDIDATE_BULK" "$CANDIDATE_QUANTUM"
    ;;
  full)
    "$0" matrix
    echo
    CANDIDATE_LABEL="64/8/2MiB" \
      CANDIDATE_CLAIM=64 \
      CANDIDATE_BULK=8 \
      CANDIDATE_QUANTUM=2097152 \
      "$0" candidate
    ;;
  *)
    echo "usage: $0 [matrix|candidate|full]" >&2
    exit 2
    ;;
esac
