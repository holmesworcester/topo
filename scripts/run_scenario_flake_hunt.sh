#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 3 ]]; then
  echo "usage: $0 <repeats> [test_name] [log_dir]"
  exit 2
fi

REPEATS="$1"
TEST_NAME="${2:-test_mdns_multitenant_self_filtering_and_sync}"
LOG_DIR="${3:-target/flake-logs}"

if ! [[ "$REPEATS" =~ ^[0-9]+$ ]] || [[ "$REPEATS" -lt 1 ]]; then
  echo "repeats must be a positive integer"
  exit 2
fi

mkdir -p "$LOG_DIR"
echo "Running $TEST_NAME for $REPEATS iterations"
echo "Logs: $LOG_DIR"

for i in $(seq 1 "$REPEATS"); do
  LOG_FILE="$LOG_DIR/${TEST_NAME}_run_${i}.log"
  echo "[$i/$REPEATS] cargo test --test scenario_test $TEST_NAME -- --nocapture"
  if ! cargo test --test scenario_test "$TEST_NAME" -- --nocapture >"$LOG_FILE" 2>&1; then
    echo "FAILED on iteration $i"
    echo "See log: $LOG_FILE"
    tail -n 60 "$LOG_FILE" || true
    exit 1
  fi
done

echo "PASS: $TEST_NAME succeeded $REPEATS/$REPEATS runs"
