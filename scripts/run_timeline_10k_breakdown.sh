#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

extract_msgs_per_sec() {
  awk '/Msgs\/s:/ { print $2 }' | tail -n1
}

run_case() {
  local label="$1"
  local groups="${2:-}"
  local output
  if [[ -n "$groups" ]]; then
    output="$(TOPO_EVENT_TIMELINE=1 TOPO_EVENT_TIMELINE_GROUPS="$groups" \
      cargo +stable test --release --manifest-path "$ROOT/Cargo.toml" \
      --test daemon_perf_test perf_sync_10k -- --nocapture --exact --test-threads=1 2>&1)"
  else
    output="$(cargo +stable test --release --manifest-path "$ROOT/Cargo.toml" \
      --test daemon_perf_test perf_sync_10k -- --nocapture --exact --test-threads=1 2>&1)"
  fi
  echo "$output" >&2
  local msgs
  msgs="$(printf '%s\n' "$output" | extract_msgs_per_sec)"
  if [[ -z "$msgs" ]]; then
    echo "failed to extract Msgs/s for $label" >&2
    exit 1
  fi
  printf '%s\n' "$msgs"
}

labels=(
  "baseline:"
  "discovery:discovery"
  "request:request"
  "transfer:transfer"
  "persist:persist"
  "projection:projection"
  "blocking:blocking"
  "full:all"
)

echo "[tests] cargo test -q --lib timeline::"
cargo test -q --manifest-path "$ROOT/Cargo.toml" timeline:: --lib -- --nocapture

echo "[tests] cargo test -q --test download_timeline_test"
cargo test -q --manifest-path "$ROOT/Cargo.toml" --test download_timeline_test -- --test-threads=1

echo "[tests] cargo test -q test_project_unblock_cascade"
cargo test -q --manifest-path "$ROOT/Cargo.toml" test_project_unblock_cascade --lib -- --nocapture

declare -a results=()
for entry in "${labels[@]}"; do
  label="${entry%%:*}"
  groups="${entry#*:}"
  if [[ -z "$groups" ]]; then
    echo "[${label}]"
    results+=("${label}:$(run_case "$label")")
  else
    echo "[${label}] groups=${groups}"
    results+=("${label}:$(run_case "$label" "$groups")")
  fi
done

python3 - "${results[@]}" <<'PY'
import sys
rows = []
for arg in sys.argv[1:]:
    label, value = arg.split(":", 1)
    rows.append((label, float(value)))

baseline = next(v for k, v in rows if k == "baseline")
print("perf_sync_10k timeline write cost breakdown")
for label, value in rows:
    delta = ((value - baseline) / baseline * 100.0) if baseline else 0.0
    print(f"  {label:10s} {value:7.0f} msgs/s  delta={delta:+6.1f}%")
PY
