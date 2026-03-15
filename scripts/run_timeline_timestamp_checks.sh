#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

extract_msgs_per_sec() {
  awk '/Msgs\/s:/ { print $2 }' | tail -n1
}

run_perf_case() {
  local label="$1"
  local env_mode="$2"
  local test_name="$3"
  local ignored_flag="${4:-}"
  local cmd=(cargo +stable test --release --manifest-path "$ROOT/Cargo.toml" --test daemon_perf_test "$test_name" -- --nocapture --exact --test-threads=1)
  if [[ -n "$ignored_flag" ]]; then
    cmd=(cargo +stable test --release --manifest-path "$ROOT/Cargo.toml" --test daemon_perf_test "$test_name" -- --nocapture --ignored --exact --test-threads=1)
  fi

  local output
  if [[ "$env_mode" == "timeline-on" ]]; then
    output="$(TOPO_EVENT_TIMELINE=1 "${cmd[@]}" 2>&1)"
  else
    output="$("${cmd[@]}" 2>&1)"
  fi
  echo "$output" >&2
  local msgs
  msgs="$(printf '%s\n' "$output" | extract_msgs_per_sec)"
  if [[ -z "$msgs" ]]; then
    echo "failed to extract Msgs/s for $label $test_name" >&2
    return 1
  fi
  printf '%s\n' "$msgs"
}

echo "[1/6] cargo fmt"
cargo fmt --manifest-path "$ROOT/Cargo.toml"

echo "[2/6] cargo test -q --lib timeline::"
cargo test -q --manifest-path "$ROOT/Cargo.toml" timeline:: --lib -- --nocapture

echo "[3/7] cargo test -q --test download_timeline_test"
cargo test -q --manifest-path "$ROOT/Cargo.toml" --test download_timeline_test -- --test-threads=1

echo "[4/7] cargo test -q test_project_unblock_cascade"
cargo test -q --manifest-path "$ROOT/Cargo.toml" test_project_unblock_cascade --lib -- --nocapture

echo "[5/7] perf_sync_10k timeline off/on"
sync10k_off="$(run_perf_case baseline timeline-off perf_sync_10k)"
sync10k_on="$(run_perf_case timeline timeline-on perf_sync_10k)"

echo "[6/7] perf_sync_100k timeline off/on"
sync100k_off="$(run_perf_case baseline timeline-off perf_sync_100k ignored)"
sync100k_on="$(run_perf_case timeline timeline-on perf_sync_100k ignored)"

python3 - "$sync10k_off" "$sync10k_on" "$sync100k_off" "$sync100k_on" <<'PY'
import sys
off10, on10, off100, on100 = map(float, sys.argv[1:])
def pct(off, on):
    return ((on - off) / off * 100.0) if off else 0.0
print("[7/7] timeline overhead summary")
print(f"perf_sync_10k:  off={off10:.0f} msgs/s  on={on10:.0f} msgs/s  delta={pct(off10, on10):+.1f}%")
print(f"perf_sync_100k: off={off100:.0f} msgs/s  on={on100:.0f} msgs/s  delta={pct(off100, on100):+.1f}%")
PY
