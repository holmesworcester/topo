#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RUNS="${1:-3}"

extract_msgs_per_sec() {
  awk '/Msgs\/s:/ { print $2 }' | tail -n1
}

run_case() {
  local mode="$1"
  local output
  if [[ "$mode" == "timeline-on" ]]; then
    output="$(TOPO_EVENT_TIMELINE=1 cargo +stable test --release --manifest-path "$ROOT/Cargo.toml" --test daemon_perf_test perf_sync_10k -- --nocapture --exact --test-threads=1 2>&1)"
  else
    output="$(cargo +stable test --release --manifest-path "$ROOT/Cargo.toml" --test daemon_perf_test perf_sync_10k -- --nocapture --exact --test-threads=1 2>&1)"
  fi
  echo "$output" >&2
  local msgs
  msgs="$(printf '%s\n' "$output" | extract_msgs_per_sec)"
  if [[ -z "$msgs" ]]; then
    echo "failed to extract Msgs/s for $mode" >&2
    exit 1
  fi
  printf '%s\n' "$msgs"
}

echo "Running perf_sync_10k comparison ($RUNS runs each, off then on)..."
declare -a off_results=()
declare -a on_results=()

for ((i=1; i<=RUNS; i++)); do
  echo "[off $i/$RUNS]"
  off_results+=("$(run_case timeline-off)")
  echo "[on  $i/$RUNS]"
  on_results+=("$(run_case timeline-on)")
done

python3 - "${off_results[@]}" -- "${on_results[@]}" <<'PY'
import sys

sep = sys.argv.index("--")
off = [float(x) for x in sys.argv[1:sep]]
on = [float(x) for x in sys.argv[sep + 1:]]

def median(xs):
    ys = sorted(xs)
    n = len(ys)
    mid = n // 2
    if n % 2:
        return ys[mid]
    return (ys[mid - 1] + ys[mid]) / 2.0

def fmt(xs):
    return ", ".join(f"{x:.0f}" for x in xs)

off_med = median(off)
on_med = median(on)
delta = ((on_med - off_med) / off_med * 100.0) if off_med else 0.0

print("perf_sync_10k timeline comparison")
print(f"  off runs: {fmt(off)}")
print(f"  on  runs: {fmt(on)}")
print(f"  median off: {off_med:.0f} msgs/s")
print(f"  median on : {on_med:.0f} msgs/s")
print(f"  median delta: {delta:+.1f}%")
PY
