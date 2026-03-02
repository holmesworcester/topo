#!/usr/bin/env bash
set -euo pipefail

# Low-memory perf regimen runner.
#
# Runs realistic low-memory checks with one daemon process per peer and
# evaluates per-peer peak RSS (VmHWM), not process-shared in-test memory.
#
# Usage:
#   scripts/run_lowmem_regimen.sh              # smoke only (10k total)
#   scripts/run_lowmem_regimen.sh smoke
#   scripts/run_lowmem_regimen.sh soak         # smoke + 100k one-way soak
#   scripts/run_lowmem_regimen.sh full         # smoke + soak + trustset test
#
# Environment overrides:
#   LOW_MEM_IOS_SMOKE_EVENTS_PER_PEER   default: 5000
#   LOW_MEM_IOS_BUDGET_MIB              default: 24
#   LOW_MEM_IOS_SOAK_EVENTS             default: 100000
#   LOW_MEM_IOS_SOAK_BUDGET_MIB         default: 24
#   TOPO_BIN                            default: target/release/topo
#   TOPO_CMD_TIMEOUT_SECS               default: 60

MODE="${1:-smoke}"

if [ "$(uname -s)" != "Linux" ]; then
  echo "error: low-memory regimen requires Linux (/proc/<pid>/status)"
  exit 2
fi

SCRIPT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN_ROOT="${LOWMEM_RUN_DIR:-${SCRIPT_ROOT}/target/lowmem-regimen}"
TOPO_BIN="${TOPO_BIN:-${SCRIPT_ROOT}/target/release/topo}"
TOPO_CMD_TIMEOUT_SECS="${TOPO_CMD_TIMEOUT_SECS:-60}"
export TMPDIR="${TMPDIR:-${SCRIPT_ROOT}/target/tmp}"

SMOKE_EVENTS_PER_PEER="${LOW_MEM_IOS_SMOKE_EVENTS_PER_PEER:-5000}"
SMOKE_BUDGET_MIB="${LOW_MEM_IOS_BUDGET_MIB:-24}"
SOAK_EVENTS="${LOW_MEM_IOS_SOAK_EVENTS:-100000}"
SOAK_BUDGET_MIB="${LOW_MEM_IOS_SOAK_BUDGET_MIB:-24}"

export LOW_MEM=1
export LOW_MEM_IOS_SOAK_EVENTS="${SOAK_EVENTS}"
export LOW_MEM_IOS_SOAK_BUDGET_MIB="${SOAK_BUDGET_MIB}"

mkdir -p "${RUN_ROOT}" "${TMPDIR}"

PASS_COUNT=0
FAIL_COUNT=0
RESULTS=()
TRACKED_DBS=()
SETUP_ALICE_DB=""
SETUP_BOB_DB=""
SETUP_ALICE_PID=""
SETUP_BOB_PID=""

banner() {
  echo
  echo "================================================================"
  echo "  $*"
  echo "================================================================"
}

run_test() {
  local label="$1"
  shift
  echo
  echo ">>> $*"
  if "$@"; then
    RESULTS+=("PASS  $label")
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    RESULTS+=("FAIL  $label")
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

run_topo() {
  timeout "${TOPO_CMD_TIMEOUT_SECS}" "${TOPO_BIN}" "$@"
}

stop_db_daemon() {
  local db="$1"
  run_topo --db "${db}" stop >/dev/null 2>&1 || true
}

cleanup() {
  local db
  for db in "${TRACKED_DBS[@]}"; do
    if [ -z "${db}" ]; then
      continue
    fi
    stop_db_daemon "${db}"
  done
}

trap cleanup EXIT

socket_path_for_db() {
  local db="$1"
  local dir base
  dir="$(dirname "${db}")"
  base="$(basename "${db}")"
  base="${base%.*}"
  printf '%s/%s.topo.sock\n' "${dir}" "${base}"
}

wait_for_socket() {
  local db="$1"
  local timeout_secs="${2:-20}"
  local socket_path start
  socket_path="$(socket_path_for_db "${db}")"
  start="$(date +%s)"
  while true; do
    if [ -S "${socket_path}" ]; then
      return 0
    fi
    if [ $(( $(date +%s) - start )) -ge "${timeout_secs}" ]; then
      echo "error: daemon socket did not appear for db=${db} (${socket_path})" >&2
      return 1
    fi
    sleep 0.2
  done
}

read_listen_addr() {
  local db="$1"
  run_topo --db "${db}" status | awk '/Listen:/ {print $2; exit}'
}

daemon_pid_for_db() {
  local db="$1"
  ps -eo pid=,args= | awk -v db="${db}" 'index($0, "--db " db " start") {print $1; exit}'
}

peak_rss_mib_for_pid() {
  local pid="$1"
  local status_file="/proc/${pid}/status"
  if [ ! -r "${status_file}" ]; then
    echo "error: cannot read ${status_file}" >&2
    return 1
  fi
  awk '
    /^VmHWM:/ { printf "%.2f", $2 / 1024.0; found = 1; exit }
    END { if (!found) exit 1 }
  ' "${status_file}"
}

mib_leq() {
  local actual="$1"
  local budget="$2"
  awk -v actual="${actual}" -v budget="${budget}" 'BEGIN { exit !(actual <= budget) }'
}

setup_two_peer_workspace() {
  local run_dir="$1"
  local alice_db="${run_dir}/alice.db"
  local bob_db="${run_dir}/bob.db"
  local invite_out invite_link addr

  run_topo --db "${alice_db}" create-workspace \
    --workspace-name "lowmem" \
    --username "alice" \
    --device-name "alice-dev" >/dev/null
  TRACKED_DBS+=("${alice_db}")
  wait_for_socket "${alice_db}" 30

  addr="$(read_listen_addr "${alice_db}")"
  if [ -z "${addr}" ]; then
    echo "error: failed to read alice listen addr" >&2
    return 1
  fi

  invite_out="$(
    run_topo --db "${alice_db}" create-invite --public-addr "${addr}"
  )"
  invite_link="$(printf '%s\n' "${invite_out}" | awk '/^quiet:\/\/invite\// {print; exit}')"
  if [ -z "${invite_link}" ]; then
    echo "error: create-invite did not emit invite link" >&2
    return 1
  fi

  run_topo --db "${bob_db}" accept-invite \
    --invite "${invite_link}" \
    --username "bob" \
    --devicename "bob-dev" >/dev/null
  TRACKED_DBS+=("${bob_db}")
  wait_for_socket "${bob_db}" 30

  local alice_pid bob_pid
  alice_pid="$(daemon_pid_for_db "${alice_db}")"
  bob_pid="$(daemon_pid_for_db "${bob_db}")"
  if [ -z "${alice_pid}" ] || [ -z "${bob_pid}" ]; then
    echo "error: failed to resolve daemon PIDs (alice=${alice_pid} bob=${bob_pid})" >&2
    return 1
  fi

  SETUP_ALICE_DB="${alice_db}"
  SETUP_BOB_DB="${bob_db}"
  SETUP_ALICE_PID="${alice_pid}"
  SETUP_BOB_PID="${bob_pid}"
}

scenario_smoke_two_daemons() {
  local run_dir="${RUN_ROOT}/smoke-$$_$(date +%s)"
  mkdir -p "${run_dir}"
  if ! setup_two_peer_workspace "${run_dir}"; then
    return 1
  fi
  local alice_db="${SETUP_ALICE_DB}"
  local bob_db="${SETUP_BOB_DB}"
  local alice_pid="${SETUP_ALICE_PID}"
  local bob_pid="${SETUP_BOB_PID}"

  local total_messages
  total_messages=$((SMOKE_EVENTS_PER_PEER * 2))
  local timeout_ms
  timeout_ms=$(( (total_messages / 1000) * 6000 ))
  if [ "${timeout_ms}" -lt 120000 ]; then
    timeout_ms=120000
  fi

  run_topo --db "${alice_db}" generate --count "${SMOKE_EVENTS_PER_PEER}" >/dev/null
  run_topo --db "${bob_db}" generate --count "${SMOKE_EVENTS_PER_PEER}" >/dev/null

  run_topo --db "${alice_db}" assert-eventually "message_count >= ${total_messages}" \
    --timeout-ms "${timeout_ms}" --interval-ms 200 >/dev/null
  run_topo --db "${bob_db}" assert-eventually "message_count >= ${total_messages}" \
    --timeout-ms "${timeout_ms}" --interval-ms 200 >/dev/null

  local alice_peak bob_peak
  alice_peak="$(peak_rss_mib_for_pid "${alice_pid}")"
  bob_peak="$(peak_rss_mib_for_pid "${bob_pid}")"

  echo "[lowmem-smoke] events_per_peer=${SMOKE_EVENTS_PER_PEER} total=${total_messages}"
  echo "[lowmem-smoke] alice pid=${alice_pid} peak_rss=${alice_peak} MiB budget=${SMOKE_BUDGET_MIB} MiB"
  echo "[lowmem-smoke] bob   pid=${bob_pid} peak_rss=${bob_peak} MiB budget=${SMOKE_BUDGET_MIB} MiB"

  stop_db_daemon "${alice_db}"
  stop_db_daemon "${bob_db}"

  if ! mib_leq "${alice_peak}" "${SMOKE_BUDGET_MIB}"; then
    echo "low_mem smoke budget exceeded for alice: ${alice_peak} MiB > ${SMOKE_BUDGET_MIB} MiB" >&2
    return 1
  fi
  if ! mib_leq "${bob_peak}" "${SMOKE_BUDGET_MIB}"; then
    echo "low_mem smoke budget exceeded for bob: ${bob_peak} MiB > ${SMOKE_BUDGET_MIB} MiB" >&2
    return 1
  fi
}

scenario_soak_two_daemons() {
  local run_dir="${RUN_ROOT}/soak-$$_$(date +%s)"
  mkdir -p "${run_dir}"
  if ! setup_two_peer_workspace "${run_dir}"; then
    return 1
  fi
  local alice_db="${SETUP_ALICE_DB}"
  local bob_db="${SETUP_BOB_DB}"
  local alice_pid="${SETUP_ALICE_PID}"
  local bob_pid="${SETUP_BOB_PID}"

  local timeout_ms
  timeout_ms=$(( (SOAK_EVENTS / 1000) * 6000 ))
  if [ "${timeout_ms}" -lt 300000 ]; then
    timeout_ms=300000
  fi

  run_topo --db "${alice_db}" generate --count "${SOAK_EVENTS}" >/dev/null

  run_topo --db "${alice_db}" assert-eventually "message_count >= ${SOAK_EVENTS}" \
    --timeout-ms "${timeout_ms}" --interval-ms 200 >/dev/null
  run_topo --db "${bob_db}" assert-eventually "message_count >= ${SOAK_EVENTS}" \
    --timeout-ms "${timeout_ms}" --interval-ms 200 >/dev/null

  local alice_peak bob_peak
  alice_peak="$(peak_rss_mib_for_pid "${alice_pid}")"
  bob_peak="$(peak_rss_mib_for_pid "${bob_pid}")"

  echo "[lowmem-soak] events=${SOAK_EVENTS}"
  echo "[lowmem-soak] alice pid=${alice_pid} peak_rss=${alice_peak} MiB budget=${SOAK_BUDGET_MIB} MiB"
  echo "[lowmem-soak] bob   pid=${bob_pid} peak_rss=${bob_peak} MiB budget=${SOAK_BUDGET_MIB} MiB"

  stop_db_daemon "${alice_db}"
  stop_db_daemon "${bob_db}"

  if ! mib_leq "${alice_peak}" "${SOAK_BUDGET_MIB}"; then
    echo "low_mem soak budget exceeded for alice: ${alice_peak} MiB > ${SOAK_BUDGET_MIB} MiB" >&2
    return 1
  fi
  if ! mib_leq "${bob_peak}" "${SOAK_BUDGET_MIB}"; then
    echo "low_mem soak budget exceeded for bob: ${bob_peak} MiB > ${SOAK_BUDGET_MIB} MiB" >&2
    return 1
  fi
}

build_release_binary() {
  if [ "${LOWMEM_SKIP_BUILD:-0}" = "1" ] && [ -x "${TOPO_BIN}" ]; then
    echo "Skipping release build (LOWMEM_SKIP_BUILD=1, binary exists)."
    return 0
  fi
  cargo +stable build --release --bin topo
}

banner "Low-Memory Regimen - mode: ${MODE}"
echo
echo "  TOPO_BIN=${TOPO_BIN}"
echo "  LOW_MEM=1"
echo "  LOW_MEM_IOS_SMOKE_EVENTS_PER_PEER=${SMOKE_EVENTS_PER_PEER}"
echo "  LOW_MEM_IOS_BUDGET_MIB=${SMOKE_BUDGET_MIB}"
echo "  LOW_MEM_IOS_SOAK_EVENTS=${SOAK_EVENTS}"
echo "  LOW_MEM_IOS_SOAK_BUDGET_MIB=${SOAK_BUDGET_MIB}"
echo "  TOPO_CMD_TIMEOUT_SECS=${TOPO_CMD_TIMEOUT_SECS}"
echo "  RUN_ROOT=${RUN_ROOT}"
echo "  TMPDIR=${TMPDIR}"
echo

run_test "build_release_topo" build_release_binary

case "${MODE}" in
  smoke)
    run_test "low_mem_smoke_10k_two_daemons" scenario_smoke_two_daemons
    ;;
  soak)
    run_test "low_mem_smoke_10k_two_daemons" scenario_smoke_two_daemons
    run_test "low_mem_soak_${SOAK_EVENTS}_two_daemons" scenario_soak_two_daemons
    ;;
  full)
    run_test "low_mem_smoke_10k_two_daemons" scenario_smoke_two_daemons
    run_test "low_mem_soak_${SOAK_EVENTS}_two_daemons" scenario_soak_two_daemons
    run_test "low_mem_large_trustset" \
      cargo +stable test --release --test low_mem_large_trustset_test \
      -- --nocapture --test-threads=1
    ;;
  *)
    echo "unknown mode: ${MODE}"
    echo "usage: scripts/run_lowmem_regimen.sh [smoke|soak|full]"
    exit 2
    ;;
esac

banner "Results"
for r in "${RESULTS[@]}"; do
  echo "  ${r}"
done
echo
echo "  passed: ${PASS_COUNT}  failed: ${FAIL_COUNT}"

if [ "${FAIL_COUNT}" -gt 0 ]; then
  echo
  echo "  *** REGIMEN FAILED ***"
  exit 1
fi

echo
echo "  REGIMEN PASSED"
exit 0
