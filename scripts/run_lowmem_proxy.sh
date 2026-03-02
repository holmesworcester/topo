#!/usr/bin/env bash
set -euo pipefail

# Fast proxy regimen for low-memory iteration:
# 1) 10k smoke (both peers lowmem, realistic two-daemon harness)
# 2) 50k asymmetric soak (sender normal, receiver lowmem)
#
# Outputs:
# - per-run artifacts under target/lowmem-proxy
# - receiver RSS/smaps maxima
# - LOW_MEM_MEMTRACE-derived queue/backpressure maxima
# - "big users" summary for quick bottleneck diagnosis

MODE="${1:-proxy}"

if [ "$(uname -s)" != "Linux" ]; then
  echo "error: low-memory proxy requires Linux (/proc/<pid>/status + smaps)"
  exit 2
fi

SCRIPT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN_ROOT="${LOWMEM_PROXY_RUN_DIR:-${SCRIPT_ROOT}/target/lowmem-proxy}"
TOPO_BIN="${TOPO_BIN:-${SCRIPT_ROOT}/target/release/topo}"
TOPO_CMD_TIMEOUT_SECS="${TOPO_CMD_TIMEOUT_SECS:-600}"
SAMPLE_INTERVAL_SECS="${LOWMEM_PROXY_SAMPLE_INTERVAL_SECS:-10}"

SMOKE_EVENTS_PER_PEER="${LOWMEM_PROXY_SMOKE_EVENTS_PER_PEER:-5000}"
SMOKE_BUDGET_MIB="${LOWMEM_PROXY_SMOKE_BUDGET_MIB:-2000}"
ASYM_EVENTS="${LOWMEM_PROXY_EVENTS:-50000}"
WAL_CAP_MIB="${LOW_MEM_WAL_CAP_MIB:-12}"

LOWMEM_MEMTRACE_ENABLED="${LOW_MEM_MEMTRACE:-1}"

export TMPDIR="${TMPDIR:-${SCRIPT_ROOT}/target/tmp}"
mkdir -p "${RUN_ROOT}" "${TMPDIR}"

banner() {
  echo
  echo "================================================================"
  echo "  $*"
  echo "================================================================"
}

run_topo() {
  timeout "${TOPO_CMD_TIMEOUT_SECS}" "${TOPO_BIN}" "$@"
}

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
  local timeout_secs="${2:-30}"
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

vmhwm_mib_for_pid() {
  local pid="$1"
  local status_file="/proc/${pid}/status"
  if [ ! -r "${status_file}" ]; then
    echo "0.00"
    return
  fi
  awk '/^VmHWM:/ { printf "%.2f", $2 / 1024.0; found = 1; exit } END { if (!found) printf "0.00" }' "${status_file}"
}

vmrss_kb_for_pid() {
  local pid="$1"
  awk '/^VmRSS:/ { print $2; found = 1; exit } END { if (!found) print 0 }' "/proc/${pid}/status" 2>/dev/null
}

shm_rss_kb_for_db() {
  local pid="$1"
  local db="$2"
  local shm_path="${db}-shm"
  awk -v target="${shm_path}" '
    BEGIN { sum = 0; in_region = 0 }
    /^[0-9a-f]+-[0-9a-f]+/ { in_region = (index($0, target) > 0) }
    in_region && /^Rss:[[:space:]]+/ { sum += $2 }
    END { print sum }
  ' "/proc/${pid}/smaps" 2>/dev/null || echo 0
}

sample_smaps_breakdown() {
  local pid="$1"
  local db="$2"
  local out_log="$3"
  local db_shm="${db}-shm"
  local db_wal="${db}-wal"
  awk -v db="${db}" -v dbshm="${db_shm}" -v dbwal="${db_wal}" '
    BEGIN { current = "anon"; total = 0 }
    /^[0-9a-f]+-[0-9a-f]+[[:space:]]/ {
      path = ""
      if (NF >= 6) {
        path = $6
        for (i = 7; i <= NF; i++) path = path " " $i
      }
      current = "anon"
      if (path == db) current = "db"
      else if (path == dbshm) current = "db_shm"
      else if (path == dbwal) current = "db_wal"
      else if (path ~ /^\//) current = "file_other"
    }
    /^Rss:[[:space:]]+/ {
      v = $2 + 0
      rss[current] += v
      total += v
    }
    END {
      printf "anon_kb=%d db_kb=%d db_shm_kb=%d db_wal_kb=%d file_other_kb=%d total_kb=%d\n",
             rss["anon"], rss["db"], rss["db_shm"], rss["db_wal"], rss["file_other"], total
    }
  ' "/proc/${pid}/smaps" 2>/dev/null | awk -v ts="$(date +%s)" '{print ts, $0}' >> "${out_log}"
}

stop_daemon() {
  local db="$1"
  run_topo --db "${db}" stop >/dev/null 2>&1 || true
}

run_smoke_proxy() {
  banner "Proxy Stage 1 - Smoke (10k total)"
  LOW_MEM_MEMTRACE="${LOWMEM_MEMTRACE_ENABLED}" \
  LOW_MEM_IOS_SMOKE_EVENTS_PER_PEER="${SMOKE_EVENTS_PER_PEER}" \
  LOW_MEM_IOS_BUDGET_MIB="${SMOKE_BUDGET_MIB}" \
  TOPO_CMD_TIMEOUT_SECS="${TOPO_CMD_TIMEOUT_SECS}" \
  "${SCRIPT_ROOT}/scripts/run_lowmem_regimen.sh" smoke
}

summarize_memtrace() {
  local memtrace_log="$1"
  local out_file="$2"

  if [ ! -s "${memtrace_log}" ]; then
    cat > "${out_file}" <<'EOF'
MEMTRACE_PRESENT=0
MAX_INIT_WANTED=0
MAX_INIT_PENDING_HAVE=0
MAX_INIT_FALLBACK_NEED=0
MAX_INIT_INGEST_USED=0
MAX_INIT_INGEST_CAP=0
MAX_RESP_INGEST_USED=0
MAX_RESP_INGEST_CAP=0
MAX_DATA_INGEST_USED=0
MAX_DATA_INGEST_CAP=0
MAX_DATA_EVENTS_INGESTED=0
MAX_DATA_BLOB=0
EOF
    return 0
  fi

  awk '
    /LOWMEM_MEMTRACE initiator/ {
      for (i=1; i<=NF; i++) {
        if ($i ~ /^wanted=/) {
          split($i,a,"="); if (a[2] > max_init_wanted) max_init_wanted = a[2]
        } else if ($i ~ /^pending_have=/) {
          split($i,a,"="); if (a[2] > max_init_pending_have) max_init_pending_have = a[2]
        } else if ($i ~ /^fallback_need=/) {
          split($i,a,"="); if (a[2] > max_init_fallback_need) max_init_fallback_need = a[2]
        } else if ($i ~ /^ingest_used=/) {
          split($i,a,"="); split(a[2],b,"/")
          used = b[1] + 0; cap = b[2] + 0
          if (used > max_init_ingest_used) {
            max_init_ingest_used = used
            max_init_ingest_cap = cap
          }
        }
      }
    }
    /LOWMEM_MEMTRACE responder/ {
      for (i=1; i<=NF; i++) {
        if ($i ~ /^ingest_used=/) {
          split($i,a,"="); split(a[2],b,"/")
          used = b[1] + 0; cap = b[2] + 0
          if (used > max_resp_ingest_used) {
            max_resp_ingest_used = used
            max_resp_ingest_cap = cap
          }
        }
      }
    }
    /LOWMEM_MEMTRACE data_rx/ {
      for (i=1; i<=NF; i++) {
        if ($i ~ /^ingest_used=/) {
          split($i,a,"="); split(a[2],b,"/")
          used = b[1] + 0; cap = b[2] + 0
          if (used > max_data_ingest_used) {
            max_data_ingest_used = used
            max_data_ingest_cap = cap
          }
        } else if ($i ~ /^events_ingested=/) {
          split($i,a,"="); if (a[2] > max_data_events) max_data_events = a[2]
        } else if ($i ~ /^max_blob=/) {
          split($i,a,"="); if (a[2] > max_data_blob) max_data_blob = a[2]
        }
      }
    }
    END {
      printf "MEMTRACE_PRESENT=1\n"
      printf "MAX_INIT_WANTED=%d\n", max_init_wanted
      printf "MAX_INIT_PENDING_HAVE=%d\n", max_init_pending_have
      printf "MAX_INIT_FALLBACK_NEED=%d\n", max_init_fallback_need
      printf "MAX_INIT_INGEST_USED=%d\n", max_init_ingest_used
      printf "MAX_INIT_INGEST_CAP=%d\n", max_init_ingest_cap
      printf "MAX_RESP_INGEST_USED=%d\n", max_resp_ingest_used
      printf "MAX_RESP_INGEST_CAP=%d\n", max_resp_ingest_cap
      printf "MAX_DATA_INGEST_USED=%d\n", max_data_ingest_used
      printf "MAX_DATA_INGEST_CAP=%d\n", max_data_ingest_cap
      printf "MAX_DATA_EVENTS_INGESTED=%d\n", max_data_events
      printf "MAX_DATA_BLOB=%d\n", max_data_blob
    }
  ' "${memtrace_log}" > "${out_file}"
}

run_asymmetric_proxy() {
  banner "Proxy Stage 2 - Asymmetric 50k (sender normal, receiver lowmem)"

  local run_dir="${RUN_ROOT}/asym-$$_$(date +%s)"
  local alice_db="${run_dir}/alice.db"
  local bob_db="${run_dir}/bob.db"
  local samples_log="${run_dir}/samples.log"
  local bob_smaps_log="${run_dir}/bob_smaps.log"
  local memtrace_log="${run_dir}/memtrace.log"
  local memtrace_summary="${run_dir}/memtrace_summary.env"
  local summary_file="${run_dir}/summary.txt"
  local alice_pid=""
  local bob_pid=""
  local sampler_pid=""
  local smaps_pid=""

  mkdir -p "${run_dir}"
  : > "${samples_log}"
  : > "${bob_smaps_log}"

  cleanup_asym() {
    set +e
    if [ -n "${sampler_pid}" ]; then
      kill "${sampler_pid}" >/dev/null 2>&1 || true
      wait "${sampler_pid}" >/dev/null 2>&1 || true
    fi
    if [ -n "${smaps_pid}" ]; then
      kill "${smaps_pid}" >/dev/null 2>&1 || true
      wait "${smaps_pid}" >/dev/null 2>&1 || true
    fi
    stop_daemon "${alice_db}"
    stop_daemon "${bob_db}"
  }
  trap cleanup_asym RETURN

  run_topo --db "${alice_db}" create-workspace \
    --workspace-name "lowmem-proxy" \
    --username "alice" \
    --device-name "alice-dev" >/dev/null
  wait_for_socket "${alice_db}" 30

  local addr invite_out invite_link
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

  LOW_MEM=1 \
  LOW_MEM_WAL_CAP_MIB="${WAL_CAP_MIB}" \
  LOW_MEM_MEMTRACE="${LOWMEM_MEMTRACE_ENABLED}" \
  LOW_MEM_MEMTRACE_FILE="${memtrace_log}" \
  run_topo --db "${bob_db}" accept-invite \
    --invite "${invite_link}" \
    --username "bob" \
    --devicename "bob-dev" >/dev/null
  wait_for_socket "${bob_db}" 30

  alice_pid="$(daemon_pid_for_db "${alice_db}")"
  bob_pid="$(daemon_pid_for_db "${bob_db}")"
  if [ -z "${alice_pid}" ] || [ -z "${bob_pid}" ]; then
    echo "error: failed to resolve daemon PIDs (alice=${alice_pid} bob=${bob_pid})" >&2
    return 1
  fi

  (
    while kill -0 "${alice_pid}" 2>/dev/null && kill -0 "${bob_pid}" 2>/dev/null; do
      printf '%s alice_rss_kb=%s alice_shm_kb=%s bob_rss_kb=%s bob_shm_kb=%s\n' \
        "$(date +%s)" \
        "$(vmrss_kb_for_pid "${alice_pid}")" \
        "$(shm_rss_kb_for_db "${alice_pid}" "${alice_db}")" \
        "$(vmrss_kb_for_pid "${bob_pid}")" \
        "$(shm_rss_kb_for_db "${bob_pid}" "${bob_db}")" >> "${samples_log}"
      sleep "${SAMPLE_INTERVAL_SECS}"
    done
  ) &
  sampler_pid="$!"

  (
    while kill -0 "${bob_pid}" 2>/dev/null; do
      sample_smaps_breakdown "${bob_pid}" "${bob_db}" "${bob_smaps_log}"
      sleep "${SAMPLE_INTERVAL_SECS}"
    done
  ) &
  smaps_pid="$!"

  run_topo --db "${alice_db}" generate --count "${ASYM_EVENTS}" >/dev/null

  local assert_timeout_ms
  assert_timeout_ms=$((TOPO_CMD_TIMEOUT_SECS * 1000))
  run_topo --db "${alice_db}" assert-eventually "message_count >= ${ASYM_EVENTS}" \
    --timeout-ms "${assert_timeout_ms}" --interval-ms 200 >/dev/null
  run_topo --db "${bob_db}" assert-eventually "message_count >= ${ASYM_EVENTS}" \
    --timeout-ms "${assert_timeout_ms}" --interval-ms 200 >/dev/null

  sleep 2
  if [ -n "${sampler_pid}" ]; then
    kill "${sampler_pid}" >/dev/null 2>&1 || true
    wait "${sampler_pid}" >/dev/null 2>&1 || true
    sampler_pid=""
  fi
  if [ -n "${smaps_pid}" ]; then
    kill "${smaps_pid}" >/dev/null 2>&1 || true
    wait "${smaps_pid}" >/dev/null 2>&1 || true
    smaps_pid=""
  fi

  local alice_vmhwm bob_vmhwm
  alice_vmhwm="$(vmhwm_mib_for_pid "${alice_pid}")"
  bob_vmhwm="$(vmhwm_mib_for_pid "${bob_pid}")"

  local max_alice_rss max_bob_rss max_alice_shm max_bob_shm
  read -r max_alice_rss max_bob_rss max_alice_shm max_bob_shm <<EOF
$(awk '
  {
    for (i=1; i<=NF; i++) {
      if ($i ~ /^alice_rss_kb=/) { split($i,a,"="); if (a[2] > arss) arss = a[2] }
      if ($i ~ /^bob_rss_kb=/) { split($i,a,"="); if (a[2] > brss) brss = a[2] }
      if ($i ~ /^alice_shm_kb=/) { split($i,a,"="); if (a[2] > ashm) ashm = a[2] }
      if ($i ~ /^bob_shm_kb=/) { split($i,a,"="); if (a[2] > bshm) bshm = a[2] }
    }
  }
  END { printf "%d %d %d %d\n", arss, brss, ashm, bshm }
' "${samples_log}")
EOF

  local max_anon max_db max_db_shm max_db_wal max_file_other max_total
  read -r max_anon max_db max_db_shm max_db_wal max_file_other max_total <<EOF
$(awk '
  {
    for (i=1; i<=NF; i++) {
      if ($i ~ /^anon_kb=/) { split($i,a,"="); if (a[2] > max_anon) max_anon = a[2] }
      if ($i ~ /^db_kb=/) { split($i,a,"="); if (a[2] > max_db) max_db = a[2] }
      if ($i ~ /^db_shm_kb=/) { split($i,a,"="); if (a[2] > max_db_shm) max_db_shm = a[2] }
      if ($i ~ /^db_wal_kb=/) { split($i,a,"="); if (a[2] > max_db_wal) max_db_wal = a[2] }
      if ($i ~ /^file_other_kb=/) { split($i,a,"="); if (a[2] > max_file_other) max_file_other = a[2] }
      if ($i ~ /^total_kb=/) { split($i,a,"="); if (a[2] > max_total) max_total = a[2] }
    }
  }
  END { printf "%d %d %d %d %d %d\n", max_anon, max_db, max_db_shm, max_db_wal, max_file_other, max_total }
' "${bob_smaps_log}")
EOF

  summarize_memtrace "${memtrace_log}" "${memtrace_summary}"
  # shellcheck disable=SC1090
  source "${memtrace_summary}"

  local anon_pct
  if [ "${max_total}" -gt 0 ]; then
    anon_pct=$(( (100 * max_anon) / max_total ))
  else
    anon_pct=0
  fi

  {
    echo "RUN_DIR=${run_dir}"
    echo "ALICE_PID=${alice_pid}"
    echo "BOB_PID=${bob_pid}"
    echo "ALICE_PEAK_VMHWM_MIB=${alice_vmhwm}"
    echo "BOB_PEAK_VMHWM_MIB=${bob_vmhwm}"
    echo "MAX_ALICE_RSS_KB=${max_alice_rss}"
    echo "MAX_BOB_RSS_KB=${max_bob_rss}"
    echo "MAX_ALICE_SHM_KB=${max_alice_shm}"
    echo "MAX_BOB_SHM_KB=${max_bob_shm}"
    echo "MAX_BOB_ANON_KB=${max_anon}"
    echo "MAX_BOB_DB_KB=${max_db}"
    echo "MAX_BOB_DB_SHM_KB=${max_db_shm}"
    echo "MAX_BOB_DB_WAL_KB=${max_db_wal}"
    echo "MAX_BOB_FILE_OTHER_KB=${max_file_other}"
    echo "MAX_BOB_TOTAL_KB=${max_total}"
    echo "MAX_BOB_ANON_PCT=${anon_pct}"
    echo "MEMTRACE_PRESENT=${MEMTRACE_PRESENT}"
    echo "MAX_INIT_WANTED=${MAX_INIT_WANTED}"
    echo "MAX_INIT_PENDING_HAVE=${MAX_INIT_PENDING_HAVE}"
    echo "MAX_INIT_FALLBACK_NEED=${MAX_INIT_FALLBACK_NEED}"
    echo "MAX_INIT_INGEST_USED=${MAX_INIT_INGEST_USED}"
    echo "MAX_INIT_INGEST_CAP=${MAX_INIT_INGEST_CAP}"
    echo "MAX_RESP_INGEST_USED=${MAX_RESP_INGEST_USED}"
    echo "MAX_RESP_INGEST_CAP=${MAX_RESP_INGEST_CAP}"
    echo "MAX_DATA_INGEST_USED=${MAX_DATA_INGEST_USED}"
    echo "MAX_DATA_INGEST_CAP=${MAX_DATA_INGEST_CAP}"
    echo "MAX_DATA_EVENTS_INGESTED=${MAX_DATA_EVENTS_INGESTED}"
    echo "MAX_DATA_BLOB=${MAX_DATA_BLOB}"
  } > "${summary_file}"

  banner "Proxy Summary"
  cat "${summary_file}"

  echo
  echo "Big Users (heuristic):"
  echo "1) Receiver anonymous memory: ${max_anon} KB (${anon_pct}% of total ${max_total} KB)"
  if [ "${MAX_RESP_INGEST_CAP}" -gt 0 ]; then
    echo "2) Responder ingest queue pressure: ${MAX_RESP_INGEST_USED}/${MAX_RESP_INGEST_CAP}"
  fi
  if [ "${MAX_DATA_INGEST_CAP}" -gt 0 ]; then
    echo "3) Data receiver ingest queue pressure: ${MAX_DATA_INGEST_USED}/${MAX_DATA_INGEST_CAP}"
  fi
  echo "4) Receiver wanted backlog peak: ${MAX_INIT_WANTED}"
  echo "5) Receiver db-shm peak: ${max_db_shm} KB (non-dominant if small)"
  echo
  echo "Artifacts:"
  echo "  ${summary_file}"
  echo "  ${samples_log}"
  echo "  ${bob_smaps_log}"
  echo "  ${memtrace_log}"
}

banner "Low-Memory Proxy"
echo "  MODE=${MODE}"
echo "  TOPO_BIN=${TOPO_BIN}"
echo "  RUN_ROOT=${RUN_ROOT}"
echo "  TMPDIR=${TMPDIR}"
echo "  TOPO_CMD_TIMEOUT_SECS=${TOPO_CMD_TIMEOUT_SECS}"
echo "  LOWMEM_PROXY_SMOKE_EVENTS_PER_PEER=${SMOKE_EVENTS_PER_PEER}"
echo "  LOWMEM_PROXY_SMOKE_BUDGET_MIB=${SMOKE_BUDGET_MIB}"
echo "  LOWMEM_PROXY_EVENTS=${ASYM_EVENTS}"
echo "  LOW_MEM_WAL_CAP_MIB=${WAL_CAP_MIB}"
echo "  LOW_MEM_MEMTRACE=${LOWMEM_MEMTRACE_ENABLED}"

case "${MODE}" in
  smoke)
    run_smoke_proxy
    ;;
  asym50k)
    run_asymmetric_proxy
    ;;
  proxy)
    run_smoke_proxy
    run_asymmetric_proxy
    ;;
  *)
    echo "usage: scripts/run_lowmem_proxy.sh [smoke|asym50k|proxy]"
    exit 2
    ;;
esac

