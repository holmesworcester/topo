#!/usr/bin/env bash
set -euo pipefail

# Fast proxy regimen for low-memory iteration:
# 1) 10k smoke (both peers lowmem, realistic two-daemon harness)
# 2) 50k asymmetric soak (sender normal, receiver lowmem)
# 3) Large-baseline delta sync (baseline normal, delta in lowmem)
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
LARGE_BASE_EVENTS="${LOWMEM_PROXY_BASE_EVENTS:-500000}"
LARGE_DELTA_EVENTS="${LOWMEM_PROXY_DELTA_EVENTS:-10000}"
LARGE_DELTA_KIND="${LOWMEM_PROXY_DELTA_KIND:-messages}"
LARGE_DELTA_FILES="${LOWMEM_PROXY_DELTA_FILES:-100}"
LARGE_DELTA_FILE_MIB="${LOWMEM_PROXY_DELTA_FILE_MIB:-1}"
LARGE_TIMEOUT_SECS="${LOWMEM_PROXY_LARGE_TIMEOUT_SECS:-3600}"
LARGE_MARKER_MESSAGES="${LOWMEM_PROXY_DELTA_MARKER_MESSAGES:-3}"

LOWMEM_MEMTRACE_ENABLED="${LOW_MEM_MEMTRACE:-1}"
LOWMEM_BUDGET_KB="${LOWMEM_PROXY_BUDGET_KB:-24576}"
LOWMEM_CGROUP_ENFORCE="${LOWMEM_PROXY_CGROUP_ENFORCE:-0}"
LOWMEM_CGROUP_LIMIT_KB="${LOWMEM_PROXY_CGROUP_LIMIT_KB:-22528}"
LOWMEM_CGROUP_PARENT="${LOWMEM_PROXY_CGROUP_PARENT:-}"

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

run_topo_long() {
  timeout "${LARGE_TIMEOUT_SECS}" "${TOPO_BIN}" "$@"
}

default_cgroup_parent() {
  local rel parent
  rel="$(awk -F: 'NR==1{print $3}' /proc/self/cgroup)"
  if [ -z "${rel}" ]; then
    return 1
  fi
  if [ "${rel}" = "/" ] || [ "${rel%/*}" = "${rel}" ]; then
    parent="/sys/fs/cgroup"
  else
    parent="/sys/fs/cgroup${rel%/*}"
  fi
  if [ ! -d "${parent}" ]; then
    return 1
  fi
  printf '%s\n' "${parent}"
}

create_limited_cgroup() {
  local name="$1"
  local limit_kb="$2"
  local parent="${LOWMEM_CGROUP_PARENT}"
  if [ -z "${parent}" ]; then
    parent="$(default_cgroup_parent)" || {
      echo "error: failed to resolve cgroup parent for lowmem cap" >&2
      return 1
    }
  fi
  if [ ! -d "${parent}" ]; then
    echo "error: cgroup parent does not exist: ${parent}" >&2
    return 1
  fi
  local cg="${parent}/${name}"
  mkdir "${cg}" || {
    echo "error: failed to create cgroup: ${cg}" >&2
    return 1
  }

  local limit_bytes=$((limit_kb * 1024))
  if ! echo "${limit_bytes}" > "${cg}/memory.max"; then
    echo "error: failed to set memory.max on ${cg}" >&2
    rmdir "${cg}" >/dev/null 2>&1 || true
    return 1
  fi
  if [ -w "${cg}/memory.swap.max" ]; then
    echo 0 > "${cg}/memory.swap.max" || true
  fi
  if [ -w "${cg}/memory.oom.group" ]; then
    echo 1 > "${cg}/memory.oom.group" || true
  fi
  printf '%s\n' "${cg}"
}

attach_pid_to_cgroup() {
  local pid="$1"
  local cg="$2"
  if [ ! -w "${cg}/cgroup.procs" ]; then
    echo "error: cannot attach pid=${pid} to cgroup=${cg} (cgroup.procs not writable)" >&2
    return 1
  fi
  echo "${pid}" > "${cg}/cgroup.procs"
}

cgroup_memory_event_value() {
  local cg="$1"
  local key="$2"
  if [ -r "${cg}/memory.events" ]; then
    awk -v k="${key}" '$1 == k { print $2; found=1 } END { if (!found) print 0 }' "${cg}/memory.events"
  else
    echo 0
  fi
}

check_process_and_cgroup_health() {
  local pid="${1:-}"
  local cg="${2:-}"
  local label="${3:-process}"

  if [ -n "${cg}" ] && [ -d "${cg}" ]; then
    local oom oom_kill
    oom="$(cgroup_memory_event_value "${cg}" "oom")"
    oom_kill="$(cgroup_memory_event_value "${cg}" "oom_kill")"
    if [ "${oom_kill}" -gt 0 ]; then
      echo "error: ${label} hit cgroup OOM (oom=${oom} oom_kill=${oom_kill} cgroup=${cg})" >&2
      return 1
    fi
  fi

  if [ -n "${pid}" ] && ! kill -0 "${pid}" 2>/dev/null; then
    local oom=0 oom_kill=0
    if [ -n "${cg}" ] && [ -d "${cg}" ]; then
      oom="$(cgroup_memory_event_value "${cg}" "oom")"
      oom_kill="$(cgroup_memory_event_value "${cg}" "oom_kill")"
    fi
    echo "error: ${label} exited before convergence (pid=${pid} oom=${oom} oom_kill=${oom_kill})" >&2
    return 1
  fi
  return 0
}

cleanup_limited_cgroup() {
  local cg="$1"
  if [ -z "${cg}" ] || [ ! -d "${cg}" ]; then
    return 0
  fi
  if [ -r "${cg}/cgroup.procs" ]; then
    while read -r pid; do
      if [ -n "${pid}" ]; then
        kill "${pid}" >/dev/null 2>&1 || true
      fi
    done < "${cg}/cgroup.procs"
  fi
  rmdir "${cg}" >/dev/null 2>&1 || true
}

is_retryable_resource_error() {
  local msg="$1"
  grep -qiE "Resource temporarily unavailable \(os error 11\)|daemon not running yet|database is locked" <<<"${msg}"
}

run_topo_retry() {
  local max_attempts="${1:-5}"
  shift
  local attempt out rc
  for attempt in $(seq 1 "${max_attempts}"); do
    out="$(run_topo "$@" 2>&1)" && {
      [ -n "${out}" ] && printf '%s\n' "${out}"
      return 0
    }
    rc=$?
    if is_retryable_resource_error "${out}" && [ "${attempt}" -lt "${max_attempts}" ]; then
      sleep 1
      continue
    fi
    printf '%s\n' "${out}" >&2
    return "${rc}"
  done
}

run_topo_long_retry() {
  local max_attempts="${1:-3}"
  shift
  local attempt out rc
  for attempt in $(seq 1 "${max_attempts}"); do
    out="$(run_topo_long "$@" 2>&1)" && {
      [ -n "${out}" ] && printf '%s\n' "${out}"
      return 0
    }
    rc=$?
    if is_retryable_resource_error "${out}" && [ "${attempt}" -lt "${max_attempts}" ]; then
      sleep 2
      continue
    fi
    printf '%s\n' "${out}" >&2
    return "${rc}"
  done
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
    BEGIN { current = "anon_unlabeled"; total = 0 }
    /^[0-9a-f]+-[0-9a-f]+[[:space:]]/ {
      path = ""
      if (NF >= 6) {
        path = $6
        for (i = 7; i <= NF; i++) path = path " " $i
      }
      current = "anon_unlabeled"
      if (path == db) current = "db"
      else if (path == dbshm) current = "db_shm"
      else if (path == dbwal) current = "db_wal"
      else if (path == "[heap]") current = "anon_heap"
      else if (path ~ /^\[stack/) current = "anon_stack"
      else if (path ~ /^\[anon:/) current = "anon_named"
      else if (path ~ /^\[/) current = "anon_other_bracket"
      else if (path ~ /^\//) current = "file_other"
    }
    /^Rss:[[:space:]]+/ {
      v = $2 + 0
      rss[current] += v
      total += v
    }
    END {
      anon_total = rss["anon_unlabeled"] + rss["anon_heap"] + rss["anon_stack"] + rss["anon_named"] + rss["anon_other_bracket"]
      printf "anon_kb=%d anon_unlabeled_kb=%d anon_heap_kb=%d anon_stack_kb=%d anon_named_kb=%d anon_other_bracket_kb=%d db_kb=%d db_shm_kb=%d db_wal_kb=%d file_other_kb=%d total_kb=%d\n",
             anon_total, rss["anon_unlabeled"], rss["anon_heap"], rss["anon_stack"], rss["anon_named"], rss["anon_other_bracket"], rss["db"], rss["db_shm"], rss["db_wal"], rss["file_other"], total
    }
  ' "/proc/${pid}/smaps" 2>/dev/null | awk -v ts="$(date +%s)" '{print ts, $0}' >> "${out_log}"
}

capture_top_anon_regions() {
  local pid="$1"
  local out_file="$2"
  local smaps_path="/proc/${pid}/smaps"
  if [ ! -r "${smaps_path}" ]; then
    echo "smaps unavailable for pid=${pid}" > "${out_file}"
    return 0
  fi
  awk '
    function flush_region() {
      if (!in_region) return
      if (path == "" || path ~ /^\[/) {
        display = path
        if (display == "") display = "<anonymous>"
        printf "%10d KB  range=%s perms=%s path=%s\n", rss_kb, range, perms, display
      }
    }
    /^[0-9a-f]+-[0-9a-f]+[[:space:]]/ {
      flush_region()
      in_region = 1
      rss_kb = 0
      range = $1
      perms = $2
      path = ""
      if (NF >= 6) {
        path = $6
        for (i = 7; i <= NF; i++) path = path " " $i
      }
      next
    }
    /^Rss:[[:space:]]+/ {
      rss_kb = $2 + 0
    }
    END {
      flush_region()
    }
  ' "${smaps_path}" 2>/dev/null | sort -nr | head -n 25 > "${out_file}"
}

stop_daemon() {
  local db="$1"
  run_topo --db "${db}" stop >/dev/null 2>&1 || true
  local deadline=$(( $(date +%s) + 20 ))
  while true; do
    local pids
    pids="$(ps -eo pid=,args= | awk -v db="${db}" 'index($0, "--db " db " start") {print $1}')"
    if [ -z "${pids}" ]; then
      return 0
    fi
    if [ "$(date +%s)" -ge "${deadline}" ]; then
      kill ${pids} >/dev/null 2>&1 || true
      return 0
    fi
    sleep 0.2
  done
}

checkpoint_truncate_wal() {
  local db="$1"
  python3 - "${db}" <<'PY'
import sqlite3
import sys

db = sys.argv[1]
try:
    conn = sqlite3.connect(db, timeout=30)
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.close()
except Exception as e:
    print(f"warn: wal checkpoint failed for {db}: {e}", file=sys.stderr)
PY
}

messages_count_for_db() {
  local db="$1"
  python3 - "${db}" <<'PY'
import sqlite3
import sys
db = sys.argv[1]
try:
    conn = sqlite3.connect(db, timeout=5)
    conn.execute("PRAGMA busy_timeout = 5000")
    cur = conn.execute("SELECT COUNT(*) FROM messages")
    row = cur.fetchone()
    print(int(row[0] if row else 0))
except sqlite3.Error:
    print(-1)
finally:
    try:
        conn.close()
    except Exception:
        pass
PY
}

messages_with_prefix_for_db() {
  local db="$1"
  local prefix="$2"
  python3 - "${db}" "${prefix}" <<'PY'
import sqlite3
import sys
db = sys.argv[1]
prefix = sys.argv[2]
try:
    conn = sqlite3.connect(db, timeout=5)
    conn.execute("PRAGMA busy_timeout = 5000")
    cur = conn.execute(
        "SELECT COUNT(*) FROM messages WHERE content LIKE ?",
        (f"{prefix}%",),
    )
    row = cur.fetchone()
    print(int(row[0] if row else 0))
except sqlite3.Error:
    print(-1)
finally:
    try:
        conn.close()
    except Exception:
        pass
PY
}

file_slice_count_for_db() {
  local db="$1"
  python3 - "${db}" <<'PY'
import sqlite3
import sys
db = sys.argv[1]
try:
    conn = sqlite3.connect(db, timeout=5)
    conn.execute("PRAGMA busy_timeout = 5000")
    cur = conn.execute("SELECT COUNT(*) FROM events WHERE event_type = 'file_slice'")
    row = cur.fetchone()
    print(int(row[0] if row else 0))
except sqlite3.Error:
    print(-1)
finally:
    try:
        conn.close()
    except Exception:
        pass
PY
}

wait_for_message_count() {
  local db="$1"
  local min_count="$2"
  local timeout_secs="$3"
  local interval_secs="${4:-1}"
  local watch_pid="${5:-}"
  local watch_cgroup="${6:-}"
  local watch_label="${7:-receiver}"
  local start now count
  start="$(date +%s)"
  while true; do
    check_process_and_cgroup_health "${watch_pid}" "${watch_cgroup}" "${watch_label}" || return 1
    count="$(messages_count_for_db "${db}")"
    if [ "${count}" -ge "${min_count}" ]; then
      return 0
    fi
    now="$(date +%s)"
    if [ $((now - start)) -ge "${timeout_secs}" ]; then
      echo "error: timed out waiting for message_count >= ${min_count} in ${db} (last=${count})" >&2
      return 1
    fi
    sleep "${interval_secs}"
  done
}

wait_for_file_slice_count() {
  local db="$1"
  local min_count="$2"
  local timeout_secs="$3"
  local interval_secs="${4:-1}"
  local watch_pid="${5:-}"
  local watch_cgroup="${6:-}"
  local watch_label="${7:-receiver}"
  local start now count
  start="$(date +%s)"
  while true; do
    check_process_and_cgroup_health "${watch_pid}" "${watch_cgroup}" "${watch_label}" || return 1
    count="$(file_slice_count_for_db "${db}")"
    if [ "${count}" -ge "${min_count}" ]; then
      return 0
    fi
    now="$(date +%s)"
    if [ $((now - start)) -ge "${timeout_secs}" ]; then
      echo "error: timed out waiting for file_slice_count >= ${min_count} in ${db} (last=${count})" >&2
      return 1
    fi
    sleep "${interval_secs}"
  done
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
MAX_INIT_HAVE_CAP=0
MAX_INIT_NEED_CAP=0
MAX_INIT_PENDING_HAVE_CAP=0
MAX_INIT_FALLBACK_CAP=0
MAX_INIT_NEED_QUEUE=0
MAX_INIT_INGEST_USED=0
MAX_INIT_INGEST_CAP=0
MAX_RESP_INGEST_USED=0
MAX_RESP_INGEST_CAP=0
MAX_DATA_INGEST_USED=0
MAX_DATA_INGEST_CAP=0
MAX_DATA_EVENTS_INGESTED=0
MAX_DATA_BLOB=0
MAX_SQLITE_MEM_CUR=0
MAX_SQLITE_MEM_HIGH=0
MAX_SQLITE_PCACHE_OVFL_CUR=0
MAX_SQLITE_PCACHE_OVFL_HIGH=0
MAX_INIT_DB_MAIN_CACHE=0
MAX_INIT_DB_MAIN_SCHEMA=0
MAX_INIT_DB_MAIN_STMT=0
MAX_INIT_DB_NEG_CACHE=0
MAX_INIT_DB_NEG_SCHEMA=0
MAX_INIT_DB_NEG_STMT=0
MAX_RESP_DB_CACHE=0
MAX_RESP_DB_SCHEMA=0
MAX_RESP_DB_STMT=0
MAX_MALL_ARENA=0
MAX_MALL_USED=0
MAX_MALL_FREE=0
MAX_MALL_MMAP=0
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
        } else if ($i ~ /^have_cap=/) {
          split($i,a,"="); if (a[2] > max_init_have_cap) max_init_have_cap = a[2]
        } else if ($i ~ /^need_cap=/) {
          split($i,a,"="); if (a[2] > max_init_need_cap) max_init_need_cap = a[2]
        } else if ($i ~ /^pending_have_cap=/) {
          split($i,a,"="); if (a[2] > max_init_pending_have_cap) max_init_pending_have_cap = a[2]
        } else if ($i ~ /^fallback_cap=/) {
          split($i,a,"="); if (a[2] > max_init_fallback_cap) max_init_fallback_cap = a[2]
        } else if ($i ~ /^need_queue=/) {
          split($i,a,"="); if (a[2] > max_init_need_queue) max_init_need_queue = a[2]
        } else if ($i ~ /^ingest_used=/) {
          split($i,a,"="); split(a[2],b,"/")
          used = b[1] + 0; cap = b[2] + 0
          if (used > max_init_ingest_used) {
            max_init_ingest_used = used
            max_init_ingest_cap = cap
          }
        } else if ($i ~ /^sqlite_mem_cur=/) {
          split($i,a,"="); if ((a[2] + 0) >= 0 && a[2] > max_sqlite_mem_cur) max_sqlite_mem_cur = a[2]
        } else if ($i ~ /^sqlite_mem_high=/) {
          split($i,a,"="); if ((a[2] + 0) >= 0 && a[2] > max_sqlite_mem_high) max_sqlite_mem_high = a[2]
        } else if ($i ~ /^sqlite_pcache_ovfl_cur=/) {
          split($i,a,"="); if ((a[2] + 0) >= 0 && a[2] > max_sqlite_pcache_ovfl_cur) max_sqlite_pcache_ovfl_cur = a[2]
        } else if ($i ~ /^sqlite_pcache_ovfl_high=/) {
          split($i,a,"="); if ((a[2] + 0) >= 0 && a[2] > max_sqlite_pcache_ovfl_high) max_sqlite_pcache_ovfl_high = a[2]
        } else if ($i ~ /^db_main_cache=/) {
          split($i,a,"="); if ((a[2] + 0) >= 0 && a[2] > max_init_db_main_cache) max_init_db_main_cache = a[2]
        } else if ($i ~ /^db_main_schema=/) {
          split($i,a,"="); if ((a[2] + 0) >= 0 && a[2] > max_init_db_main_schema) max_init_db_main_schema = a[2]
        } else if ($i ~ /^db_main_stmt=/) {
          split($i,a,"="); if ((a[2] + 0) >= 0 && a[2] > max_init_db_main_stmt) max_init_db_main_stmt = a[2]
        } else if ($i ~ /^db_neg_cache=/) {
          split($i,a,"="); if ((a[2] + 0) >= 0 && a[2] > max_init_db_neg_cache) max_init_db_neg_cache = a[2]
        } else if ($i ~ /^db_neg_schema=/) {
          split($i,a,"="); if ((a[2] + 0) >= 0 && a[2] > max_init_db_neg_schema) max_init_db_neg_schema = a[2]
        } else if ($i ~ /^db_neg_stmt=/) {
          split($i,a,"="); if ((a[2] + 0) >= 0 && a[2] > max_init_db_neg_stmt) max_init_db_neg_stmt = a[2]
        } else if ($i ~ /^mall_arena=/) {
          split($i,a,"="); if ((a[2] + 0) >= 0 && a[2] > max_mall_arena) max_mall_arena = a[2]
        } else if ($i ~ /^mall_used=/) {
          split($i,a,"="); if ((a[2] + 0) >= 0 && a[2] > max_mall_used) max_mall_used = a[2]
        } else if ($i ~ /^mall_free=/) {
          split($i,a,"="); if ((a[2] + 0) >= 0 && a[2] > max_mall_free) max_mall_free = a[2]
        } else if ($i ~ /^mall_mmap=/) {
          split($i,a,"="); if ((a[2] + 0) >= 0 && a[2] > max_mall_mmap) max_mall_mmap = a[2]
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
        } else if ($i ~ /^sqlite_mem_cur=/) {
          split($i,a,"="); if ((a[2] + 0) >= 0 && a[2] > max_sqlite_mem_cur) max_sqlite_mem_cur = a[2]
        } else if ($i ~ /^sqlite_mem_high=/) {
          split($i,a,"="); if ((a[2] + 0) >= 0 && a[2] > max_sqlite_mem_high) max_sqlite_mem_high = a[2]
        } else if ($i ~ /^sqlite_pcache_ovfl_cur=/) {
          split($i,a,"="); if ((a[2] + 0) >= 0 && a[2] > max_sqlite_pcache_ovfl_cur) max_sqlite_pcache_ovfl_cur = a[2]
        } else if ($i ~ /^sqlite_pcache_ovfl_high=/) {
          split($i,a,"="); if ((a[2] + 0) >= 0 && a[2] > max_sqlite_pcache_ovfl_high) max_sqlite_pcache_ovfl_high = a[2]
        } else if ($i ~ /^db_cache=/) {
          split($i,a,"="); if ((a[2] + 0) >= 0 && a[2] > max_resp_db_cache) max_resp_db_cache = a[2]
        } else if ($i ~ /^db_schema=/) {
          split($i,a,"="); if ((a[2] + 0) >= 0 && a[2] > max_resp_db_schema) max_resp_db_schema = a[2]
        } else if ($i ~ /^db_stmt=/) {
          split($i,a,"="); if ((a[2] + 0) >= 0 && a[2] > max_resp_db_stmt) max_resp_db_stmt = a[2]
        } else if ($i ~ /^mall_arena=/) {
          split($i,a,"="); if ((a[2] + 0) >= 0 && a[2] > max_mall_arena) max_mall_arena = a[2]
        } else if ($i ~ /^mall_used=/) {
          split($i,a,"="); if ((a[2] + 0) >= 0 && a[2] > max_mall_used) max_mall_used = a[2]
        } else if ($i ~ /^mall_free=/) {
          split($i,a,"="); if ((a[2] + 0) >= 0 && a[2] > max_mall_free) max_mall_free = a[2]
        } else if ($i ~ /^mall_mmap=/) {
          split($i,a,"="); if ((a[2] + 0) >= 0 && a[2] > max_mall_mmap) max_mall_mmap = a[2]
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
      printf "MAX_INIT_HAVE_CAP=%d\n", max_init_have_cap
      printf "MAX_INIT_NEED_CAP=%d\n", max_init_need_cap
      printf "MAX_INIT_PENDING_HAVE_CAP=%d\n", max_init_pending_have_cap
      printf "MAX_INIT_FALLBACK_CAP=%d\n", max_init_fallback_cap
      printf "MAX_INIT_NEED_QUEUE=%d\n", max_init_need_queue
      printf "MAX_INIT_INGEST_USED=%d\n", max_init_ingest_used
      printf "MAX_INIT_INGEST_CAP=%d\n", max_init_ingest_cap
      printf "MAX_RESP_INGEST_USED=%d\n", max_resp_ingest_used
      printf "MAX_RESP_INGEST_CAP=%d\n", max_resp_ingest_cap
      printf "MAX_DATA_INGEST_USED=%d\n", max_data_ingest_used
      printf "MAX_DATA_INGEST_CAP=%d\n", max_data_ingest_cap
      printf "MAX_DATA_EVENTS_INGESTED=%d\n", max_data_events
      printf "MAX_DATA_BLOB=%d\n", max_data_blob
      printf "MAX_SQLITE_MEM_CUR=%d\n", max_sqlite_mem_cur
      printf "MAX_SQLITE_MEM_HIGH=%d\n", max_sqlite_mem_high
      printf "MAX_SQLITE_PCACHE_OVFL_CUR=%d\n", max_sqlite_pcache_ovfl_cur
      printf "MAX_SQLITE_PCACHE_OVFL_HIGH=%d\n", max_sqlite_pcache_ovfl_high
      printf "MAX_INIT_DB_MAIN_CACHE=%d\n", max_init_db_main_cache
      printf "MAX_INIT_DB_MAIN_SCHEMA=%d\n", max_init_db_main_schema
      printf "MAX_INIT_DB_MAIN_STMT=%d\n", max_init_db_main_stmt
      printf "MAX_INIT_DB_NEG_CACHE=%d\n", max_init_db_neg_cache
      printf "MAX_INIT_DB_NEG_SCHEMA=%d\n", max_init_db_neg_schema
      printf "MAX_INIT_DB_NEG_STMT=%d\n", max_init_db_neg_stmt
      printf "MAX_RESP_DB_CACHE=%d\n", max_resp_db_cache
      printf "MAX_RESP_DB_SCHEMA=%d\n", max_resp_db_schema
      printf "MAX_RESP_DB_STMT=%d\n", max_resp_db_stmt
      printf "MAX_MALL_ARENA=%d\n", max_mall_arena
      printf "MAX_MALL_USED=%d\n", max_mall_used
      printf "MAX_MALL_FREE=%d\n", max_mall_free
      printf "MAX_MALL_MMAP=%d\n", max_mall_mmap
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
  local bob_anon_regions="${run_dir}/bob_anon_regions.txt"
  local memtrace_log="${run_dir}/memtrace.log"
  local memtrace_summary="${run_dir}/memtrace_summary.env"
  local summary_file="${run_dir}/summary.txt"
  local alice_pid=""
  local bob_pid=""
  local bob_cgroup=""
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
    cleanup_limited_cgroup "${bob_cgroup}"
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
    run_topo --db "${alice_db}" invite --public-addr "${addr}"
  )"
  invite_link="$(printf '%s\n' "${invite_out}" | awk '/^quiet:\/\/invite\// {print; exit}')"
  if [ -z "${invite_link}" ]; then
    echo "error: invite did not emit invite link" >&2
    return 1
  fi

  LOW_MEM_IOS=1 \
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

  if [ "${LOWMEM_CGROUP_ENFORCE}" = "1" ]; then
    bob_cgroup="$(create_limited_cgroup "lowmem-proxy-asym-bob-$$_$(date +%s)" "${LOWMEM_CGROUP_LIMIT_KB}")"
    attach_pid_to_cgroup "${bob_pid}" "${bob_cgroup}"
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
  capture_top_anon_regions "${bob_pid}" "${bob_anon_regions}"
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

  local max_anon max_anon_unlabeled max_anon_heap max_anon_stack max_anon_named max_anon_other_bracket max_db max_db_shm max_db_wal max_file_other max_total
  read -r max_anon max_anon_unlabeled max_anon_heap max_anon_stack max_anon_named max_anon_other_bracket max_db max_db_shm max_db_wal max_file_other max_total <<EOF
$(awk '
  {
    for (i=1; i<=NF; i++) {
      if ($i ~ /^anon_kb=/) { split($i,a,"="); if (a[2] > max_anon) max_anon = a[2] }
      if ($i ~ /^anon_unlabeled_kb=/) { split($i,a,"="); if (a[2] > max_anon_unlabeled) max_anon_unlabeled = a[2] }
      if ($i ~ /^anon_heap_kb=/) { split($i,a,"="); if (a[2] > max_anon_heap) max_anon_heap = a[2] }
      if ($i ~ /^anon_stack_kb=/) { split($i,a,"="); if (a[2] > max_anon_stack) max_anon_stack = a[2] }
      if ($i ~ /^anon_named_kb=/) { split($i,a,"="); if (a[2] > max_anon_named) max_anon_named = a[2] }
      if ($i ~ /^anon_other_bracket_kb=/) { split($i,a,"="); if (a[2] > max_anon_other_bracket) max_anon_other_bracket = a[2] }
      if ($i ~ /^db_kb=/) { split($i,a,"="); if (a[2] > max_db) max_db = a[2] }
      if ($i ~ /^db_shm_kb=/) { split($i,a,"="); if (a[2] > max_db_shm) max_db_shm = a[2] }
      if ($i ~ /^db_wal_kb=/) { split($i,a,"="); if (a[2] > max_db_wal) max_db_wal = a[2] }
      if ($i ~ /^file_other_kb=/) { split($i,a,"="); if (a[2] > max_file_other) max_file_other = a[2] }
      if ($i ~ /^total_kb=/) { split($i,a,"="); if (a[2] > max_total) max_total = a[2] }
    }
  }
  END { printf "%d %d %d %d %d %d %d %d %d %d %d\n", max_anon, max_anon_unlabeled, max_anon_heap, max_anon_stack, max_anon_named, max_anon_other_bracket, max_db, max_db_shm, max_db_wal, max_file_other, max_total }
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

  local pass_under_budget=0
  if [ "${max_total}" -le "${LOWMEM_BUDGET_KB}" ]; then
    pass_under_budget=1
  fi

  local cgroup_enforced=0 cgroup_limit_kb=0 cgroup_oom=0 cgroup_oom_kill=0 cgroup_path=""
  if [ -n "${bob_cgroup}" ]; then
    cgroup_enforced=1
    cgroup_limit_kb="${LOWMEM_CGROUP_LIMIT_KB}"
    cgroup_oom="$(cgroup_memory_event_value "${bob_cgroup}" "oom")"
    cgroup_oom_kill="$(cgroup_memory_event_value "${bob_cgroup}" "oom_kill")"
    cgroup_path="${bob_cgroup}"
  fi

  local sqlite_mem_kb mall_arena_kb mall_used_kb mall_free_kb mall_mmap_kb anon_minus_sqlite_kb
  sqlite_mem_kb=$(( (MAX_SQLITE_MEM_CUR + 1023) / 1024 ))
  mall_arena_kb=$(( (MAX_MALL_ARENA + 1023) / 1024 ))
  mall_used_kb=$(( (MAX_MALL_USED + 1023) / 1024 ))
  mall_free_kb=$(( (MAX_MALL_FREE + 1023) / 1024 ))
  mall_mmap_kb=$(( (MAX_MALL_MMAP + 1023) / 1024 ))
  anon_minus_sqlite_kb=$(( max_anon - sqlite_mem_kb ))
  if [ "${anon_minus_sqlite_kb}" -lt 0 ]; then
    anon_minus_sqlite_kb=0
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
    echo "MAX_BOB_ANON_UNLABELED_KB=${max_anon_unlabeled}"
    echo "MAX_BOB_ANON_HEAP_KB=${max_anon_heap}"
    echo "MAX_BOB_ANON_STACK_KB=${max_anon_stack}"
    echo "MAX_BOB_ANON_NAMED_KB=${max_anon_named}"
    echo "MAX_BOB_ANON_OTHER_BRACKET_KB=${max_anon_other_bracket}"
    echo "MAX_BOB_DB_KB=${max_db}"
    echo "MAX_BOB_DB_SHM_KB=${max_db_shm}"
    echo "MAX_BOB_DB_WAL_KB=${max_db_wal}"
    echo "MAX_BOB_FILE_OTHER_KB=${max_file_other}"
    echo "MAX_BOB_TOTAL_KB=${max_total}"
    echo "LOWMEM_BUDGET_KB=${LOWMEM_BUDGET_KB}"
    echo "PASS_UNDER_24MB=${pass_under_budget}"
    echo "CGROUP_ENFORCED=${cgroup_enforced}"
    echo "CGROUP_LIMIT_KB=${cgroup_limit_kb}"
    echo "CGROUP_OOM=${cgroup_oom}"
    echo "CGROUP_OOM_KILL=${cgroup_oom_kill}"
    echo "CGROUP_PATH=${cgroup_path}"
    echo "MAX_BOB_ANON_PCT=${anon_pct}"
    echo "MEMTRACE_PRESENT=${MEMTRACE_PRESENT}"
    echo "MAX_INIT_WANTED=${MAX_INIT_WANTED}"
    echo "MAX_INIT_PENDING_HAVE=${MAX_INIT_PENDING_HAVE}"
    echo "MAX_INIT_FALLBACK_NEED=${MAX_INIT_FALLBACK_NEED}"
    echo "MAX_INIT_HAVE_CAP=${MAX_INIT_HAVE_CAP}"
    echo "MAX_INIT_NEED_CAP=${MAX_INIT_NEED_CAP}"
    echo "MAX_INIT_PENDING_HAVE_CAP=${MAX_INIT_PENDING_HAVE_CAP}"
    echo "MAX_INIT_FALLBACK_CAP=${MAX_INIT_FALLBACK_CAP}"
    echo "MAX_INIT_NEED_QUEUE=${MAX_INIT_NEED_QUEUE}"
    echo "MAX_INIT_INGEST_USED=${MAX_INIT_INGEST_USED}"
    echo "MAX_INIT_INGEST_CAP=${MAX_INIT_INGEST_CAP}"
    echo "MAX_RESP_INGEST_USED=${MAX_RESP_INGEST_USED}"
    echo "MAX_RESP_INGEST_CAP=${MAX_RESP_INGEST_CAP}"
    echo "MAX_DATA_INGEST_USED=${MAX_DATA_INGEST_USED}"
    echo "MAX_DATA_INGEST_CAP=${MAX_DATA_INGEST_CAP}"
    echo "MAX_DATA_EVENTS_INGESTED=${MAX_DATA_EVENTS_INGESTED}"
    echo "MAX_DATA_BLOB=${MAX_DATA_BLOB}"
    echo "MAX_SQLITE_MEM_CUR=${MAX_SQLITE_MEM_CUR}"
    echo "MAX_SQLITE_MEM_HIGH=${MAX_SQLITE_MEM_HIGH}"
    echo "MAX_SQLITE_PCACHE_OVFL_CUR=${MAX_SQLITE_PCACHE_OVFL_CUR}"
    echo "MAX_SQLITE_PCACHE_OVFL_HIGH=${MAX_SQLITE_PCACHE_OVFL_HIGH}"
    echo "MAX_INIT_DB_MAIN_CACHE=${MAX_INIT_DB_MAIN_CACHE}"
    echo "MAX_INIT_DB_MAIN_SCHEMA=${MAX_INIT_DB_MAIN_SCHEMA}"
    echo "MAX_INIT_DB_MAIN_STMT=${MAX_INIT_DB_MAIN_STMT}"
    echo "MAX_INIT_DB_NEG_CACHE=${MAX_INIT_DB_NEG_CACHE}"
    echo "MAX_INIT_DB_NEG_SCHEMA=${MAX_INIT_DB_NEG_SCHEMA}"
    echo "MAX_INIT_DB_NEG_STMT=${MAX_INIT_DB_NEG_STMT}"
    echo "MAX_RESP_DB_CACHE=${MAX_RESP_DB_CACHE}"
    echo "MAX_RESP_DB_SCHEMA=${MAX_RESP_DB_SCHEMA}"
    echo "MAX_RESP_DB_STMT=${MAX_RESP_DB_STMT}"
    echo "MAX_MALL_ARENA=${MAX_MALL_ARENA}"
    echo "MAX_MALL_USED=${MAX_MALL_USED}"
    echo "MAX_MALL_FREE=${MAX_MALL_FREE}"
    echo "MAX_MALL_MMAP=${MAX_MALL_MMAP}"
    echo "MAX_BOB_ANON_MINUS_SQLITE_KB=${anon_minus_sqlite_kb}"
  } > "${summary_file}"

  banner "Proxy Summary"
  cat "${summary_file}"

  echo
  echo "Big Users (heuristic):"
  echo "1) Receiver anonymous memory: ${max_anon} KB (${anon_pct}% of total ${max_total} KB)"
  echo "2) SQLite tracked heap (process-global): ${MAX_SQLITE_MEM_CUR} bytes (~${sqlite_mem_kb} KB)"
  echo "3) Receiver anon minus tracked SQLite heap: ${anon_minus_sqlite_kb} KB"
  echo "3a) Anon breakdown (unlabeled/heap/stack/named/[bracket-other]): ${max_anon_unlabeled}/${max_anon_heap}/${max_anon_stack}/${max_anon_named}/${max_anon_other_bracket} KB"
  echo "3b) glibc allocator (arena/used/free/mmap): ${mall_arena_kb}/${mall_used_kb}/${mall_free_kb}/${mall_mmap_kb} KB"
  if [ "${MAX_RESP_INGEST_CAP}" -gt 0 ]; then
    echo "4) Responder ingest queue pressure: ${MAX_RESP_INGEST_USED}/${MAX_RESP_INGEST_CAP}"
  fi
  if [ "${MAX_DATA_INGEST_CAP}" -gt 0 ]; then
    echo "5) Data receiver ingest queue pressure: ${MAX_DATA_INGEST_USED}/${MAX_DATA_INGEST_CAP}"
  fi
  echo "6) Receiver wanted backlog peak: ${MAX_INIT_WANTED}"
  echo "7) Initiator vector caps (have/need/pending/fallback): ${MAX_INIT_HAVE_CAP}/${MAX_INIT_NEED_CAP}/${MAX_INIT_PENDING_HAVE_CAP}/${MAX_INIT_FALLBACK_CAP}"
  echo "7a) Deferred need queue peak (DB-backed): ${MAX_INIT_NEED_QUEUE}"
  echo "8) Receiver db-shm peak: ${max_db_shm} KB (non-dominant if small)"
  if [ -s "${bob_anon_regions}" ]; then
    echo "Top anonymous regions by RSS:"
    sed -n '1,5p' "${bob_anon_regions}"
  fi
  echo
  echo "Artifacts:"
  echo "  ${summary_file}"
  echo "  ${samples_log}"
  echo "  ${bob_smaps_log}"
  echo "  ${bob_anon_regions}"
  echo "  ${memtrace_log}"

  if [ "${cgroup_oom_kill}" -gt 0 ]; then
    echo "error: receiver exceeded enforced cgroup limit (${cgroup_limit_kb} KB) and was OOM-killed" >&2
    return 1
  fi
}

run_large_delta_proxy() {
  banner "Proxy Stage 3 - Large Baseline + Delta (baseline normal, receiver lowmem)"

  local run_dir="${RUN_ROOT}/delta-$$_$(date +%s)"
  local alice_db="${run_dir}/alice.db"
  local bob_db="${run_dir}/bob.db"
  local samples_log="${run_dir}/samples.log"
  local bob_smaps_log="${run_dir}/bob_smaps.log"
  local bob_anon_regions="${run_dir}/bob_anon_regions.txt"
  local memtrace_log="${run_dir}/memtrace.log"
  local memtrace_summary="${run_dir}/memtrace_summary.env"
  local summary_file="${run_dir}/summary.txt"
  local alice_pid=""
  local bob_pid=""
  local bob_cgroup=""
  local sampler_pid=""
  local smaps_pid=""

  mkdir -p "${run_dir}"
  : > "${samples_log}"
  : > "${bob_smaps_log}"

  local delta_kind="${LARGE_DELTA_KIND}"
  local marker_messages="${LARGE_MARKER_MESSAGES}"
  local generated_delta_events=0
  local file_delta_files=0
  local file_delta_size_mib=0
  local expected_file_slices=0

  case "${delta_kind}" in
    messages)
      if [ "${marker_messages}" -gt "${LARGE_DELTA_EVENTS}" ]; then
        marker_messages="${LARGE_DELTA_EVENTS}"
      fi
      generated_delta_events=$((LARGE_DELTA_EVENTS - marker_messages))
      ;;
    files)
      file_delta_files="${LARGE_DELTA_FILES}"
      file_delta_size_mib="${LARGE_DELTA_FILE_MIB}"
      local file_size_bytes=$((file_delta_size_mib * 1024 * 1024))
      local slice_size=262144
      local slices_per_file=$(( (file_size_bytes + slice_size - 1) / slice_size ))
      expected_file_slices=$((file_delta_files * slices_per_file))
      ;;
    *)
      echo "error: unsupported LOWMEM_PROXY_DELTA_KIND=${delta_kind} (expected messages|files)" >&2
      return 1
      ;;
  esac

  local marker_prefix="delta-notify-$$-$(date +%s)"

  cleanup_delta() {
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
    cleanup_limited_cgroup "${bob_cgroup}"
  }
  trap cleanup_delta RETURN

  run_topo_retry 5 --db "${alice_db}" create-workspace \
    --workspace-name "lowmem-delta" \
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
    run_topo_retry 5 --db "${alice_db}" invite --public-addr "${addr}"
  )"
  invite_link="$(printf '%s\n' "${invite_out}" | awk '/^quiet:\/\/invite\// {print; exit}')"
  if [ -z "${invite_link}" ]; then
    echo "error: invite did not emit invite link" >&2
    return 1
  fi

  run_topo_retry 5 --db "${bob_db}" accept-invite \
    --invite "${invite_link}" \
    --username "bob" \
    --devicename "bob-dev" >/dev/null
  wait_for_socket "${bob_db}" 30

  echo "Seeding baseline events on sender: ${LARGE_BASE_EVENTS}"
  run_topo_long_retry 3 --db "${alice_db}" generate --count "${LARGE_BASE_EVENTS}" >/dev/null
  wait_for_message_count "${alice_db}" "${LARGE_BASE_EVENTS}" "${LARGE_TIMEOUT_SECS}" 1
  wait_for_message_count "${bob_db}" "${LARGE_BASE_EVENTS}" "${LARGE_TIMEOUT_SECS}" 1

  local pre_delta_count
  pre_delta_count="$(messages_count_for_db "${bob_db}")"
  local pre_delta_file_slices
  pre_delta_file_slices="$(file_slice_count_for_db "${bob_db}")"

  stop_daemon "${bob_db}"
  checkpoint_truncate_wal "${bob_db}"
  checkpoint_truncate_wal "${alice_db}"

  LOW_MEM_IOS=1 \
  LOW_MEM_WAL_CAP_MIB="${WAL_CAP_MIB}" \
  LOW_MEM_MEMTRACE="${LOWMEM_MEMTRACE_ENABLED}" \
  LOW_MEM_MEMTRACE_FILE="${memtrace_log}" \
  run_topo_retry 5 --db "${bob_db}" status >/dev/null
  wait_for_socket "${bob_db}" 30

  alice_pid="$(daemon_pid_for_db "${alice_db}")"
  bob_pid="$(daemon_pid_for_db "${bob_db}")"
  if [ -z "${alice_pid}" ] || [ -z "${bob_pid}" ]; then
    echo "error: failed to resolve daemon PIDs (alice=${alice_pid} bob=${bob_pid})" >&2
    return 1
  fi

  if [ "${LOWMEM_CGROUP_ENFORCE}" = "1" ]; then
    bob_cgroup="$(create_limited_cgroup "lowmem-proxy-delta-bob-$$_$(date +%s)" "${LOWMEM_CGROUP_LIMIT_KB}")"
    attach_pid_to_cgroup "${bob_pid}" "${bob_cgroup}"
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

  local i
  for i in $(seq 1 "${marker_messages}"); do
    run_topo_retry 5 --db "${alice_db}" send "${marker_prefix}-msg-${i}" >/dev/null
  done
  if [ "${delta_kind}" = "messages" ]; then
    if [ "${generated_delta_events}" -gt 0 ]; then
      run_topo_long_retry 3 --db "${alice_db}" generate --count "${generated_delta_events}" >/dev/null
    fi
  else
    if [ "${file_delta_files}" -gt 0 ]; then
      run_topo_long_retry 3 --db "${alice_db}" generate-files \
        --count "${file_delta_files}" \
        --size-mib "${file_delta_size_mib}" >/dev/null
    fi
  fi

  local expected_total_messages
  if [ "${delta_kind}" = "messages" ]; then
    expected_total_messages=$((LARGE_BASE_EVENTS + LARGE_DELTA_EVENTS))
  else
    expected_total_messages=$((LARGE_BASE_EVENTS + marker_messages + file_delta_files))
  fi
  local delta_message_budget=$((expected_total_messages - LARGE_BASE_EVENTS))
  wait_for_message_count "${alice_db}" "${expected_total_messages}" "${LARGE_TIMEOUT_SECS}" 1
  wait_for_message_count "${bob_db}" "${expected_total_messages}" "${LARGE_TIMEOUT_SECS}" 1 "${bob_pid}" "${bob_cgroup}" "receiver bob"
  if [ "${delta_kind}" = "files" ] && [ "${expected_file_slices}" -gt 0 ]; then
    wait_for_file_slice_count "${alice_db}" "${expected_file_slices}" "${LARGE_TIMEOUT_SECS}" 1
    wait_for_file_slice_count "${bob_db}" "${expected_file_slices}" "${LARGE_TIMEOUT_SECS}" 1 "${bob_pid}" "${bob_cgroup}" "receiver bob"
  fi

  local marker_synced
  marker_synced="$(messages_with_prefix_for_db "${bob_db}" "${marker_prefix}")"
  if [ "${marker_synced}" -lt "${marker_messages}" ]; then
    echo "error: marker message sync incomplete (expected ${marker_messages}, got ${marker_synced})" >&2
    return 1
  fi

  local post_delta_count
  post_delta_count="$(messages_count_for_db "${bob_db}")"
  local post_delta_file_slices
  post_delta_file_slices="$(file_slice_count_for_db "${bob_db}")"

  sleep 2
  capture_top_anon_regions "${bob_pid}" "${bob_anon_regions}"
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

  local max_anon max_anon_unlabeled max_anon_heap max_anon_stack max_anon_named max_anon_other_bracket max_db max_db_shm max_db_wal max_file_other max_total
  read -r max_anon max_anon_unlabeled max_anon_heap max_anon_stack max_anon_named max_anon_other_bracket max_db max_db_shm max_db_wal max_file_other max_total <<EOF
$(awk '
  {
    for (i=1; i<=NF; i++) {
      if ($i ~ /^anon_kb=/) { split($i,a,"="); if (a[2] > max_anon) max_anon = a[2] }
      if ($i ~ /^anon_unlabeled_kb=/) { split($i,a,"="); if (a[2] > max_anon_unlabeled) max_anon_unlabeled = a[2] }
      if ($i ~ /^anon_heap_kb=/) { split($i,a,"="); if (a[2] > max_anon_heap) max_anon_heap = a[2] }
      if ($i ~ /^anon_stack_kb=/) { split($i,a,"="); if (a[2] > max_anon_stack) max_anon_stack = a[2] }
      if ($i ~ /^anon_named_kb=/) { split($i,a,"="); if (a[2] > max_anon_named) max_anon_named = a[2] }
      if ($i ~ /^anon_other_bracket_kb=/) { split($i,a,"="); if (a[2] > max_anon_other_bracket) max_anon_other_bracket = a[2] }
      if ($i ~ /^db_kb=/) { split($i,a,"="); if (a[2] > max_db) max_db = a[2] }
      if ($i ~ /^db_shm_kb=/) { split($i,a,"="); if (a[2] > max_db_shm) max_db_shm = a[2] }
      if ($i ~ /^db_wal_kb=/) { split($i,a,"="); if (a[2] > max_db_wal) max_db_wal = a[2] }
      if ($i ~ /^file_other_kb=/) { split($i,a,"="); if (a[2] > max_file_other) max_file_other = a[2] }
      if ($i ~ /^total_kb=/) { split($i,a,"="); if (a[2] > max_total) max_total = a[2] }
    }
  }
  END { printf "%d %d %d %d %d %d %d %d %d %d %d\n", max_anon, max_anon_unlabeled, max_anon_heap, max_anon_stack, max_anon_named, max_anon_other_bracket, max_db, max_db_shm, max_db_wal, max_file_other, max_total }
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

  local pass_under_budget=0
  if [ "${max_total}" -le "${LOWMEM_BUDGET_KB}" ]; then
    pass_under_budget=1
  fi

  local cgroup_enforced=0 cgroup_limit_kb=0 cgroup_oom=0 cgroup_oom_kill=0 cgroup_path=""
  if [ -n "${bob_cgroup}" ]; then
    cgroup_enforced=1
    cgroup_limit_kb="${LOWMEM_CGROUP_LIMIT_KB}"
    cgroup_oom="$(cgroup_memory_event_value "${bob_cgroup}" "oom")"
    cgroup_oom_kill="$(cgroup_memory_event_value "${bob_cgroup}" "oom_kill")"
    cgroup_path="${bob_cgroup}"
  fi

  local sqlite_mem_kb mall_arena_kb mall_used_kb mall_free_kb mall_mmap_kb anon_minus_sqlite_kb
  sqlite_mem_kb=$(( (MAX_SQLITE_MEM_CUR + 1023) / 1024 ))
  mall_arena_kb=$(( (MAX_MALL_ARENA + 1023) / 1024 ))
  mall_used_kb=$(( (MAX_MALL_USED + 1023) / 1024 ))
  mall_free_kb=$(( (MAX_MALL_FREE + 1023) / 1024 ))
  mall_mmap_kb=$(( (MAX_MALL_MMAP + 1023) / 1024 ))
  anon_minus_sqlite_kb=$(( max_anon - sqlite_mem_kb ))
  if [ "${anon_minus_sqlite_kb}" -lt 0 ]; then
    anon_minus_sqlite_kb=0
  fi

  {
    echo "RUN_DIR=${run_dir}"
    echo "SCENARIO=large_delta"
    echo "DELTA_KIND=${delta_kind}"
    echo "BASE_EVENTS=${LARGE_BASE_EVENTS}"
    echo "DELTA_EVENTS=${delta_message_budget}"
    echo "DELTA_FILES=${file_delta_files}"
    echo "DELTA_FILE_SIZE_MIB=${file_delta_size_mib}"
    echo "DELTA_FILE_SLICES_EXPECTED=${expected_file_slices}"
    echo "PRE_DELTA_MESSAGES=${pre_delta_count}"
    echo "POST_DELTA_MESSAGES=${post_delta_count}"
    echo "DELTA_MESSAGES_OBSERVED=$((post_delta_count - pre_delta_count))"
    echo "PRE_DELTA_FILE_SLICES=${pre_delta_file_slices}"
    echo "POST_DELTA_FILE_SLICES=${post_delta_file_slices}"
    echo "DELTA_FILE_SLICES_OBSERVED=$((post_delta_file_slices - pre_delta_file_slices))"
    echo "DELTA_MARKER_PREFIX=${marker_prefix}"
    echo "DELTA_MARKERS_EXPECTED=${marker_messages}"
    echo "DELTA_MARKERS_SYNCED=${marker_synced}"
    echo "ALICE_PID=${alice_pid}"
    echo "BOB_PID=${bob_pid}"
    echo "ALICE_PEAK_VMHWM_MIB=${alice_vmhwm}"
    echo "BOB_PEAK_VMHWM_MIB=${bob_vmhwm}"
    echo "MAX_ALICE_RSS_KB=${max_alice_rss}"
    echo "MAX_BOB_RSS_KB=${max_bob_rss}"
    echo "MAX_ALICE_SHM_KB=${max_alice_shm}"
    echo "MAX_BOB_SHM_KB=${max_bob_shm}"
    echo "MAX_BOB_ANON_KB=${max_anon}"
    echo "MAX_BOB_ANON_UNLABELED_KB=${max_anon_unlabeled}"
    echo "MAX_BOB_ANON_HEAP_KB=${max_anon_heap}"
    echo "MAX_BOB_ANON_STACK_KB=${max_anon_stack}"
    echo "MAX_BOB_ANON_NAMED_KB=${max_anon_named}"
    echo "MAX_BOB_ANON_OTHER_BRACKET_KB=${max_anon_other_bracket}"
    echo "MAX_BOB_DB_KB=${max_db}"
    echo "MAX_BOB_DB_SHM_KB=${max_db_shm}"
    echo "MAX_BOB_DB_WAL_KB=${max_db_wal}"
    echo "MAX_BOB_FILE_OTHER_KB=${max_file_other}"
    echo "MAX_BOB_TOTAL_KB=${max_total}"
    echo "LOWMEM_BUDGET_KB=${LOWMEM_BUDGET_KB}"
    echo "PASS_UNDER_24MB=${pass_under_budget}"
    echo "CGROUP_ENFORCED=${cgroup_enforced}"
    echo "CGROUP_LIMIT_KB=${cgroup_limit_kb}"
    echo "CGROUP_OOM=${cgroup_oom}"
    echo "CGROUP_OOM_KILL=${cgroup_oom_kill}"
    echo "CGROUP_PATH=${cgroup_path}"
    echo "MAX_BOB_ANON_PCT=${anon_pct}"
    echo "MEMTRACE_PRESENT=${MEMTRACE_PRESENT}"
    echo "MAX_INIT_WANTED=${MAX_INIT_WANTED}"
    echo "MAX_INIT_PENDING_HAVE=${MAX_INIT_PENDING_HAVE}"
    echo "MAX_INIT_FALLBACK_NEED=${MAX_INIT_FALLBACK_NEED}"
    echo "MAX_INIT_HAVE_CAP=${MAX_INIT_HAVE_CAP}"
    echo "MAX_INIT_NEED_CAP=${MAX_INIT_NEED_CAP}"
    echo "MAX_INIT_PENDING_HAVE_CAP=${MAX_INIT_PENDING_HAVE_CAP}"
    echo "MAX_INIT_FALLBACK_CAP=${MAX_INIT_FALLBACK_CAP}"
    echo "MAX_INIT_NEED_QUEUE=${MAX_INIT_NEED_QUEUE}"
    echo "MAX_INIT_INGEST_USED=${MAX_INIT_INGEST_USED}"
    echo "MAX_INIT_INGEST_CAP=${MAX_INIT_INGEST_CAP}"
    echo "MAX_RESP_INGEST_USED=${MAX_RESP_INGEST_USED}"
    echo "MAX_RESP_INGEST_CAP=${MAX_RESP_INGEST_CAP}"
    echo "MAX_DATA_INGEST_USED=${MAX_DATA_INGEST_USED}"
    echo "MAX_DATA_INGEST_CAP=${MAX_DATA_INGEST_CAP}"
    echo "MAX_DATA_EVENTS_INGESTED=${MAX_DATA_EVENTS_INGESTED}"
    echo "MAX_DATA_BLOB=${MAX_DATA_BLOB}"
    echo "MAX_SQLITE_MEM_CUR=${MAX_SQLITE_MEM_CUR}"
    echo "MAX_SQLITE_MEM_HIGH=${MAX_SQLITE_MEM_HIGH}"
    echo "MAX_SQLITE_PCACHE_OVFL_CUR=${MAX_SQLITE_PCACHE_OVFL_CUR}"
    echo "MAX_SQLITE_PCACHE_OVFL_HIGH=${MAX_SQLITE_PCACHE_OVFL_HIGH}"
    echo "MAX_INIT_DB_MAIN_CACHE=${MAX_INIT_DB_MAIN_CACHE}"
    echo "MAX_INIT_DB_MAIN_SCHEMA=${MAX_INIT_DB_MAIN_SCHEMA}"
    echo "MAX_INIT_DB_MAIN_STMT=${MAX_INIT_DB_MAIN_STMT}"
    echo "MAX_INIT_DB_NEG_CACHE=${MAX_INIT_DB_NEG_CACHE}"
    echo "MAX_INIT_DB_NEG_SCHEMA=${MAX_INIT_DB_NEG_SCHEMA}"
    echo "MAX_INIT_DB_NEG_STMT=${MAX_INIT_DB_NEG_STMT}"
    echo "MAX_RESP_DB_CACHE=${MAX_RESP_DB_CACHE}"
    echo "MAX_RESP_DB_SCHEMA=${MAX_RESP_DB_SCHEMA}"
    echo "MAX_RESP_DB_STMT=${MAX_RESP_DB_STMT}"
    echo "MAX_MALL_ARENA=${MAX_MALL_ARENA}"
    echo "MAX_MALL_USED=${MAX_MALL_USED}"
    echo "MAX_MALL_FREE=${MAX_MALL_FREE}"
    echo "MAX_MALL_MMAP=${MAX_MALL_MMAP}"
    echo "MAX_BOB_ANON_MINUS_SQLITE_KB=${anon_minus_sqlite_kb}"
  } > "${summary_file}"

  banner "Proxy Summary"
  cat "${summary_file}"

  echo
  echo "Big Users (heuristic):"
  echo "1) Receiver anonymous memory: ${max_anon} KB (${anon_pct}% of total ${max_total} KB)"
  echo "2) SQLite tracked heap (process-global): ${MAX_SQLITE_MEM_CUR} bytes (~${sqlite_mem_kb} KB)"
  echo "3) Receiver anon minus tracked SQLite heap: ${anon_minus_sqlite_kb} KB"
  echo "3a) Anon breakdown (unlabeled/heap/stack/named/[bracket-other]): ${max_anon_unlabeled}/${max_anon_heap}/${max_anon_stack}/${max_anon_named}/${max_anon_other_bracket} KB"
  echo "3b) glibc allocator (arena/used/free/mmap): ${mall_arena_kb}/${mall_used_kb}/${mall_free_kb}/${mall_mmap_kb} KB"
  if [ "${MAX_RESP_INGEST_CAP}" -gt 0 ]; then
    echo "4) Responder ingest queue pressure: ${MAX_RESP_INGEST_USED}/${MAX_RESP_INGEST_CAP}"
  fi
  if [ "${MAX_DATA_INGEST_CAP}" -gt 0 ]; then
    echo "5) Data receiver ingest queue pressure: ${MAX_DATA_INGEST_USED}/${MAX_DATA_INGEST_CAP}"
  fi
  echo "6) Receiver wanted backlog peak: ${MAX_INIT_WANTED}"
  echo "7) Initiator vector caps (have/need/pending/fallback): ${MAX_INIT_HAVE_CAP}/${MAX_INIT_NEED_CAP}/${MAX_INIT_PENDING_HAVE_CAP}/${MAX_INIT_FALLBACK_CAP}"
  echo "7a) Deferred need queue peak (DB-backed): ${MAX_INIT_NEED_QUEUE}"
  echo "8) Receiver db-shm peak: ${max_db_shm} KB (non-dominant if small)"
  if [ -s "${bob_anon_regions}" ]; then
    echo "Top anonymous regions by RSS:"
    sed -n '1,5p' "${bob_anon_regions}"
  fi
  echo
  echo "Artifacts:"
  echo "  ${summary_file}"
  echo "  ${samples_log}"
  echo "  ${bob_smaps_log}"
  echo "  ${bob_anon_regions}"
  echo "  ${memtrace_log}"

  if [ "${cgroup_oom_kill}" -gt 0 ]; then
    echo "error: receiver exceeded enforced cgroup limit (${cgroup_limit_kb} KB) and was OOM-killed" >&2
    return 1
  fi
}

case "${MODE}" in
  delta10k)
    LARGE_DELTA_KIND="messages"
    ;;
  deltafiles)
    LARGE_DELTA_KIND="files"
    ;;
  deltafilesfast)
    LARGE_DELTA_KIND="files"
    LARGE_BASE_EVENTS=0
    # Keep one small marker to reliably trigger a sync round for file-only deltas.
    LARGE_MARKER_MESSAGES=1
    if [ -z "${LOWMEM_PROXY_DELTA_FILES+x}" ]; then
      LARGE_DELTA_FILES=10
    fi
    if [ -z "${LOWMEM_PROXY_DELTA_FILE_MIB+x}" ]; then
      LARGE_DELTA_FILE_MIB=1
    fi
    ;;
  deltafilesquick)
    LARGE_DELTA_KIND="files"
    LARGE_BASE_EVENTS=0
    LARGE_MARKER_MESSAGES=1
    LARGE_DELTA_FILES="${LOWMEM_PROXY_QUICK_DELTA_FILES:-10}"
    LARGE_DELTA_FILE_MIB="${LOWMEM_PROXY_QUICK_DELTA_FILE_MIB:-1}"
    LARGE_TIMEOUT_SECS="${LOWMEM_PROXY_QUICK_TIMEOUT_SECS:-180}"
    ;;
esac

banner "Low-Memory Proxy"
echo "  MODE=${MODE}"
echo "  TOPO_BIN=${TOPO_BIN}"
echo "  RUN_ROOT=${RUN_ROOT}"
echo "  TMPDIR=${TMPDIR}"
echo "  TOPO_CMD_TIMEOUT_SECS=${TOPO_CMD_TIMEOUT_SECS}"
echo "  LOWMEM_PROXY_SMOKE_EVENTS_PER_PEER=${SMOKE_EVENTS_PER_PEER}"
echo "  LOWMEM_PROXY_SMOKE_BUDGET_MIB=${SMOKE_BUDGET_MIB}"
echo "  LOWMEM_PROXY_EVENTS=${ASYM_EVENTS}"
echo "  LOWMEM_PROXY_BASE_EVENTS=${LARGE_BASE_EVENTS}"
echo "  LOWMEM_PROXY_DELTA_KIND=${LARGE_DELTA_KIND}"
echo "  LOWMEM_PROXY_DELTA_EVENTS=${LARGE_DELTA_EVENTS}"
echo "  LOWMEM_PROXY_DELTA_FILES=${LARGE_DELTA_FILES}"
echo "  LOWMEM_PROXY_DELTA_FILE_MIB=${LARGE_DELTA_FILE_MIB}"
echo "  LOWMEM_PROXY_LARGE_TIMEOUT_SECS=${LARGE_TIMEOUT_SECS}"
echo "  LOWMEM_PROXY_DELTA_MARKER_MESSAGES=${LARGE_MARKER_MESSAGES}"
echo "  LOW_MEM_WAL_CAP_MIB=${WAL_CAP_MIB}"
echo "  LOW_MEM_MEMTRACE=${LOWMEM_MEMTRACE_ENABLED}"
echo "  LOWMEM_PROXY_BUDGET_KB=${LOWMEM_BUDGET_KB}"
echo "  LOWMEM_PROXY_CGROUP_ENFORCE=${LOWMEM_CGROUP_ENFORCE}"
echo "  LOWMEM_PROXY_CGROUP_LIMIT_KB=${LOWMEM_CGROUP_LIMIT_KB}"
echo "  LOWMEM_PROXY_CGROUP_PARENT=${LOWMEM_CGROUP_PARENT:-auto}"

case "${MODE}" in
  smoke)
    run_smoke_proxy
    ;;
  asym50k)
    run_asymmetric_proxy
    ;;
  delta10k)
    run_large_delta_proxy
    ;;
  deltafiles)
    run_large_delta_proxy
    ;;
  deltafilesfast)
    run_large_delta_proxy
    ;;
  deltafilesquick)
    run_large_delta_proxy
    ;;
  proxy)
    run_smoke_proxy
    run_asymmetric_proxy
    ;;
  *)
    echo "usage: scripts/run_lowmem_proxy.sh [smoke|asym50k|delta10k|deltafiles|deltafilesfast|deltafilesquick|proxy]"
    exit 2
    ;;
esac
