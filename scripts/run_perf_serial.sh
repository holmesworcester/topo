#!/usr/bin/env bash
set -euo pipefail

# Run perf integration tests in a strict serial order to avoid cross-test
# interference from concurrent endpoint binds and background sync sessions.
#
# Usage:
#   scripts/run_perf_serial.sh            # core suite
#   scripts/run_perf_serial.sh core
#   scripts/run_perf_serial.sh full
#   scripts/run_perf_serial.sh lowmem
#
# By default, this script also updates docs/PERF.md auto-results section.
# To disable docs writes for a local run:
#   WRITE_PERF_MD=0 scripts/run_perf_serial.sh core

MODE="${1:-core}"
WRITE_PERF_MD="${WRITE_PERF_MD:-1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PERF_MD="${REPO_ROOT}/docs/PERF.md"
LOWMEM_PROXY_SCRIPT="${REPO_ROOT}/scripts/run_lowmem_proxy.sh"
TMP_DIR="$(mktemp -d)"
AUTO_RESULTS_FILE="${TMP_DIR}/auto_results.md"

PERF_LOWMEM_BASELINE_SMALL="${PERF_LOWMEM_BASELINE_SMALL:-500000}"
PERF_LOWMEM_BASELINE_LARGE="${PERF_LOWMEM_BASELINE_LARGE:-1000000}"
PERF_LOWMEM_DELTA_TARGET="${PERF_LOWMEM_DELTA_TARGET:-10000}"
PERF_LOWMEM_DELTA_BRACKET="${PERF_LOWMEM_DELTA_BRACKET:-50000}"
PERF_LOWMEM_FILES_SLICES="${PERF_LOWMEM_FILES_SLICES:-400}"
PERF_LOWMEM_FILE_BASELINE="${PERF_LOWMEM_FILE_BASELINE:-500000}"
PERF_LOWMEM_FILE_COUNT="${PERF_LOWMEM_FILE_COUNT:-100}"
PERF_LOWMEM_FILE_SIZE_MIB="${PERF_LOWMEM_FILE_SIZE_MIB:-1}"
PERF_LOWMEM_BUDGET_KB="${PERF_LOWMEM_BUDGET_KB:-24576}"
PERF_LOWMEM_CGROUP_ENFORCE="${PERF_LOWMEM_CGROUP_ENFORCE:-1}"
PERF_LOWMEM_CGROUP_LIMIT_KB="${PERF_LOWMEM_CGROUP_LIMIT_KB:-22528}"
PERF_LOWMEM_POC_ENABLE="${PERF_LOWMEM_POC_ENABLE:-1}"
PERF_LOWMEM_POC_MSG_BASELINE="${PERF_LOWMEM_POC_MSG_BASELINE:-1000000}"
PERF_LOWMEM_POC_MSG_DELTA="${PERF_LOWMEM_POC_MSG_DELTA:-10000}"
PERF_LOWMEM_POC_FILE_BASELINE="${PERF_LOWMEM_POC_FILE_BASELINE:-0}"
PERF_LOWMEM_POC_FILE_COUNT="${PERF_LOWMEM_POC_FILE_COUNT:-10000}"
PERF_LOWMEM_POC_FILE_SIZE_MIB="${PERF_LOWMEM_POC_FILE_SIZE_MIB:-1}"
PERF_LOWMEM_POC_FILE_TIMEOUT_SECS="${PERF_LOWMEM_POC_FILE_TIMEOUT_SECS:-3600}"
PERF_LOWMEM_POC_REALISM_FILE_BASELINE="${PERF_LOWMEM_POC_REALISM_FILE_BASELINE:-500000}"
PERF_LOWMEM_POC_REALISM_FILE_COUNT="${PERF_LOWMEM_POC_REALISM_FILE_COUNT:-100}"
PERF_LOWMEM_POC_REALISM_FILE_SIZE_MIB="${PERF_LOWMEM_POC_REALISM_FILE_SIZE_MIB:-1}"
PERF_LOWMEM_FULL_ENABLE="${PERF_LOWMEM_FULL_ENABLE:-1}"
PERF_LOWMEM_RUN_SMALL_TARGET="${PERF_LOWMEM_RUN_SMALL_TARGET:-1}"
PERF_LOWMEM_RUN_SMALL_BRACKET="${PERF_LOWMEM_RUN_SMALL_BRACKET:-1}"
PERF_LOWMEM_RUN_LARGE_TARGET="${PERF_LOWMEM_RUN_LARGE_TARGET:-1}"
PERF_LOWMEM_RUN_FILE_PROXY="${PERF_LOWMEM_RUN_FILE_PROXY:-1}"

cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

SUMMARY_PATTERN='^(===|  Setup:|  Blocking:|  Cascade:|  Cascade rate:|  Total:|  Wall time:|  Messages:|  Msgs/s:|  Peak RSS:|  Catchup wall|  Events/s|  MB/s:|  Total attributed:|  Throughput:|  Tail converge|  All converge|  Hop latency|Generated|RUN_DIR=|SCENARIO=|DELTA_KIND=|BASE_EVENTS=|DELTA_EVENTS=|DELTA_FILES=|DELTA_FILE_SIZE_MIB=|DELTA_FILE_SLICES_EXPECTED=|PRE_DELTA_MESSAGES=|POST_DELTA_MESSAGES=|DELTA_MESSAGES_OBSERVED=|PRE_DELTA_FILE_SLICES=|POST_DELTA_FILE_SLICES=|DELTA_FILE_SLICES_OBSERVED=|DELTA_MARKER_PREFIX=|DELTA_MARKERS_EXPECTED=|DELTA_MARKERS_SYNCED=|ALICE_PEAK_VMHWM_MIB=|BOB_PEAK_VMHWM_MIB=|MAX_BOB_TOTAL_KB=|LOWMEM_BUDGET_KB=|PASS_UNDER_24MB=|CGROUP_ENFORCED=|CGROUP_LIMIT_KB=|CGROUP_OOM=|CGROUP_OOM_KILL=|MAX_BOB_ANON_KB=|MAX_BOB_ANON_UNLABELED_KB=|MAX_BOB_DB_SHM_KB=|MAX_BOB_DB_WAL_KB=|MAX_SQLITE_MEM_CUR=|MAX_SQLITE_MEM_HIGH=|MAX_MALL_ARENA=|MAX_MALL_USED=|MAX_MALL_FREE=|MAX_MALL_MMAP=|MAX_INIT_WANTED=|MAX_INIT_NEED_QUEUE=|MAX_DATA_EVENTS_INGESTED=|MAX_DATA_BLOB=|MEMTRACE_PRESENT=)'

append_auto_result() {
  local label="$1"
  local cmd_rendered="$2"
  local log_path="$3"

  {
    echo "### ${label}"
    echo
    echo '```bash'
    echo "${cmd_rendered}"
    echo '```'
    echo
    echo '```text'
    if rg -q "${SUMMARY_PATTERN}" "${log_path}"; then
      rg "${SUMMARY_PATTERN}" "${log_path}"
    else
      cat "${log_path}"
    fi
    echo '```'
    echo
  } >> "${AUTO_RESULTS_FILE}"
}

run() {
  local label="$1"
  shift
  local log_path="${TMP_DIR}/$(echo "${label}" | tr ' ' '_' | tr -cd '[:alnum:]_.-').log"
  local cmd_rendered
  cmd_rendered="$(printf "%q " "$@")"

  echo
  echo ">>> $*"
  "$@" 2>&1 | tee "${log_path}"

  if [[ "${WRITE_PERF_MD}" == "1" ]]; then
    append_auto_result "${label}" "${cmd_rendered}" "${log_path}"
  fi
}

run_lowmem_matrix() {
  if [[ "${PERF_LOWMEM_RUN_SMALL_TARGET}" == "1" ]]; then
    run "Lowmem Delta (500k+10k messages)" \
      env \
      LOWMEM_PROXY_BASE_EVENTS="${PERF_LOWMEM_BASELINE_SMALL}" \
      LOWMEM_PROXY_DELTA_EVENTS="${PERF_LOWMEM_DELTA_TARGET}" \
      "${LOWMEM_PROXY_SCRIPT}" delta10k
  fi

  if [[ "${PERF_LOWMEM_RUN_SMALL_BRACKET}" == "1" ]]; then
    run "Lowmem Delta (500k+50k messages)" \
      env \
      LOWMEM_PROXY_BASE_EVENTS="${PERF_LOWMEM_BASELINE_SMALL}" \
      LOWMEM_PROXY_DELTA_EVENTS="${PERF_LOWMEM_DELTA_BRACKET}" \
      "${LOWMEM_PROXY_SCRIPT}" delta10k
  fi

  if [[ "${PERF_LOWMEM_RUN_LARGE_TARGET}" == "1" ]]; then
    run "Lowmem Delta (1M+10k messages)" \
      env \
      LOWMEM_PROXY_BASE_EVENTS="${PERF_LOWMEM_BASELINE_LARGE}" \
      LOWMEM_PROXY_DELTA_EVENTS="${PERF_LOWMEM_DELTA_TARGET}" \
      "${LOWMEM_PROXY_SCRIPT}" delta10k
  fi

  if [[ "${PERF_LOWMEM_RUN_FILE_PROXY}" == "1" ]]; then
    run "Lowmem Delta Files (500k+100x1MiB)" \
      env \
      LOWMEM_PROXY_BASE_EVENTS="${PERF_LOWMEM_FILE_BASELINE}" \
      LOWMEM_PROXY_DELTA_FILES="${PERF_LOWMEM_FILE_COUNT}" \
      LOWMEM_PROXY_DELTA_FILE_MIB="${PERF_LOWMEM_FILE_SIZE_MIB}" \
      LOWMEM_PROXY_BUDGET_KB="${PERF_LOWMEM_BUDGET_KB}" \
      "${LOWMEM_PROXY_SCRIPT}" deltafiles
  fi
}

run_lowmem_poc() {
  if [[ "${PERF_LOWMEM_POC_ENABLE}" != "1" ]]; then
    return
  fi

  run "Lowmem POC Messages (1M+10k, 24MB gate)" \
    env \
    LOWMEM_PROXY_BASE_EVENTS="${PERF_LOWMEM_POC_MSG_BASELINE}" \
    LOWMEM_PROXY_DELTA_EVENTS="${PERF_LOWMEM_POC_MSG_DELTA}" \
    LOWMEM_PROXY_BUDGET_KB="${PERF_LOWMEM_BUDGET_KB}" \
    LOWMEM_PROXY_CGROUP_ENFORCE="${PERF_LOWMEM_CGROUP_ENFORCE}" \
    LOWMEM_PROXY_CGROUP_LIMIT_KB="${PERF_LOWMEM_CGROUP_LIMIT_KB}" \
    "${LOWMEM_PROXY_SCRIPT}" delta10k

  run "Lowmem POC Files Realism (500k+100x1MiB, 24MB gate)" \
    env \
    LOWMEM_PROXY_BASE_EVENTS="${PERF_LOWMEM_POC_REALISM_FILE_BASELINE}" \
    LOWMEM_PROXY_DELTA_FILES="${PERF_LOWMEM_POC_REALISM_FILE_COUNT}" \
    LOWMEM_PROXY_DELTA_FILE_MIB="${PERF_LOWMEM_POC_REALISM_FILE_SIZE_MIB}" \
    LOWMEM_PROXY_BUDGET_KB="${PERF_LOWMEM_BUDGET_KB}" \
    LOWMEM_PROXY_CGROUP_ENFORCE="${PERF_LOWMEM_CGROUP_ENFORCE}" \
    LOWMEM_PROXY_CGROUP_LIMIT_KB="${PERF_LOWMEM_CGROUP_LIMIT_KB}" \
    "${LOWMEM_PROXY_SCRIPT}" deltafiles

  run "Lowmem POC Files Extreme (0+10k x1MiB, 24MB gate)" \
    env \
    LOWMEM_PROXY_QUICK_DELTA_FILES="${PERF_LOWMEM_POC_FILE_COUNT}" \
    LOWMEM_PROXY_QUICK_DELTA_FILE_MIB="${PERF_LOWMEM_POC_FILE_SIZE_MIB}" \
    LOWMEM_PROXY_QUICK_TIMEOUT_SECS="${PERF_LOWMEM_POC_FILE_TIMEOUT_SECS}" \
    LOWMEM_PROXY_BUDGET_KB="${PERF_LOWMEM_BUDGET_KB}" \
    LOWMEM_PROXY_CGROUP_ENFORCE="${PERF_LOWMEM_CGROUP_ENFORCE}" \
    LOWMEM_PROXY_CGROUP_LIMIT_KB="${PERF_LOWMEM_CGROUP_LIMIT_KB}" \
    "${LOWMEM_PROXY_SCRIPT}" deltafilesquick
}

ensure_perf_md_markers() {
  if rg -q "^<!-- PERF_AUTO_RESULTS_START -->$" "${PERF_MD}"; then
    return
  fi

  cat >> "${PERF_MD}" <<'EOF'

### Auto-Generated Latest Serial Run

This section is updated by `scripts/run_perf_serial.sh` when `WRITE_PERF_MD=1`.

<!-- PERF_AUTO_RESULTS_START -->
_Not generated yet. Run `scripts/run_perf_serial.sh core`._
<!-- PERF_AUTO_RESULTS_END -->
EOF
}

replace_perf_md_auto_section() {
  local replacement_file="$1"
  local tmp_out="${TMP_DIR}/PERF.md.out"

  awk \
    -v start='<!-- PERF_AUTO_RESULTS_START -->' \
    -v end='<!-- PERF_AUTO_RESULTS_END -->' \
    -v repl_file="${replacement_file}" '
      BEGIN {
        while ((getline line < repl_file) > 0) {
          repl = repl line "\n";
        }
        close(repl_file);
      }
      {
        if ($0 == start) {
          print;
          printf "%s", repl;
          in_block = 1;
          next;
        }
        if (in_block) {
          if ($0 == end) {
            in_block = 0;
            print;
          }
          next;
        }
        print;
      }
    ' "${PERF_MD}" > "${tmp_out}"

  mv "${tmp_out}" "${PERF_MD}"
}

case "$MODE" in
  core)
    run "Core Sync (perf_test)" cargo +stable test --release --test perf_test -- --nocapture --test-threads=1
    run "File Throughput (file_throughput)" cargo +stable test --release --test file_throughput -- --nocapture --test-threads=1
    run "Sync Graph (ten_hop_chain_10k)" cargo +stable test --release --test sync_graph_test ten_hop_chain_10k -- --nocapture --test-threads=1
    run "Topo Cascade (topo_cascade_10k)" cargo +stable test --release --test topo_cascade_test topo_cascade_10k -- --nocapture --test-threads=1
    ;;
  lowmem)
    run_lowmem_matrix
    run_lowmem_poc
    ;;
  full)
    run "Core Sync (perf_test, include ignored)" cargo +stable test --release --test perf_test -- --nocapture --include-ignored --test-threads=1
    run "File Throughput (file_throughput, include ignored)" cargo +stable test --release --test file_throughput -- --nocapture --include-ignored --test-threads=1
    run "Sync Graph (all, include ignored)" cargo +stable test --release --test sync_graph_test -- --nocapture --include-ignored --test-threads=1
    run "Topo Cascade (topo_cascade_10k)" cargo +stable test --release --test topo_cascade_test topo_cascade_10k -- --nocapture --test-threads=1
    run "Low-Memory (low_mem_test, include ignored)" cargo +stable test --release --test low_mem_test -- --nocapture --include-ignored --test-threads=1
    if [[ "${PERF_LOWMEM_FULL_ENABLE}" == "1" ]]; then
      run_lowmem_matrix
      run_lowmem_poc
    fi
    ;;
  *)
    echo "unknown mode: $MODE"
    echo "usage: scripts/run_perf_serial.sh [core|lowmem|full]"
    exit 2
    ;;
esac

if [[ "${WRITE_PERF_MD}" == "1" ]]; then
  ensure_perf_md_markers
  {
    echo "_Generated by \`scripts/run_perf_serial.sh ${MODE}\` on $(date -u +"%Y-%m-%d %H:%M:%S UTC")._"
    echo
    cat "${AUTO_RESULTS_FILE}"
  } > "${TMP_DIR}/replacement.md"
  replace_perf_md_auto_section "${TMP_DIR}/replacement.md"
  echo
  echo "Updated ${PERF_MD} auto-results section."
fi
