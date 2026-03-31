#!/usr/bin/env bash
set -euo pipefail

# Quick lowmem RSS measurement.
# Usage: scripts/measure_lowmem_rss.sh <baseline_events> <delta_events>

BASELINE="${1:-1000}"
DELTA="${2:-1000}"
TOPO="${TOPO_BIN:-./target/release/topo}"

RUN_DIR="$(mktemp -d "/tmp/lowmem-measure-XXXXXX")"
ALICE_DB="${RUN_DIR}/alice.db"
BOB_DB="${RUN_DIR}/bob.db"

cleanup() {
  "${TOPO}" --db "${ALICE_DB}" stop >/dev/null 2>&1 || true
  "${TOPO}" --db "${BOB_DB}" stop >/dev/null 2>&1 || true
  sleep 1
  ps -eo pid=,args= 2>/dev/null | awk -v d="${RUN_DIR}" 'index($0, d) {print $1}' | while read pid; do
    kill "$pid" 2>/dev/null || true
  done
  rm -rf "${RUN_DIR}"
}
trap cleanup EXIT

# 1. Start alice daemon, then create workspace
TOPO_DISABLE_DISCOVERY=1 RUST_LOG=warn "${TOPO}" --db "${ALICE_DB}" start --bind 127.0.0.1:0 \
  >>"${RUN_DIR}/alice.log" 2>&1 &
sleep 3

"${TOPO}" --db "${ALICE_DB}" create-workspace \
  --workspace-name "measure" --username "alice" --device-name "desktop" >/dev/null 2>&1

ALICE_ADDR="$("${TOPO}" --db "${ALICE_DB}" status 2>/dev/null | awk '/Listen:/ {print $2; exit}' | sed 's/0\.0\.0\.0:/127.0.0.1:/')"
if [ -z "${ALICE_ADDR}" ]; then
  echo "ERROR: alice daemon not responding" >&2; exit 1
fi

# 2. Generate baseline messages on alice (spread over 365 days)
if [ "${BASELINE}" -gt 0 ]; then
  "${TOPO}" --db "${ALICE_DB}" generate --count "${BASELINE}" --history-span 365d >/dev/null 2>&1
  "${TOPO}" --db "${ALICE_DB}" assert-eventually \
    "message_count >= ${BASELINE}" --timeout-ms 300000 >/dev/null 2>&1
fi

# 3. Create invite + start bob in normal mode + accept
INVITE="$("${TOPO}" --db "${ALICE_DB}" invite --public-addr "${ALICE_ADDR}" 2>/dev/null | grep -oE '(topo|quiet)://invite/[^ ]+')"
if [ -z "${INVITE}" ]; then
  echo "ERROR: no invite link" >&2; exit 1
fi

TOPO_DISABLE_DISCOVERY=1 RUST_LOG=warn "${TOPO}" --db "${BOB_DB}" start --bind 127.0.0.1:0 \
  >>"${RUN_DIR}/bob.log" 2>&1 &
sleep 3

"${TOPO}" --db "${BOB_DB}" accept "${INVITE}" \
  --username "bob" --devicename "bob-dev" >/dev/null 2>&1

# 4. Wait for baseline sync
if [ "${BASELINE}" -gt 0 ]; then
  "${TOPO}" --db "${BOB_DB}" assert-eventually \
    "message_count >= ${BASELINE}" --timeout-ms 600000 >/dev/null 2>&1 || {
    echo "WARN: baseline sync incomplete" >&2
  }
fi

# 5. Stop bob
"${TOPO}" --db "${BOB_DB}" stop >/dev/null 2>&1 || true
sleep 2
ps -eo pid=,args= 2>/dev/null | awk -v d="${BOB_DB}" 'index($0, d) && /start/ {print $1}' | while read pid; do
  kill "$pid" 2>/dev/null || true
done
sleep 1

# 6. Generate delta messages on alice (within last 6 days for lowmem window)
if [ "${DELTA}" -gt 0 ]; then
  "${TOPO}" --db "${ALICE_DB}" generate --count "${DELTA}" --history-span 6d >/dev/null 2>&1
  TOTAL=$((BASELINE + DELTA))
  "${TOPO}" --db "${ALICE_DB}" assert-eventually \
    "message_count >= ${TOTAL}" --timeout-ms 300000 >/dev/null 2>&1
fi

# 7. Restart bob in lowmem mode
LOW_MEM_IOS=1 LOW_MEM_WAL_CAP_MIB=12 LOW_MEM_MEMTRACE=1 \
  TOPO_DISABLE_DISCOVERY=1 RUST_LOG=warn \
  "${TOPO}" --db "${BOB_DB}" start --bind 127.0.0.1:0 \
  >>"${RUN_DIR}/bob.log" 2>&1 &
sleep 3

DAEMON_PID="$(ps -eo pid=,args= 2>/dev/null | awk -v d="${BOB_DB}" 'index($0, d) && /start/ {print $1; exit}')"
if [ -z "${DAEMON_PID}" ]; then
  echo "ERROR: bob daemon didn't start" >&2; exit 1
fi

# 8. Wait for delta sync
TOTAL=$((BASELINE + DELTA))
SYNC_TIMEOUT=300
START_TS="$(date +%s)"
LAST_COUNT=0
STALL_COUNT=0
while true; do
  BOB_MSG="$(python3 -c "
import sqlite3
try:
    c = sqlite3.connect('${BOB_DB}', timeout=5)
    c.execute('PRAGMA busy_timeout = 5000')
    r = c.execute('SELECT COUNT(*) FROM messages').fetchone()
    print(r[0] if r else 0)
except: print(0)
" 2>/dev/null)"

  NOW="$(date +%s)"
  ELAPSED=$((NOW - START_TS))

  if [ "${BOB_MSG}" -ge "${TOTAL}" ]; then
    break
  fi

  if [ "${BOB_MSG}" = "${LAST_COUNT}" ]; then
    STALL_COUNT=$((STALL_COUNT + 1))
  else
    STALL_COUNT=0
    LAST_COUNT="${BOB_MSG}"
  fi

  if [ "${STALL_COUNT}" -ge 60 ] && [ "${BOB_MSG}" -gt 0 ]; then
    echo "WARN: sync stalled at ${BOB_MSG}/${TOTAL} after ${ELAPSED}s" >&2
    break
  fi

  if [ "${ELAPSED}" -ge "${SYNC_TIMEOUT}" ]; then
    echo "WARN: sync timeout at ${BOB_MSG}/${TOTAL} after ${ELAPSED}s" >&2
    break
  fi
  sleep 1
done

# 9. Measure VmHWM
VMHWM_KB="$(awk '/^VmHWM:/ {print $2; exit}' "/proc/${DAEMON_PID}/status" 2>/dev/null || echo 0)"
VMHWM_MIB="$(python3 -c "print(f'{${VMHWM_KB}/1024:.2f}')")"

echo "BASELINE=${BASELINE} DELTA=${DELTA} BOB_MSGS=${BOB_MSG} BOB_PEAK_RSS_MIB=${VMHWM_MIB}"
