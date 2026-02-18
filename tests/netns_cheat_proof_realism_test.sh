#!/usr/bin/env bash
#
# Cheat-proof realism harness (netns-first).
#
# Scope:
# - real network segmentation with 3 LANs and overlapping peers,
# - invite-link bootstrap over routed (non-LAN) paths,
# - daemon-only sync operation (p7d + p7ctl assertions),
# - local discovery exercised after inviter shutdown.
#
# IMPORTANT:
# - This is NETWORK-realism first.
# - Linux netns alone does NOT provide strong filesystem isolation between peers.
# - For strict anti-cheat filesystem/process isolation, move to containers next.
#
# Topology:
#   LAN1 (10.11.1.0/24): A, B, C
#   LAN2 (10.11.2.0/24): C, D, E
#   LAN3 (10.11.3.0/24): E, F, A
#   Router namespace R forwards between all LANs.
#
# Overlap peers:
#   A in LAN1+LAN3
#   C in LAN1+LAN2
#   E in LAN2+LAN3
#
# Workspace model:
#   Single shared workspace bootstrapped by A (via invites), so trust can converge
#   through realistic bootstrap sync and then local mDNS discovery.
#
# Usage:
#   sudo tests/netns_cheat_proof_realism_test.sh
#   sudo tests/netns_cheat_proof_realism_test.sh --keep-logs
#   sudo tests/netns_cheat_proof_realism_test.sh --cleanup

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BIN="${PROJECT_DIR}/target/debug/topo"



PREFIX="cp7"
TMPDIR="$(mktemp -d /tmp/cp7_realism.XXXXXX)"
TEST_FAILED=0
KEEP_LOGS=0
CLEANUP_ONLY=0

NS_R="${PREFIX}_r"
NS_A="${PREFIX}_a"
NS_B="${PREFIX}_b"
NS_C="${PREFIX}_c"
NS_D="${PREFIX}_d"
NS_E="${PREFIX}_e"
NS_F="${PREFIX}_f"

BR1="${PREFIX}_br1"
BR2="${PREFIX}_br2"
BR3="${PREFIX}_br3"

PIDS=()
PID_A=""
PID_B=""
PID_C=""
PID_D=""
PID_E=""
PID_F=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; TEST_FAILED=1; exit 1; }

usage() {
    cat <<EOF
Usage: $0 [--keep-logs|--cleanup]
  --keep-logs  preserve logs/TMPDIR even on success
  --cleanup    remove netns/bridge leftovers and exit
EOF
}

for arg in "$@"; do
    case "$arg" in
        --keep-logs) KEEP_LOGS=1 ;;
        --cleanup) CLEANUP_ONLY=1 ;;
        -h|--help) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
done

clean_net() {
    for ns in "$NS_R" "$NS_A" "$NS_B" "$NS_C" "$NS_D" "$NS_E" "$NS_F"; do
        ip netns del "$ns" 2>/dev/null || true
    done
    ip link del "$BR1" 2>/dev/null || true
    ip link del "$BR2" 2>/dev/null || true
    ip link del "$BR3" 2>/dev/null || true
}

kill_ns_processes() {
    for ns in "$NS_A" "$NS_B" "$NS_C" "$NS_D" "$NS_E" "$NS_F"; do
        if ip netns list | grep -q "^${ns}\\b"; then
            local pids
            pids="$(ip netns pids "$ns" 2>/dev/null || true)"
            if [[ -n "$pids" ]]; then
                # Kill namespace-contained daemons even if launcher wrapper PIDs were lost.
                kill $pids 2>/dev/null || true
                sleep 0.1
                kill -9 $pids 2>/dev/null || true
            fi
        fi
    done
}

cleanup() {
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    kill_ns_processes
    clean_net
    if [[ "$TEST_FAILED" == "1" || "$KEEP_LOGS" == "1" ]]; then
        warn "Logs preserved in $TMPDIR"
    else
        rm -rf "$TMPDIR"
    fi
}
trap cleanup EXIT

[[ $(id -u) -eq 0 ]] || exec sudo --preserve-env=PATH,HOME "$0" "$@"

if [[ "$CLEANUP_ONLY" == "1" ]]; then
    clean_net
    rm -rf "$TMPDIR"
    exit 0
fi

command -v ip >/dev/null || fail "ip command not found"
[[ -x "$BIN" ]] || fail "Missing $BIN (run: cargo build --bins)"
[[ -x "$BIN start"  ]] || fail "Missing $BIN start (run: cargo build --bins)"
[[ -x "$BIN" ]] || fail "Missing $BIN (run: cargo build --bins)"

wait_for_file() {
    local path="$1"
    local timeout_s="$2"
    local deadline=$((SECONDS + timeout_s))
    while [[ ! -S "$path" && $SECONDS -lt $deadline ]]; do
        sleep 0.1
    done
    [[ -S "$path" ]] || fail "Timed out waiting for socket: $path"
}

add_bridge() {
    local br="$1"
    ip link add "$br" type bridge
    ip link set "$br" up
}

add_ns_iface() {
    local ns="$1"
    local ifname="$2"
    local br="$3"
    local cidr="$4"
    local host_if="${PREFIX}_${ns##*_}_${ifname}h"
    local ns_if="${PREFIX}_${ns##*_}_${ifname}n"

    ip link add "$host_if" type veth peer name "$ns_if"
    ip link set "$ns_if" netns "$ns"
    ip link set "$host_if" master "$br"
    ip link set "$host_if" up

    ip netns exec "$ns" ip addr add "$cidr" dev "$ns_if"
    ip netns exec "$ns" ip link set "$ns_if" up
}

set_default_route() {
    local ns="$1"
    local gw="$2"
    ip netns exec "$ns" ip route replace default via "$gw"
}

run_p7ctl() {
    local db="$1"
    local sock="$2"
    shift 2
    "$BIN" --db "$db" --socket "$sock" "$@"
}

assert_eventually() {
    local db="$1"
    local sock="$2"
    local predicate="$3"
    local timeout_ms="$4"
    local out
    out="$(run_p7ctl "$db" "$sock" assert-eventually "$predicate" --timeout-ms "$timeout_ms" 2>&1)" || {
        echo "$out"
        fail "assert-eventually failed for '$predicate' on $db"
    }
}

send_message() {
    local db="$1"
    local sock="$2"
    local content="$3"
    local out
    out="$(run_p7ctl "$db" "$sock" send "$content" 2>&1)" || {
        echo "$out"
        fail "send failed ($content) on $db"
    }
}

start_daemon() {
    local ns="$1"
    local db="$2"
    local sock="$3"
    local log_file="$4"
    ip netns exec "$ns" "$BIN start" \
        --db "$db" \
        --socket "$sock" \
        --bind "0.0.0.0:4433" \
        >"$log_file" 2>&1 &
    local pid=$!
    PIDS+=("$pid")
    wait_for_file "$sock" 6
    echo "$pid"
}

log "Creating namespaces and bridges..."
clean_net

for ns in "$NS_R" "$NS_A" "$NS_B" "$NS_C" "$NS_D" "$NS_E" "$NS_F"; do
    ip netns add "$ns"
    ip netns exec "$ns" ip link set lo up
done

add_bridge "$BR1"
add_bridge "$BR2"
add_bridge "$BR3"

log "Wiring router R..."
add_ns_iface "$NS_R" "eth1" "$BR1" "10.11.1.1/24"
add_ns_iface "$NS_R" "eth2" "$BR2" "10.11.2.1/24"
add_ns_iface "$NS_R" "eth3" "$BR3" "10.11.3.1/24"
ip netns exec "$NS_R" sysctl -qw net.ipv4.ip_forward=1

log "Wiring peers (overlapping LAN membership)..."
add_ns_iface "$NS_A" "eth1" "$BR1" "10.11.1.10/24"
add_ns_iface "$NS_A" "eth2" "$BR3" "10.11.3.10/24"
add_ns_iface "$NS_B" "eth1" "$BR1" "10.11.1.11/24"
add_ns_iface "$NS_C" "eth1" "$BR1" "10.11.1.12/24"
add_ns_iface "$NS_C" "eth2" "$BR2" "10.11.2.12/24"
add_ns_iface "$NS_D" "eth1" "$BR2" "10.11.2.13/24"
add_ns_iface "$NS_E" "eth1" "$BR2" "10.11.2.14/24"
add_ns_iface "$NS_E" "eth2" "$BR3" "10.11.3.14/24"
add_ns_iface "$NS_F" "eth1" "$BR3" "10.11.3.15/24"

set_default_route "$NS_A" "10.11.1.1"
set_default_route "$NS_B" "10.11.1.1"
set_default_route "$NS_C" "10.11.1.1"
set_default_route "$NS_D" "10.11.2.1"
set_default_route "$NS_E" "10.11.2.1"
set_default_route "$NS_F" "10.11.3.1"

log "Connectivity smoke checks..."
ip netns exec "$NS_D" ping -c1 -W1 10.11.1.10 >/dev/null || fail "D cannot reach A bootstrap addr"
ip netns exec "$NS_F" ping -c1 -W1 10.11.1.10 >/dev/null || fail "F cannot reach A bootstrap addr"
ip netns exec "$NS_B" ping -c1 -W1 10.11.3.15 >/dev/null || fail "B cannot reach F via router"

DB_A="$TMPDIR/a.db"; SOCK_A="$TMPDIR/a.sock"
DB_B="$TMPDIR/b.db"; SOCK_B="$TMPDIR/b.sock"
DB_C="$TMPDIR/c.db"; SOCK_C="$TMPDIR/c.sock"
DB_D="$TMPDIR/d.db"; SOCK_D="$TMPDIR/d.sock"
DB_E="$TMPDIR/e.db"; SOCK_E="$TMPDIR/e.sock"
DB_F="$TMPDIR/f.db"; SOCK_F="$TMPDIR/f.sock"

log "Bootstrapping workspace on A and creating invite links..."
"$BIN" send "bootstrap-from-a" --db "$DB_A" >/dev/null || fail "A bootstrap send failed"

INV_B="$("$BIN" create-invite --db "$DB_A" --bootstrap "10.11.1.10:4433" | tr -d '\n')"
INV_C="$("$BIN" create-invite --db "$DB_A" --bootstrap "10.11.1.10:4433" | tr -d '\n')"
INV_D="$("$BIN" create-invite --db "$DB_A" --bootstrap "10.11.1.10:4433" | tr -d '\n')"
INV_E="$("$BIN" create-invite --db "$DB_A" --bootstrap "10.11.1.10:4433" | tr -d '\n')"
INV_F="$("$BIN" create-invite --db "$DB_A" --bootstrap "10.11.1.10:4433" | tr -d '\n')"

[[ "$INV_B" == quiet://invite/* ]] || fail "invalid invite link format for B"
[[ "$INV_F" == quiet://invite/* ]] || fail "invalid invite link format for F"

log "Starting inviter daemon A..."
PID_A="$(start_daemon "$NS_A" "$DB_A" "$SOCK_A" "$TMPDIR/a.log")"

log "Accepting invites from segmented peers (internet bootstrap mode)..."
ip netns exec "$NS_B" "$BIN" accept-invite --db "$DB_B" --invite "$INV_B" --username "b" --devicename "dev-b" >/dev/null
ip netns exec "$NS_C" "$BIN" accept-invite --db "$DB_C" --invite "$INV_C" --username "c" --devicename "dev-c" >/dev/null
ip netns exec "$NS_D" "$BIN" accept-invite --db "$DB_D" --invite "$INV_D" --username "d" --devicename "dev-d" >/dev/null
ip netns exec "$NS_E" "$BIN" accept-invite --db "$DB_E" --invite "$INV_E" --username "e" --devicename "dev-e" >/dev/null
ip netns exec "$NS_F" "$BIN" accept-invite --db "$DB_F" --invite "$INV_F" --username "f" --devicename "dev-f" >/dev/null

log "Starting peer daemons without manual --connect..."
PID_B="$(start_daemon "$NS_B" "$DB_B" "$SOCK_B" "$TMPDIR/b.log")"
PID_C="$(start_daemon "$NS_C" "$DB_C" "$SOCK_C" "$TMPDIR/c.log")"
PID_D="$(start_daemon "$NS_D" "$DB_D" "$SOCK_D" "$TMPDIR/d.log")"
PID_E="$(start_daemon "$NS_E" "$DB_E" "$SOCK_E" "$TMPDIR/e.log")"
PID_F="$(start_daemon "$NS_F" "$DB_F" "$SOCK_F" "$TMPDIR/f.log")"

log "Seeding one message per non-inviter peer through daemon RPC..."
send_message "$DB_B" "$SOCK_B" "msg-from-b"
send_message "$DB_C" "$SOCK_C" "msg-from-c"
send_message "$DB_D" "$SOCK_D" "msg-from-d"
send_message "$DB_E" "$SOCK_E" "msg-from-e"
send_message "$DB_F" "$SOCK_F" "msg-from-f"

log "Waiting for full workspace convergence (bootstrap + 5 peer messages = >=6)..."
for tuple in \
  "$DB_A:$SOCK_A" "$DB_B:$SOCK_B" "$DB_C:$SOCK_C" \
  "$DB_D:$SOCK_D" "$DB_E:$SOCK_E" "$DB_F:$SOCK_F"
do
    db="${tuple%%:*}"
    sock="${tuple##*:}"
    assert_eventually "$db" "$sock" "message_count >= 6" 45000
done

log "Discovery-resilience check: stop inviter A, verify mesh continues..."
kill "$PID_A" 2>/dev/null || true
wait "$PID_A" 2>/dev/null || true
PID_A=""

send_message "$DB_B" "$SOCK_B" "post-a-down-from-b"
assert_eventually "$DB_F" "$SOCK_F" "message_count >= 7" 45000

echo ""
echo "==============================================="
echo " netns cheat-proof realism harness: PASS"
echo "==============================================="
echo "Logs: $TMPDIR"
echo ""
echo "Notes:"
echo "  - Placeholder autodial path is exercised (invite bootstrap addresses)."
echo "  - Local discovery is exercised by post-inviter-down propagation."
echo "  - This harness does NOT provide strict filesystem anti-cheat isolation."
echo "    Move to containerized runtime for that guarantee."
