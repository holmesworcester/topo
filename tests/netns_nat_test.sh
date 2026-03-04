#!/usr/bin/env bash
#
# NAT hole-punch integration test using Linux network namespaces.
#
# Topology:
#   ns_a (10.1.0.2) -- ns_nat_a (10.1.0.1 / 10.100.0.10) --+
#                                                             |-- bridge (pub)
#   ns_b (10.2.0.2) -- ns_nat_b (10.2.0.1 / 10.100.0.20) --+        |
#                                                         ns_i (10.100.0.1)
#
# Modes:
#   cone      (default): endpoint-independent mapping, expected PASS
#   symmetric           : endpoint-dependent mapping, expected FAIL
#
# Usage:
#   sudo tests/netns_nat_test.sh
#   sudo tests/netns_nat_test.sh --symmetric
#   sudo tests/netns_nat_test.sh --cleanup

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BIN="${PROJECT_DIR}/target/release/topo"
PREFIX="hp"
TMPDIR="$(mktemp -d /tmp/hp_nat_test.XXXXXX)"

MODE="cone"
CLEANUP_ONLY=false

case "${1:-}" in
    ""|"--cone") MODE="cone" ;;
    "--symmetric") MODE="symmetric" ;;
    "--cleanup") CLEANUP_ONLY=true ;;
    *)
        echo "Usage: $0 [--cone|--symmetric|--cleanup]"
        exit 2
        ;;
esac

# Colours for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; TEST_FAILED=1; exit 1; }

clean_namespaces() {
    for ns in ${PREFIX}_i ${PREFIX}_na ${PREFIX}_nb ${PREFIX}_a ${PREFIX}_b; do
        ip netns del "$ns" 2>/dev/null || true
    done
    ip link del "${PREFIX}_pub" 2>/dev/null || true
}

# Must run as root for netns/nft/tc
[[ $(id -u) -eq 0 ]] || {
    exec sudo --preserve-env=PATH,HOME "$0" "${1:-}"
}

if $CLEANUP_ONLY; then
    clean_namespaces
    rm -rf "$TMPDIR"
    exit 0
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
PIDS=()
cleanup() {
    log "Cleaning up processes..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    log "Cleaning up namespaces..."
    clean_namespaces
    if [[ "${TEST_FAILED:-0}" == "1" ]]; then
        warn "Logs preserved in $TMPDIR"
    else
        log "Logs in $TMPDIR (removing)"
        rm -rf "$TMPDIR"
    fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------
[[ -x "$BIN" ]] || fail "Release binary not found at $BIN — run cargo build --release"
command -v ip >/dev/null || fail "ip command not found"
command -v nft >/dev/null || fail "nft command not found"

HAS_CONNTRACK=false
if command -v conntrack >/dev/null; then
    HAS_CONNTRACK=true
fi

log "Binary: $BIN"
log "Temp dir: $TMPDIR"
log "Mode: $MODE"

# ---------------------------------------------------------------------------
# Create namespaces
# ---------------------------------------------------------------------------
clean_namespaces
for ns in ${PREFIX}_i ${PREFIX}_na ${PREFIX}_nb ${PREFIX}_a ${PREFIX}_b; do
    ip netns add "$ns"
    ip netns exec "$ns" ip link set lo up
done

# ---------------------------------------------------------------------------
# Public bridge
# ---------------------------------------------------------------------------
ip link add "${PREFIX}_pub" type bridge
ip link set "${PREFIX}_pub" up

add_pub_veth() {
    local ns=$1 veth=$2
    ip link add "${veth}" type veth peer name "${veth}_br"
    ip link set "${veth}" netns "$ns"
    ip link set "${veth}_br" master "${PREFIX}_pub"
    ip link set "${veth}_br" up
}

# Introducer
add_pub_veth "${PREFIX}_i" "${PREFIX}_vi"
ip netns exec "${PREFIX}_i" ip addr add 10.100.0.1/24 dev "${PREFIX}_vi"
ip netns exec "${PREFIX}_i" ip link set "${PREFIX}_vi" up

# NAT A - WAN side
add_pub_veth "${PREFIX}_na" "${PREFIX}_vna"
ip netns exec "${PREFIX}_na" ip addr add 10.100.0.10/24 dev "${PREFIX}_vna"
ip netns exec "${PREFIX}_na" ip link set "${PREFIX}_vna" up

# NAT B - WAN side
add_pub_veth "${PREFIX}_nb" "${PREFIX}_vnb"
ip netns exec "${PREFIX}_nb" ip addr add 10.100.0.20/24 dev "${PREFIX}_vnb"
ip netns exec "${PREFIX}_nb" ip link set "${PREFIX}_vnb" up

# ---------------------------------------------------------------------------
# Private LANs
# ---------------------------------------------------------------------------
ip link add "${PREFIX}_va" type veth peer name "${PREFIX}_va_nat"
ip link set "${PREFIX}_va" netns "${PREFIX}_a"
ip link set "${PREFIX}_va_nat" netns "${PREFIX}_na"
ip netns exec "${PREFIX}_a"  ip addr add 10.1.0.2/24 dev "${PREFIX}_va"
ip netns exec "${PREFIX}_a"  ip link set "${PREFIX}_va" up
ip netns exec "${PREFIX}_na" ip addr add 10.1.0.1/24 dev "${PREFIX}_va_nat"
ip netns exec "${PREFIX}_na" ip link set "${PREFIX}_va_nat" up

ip link add "${PREFIX}_vb" type veth peer name "${PREFIX}_vb_nat"
ip link set "${PREFIX}_vb" netns "${PREFIX}_b"
ip link set "${PREFIX}_vb_nat" netns "${PREFIX}_nb"
ip netns exec "${PREFIX}_b"  ip addr add 10.2.0.2/24 dev "${PREFIX}_vb"
ip netns exec "${PREFIX}_b"  ip link set "${PREFIX}_vb" up
ip netns exec "${PREFIX}_nb" ip addr add 10.2.0.1/24 dev "${PREFIX}_vb_nat"
ip netns exec "${PREFIX}_nb" ip link set "${PREFIX}_vb_nat" up

# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------
ip netns exec "${PREFIX}_a" ip route add default via 10.1.0.1
ip netns exec "${PREFIX}_b" ip route add default via 10.2.0.1
ip netns exec "${PREFIX}_na" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "${PREFIX}_nb" sysctl -qw net.ipv4.ip_forward=1

# ---------------------------------------------------------------------------
# NAT rules
# ---------------------------------------------------------------------------
for info in "na:${PREFIX}_vna" "nb:${PREFIX}_vnb"; do
    ns="${PREFIX}_${info%%:*}"
    wan="${info##*:}"

    if [[ "$MODE" == "cone" ]]; then
        # EIM + address-dependent filtering. notrack avoids phantom conntrack
        # entries that can force port remaps and break hole-punch assumptions.
        ip netns exec "$ns" nft -f - <<EOF_CONE
 table ip raw {
     chain prerouting {
         type filter hook prerouting priority -300; policy accept;
         iifname "$wan" ct state new counter notrack
     }
 }
 table ip nat {
     chain postrouting {
         type nat hook postrouting priority 100; policy accept;
         oifname "$wan" masquerade
     }
 }
 table ip filter {
     chain input {
         type filter hook input priority 0; policy accept;
         iifname "$wan" ct state new,untracked counter drop
     }
     chain forward {
         type filter hook forward priority 0; policy drop;
         ct state established,related accept
         iifname != "$wan" accept
     }
 }
EOF_CONE
    else
        # Symmetric-ish behavior: force destination-dependent random source port
        # allocation on outbound NAT.
        ip netns exec "$ns" nft -f - <<EOF_SYM
 table ip nat {
     chain postrouting {
         type nat hook postrouting priority 100; policy accept;
         oifname "$wan" masquerade random,fully-random
     }
 }
 table ip filter {
     chain input {
         type filter hook input priority 0; policy accept;
         iifname "$wan" ct state new counter drop
     }
     chain forward {
         type filter hook forward priority 0; policy drop;
         ct state established,related accept
         iifname != "$wan" accept
     }
 }
EOF_SYM
    fi
done

# ---------------------------------------------------------------------------
# Connectivity checks
# ---------------------------------------------------------------------------
log "Verifying connectivity..."
ip netns exec "${PREFIX}_a" ping -c1 -W1 10.100.0.1 >/dev/null || fail "A cannot reach I through NAT"
ip netns exec "${PREFIX}_b" ping -c1 -W1 10.100.0.1 >/dev/null || fail "B cannot reach I through NAT"
if ip netns exec "${PREFIX}_i" ping -c1 -W1 10.1.0.2 >/dev/null 2>&1; then
    fail "I can reach A's private IP — NAT not working"
fi
log "Connectivity OK, NAT blocking verified"

# ---------------------------------------------------------------------------
# Bootstrap identities and invite-based trust
# ---------------------------------------------------------------------------
DB_I="$TMPDIR/i.db"
DB_A="$TMPDIR/a.db"
DB_B="$TMPDIR/b.db"

# Introducer workspace bootstrap
"$BIN" send "hello from I" --db "$DB_I" >/dev/null

# Realistic out-of-band data: invite links only.
INV_A=$("$BIN" create-invite --db "$DB_I" --public-addr "10.100.0.1:4433" | grep '^topo://')
INV_B=$("$BIN" create-invite --db "$DB_I" --public-addr "10.100.0.1:4433" | grep '^topo://')
[[ "$INV_A" == topo://invite/* ]] || fail "invalid invite for A"
[[ "$INV_B" == topo://invite/* ]] || fail "invalid invite for B"

# ---------------------------------------------------------------------------
# Start daemons
# ---------------------------------------------------------------------------
log "Starting introducer I..."
ip netns exec "${PREFIX}_i" env RUST_LOG=info "$BIN" sync \
    --bind 10.100.0.1:4433 \
    --db "$DB_I" \
    >"$TMPDIR/i.log" 2>&1 &
PIDS+=($!)
sleep 0.5

# Accept invites from segmented peers (bootstrap over NAT to introducer).
ip netns exec "${PREFIX}_a" "$BIN" accept-invite \
    --db "$DB_A" \
    --invite "$INV_A" \
    --username "peer-a" \
    --devicename "nat-a" \
    >/dev/null
ip netns exec "${PREFIX}_b" "$BIN" accept-invite \
    --db "$DB_B" \
    --invite "$INV_B" \
    --username "peer-b" \
    --devicename "nat-b" \
    >/dev/null

FP_I=$("$BIN" transport-identity --db "$DB_I" 2>/dev/null)
FP_A=$("$BIN" transport-identity --db "$DB_A" 2>/dev/null)
FP_B=$("$BIN" transport-identity --db "$DB_B" 2>/dev/null)
log "I = ${FP_I:0:16}..."
log "A = ${FP_A:0:16}..."
log "B = ${FP_B:0:16}..."

# Seed additional messages after invite acceptance and capture event IDs.
SEND_A_OUT=$("$BIN" send "hello from A" --db "$DB_A")
SEND_B_OUT=$("$BIN" send "hello from B" --db "$DB_B")
MSG_A_EID=$(echo "$SEND_A_OUT" | sed -n 's/^event_id://p' | tail -n1)
MSG_B_EID=$(echo "$SEND_B_OUT" | sed -n 's/^event_id://p' | tail -n1)
if [[ -z "$MSG_A_EID" || -z "$MSG_B_EID" ]]; then
    fail "Failed to parse seed message event IDs"
fi

log "Starting peer A (behind NAT)..."
ip netns exec "${PREFIX}_a" env RUST_LOG=info "$BIN" sync \
    --bind 0.0.0.0:4433 \
    --db "$DB_A" \
    >"$TMPDIR/a.log" 2>&1 &
PIDS+=($!)

log "Starting peer B (behind NAT)..."
ip netns exec "${PREFIX}_b" env RUST_LOG=info "$BIN" sync \
    --bind 0.0.0.0:4433 \
    --db "$DB_B" \
    >"$TMPDIR/b.log" 2>&1 &
PIDS+=($!)

# ---------------------------------------------------------------------------
# Phase 1: Relay sync convergence
# ---------------------------------------------------------------------------
log "Waiting for relay sync convergence (cross-peer message IDs)..."
if ! "$BIN" assert-eventually "has_event:${MSG_B_EID} >= 1" --db "$DB_A" --timeout-ms 20000 2>/dev/null; then
    fail "A did not receive B's seed message via relay"
fi
if ! "$BIN" assert-eventually "has_event:${MSG_A_EID} >= 1" --db "$DB_B" --timeout-ms 20000 2>/dev/null; then
    fail "B did not receive A's seed message via relay"
fi
log "Relay sync OK: A/B observed each other's seed message IDs"

# ---------------------------------------------------------------------------
# Phase 2: Explicit intro API calls + punch polling
# ---------------------------------------------------------------------------
log "Sending explicit Intro API calls from introducer and waiting for punch..."
PUNCH_DEADLINE=$((SECONDS + 45))
PUNCH_OK=false
NEXT_INTRO_AT=0
INTRO_CALLS=0

while [[ $SECONDS -lt $PUNCH_DEADLINE ]]; do
    if [[ $SECONDS -ge $NEXT_INTRO_AT ]]; then
        if ip netns exec "${PREFIX}_i" env RUST_LOG=info "$BIN" intro \
            --db "$DB_I" \
            --peer-a "$FP_A" --peer-b "$FP_B" \
            --ttl-ms 30000 --attempt-window-ms 5000 \
            >>"$TMPDIR/i_intro.log" 2>&1; then
            INTRO_CALLS=$((INTRO_CALLS + 1))
        fi
        NEXT_INTRO_AT=$((SECONDS + 2))
    fi

    A_STATUS=$("$BIN" intro-attempts --db "$DB_A" 2>/dev/null || true)
    B_STATUS=$("$BIN" intro-attempts --db "$DB_B" 2>/dev/null || true)

    A_CONNECTED=$(echo "$A_STATUS" | grep -c "connected" || true)
    B_CONNECTED=$(echo "$B_STATUS" | grep -c "connected" || true)

    if [[ "$A_CONNECTED" -gt 0 ]] || [[ "$B_CONNECTED" -gt 0 ]]; then
        PUNCH_OK=true
        break
    fi

    if (( SECONDS % 5 == 0 )); then
        log "  ... intro_calls=$INTRO_CALLS, waiting for connected intro_attempt"
    fi

    sleep 1
done

# ---------------------------------------------------------------------------
# Phase 3: If punch connected, verify direct sync with new messages
# ---------------------------------------------------------------------------
if $PUNCH_OK; then
    log "Punch connected! Verifying direct sync..."
    SEND_A2_OUT=$("$BIN" send "direct-from-A" --db "$DB_A")
    SEND_B2_OUT=$("$BIN" send "direct-from-B" --db "$DB_B")
    DIRECT_A_EID=$(echo "$SEND_A2_OUT" | sed -n 's/^event_id://p' | tail -n1)
    DIRECT_B_EID=$(echo "$SEND_B2_OUT" | sed -n 's/^event_id://p' | tail -n1)
    if [[ -z "$DIRECT_A_EID" || -z "$DIRECT_B_EID" ]]; then
        fail "Failed to parse direct message event IDs"
    fi

    if ! "$BIN" assert-eventually "has_event:${DIRECT_B_EID} >= 1" --db "$DB_A" --timeout-ms 15000 2>/dev/null; then
        fail "A did not receive B's direct message after punch"
    fi
    if ! "$BIN" assert-eventually "has_event:${DIRECT_A_EID} >= 1" --db "$DB_B" --timeout-ms 15000 2>/dev/null; then
        fail "B did not receive A's direct message after punch"
    fi
fi

# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------
echo ""
echo "=========================================="
echo "  NAT Hole Punch Test Results"
echo "=========================================="
echo "  mode: $MODE"
echo "  intro_calls: $INTRO_CALLS"

echo "  A intro attempts:"
"$BIN" intro-attempts --db "$DB_A" 2>/dev/null | sed 's/^/    /' || true
echo ""
echo "  B intro attempts:"
"$BIN" intro-attempts --db "$DB_B" 2>/dev/null | sed 's/^/    /' || true
echo ""

echo "  I intro log:"
grep -i "intro\|punch\|IntroOffer" "$TMPDIR/i.log" "$TMPDIR/i_intro.log" 2>/dev/null | tail -15 | sed 's/^/    /' || echo "    (none)"
echo ""
echo "  A intro log:"
grep -i "intro\|punch\|IntroOffer" "$TMPDIR/a.log" 2>/dev/null | tail -10 | sed 's/^/    /' || echo "    (none)"
echo ""
echo "  B intro log:"
grep -i "intro\|punch\|IntroOffer" "$TMPDIR/b.log" 2>/dev/null | tail -10 | sed 's/^/    /' || echo "    (none)"
echo ""

if $PUNCH_OK; then
    echo -e "  ${GREEN}Observed connected intro_attempt (hole punch succeeded)${NC}"
else
    echo -e "  ${YELLOW}No connected intro_attempt observed within deadline${NC}"
fi

if $HAS_CONNTRACK; then
    echo ""
    echo "  NAT A conntrack:"
    ip netns exec "${PREFIX}_na" conntrack -L 2>/dev/null | sed 's/^/    /' || echo "    (empty or unavailable)"
    echo ""
    echo "  NAT B conntrack:"
    ip netns exec "${PREFIX}_nb" conntrack -L 2>/dev/null | sed 's/^/    /' || echo "    (empty or unavailable)"
fi

EXPECTED="PASS"
if [[ "$MODE" == "symmetric" ]]; then
    EXPECTED="FAIL"
fi

ACTUAL="FAIL"
if $PUNCH_OK; then
    ACTUAL="PASS"
fi

echo ""
echo "  expected=$EXPECTED actual=$ACTUAL"

if [[ "$EXPECTED" == "$ACTUAL" ]]; then
    echo -e "  ${GREEN}PASS${NC}: behavior matches expected NAT mode"
else
    echo -e "  ${RED}FAIL${NC}: behavior does not match expected NAT mode"
    echo ""
    echo "  NAT A nft ruleset:"
    ip netns exec "${PREFIX}_na" nft list ruleset 2>/dev/null | sed 's/^/    /'
    echo ""
    echo "  NAT B nft ruleset:"
    ip netns exec "${PREFIX}_nb" nft list ruleset 2>/dev/null | sed 's/^/    /'
    echo ""
    echo "  Last 40 lines of I log:"
    tail -40 "$TMPDIR/i.log" 2>/dev/null | sed 's/^/    /'
    echo ""
    echo "  Last 40 lines of I intro log:"
    tail -40 "$TMPDIR/i_intro.log" 2>/dev/null | sed 's/^/    /'
    echo ""
    echo "  Last 40 lines of A log:"
    tail -40 "$TMPDIR/a.log" 2>/dev/null | sed 's/^/    /'
    echo ""
    echo "  Last 40 lines of B log:"
    tail -40 "$TMPDIR/b.log" 2>/dev/null | sed 's/^/    /'
    TEST_FAILED=1
    exit 1
fi

echo "=========================================="
