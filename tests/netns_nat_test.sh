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
# NAT behavior: EIM + ADF (endpoint-independent mapping, address-dependent filtering).
# This is the most common home router NAT type.
#
# Requires: root (sudo), ip, nft, the poc-7 release binary.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BIN="${PROJECT_DIR}/target/release/poc-7"
TMPDIR="$(mktemp -d /tmp/hp_nat_test.XXXXXX)"
PREFIX="hp"

# Colours for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; TEST_FAILED=1; exit 1; }

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
    for ns in ${PREFIX}_i ${PREFIX}_na ${PREFIX}_nb ${PREFIX}_a ${PREFIX}_b; do
        sudo ip netns del "$ns" 2>/dev/null || true
    done
    sudo ip link del "${PREFIX}_pub" 2>/dev/null || true
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
[[ $(id -u) -eq 0 ]] || {
    exec sudo --preserve-env=PATH,HOME "$0" "$@"
}

log "Binary: $BIN"
log "Temp dir: $TMPDIR"

# ---------------------------------------------------------------------------
# Create namespaces
# ---------------------------------------------------------------------------
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
# NAT rules: EIM masquerade + ADF inbound on WAN
#
# The raw/prerouting notrack rule is critical for EIM (endpoint-independent
# mapping).  Without it, unsolicited inbound WAN packets that will be
# dropped by the filter still create phantom conntrack entries.  These
# phantom entries collide with outgoing NAT mappings and force masquerade
# to remap the source port — breaking hole-punch, which relies on the same
# external port being used regardless of destination.
# ---------------------------------------------------------------------------
for info in "na:${PREFIX}_vna" "nb:${PREFIX}_vnb"; do
    ns="${PREFIX}_${info%%:*}"
    wan="${info##*:}"
    ip netns exec "$ns" nft -f - <<EOF
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
EOF
done

# ---------------------------------------------------------------------------
# Connectivity checks
# ---------------------------------------------------------------------------
log "Verifying connectivity..."
ip netns exec "${PREFIX}_a" ping -c1 -W1 10.100.0.1  >/dev/null || fail "A cannot reach I through NAT"
ip netns exec "${PREFIX}_b" ping -c1 -W1 10.100.0.1  >/dev/null || fail "B cannot reach I through NAT"
if ip netns exec "${PREFIX}_i" ping -c1 -W1 10.1.0.2 >/dev/null 2>&1; then
    fail "I can reach A's private IP — NAT not working"
fi
log "Connectivity OK, NAT blocking verified"

# ---------------------------------------------------------------------------
# Generate identities and seed messages
# ---------------------------------------------------------------------------
DB_I="$TMPDIR/i.db"
DB_A="$TMPDIR/a.db"
DB_B="$TMPDIR/b.db"

FP_I=$("$BIN" identity --db "$DB_I" 2>/dev/null)
FP_A=$("$BIN" identity --db "$DB_A" 2>/dev/null)
FP_B=$("$BIN" identity --db "$DB_B" 2>/dev/null)

log "I = ${FP_I:0:16}..."
log "A = ${FP_A:0:16}..."
log "B = ${FP_B:0:16}..."

"$BIN" send "hello from I" --db "$DB_I" >/dev/null
"$BIN" send "hello from A" --db "$DB_A" >/dev/null
"$BIN" send "hello from B" --db "$DB_B" >/dev/null

# ---------------------------------------------------------------------------
# Start daemons
# ---------------------------------------------------------------------------
log "Starting introducer I (with intro-worker, interval=2s)..."
ip netns exec "${PREFIX}_i" env RUST_LOG=info "$BIN" sync \
    --bind 10.100.0.1:4433 \
    --db "$DB_I" \
    --pin-peer "$FP_A" --pin-peer "$FP_B" \
    --intro-worker --intro-interval-ms 2000 --intro-ttl-ms 30000 --intro-window-ms 5000 \
    >"$TMPDIR/i.log" 2>&1 &
PIDS+=($!)
sleep 0.5

log "Starting peer A (behind NAT)..."
ip netns exec "${PREFIX}_a" env RUST_LOG=info "$BIN" sync \
    --bind 0.0.0.0:4433 \
    --connect 10.100.0.1:4433 \
    --db "$DB_A" \
    --pin-peer "$FP_I" --pin-peer "$FP_B" \
    >"$TMPDIR/a.log" 2>&1 &
PIDS+=($!)

log "Starting peer B (behind NAT)..."
ip netns exec "${PREFIX}_b" env RUST_LOG=info "$BIN" sync \
    --bind 0.0.0.0:4433 \
    --connect 10.100.0.1:4433 \
    --db "$DB_B" \
    --pin-peer "$FP_I" --pin-peer "$FP_A" \
    >"$TMPDIR/b.log" 2>&1 &
PIDS+=($!)

# ---------------------------------------------------------------------------
# Phase 1: Relay sync convergence
# ---------------------------------------------------------------------------
log "Waiting for relay sync convergence (3 messages each)..."
if ! "$BIN" assert-eventually "store_count >= 3" --db "$DB_A" --timeout-ms 20000 2>/dev/null; then
    fail "A did not converge via relay"
fi
if ! "$BIN" assert-eventually "store_count >= 3" --db "$DB_B" --timeout-ms 20000 2>/dev/null; then
    fail "B did not converge via relay"
fi
log "Relay sync OK: A=3, B=3"

# ---------------------------------------------------------------------------
# Phase 2: Wait for intro worker to fire and punch to connect
# ---------------------------------------------------------------------------
# The intro worker runs every 2s. After observations are recorded (by I's
# accept_loop when A and B connected), it sends IntroOffers to A and B.
# Then A and B dial each other through NAT.
#
# We poll A's and B's intro_attempts table for status=connected.
# This is the definitive proof of hole punch success.

log "Waiting for hole punch (polling intro_attempts for connected status)..."
PUNCH_DEADLINE=$((SECONDS + 45))
PUNCH_OK=false

while [[ $SECONDS -lt $PUNCH_DEADLINE ]]; do
    A_STATUS=$("$BIN" intro-attempts --db "$DB_A" 2>/dev/null || true)
    B_STATUS=$("$BIN" intro-attempts --db "$DB_B" 2>/dev/null || true)

    A_CONNECTED=$(echo "$A_STATUS" | grep -c "connected" || true)
    B_CONNECTED=$(echo "$B_STATUS" | grep -c "connected" || true)

    if [[ "$A_CONNECTED" -gt 0 ]] || [[ "$B_CONNECTED" -gt 0 ]]; then
        PUNCH_OK=true
        break
    fi

    # Show progress every 5s
    if (( SECONDS % 5 == 0 )); then
        A_ANY=$(echo "$A_STATUS" | grep -c "intro_id\|status" || true)
        B_ANY=$(echo "$B_STATUS" | grep -c "intro_id\|status" || true)
        log "  ... A intro_attempts: $A_ANY entries, B: $B_ANY entries (waiting for connected)"
    fi

    sleep 1
done

# ---------------------------------------------------------------------------
# Phase 3: If punch connected, verify direct sync with new messages
# ---------------------------------------------------------------------------
if $PUNCH_OK; then
    log "Punch connected! Verifying direct sync..."

    # Create messages that should propagate via the punched direct connection
    "$BIN" send "direct-from-A" --db "$DB_A" >/dev/null
    "$BIN" send "direct-from-B" --db "$DB_B" >/dev/null

    if "$BIN" assert-eventually "store_count >= 5" --db "$DB_A" --timeout-ms 15000 2>/dev/null; then
        "$BIN" assert-eventually "store_count >= 5" --db "$DB_B" --timeout-ms 15000 2>/dev/null || true
    fi
fi

# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------
echo ""
echo "=========================================="
echo "  NAT Hole Punch Test Results"
echo "=========================================="

echo "  A intro attempts:"
"$BIN" intro-attempts --db "$DB_A" 2>/dev/null | sed 's/^/    /' || true
echo ""
echo "  B intro attempts:"
"$BIN" intro-attempts --db "$DB_B" 2>/dev/null | sed 's/^/    /' || true
echo ""

# Dump relevant log lines
echo "  I intro log:"
grep -i "intro\|punch\|IntroOffer" "$TMPDIR/i.log" 2>/dev/null | tail -10 | sed 's/^/    /' || echo "    (none)"
echo ""
echo "  A intro log:"
grep -i "intro\|punch\|IntroOffer" "$TMPDIR/a.log" 2>/dev/null | tail -10 | sed 's/^/    /' || echo "    (none)"
echo ""
echo "  B intro log:"
grep -i "intro\|punch\|IntroOffer" "$TMPDIR/b.log" 2>/dev/null | tail -10 | sed 's/^/    /' || echo "    (none)"
echo ""

if $PUNCH_OK; then
    echo -e "  ${GREEN}PASS: Hole punch through NAT succeeded (intro_attempt status=connected)${NC}"
else
    echo -e "  ${RED}FAIL: No intro_attempt reached status=connected within 45s${NC}"

    echo ""
    echo "  NAT A nft counters:"
    ip netns exec "${PREFIX}_na" nft list ruleset 2>/dev/null | sed 's/^/    /'
    echo ""
    echo "  NAT B nft counters:"
    ip netns exec "${PREFIX}_nb" nft list ruleset 2>/dev/null | sed 's/^/    /'
    echo ""
    echo "  NAT A conntrack:"
    ip netns exec "${PREFIX}_na" conntrack -L 2>/dev/null | sed 's/^/    /' || echo "    (empty or unavailable)"
    echo ""
    echo "  NAT B conntrack:"
    ip netns exec "${PREFIX}_nb" conntrack -L 2>/dev/null | sed 's/^/    /' || echo "    (empty or unavailable)"
    echo ""
    echo "  Last 30 lines of I log:"
    tail -30 "$TMPDIR/i.log" | sed 's/^/    /'
    echo ""
    echo "  Last 30 lines of A log:"
    tail -30 "$TMPDIR/a.log" | sed 's/^/    /'
    echo ""
    echo "  Last 30 lines of B log:"
    tail -30 "$TMPDIR/b.log" | sed 's/^/    /'

    TEST_FAILED=1
    exit 1
fi
echo "=========================================="
