#!/usr/bin/env bash
set -euo pipefail

# Verus formal verification proof checker.
# Requires verus to be installed; see verus-proofs/README for setup.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROOFS="$ROOT/verus-proofs"

if [ ! -d "$PROOFS" ]; then
    echo "ERROR: verus-proofs directory not found at $PROOFS"
    exit 1
fi

# Locate cargo-verus: check PATH, then common install locations
CARGO_VERUS=""
if command -v cargo-verus &>/dev/null; then
    CARGO_VERUS="cargo-verus"
elif [ -x "$HOME/verus-install/verus-x86-linux/cargo-verus" ]; then
    CARGO_VERUS="$HOME/verus-install/verus-x86-linux/cargo-verus"
elif [ -x "$HOME/verus/cargo-verus" ]; then
    CARGO_VERUS="$HOME/verus/cargo-verus"
else
    if [ "${TOPO_REQUIRE_VERUS:-0}" = "1" ]; then
        echo "FAIL: cargo-verus not found but TOPO_REQUIRE_VERUS=1"
        echo "      Install from https://github.com/verus-lang/verus"
        exit 1
    fi
    echo "SKIP: cargo-verus not found (install from https://github.com/verus-lang/verus)"
    echo "      Verus proofs were not checked."
    exit 0
fi

echo "==> Running Verus formal verification proofs"
echo "    Tool: $CARGO_VERUS"
cd "$PROOFS"

OUTPUT=$("$CARGO_VERUS" verify 2>&1)
EXIT_CODE=$?

# Extract verification summary
SUMMARY=$(echo "$OUTPUT" | grep "^verification results::" || true)

if [ $EXIT_CODE -eq 0 ] && echo "$SUMMARY" | grep -q "0 errors"; then
    echo "    $SUMMARY"
    echo "    PASS"
else
    echo "$OUTPUT"
    echo "    FAIL: Verus verification errors detected"
    exit 1
fi
