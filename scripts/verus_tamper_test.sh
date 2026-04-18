#!/usr/bin/env bash
#
# Verus tamper test — a liveness check for the SMT-on-real-bodies model.
#
# Patches an ensures-protected function body to violate its postcondition,
# runs cargo-verus verify, and asserts the run FAILS with "postcondition not
# satisfied". Reverts the patch regardless of outcome.
#
# If this passes (verify-fails-as-expected), we have evidence that cargo-verus
# actually checks the body against the ensures. If it doesn't fail, the
# ensures clauses are toothless and the whole migration is a lie.
#
# Target: `decide_session_open_failure_plan` in
# verus-proofs/src/runtime/peering/loops/connect.rs — chosen because it's tiny,
# has an unambiguous ensures, and was the first function migrated (see commit
# history on branch verus-real-proofs).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="$ROOT/verus-proofs/src/runtime/peering/loops/connect.rs"
BACKUP="${TARGET}.tamper.bak"

# Locate cargo-verus (same pattern as run_verus_proofs.sh).
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
        exit 1
    fi
    echo "SKIP: cargo-verus not found (tamper test requires Verus install)"
    exit 0
fi

restore() {
    if [ -f "$BACKUP" ]; then
        mv "$BACKUP" "$TARGET"
        echo "  restored $TARGET"
    fi
}
trap restore EXIT

echo "==> Verus tamper test"
echo "    Tool: $CARGO_VERUS"
echo "    Target: $TARGET"

cp "$TARGET" "$BACKUP"

# Flip the branches inside decide_session_open_failure_plan. The ensures clause
# states: connection_lost ==> EvictAndBreak, !connection_lost ==> Break.
# This patch makes the body return the opposite, violating both clauses.
#
# Before:
#     if context.connection_lost {
#         SessionOpenFailurePlan::EvictAndBreak
#     } else {
#         SessionOpenFailurePlan::Break
#     }
#
# After (tampered):
#     if context.connection_lost {
#         SessionOpenFailurePlan::Break
#     } else {
#         SessionOpenFailurePlan::EvictAndBreak
#     }
python3 - "$TARGET" <<'PY'
import sys, re

path = sys.argv[1]
src = open(path).read()

pattern = re.compile(
    r'(pub fn decide_session_open_failure_plan\([^)]*\)\s*-> \(plan: SessionOpenFailurePlan\)\s*'
    r'ensures[^{]*\{)\s*'
    r'if context\.connection_lost \{\s*'
    r'SessionOpenFailurePlan::EvictAndBreak\s*'
    r'\} else \{\s*'
    r'SessionOpenFailurePlan::Break\s*'
    r'\}',
    re.DOTALL,
)

replacement = (
    r'\1\n'
    '    if context.connection_lost {\n'
    '        SessionOpenFailurePlan::Break\n'
    '    } else {\n'
    '        SessionOpenFailurePlan::EvictAndBreak\n'
    '    }'
)

new_src, n = pattern.subn(replacement, src, count=1)
if n != 1:
    print("ERROR: could not locate decide_session_open_failure_plan body to tamper", file=sys.stderr)
    print("       the target function's shape may have changed; update scripts/verus_tamper_test.sh", file=sys.stderr)
    sys.exit(2)

open(path, "w").write(new_src)
print("  tampered decide_session_open_failure_plan body (branches flipped)")
PY

echo "==> Running cargo-verus verify (expected to FAIL)"
cd "$ROOT/verus-proofs"
set +e
OUTPUT=$("$CARGO_VERUS" verify 2>&1)
EXIT_CODE=$?
set -e

cd "$ROOT"

if [ $EXIT_CODE -eq 0 ]; then
    echo "FAIL: cargo-verus verify PASSED after tampering the function body."
    echo "      This means the ensures clause is not being checked against the body."
    echo "      The proof-on-real-code guarantee is broken. Investigate immediately."
    echo "--- verify output ---"
    echo "$OUTPUT"
    exit 1
fi

if echo "$OUTPUT" | grep -q "postcondition not satisfied"; then
    echo "PASS: cargo-verus verify detected the tampered body with 'postcondition not satisfied'."
    exit 0
else
    echo "FAIL: cargo-verus verify failed, but not with 'postcondition not satisfied'."
    echo "      This likely indicates a build/type error from the tamper patch, not an ensures violation."
    echo "      Update scripts/verus_tamper_test.sh to keep the body type-checkable while violating the ensures."
    echo "--- verify output ---"
    echo "$OUTPUT"
    exit 1
fi
