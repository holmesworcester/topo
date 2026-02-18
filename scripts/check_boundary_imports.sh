#!/usr/bin/env bash
# Boundary import enforcement for Option B network boundary refactor.
# Exits non-zero on any violation.
set -euo pipefail

FAIL=0

check_no_match() {
  local pattern="$1"
  local path="$2"
  if rg -n "$pattern" "$path" 2>/dev/null; then
    echo "BOUNDARY VIOLATION: pattern '$pattern' matched in $path" >&2
    FAIL=1
  fi
}

echo "Checking boundary imports..."

# network must not reach into sync internals
check_no_match 'crate::sync' src/network/
# network must not reach into projection
check_no_match 'crate::projection' src/network/
# network must not reach into event_runtime internals (top-level re-exports OK)
check_no_match 'crate::event_runtime::ingest_runtime' src/network/

# replication must not reach into projection directly
check_no_match 'crate::projection' src/replication/
# replication must not use concrete QUIC types
check_no_match 'quinn::' src/replication/

# event_runtime must not reach into network, replication, or sync
check_no_match 'crate::network' src/event_runtime/
check_no_match 'crate::replication' src/event_runtime/
check_no_match 'crate::sync' src/event_runtime/

if [ "$FAIL" -ne 0 ]; then
  echo "FAILED: boundary violations found" >&2
  exit 1
fi

echo "All boundary checks passed."
