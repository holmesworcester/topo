#!/usr/bin/env bash
# Boundary import enforcement for Option B network boundary refactor.
# Phase 6: hardened with explicit forbidden edges and positive contract checks.
# Exits non-zero on any violation.
set -euo pipefail

FAIL=0

check_no_match() {
  local pattern="$1"
  local path="$2"
  # Skip comment-only matches (lines starting with // or //!)
  if rg -n "$pattern" "$path" --glob '*.rs' 2>/dev/null | grep -v '^\S*:\s*//' >/dev/null 2>&1; then
    rg -n "$pattern" "$path" --glob '*.rs' 2>/dev/null | grep -v '^\S*:\s*//'
    echo "BOUNDARY VIOLATION: pattern '$pattern' matched in $path" >&2
    FAIL=1
  fi
}

check_required() {
  local pattern="$1"
  local path="$2"
  if ! rg -q "$pattern" "$path" --glob '*.rs' 2>/dev/null; then
    echo "POSITIVE CHECK FAILED: expected '$pattern' in $path" >&2
    FAIL=1
  fi
}

echo "=== Forbidden edges ==="

# -- peering must not reach into internals --
# peering -> projection
check_no_match 'crate::projection' src/peering/
# peering -> event_pipeline internals (must use contract types only)
check_no_match 'crate::event_pipeline::ingest_runtime' src/peering/
check_no_match 'crate::event_pipeline::batch_writer' src/peering/
check_no_match 'crate::event_pipeline::drain_project_queue' src/peering/
check_no_match 'crate::event_pipeline::IngestItem' src/peering/

# -- sync (session layer) must not depend on transport concrete types --
# sync -> projection
check_no_match 'crate::projection' src/sync/
# sync -> QUIC concrete types
check_no_match 'quinn::' src/sync/
# sync -> SyncSessionIo concrete type
check_no_match 'SyncSessionIo<' src/sync/
# sync -> into_any downcast path
check_no_match '\.into_any\(' src/sync/
check_no_match 'downcast::<' src/sync/

# -- event_pipeline must not reach into peering, sync-session layer, or protocol --
check_no_match 'crate::peering' src/event_pipeline/
check_no_match 'crate::sync::session' src/event_pipeline/
check_no_match 'crate::sync' src/event_pipeline/

echo "=== Positive contract checks ==="

# peering and sync must import from contracts, not event_pipeline
check_required 'contracts::event_runtime_contract' src/peering/
check_required 'contracts::network_contract' src/peering/
check_required 'contracts::event_runtime_contract' src/sync/
check_required 'contracts::network_contract' src/sync/

if [ "$FAIL" -ne 0 ]; then
  echo "FAILED: boundary violations found" >&2
  exit 1
fi

echo "All boundary checks passed."
