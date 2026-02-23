#!/usr/bin/env bash
# Boundary import enforcement for peering/sync/event_pipeline boundary refactor.
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
# sync -> QuicTransportSessionIo concrete type
check_no_match 'QuicTransportSessionIo<' src/sync/
# sync -> into_any downcast path
check_no_match '\.into_any\(' src/sync/
check_no_match 'downcast::<' src/sync/

# -- event_pipeline must not reach into peering, sync-session layer, or protocol --
check_no_match 'crate::peering' src/event_pipeline/
check_no_match 'crate::sync::session' src/event_pipeline/
check_no_match 'crate::sync' src/event_pipeline/

# -- transport identity boundary: only transport/identity_adapter.rs may call raw install fns --
check_no_match 'install_peer_key_transport_identity' src/service.rs
check_no_match 'install_invite_bootstrap_transport_identity' src/service.rs
check_no_match 'install_peer_key_transport_identity' src/event_modules/
check_no_match 'install_invite_bootstrap_transport_identity' src/event_modules/
check_no_match 'install_peer_key_transport_identity' src/projection/
check_no_match 'install_invite_bootstrap_transport_identity' src/projection/

# -- identity module elimination: no crate::identity:: imports anywhere --
check_no_match 'crate::identity::' src/
check_no_match 'pub mod identity;' src/lib.rs

# -- event-module locality: service.rs must not call event-domain invite/identity ops directly --
check_no_match 'identity_ops::create_user_invite' src/service.rs
check_no_match 'identity_ops::create_device_link_invite' src/service.rs
check_no_match 'identity_ops::ensure_content_key_for_peer' src/service.rs
check_no_match 'invite_link::create_invite_link' src/service.rs

# identity primitive helpers must not be called from service.rs, event_pipeline.rs, or tests
# (they should go through workspace::commands APIs)
check_no_match 'identity_ops::create_user_invite_events' src/service.rs
check_no_match 'identity_ops::create_device_link_invite_events' src/service.rs
check_no_match 'identity_ops::create_user_invite_events' src/event_pipeline.rs
check_no_match 'identity_ops::create_device_link_invite_events' src/event_pipeline.rs
check_no_match 'identity_ops::create_user_invite_events' src/testutil/
check_no_match 'identity_ops::create_device_link_invite_events' src/testutil/

# service.rs must not contain svc_bootstrap_workspace_conn
check_no_match 'svc_bootstrap_workspace_conn' src/service.rs
check_no_match 'workspace::commands::retry_pending_invite_content_key_unwraps' src/event_pipeline.rs
check_no_match 'workspace::commands::create_workspace' src/event_pipeline.rs
check_no_match 'workspace::commands::join_workspace_as_new_user' src/event_pipeline.rs
check_no_match 'workspace::commands::add_device_to_workspace' src/event_pipeline.rs

# -- peering readability: bootstrap helpers must not be production-owned --
# Production runtime must not depend on test bootstrap helpers (R2/SC2)
check_no_match 'testutil::bootstrap' src/peering/
check_no_match 'testutil::bootstrap' src/service.rs
check_no_match 'testutil::bootstrap' src/event_pipeline.rs
# peering/workflows must not contain bootstrap module (moved to testutil)
check_no_match 'mod bootstrap' src/peering/workflows/

# -- peering readability: target planning single ownership (R3/SC3) --
# Target planning must live in target_planner, not scattered across runtime
check_required 'mod target_planner' src/peering/runtime/mod.rs

# -- transport encapsulation boundary --
# peering must not directly construct DualConnection or QuicTransportSessionIo
check_no_match 'DualConnection::new' src/peering/
check_no_match 'QuicTransportSessionIo::new' src/peering/
# peering must not call open_bi/accept_bi (stream wiring belongs to transport)
check_no_match 'open_bi(' src/peering/
check_no_match 'accept_bi(' src/peering/
# peering must not use quinn stream types (SendStream/RecvStream)
check_no_match 'quinn::SendStream' src/peering/
check_no_match 'quinn::RecvStream' src/peering/
# peering connection lifecycle must route through transport helpers
check_no_match 'peer_identity_from_connection' src/peering/
check_no_match 'endpoint\.connect_with\(' src/peering/loops/
check_no_match 'endpoint\.connect\(' src/peering/loops/
check_no_match 'endpoint\.accept\(' src/peering/loops/
check_no_match 'endpoint\.connect_with\(' src/peering/workflows/
check_no_match 'endpoint\.connect\(' src/peering/workflows/

echo "=== Positive contract checks ==="

# peering and sync must import from contracts, not event_pipeline
check_required 'contracts::event_pipeline_contract' src/peering/
check_required 'contracts::peering_contract' src/peering/
check_required 'contracts::event_pipeline_contract' src/sync/
check_required 'contracts::peering_contract' src/sync/

# transport identity adapter must use contract types
check_required 'TransportIdentityAdapter' src/transport/identity_adapter.rs
check_required 'TransportIdentityIntent' src/transport/identity_adapter.rs

# transport session factory must own stream wiring
check_required 'open_session_io' src/transport/session_factory.rs
check_required 'accept_session_io' src/transport/session_factory.rs
check_required 'DualConnection::new' src/transport/session_factory.rs
# transport connection lifecycle helpers must own dial/accept + peer identity
check_required 'pub async fn dial_peer' src/transport/connection_lifecycle.rs
check_required 'pub async fn accept_peer' src/transport/connection_lifecycle.rs

# projection must route through adapter contract, not raw install fns
check_required 'ApplyTransportIdentityIntent' src/projection/

# -- identity eventization positive checks (SC4): event-module commands own workflows --
check_required 'pub fn create_workspace' src/event_modules/workspace/commands.rs
check_required 'pub fn join_workspace_as_new_user' src/event_modules/workspace/commands.rs
check_required 'pub fn add_device_to_workspace' src/event_modules/workspace/commands.rs
check_required 'pub fn create_user_invite' src/event_modules/workspace/commands.rs
check_required 'pub fn create_device_link_invite' src/event_modules/workspace/commands.rs
check_required 'pub fn retry_pending_invite_content_key_unwraps' src/event_modules/workspace/commands.rs

# workspace command wrappers live in workspace/commands.rs (not service.rs)
check_required 'pub fn create_workspace_for_db' src/event_modules/workspace/commands.rs
check_required 'pub fn accept_invite' src/event_modules/workspace/commands.rs
check_required 'pub fn accept_device_link' src/event_modules/workspace/commands.rs

# event_pipeline.rs uses generic post-drain hooks (not direct workspace/identity calls)
check_required 'event_modules::post_drain_hooks' src/event_pipeline.rs

if [ "$FAIL" -ne 0 ]; then
  echo "FAILED: boundary violations found" >&2
  exit 1
fi

echo "All boundary checks passed."
