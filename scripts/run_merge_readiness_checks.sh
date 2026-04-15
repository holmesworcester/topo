#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$ROOT/Cargo.toml"

export TMPDIR="${TMPDIR:-/home/holmes/tmp-rust}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/home/holmes/poc-7-hot-cold-sync-target}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"

run() {
    echo
    echo "==> $*"
    "$@"
}

run_expect_tests() {
    local tmp
    tmp="$(mktemp)"
    echo
    echo "==> $*"
    if ! "$@" >"$tmp" 2>&1; then
        cat "$tmp"
        rm -f "$tmp"
        return 1
    fi
    cat "$tmp"
    if grep -q "running 0 tests" "$tmp"; then
        rm -f "$tmp"
        echo "FAIL: filtered cargo test matched zero tests"
        return 1
    fi
    rm -f "$tmp"
}

run_cli_case() {
    local test_name="$1"
    run_expect_tests cargo test -q --manifest-path "$MANIFEST" --test cli_test "$test_name" -- --nocapture --test-threads=1
}

usage() {
    cat <<'EOF'
Usage:
  scripts/run_merge_readiness_checks.sh targeted
  scripts/run_merge_readiness_checks.sh full-cli
  scripts/run_merge_readiness_checks.sh full-suite

Modes:
  targeted   Run the primary agent/merge-readiness gate: formal checks first,
             then the historically flaky serial regressions.
  full-cli   Run the entire cli_test binary serially.
  full-suite Run targeted, then full-cli, then cargo test -q for the repo.
EOF
}

mode="${1:-targeted}"

run_primary_formal_gate() {
    run_expect_tests cargo test -q --manifest-path "$MANIFEST" --lib boundary_tests:: -- --nocapture
    run_expect_tests cargo test -q --manifest-path "$MANIFEST" --lib registry_formal_projector_coverage -- --nocapture
    run env TOPO_REQUIRE_VERUS=1 "$ROOT/scripts/run_verus_proofs.sh"
}

case "$mode" in
    targeted)
        run_primary_formal_gate
        run_expect_tests cargo test -q --manifest-path "$MANIFEST" --lib workspace::queries::tests:: -- --nocapture
        run_expect_tests cargo test -q --manifest-path "$MANIFEST" --test rpc_test joining_tenant_view_and_status_show_tag_and_send_fails -- --nocapture --test-threads=1
        run_expect_tests cargo test -q --manifest-path "$MANIFEST" --test cheat_proof_realism_test -- --nocapture --test-threads=1
        run_expect_tests cargo test -q --manifest-path "$MANIFEST" --test double_send_test duplicate_sends_stay_below_regression_threshold -- --nocapture --test-threads=1
        run_expect_tests cargo test -q --manifest-path "$MANIFEST" --test cli_device_link_discovery_test -- --nocapture --test-threads=1
        run_cli_case test_cli_bidirectional_sync
        run_cli_case test_cli_sync_bootstrap_from_accepted_invite_data
        run_expect_tests cargo test -q --manifest-path "$MANIFEST" --test cli_invite_discovery_empty_bootstrap_test -- --nocapture --test-threads=1
        run_expect_tests cargo test -q --manifest-path "$MANIFEST" --test cli_invite_discovery_wrong_bootstrap_test -- --nocapture --test-threads=1
        run_cli_case test_cli_multi_use_device_links_mix_reuse_and_new_creation
        run_cli_case test_cli_live_daemon_accept_second_workspace_can_switch_back_and_sync_original_tenant
        run_cli_case test_cli_shared_db_same_workspace_accepts_distinct_explicit_invites
        run_expect_tests cargo test -q --manifest-path "$MANIFEST" --test cli_observability_test test_mdns_multitenant_self_filtering -- --nocapture --test-threads=1
        run_cli_case test_cli_shared_db_multitenant_cross_workspace_isolation
        ;;
    full-cli)
        run cargo test -q --manifest-path "$MANIFEST" --test cli_test -- --nocapture --test-threads=1
        ;;
    full-suite)
        "$0" targeted
        "$0" full-cli
        run cargo test -q --manifest-path "$MANIFEST"
        ;;
    *)
        usage
        exit 2
        ;;
esac
