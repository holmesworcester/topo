#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"

cargo test -q --manifest-path "$repo_root/Cargo.toml" --test sync_contract_tests -- --test-threads=1
cargo test -q --manifest-path "$repo_root/Cargo.toml" --test cli_device_link_discovery_test -- --test-threads=1
cargo test -q --manifest-path "$repo_root/Cargo.toml" --test cli_invite_discovery_empty_bootstrap_test -- --test-threads=1
cargo test -q --manifest-path "$repo_root/Cargo.toml" --test cli_live_file_sync_test -- --test-threads=1
cargo test -q --manifest-path "$repo_root/Cargo.toml" --test cli_test -- --test-threads=1
cargo test -q --manifest-path "$repo_root/Cargo.toml"
