#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/.."

cargo fmt --manifest-path Cargo.toml

cargo test -q --manifest-path Cargo.toml --lib
cargo test -q --manifest-path Cargo.toml --test sync_contract_tests -- --test-threads=1
cargo test -q --manifest-path Cargo.toml --test cli_device_link_discovery_test -- --test-threads=1
cargo test -q --manifest-path Cargo.toml --test cli_test test_cli_local_mdns_discovery_without_bootstrap_addresses -- --nocapture --test-threads=1
cargo test -q --manifest-path Cargo.toml --test cli_test test_cli_reused_invite_live_daemon_reloads_bootstrap_transport_identity -- --nocapture --test-threads=1

cargo +stable test --release --manifest-path Cargo.toml --test daemon_perf_test perf_sync_10k -- --nocapture --exact --test-threads=1
cargo +stable test --release --manifest-path Cargo.toml --test daemon_perf_test perf_continuous_10k -- --nocapture --exact --test-threads=1
cargo +stable test --release --manifest-path Cargo.toml --test daemon_perf_test perf_sync_50k -- --nocapture --ignored --exact --test-threads=1
cargo +stable test --release --manifest-path Cargo.toml --test sync_graph_test catchup_non_uniform_sources -- --nocapture --test-threads=1
cargo +stable test --release --manifest-path Cargo.toml --test sync_graph_test catchup_dead_peer_dropout -- --nocapture --test-threads=1
cargo +stable test --release --manifest-path Cargo.toml --test file_throughput_test -- --nocapture --test-threads=1
