//! Catchup benchmark focused on sink durable receipt throughput.
//!
//! The sink is taken offline, the source preloads a backlog, then the sink
//! restarts and catches up. This measures durable receipt (`recorded_events`)
//! separately from projected message visibility.

mod cli_harness;
mod daemon_perf_harness;

use std::time::Duration;

use daemon_perf_harness::{
    emit_durable_summary, run_preloaded_durable_catchup, BenchNetworkPath,
};

fn run_durable_catchup_bench(name: &str, title: &str, messages: i64, catchup_timeout_secs: u64) {
    let measurement = run_preloaded_durable_catchup(
        messages,
        Duration::from_secs(30),
        Duration::from_secs(60),
        Duration::from_secs(catchup_timeout_secs),
        BenchNetworkPath::direct,
    );

    emit_durable_summary(name, title, &measurement);
}

#[test]
fn perf_durable_catchup_10k() {
    run_durable_catchup_bench(
        "daemon_durable_catchup_perf_test.perf_durable_catchup_10k",
        "10k durable catchup (offline preload, warm restart)",
        10_000,
        300,
    );
}

#[test]
#[ignore]
fn perf_durable_catchup_50k() {
    run_durable_catchup_bench(
        "daemon_durable_catchup_perf_test.perf_durable_catchup_50k",
        "50k durable catchup (offline preload, warm restart)",
        50_000,
        600,
    );
}

#[test]
#[ignore]
fn perf_durable_catchup_200k() {
    run_durable_catchup_bench(
        "daemon_durable_catchup_perf_test.perf_durable_catchup_200k",
        "200k durable catchup (offline preload, warm restart)",
        200_000,
        1_200,
    );
}
