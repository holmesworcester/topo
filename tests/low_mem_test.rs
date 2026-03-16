//! Low-memory mode budget tests.
//!
//! These tests enforce bounded memory behavior under `LOW_MEM_IOS=1`.
//! RSS-sampling tests are ignored by default because authoritative
//! hard-cap validation comes from the daemon + cgroup harness.

use std::time::Duration;

use topo::testutil::{converge_workspace_transport_graph, sync_until_converged, Peer};

fn peak_rss_mib() -> Option<f64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if line.starts_with("VmHWM:") {
            let kb: f64 = line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())?;
            return Some(kb / 1024.0);
        }
    }
    None
}

fn current_rss_mib() -> Option<f64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if line.starts_with("VmRSS:") {
            let kb: f64 = line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())?;
            return Some(kb / 1024.0);
        }
    }
    None
}

struct EnvGuard {
    prev_low_mem_ios: Option<String>,
}

impl EnvGuard {
    fn enable_low_mem_ios() -> Self {
        let prev_low_mem_ios = std::env::var("LOW_MEM_IOS").ok();
        std::env::set_var("LOW_MEM_IOS", "1");
        Self { prev_low_mem_ios }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.prev_low_mem_ios {
            Some(v) => std::env::set_var("LOW_MEM_IOS", v),
            None => std::env::remove_var("LOW_MEM_IOS"),
        }
    }
}

/// Hard ceiling: 24 MiB per instance (iOS notification extension limit).
/// DO NOT bump this — if the test fails, reduce memory usage instead.
///
/// This test runs 2 peer instances in one process, so the process-level
/// budget is 2 × 24 = 48 MiB.
fn rss_budget_mib_default() -> f64 {
    48.0
}

fn rss_budget_mib_from_env(var: &str, default: f64) -> f64 {
    std::env::var(var)
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(default)
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn low_mem_ios_functional_smoke_2k() {
    let _env = EnvGuard::enable_low_mem_ios();

    let alice = Peer::new_with_identity("alice_lowmem_functional");
    let bob = Peer::new_in_workspace("bob_lowmem_functional", &alice).await;
    let peers = vec![alice, bob];
    converge_workspace_transport_graph(&peers).await;
    let mut peers = peers.into_iter();
    let alice = peers.next().expect("missing alice");
    let bob = peers.next().expect("missing bob");

    alice.batch_create_messages(1_000);
    bob.batch_create_messages(1_000);

    let expected_recorded_messages = 2_000;

    let _metrics = sync_until_converged(
        &alice,
        &bob,
        || {
            alice.recorded_message_event_count() >= expected_recorded_messages
                && bob.recorded_message_event_count() >= expected_recorded_messages
        },
        Duration::from_secs(120),
    )
    .await;

    assert_eq!(
        alice.recorded_message_event_count(),
        expected_recorded_messages
    );
    assert_eq!(
        bob.recorded_message_event_count(),
        expected_recorded_messages
    );

    eprintln!();
    eprintln!("=== Low-mem functional smoke (2k) ===");
    eprintln!("  Alice messages: {}", alice.message_count());
    eprintln!("  Bob messages:   {}", bob.message_count());
    if let Some(current) = current_rss_mib() {
        eprintln!("  Current RSS:    {:.2} MiB", current);
    }
    eprintln!();
}

#[tokio::test]
#[cfg(target_os = "linux")]
#[ignore = "RSS-sampling sanity only; use lowmem cgroup for hard gates"]
async fn low_mem_ios_budget_smoke_10k() {
    let _env = EnvGuard::enable_low_mem_ios();

    let alice = Peer::new_with_identity("alice_lowmem_smoke");
    let bob = Peer::new_in_workspace("bob_lowmem_smoke", &alice).await;
    let peers = vec![alice, bob];
    converge_workspace_transport_graph(&peers).await;
    let mut peers = peers.into_iter();
    let alice = peers.next().expect("missing alice");
    let bob = peers.next().expect("missing bob");

    alice.batch_create_messages(5_000);
    bob.batch_create_messages(5_000);

    let expected_recorded_messages = 10_000;

    let _metrics = sync_until_converged(
        &alice,
        &bob,
        || {
            alice.recorded_message_event_count() >= expected_recorded_messages
                && bob.recorded_message_event_count() >= expected_recorded_messages
        },
        Duration::from_secs(180),
    )
    .await;

    assert_eq!(
        alice.recorded_message_event_count(),
        expected_recorded_messages
    );
    assert_eq!(
        bob.recorded_message_event_count(),
        expected_recorded_messages
    );

    // Use current RSS here instead of process-wide VmHWM so this test's budget
    // is not polluted by other low_mem_test cases that may run in the same
    // process before this one.
    let peak = current_rss_mib().expect("VmRSS unavailable on this platform");
    let budget = rss_budget_mib_from_env("LOW_MEM_IOS_BUDGET_MIB", rss_budget_mib_default());
    assert!(
        peak <= budget,
        "low_mem_ios RSS budget exceeded: current={:.2} MiB budget={:.2} MiB",
        peak,
        budget
    );

    eprintln!();
    eprintln!("=== Low-mem budget smoke (10k) ===");
    eprintln!("  Messages/peer:  {}", 5_000);
    eprintln!("  Current RSS:    {:.2} MiB", peak);
    eprintln!("  Budget:         {:.2} MiB", budget);
    eprintln!();
}

#[tokio::test]
#[cfg(target_os = "linux")]
#[ignore = "long-running RSS-sampling soak; run explicitly"]
async fn low_mem_ios_budget_soak_million() {
    let _env = EnvGuard::enable_low_mem_ios();

    let events: usize = std::env::var("LOW_MEM_IOS_SOAK_EVENTS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_000_000);
    let budget = rss_budget_mib_from_env("LOW_MEM_IOS_SOAK_BUDGET_MIB", 24.0);

    let alice = Peer::new_with_identity("alice_lowmem_soak");
    let bob = Peer::new_in_workspace("bob_lowmem_soak", &alice).await;
    let peers = vec![alice, bob];
    converge_workspace_transport_graph(&peers).await;
    let mut peers = peers.into_iter();
    let alice = peers.next().expect("missing alice");
    let bob = peers.next().expect("missing bob");

    alice.batch_create_messages(events);

    let _metrics = sync_until_converged(
        &alice,
        &bob,
        || bob.recorded_message_event_count() >= events as i64,
        Duration::from_secs(3600),
    )
    .await;

    assert_eq!(alice.recorded_message_event_count(), events as i64);
    assert_eq!(bob.recorded_message_event_count(), events as i64);

    let peak = peak_rss_mib().expect("VmHWM unavailable on this platform");
    assert!(
        peak <= budget,
        "low_mem_ios soak RSS budget exceeded: peak={:.2} MiB budget={:.2} MiB events={}",
        peak,
        budget,
        events
    );

    eprintln!();
    eprintln!("=== Low-mem soak ({events}) ===");
    eprintln!("  Peak RSS:       {:.2} MiB", peak);
    eprintln!("  Budget:         {:.2} MiB", budget);
    eprintln!();
}
