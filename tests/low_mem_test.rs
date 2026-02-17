//! Low-memory mode budget tests.
//!
//! These tests enforce bounded memory behavior under `LOW_MEM_IOS=1`.
//! The soak test is ignored by default because it is long-running.

use std::time::Duration;

use poc_7::testutil::{Peer, sync_until_converged};
use poc_7::db::{open_connection, transport_trust::is_peer_allowed};



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
    prev_low_mem: Option<String>,
}

impl EnvGuard {
    fn enable_low_mem_ios() -> Self {
        let prev_low_mem_ios = std::env::var("LOW_MEM_IOS").ok();
        let prev_low_mem = std::env::var("LOW_MEM").ok();
        std::env::set_var("LOW_MEM_IOS", "1");
        // Keep legacy knob aligned so older code paths in bench helpers stay consistent.
        std::env::set_var("LOW_MEM", "1");
        Self {
            prev_low_mem_ios,
            prev_low_mem,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.prev_low_mem_ios {
            Some(v) => std::env::set_var("LOW_MEM_IOS", v),
            None => std::env::remove_var("LOW_MEM_IOS"),
        }
        match &self.prev_low_mem {
            Some(v) => std::env::set_var("LOW_MEM", v),
            None => std::env::remove_var("LOW_MEM"),
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
async fn low_mem_ios_budget_smoke_10k() {
    let _env = EnvGuard::enable_low_mem_ios();

    let alice = Peer::new_with_identity("alice_lowmem_smoke");
    let bob = Peer::new_with_identity("bob_lowmem_smoke");

    alice.batch_create_messages(5_000);
    bob.batch_create_messages(5_000);

    let sample = alice.sample_event_ids(1)[0].clone();
    let _metrics = sync_until_converged(&alice, &bob, || bob.has_event(&sample), Duration::from_secs(180)).await;

    assert_eq!(alice.message_count(), 5_000);
    assert_eq!(bob.message_count(), 5_000);

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
}

#[tokio::test]
#[cfg(target_os = "linux")]
#[ignore = "long-running soak; run explicitly during hardening"]
async fn low_mem_ios_budget_soak_million() {
    let _env = EnvGuard::enable_low_mem_ios();

    let events: usize = std::env::var("LOW_MEM_IOS_SOAK_EVENTS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_000_000);
    let budget = rss_budget_mib_from_env("LOW_MEM_IOS_SOAK_BUDGET_MIB", 24.0);

    let alice = Peer::new_with_identity("alice_lowmem_soak");
    let bob = Peer::new_with_identity("bob_lowmem_soak");

    alice.batch_create_messages(events);
    let sample = alice.sample_event_ids(1)[0].clone();
    let _metrics = sync_until_converged(&alice, &bob, || bob.has_event(&sample), Duration::from_secs(3600)).await;

    assert_eq!(alice.message_count(), events as i64);

    let peak = peak_rss_mib().expect("VmHWM unavailable on this platform");
    assert!(
        peak <= budget,
        "low_mem_ios soak RSS budget exceeded: peak={:.2} MiB budget={:.2} MiB events={}",
        peak,
        budget,
        events
    );
}

/// Correctness test: seed 100K transport keys and verify allow/deny via SQL lookup.
/// Ensures `is_peer_allowed` returns the correct result without materializing the
/// full trust set.
#[test]
#[cfg(target_os = "linux")]
fn large_trustset_allow_deny_correctness() {
    let _env = EnvGuard::enable_low_mem_ios();

    let alice = Peer::new_with_identity("alice_trustset_correctness");
    let fps = alice.seed_transport_keys(100_000);

    let db = open_connection(&alice.db_path).expect("open db");

    // Spot-check: first, last, and a middle key should be allowed.
    for &idx in &[0usize, 49_999, 99_999] {
        assert!(
            is_peer_allowed(&db, &alice.identity, &fps[idx]).expect("is_peer_allowed"),
            "expected allowed for seeded key index {}",
            idx
        );
    }

    // Unknown key must be denied.
    let unknown = [0xFFu8; 32];
    assert!(
        !is_peer_allowed(&db, &alice.identity, &unknown).expect("is_peer_allowed"),
        "expected denied for unknown key"
    );
}

/// Memory budget test: seed 100K transport keys, then perform lookups and verify
/// that the RSS delta stays within budget (proving we don't load the full set).
/// Uses VmRSS delta instead of VmHWM to avoid pollution from other tests sharing
/// the same process.
#[test]
#[cfg(target_os = "linux")]
fn low_mem_large_trustset_budget() {
    let _env = EnvGuard::enable_low_mem_ios();

    let alice = Peer::new_with_identity("alice_trustset_budget");
    let fps = alice.seed_transport_keys(100_000);

    let db = open_connection(&alice.db_path).expect("open db");

    // Warm the SQLite page cache so it doesn't count against our delta.
    let _warmup: i64 = db.query_row(
        "SELECT COUNT(*) FROM transport_keys WHERE recorded_by = ?1",
        rusqlite::params![&alice.identity],
        |row| row.get(0),
    ).expect("warmup query");

    let rss_before = current_rss_mib().expect("VmRSS unavailable");

    // Perform 1000 lookups across the key space.
    for i in (0..100_000).step_by(100) {
        let allowed = is_peer_allowed(&db, &alice.identity, &fps[i]).expect("lookup");
        assert!(allowed, "key {} should be allowed", i);
    }

    // Also check an unknown key.
    let unknown = [0xFFu8; 32];
    assert!(!is_peer_allowed(&db, &alice.identity, &unknown).expect("lookup unknown"));

    let rss_after = current_rss_mib().expect("VmRSS unavailable");
    let delta = rss_after - rss_before;

    // Budget: 2 MiB delta. If we were materializing 100K × 32 bytes = 3.2 MiB
    // plus HashSet overhead (~6+ MiB), this would fail.
    let budget = 2.0;
    assert!(
        delta <= budget,
        "large_trustset RSS delta exceeded: delta={:.2} MiB (before={:.2}, after={:.2}) budget={:.2} MiB",
        delta,
        rss_before,
        rss_after,
        budget
    );
}
