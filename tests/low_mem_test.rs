//! Low-memory mode budget tests.
//!
//! These tests enforce bounded memory behavior under `LOW_MEM_IOS=1`.
//! The soak test is ignored by default because it is long-running.

use std::time::Duration;

use poc_7::db::{open_connection, transport_trust};
use poc_7::testutil::{Peer, sync_until_converged};
use poc_7::transport::AllowedPeers;



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

/// Current resident set size (VmRSS). Unlike VmHWM this reflects current
/// memory usage and can decrease after allocations are freed.
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

fn rss_budget_mib_default() -> f64 {
    if cfg!(debug_assertions) {
        28.0
    } else {
        24.0
    }
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

    // 6 identity per peer + 10k content; after sync each has 6 own + 5 other shared + 10k = 10011
    let expected_store = 10_000 + 11;
    let _metrics = sync_until_converged(&alice, &bob, expected_store, Duration::from_secs(180)).await;

    assert_eq!(alice.store_count(), expected_store);
    assert_eq!(bob.store_count(), expected_store);

    let peak = peak_rss_mib().expect("VmHWM unavailable on this platform");
    let budget = rss_budget_mib_from_env("LOW_MEM_IOS_BUDGET_MIB", rss_budget_mib_default());
    assert!(
        peak <= budget,
        "low_mem_ios RSS budget exceeded: peak={:.2} MiB budget={:.2} MiB",
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
    // 6 identity per peer + N content; after sync each has 6 own + 5 other shared + N = N + 11
    let expected_store = events as i64 + 11;
    let _metrics = sync_until_converged(&alice, &bob, expected_store, Duration::from_secs(3600)).await;

    assert_eq!(alice.store_count(), expected_store);
    assert_eq!(bob.store_count(), expected_store);

    let peak = peak_rss_mib().expect("VmHWM unavailable on this platform");
    assert!(
        peak <= budget,
        "low_mem_ios soak RSS budget exceeded: peak={:.2} MiB budget={:.2} MiB events={}",
        peak,
        budget,
        events
    );
}

// ---------------------------------------------------------------------------
// Large trust-set tests (Phase 6)
// ---------------------------------------------------------------------------

/// Seed 100_000 transport keys and verify allow/deny correctness using
/// is_peer_allowed (SQL indexed lookup, no full-set materialization).
#[test]
fn large_trustset_allow_deny_correctness() {
    let peer = Peer::new_with_identity("large_trust_correctness");
    let fps = peer.seed_transport_keys(100_000);

    let db = open_connection(&peer.db_path).expect("open db");
    let cli_pins = AllowedPeers::from_fingerprints(vec![]);

    // Spot-check: first, last, and a middle entry should be allowed
    for &idx in &[0, 49_999, 99_999] {
        assert!(
            transport_trust::is_peer_allowed(&db, &peer.identity, &fps[idx], &cli_pins).unwrap(),
            "trusted key at index {} should be allowed",
            idx,
        );
    }

    // An unknown fingerprint must be denied
    let unknown: [u8; 32] = [0xFFu8; 32];
    assert!(
        !transport_trust::is_peer_allowed(&db, &peer.identity, &unknown, &cli_pins).unwrap(),
        "unknown fingerprint should be denied",
    );

    // has_any_trust should return true
    assert!(transport_trust::has_any_trust(&db, &peer.identity).unwrap());

    // trust_source_count should match
    let count = transport_trust::trust_source_count(&db, &peer.identity).unwrap();
    assert_eq!(count, 100_000, "trust_source_count should be 100_000");
}

/// Under low-memory mode, the startup and handshake trust paths must not
/// materialize the full trust set into Rust heap memory.
///
/// Strategy: open the DB and warm the SQLite page cache first, then measure
/// RSS delta across has_any_trust_combined + is_peer_allowed. If these paths
/// materialized 100K fingerprints into a HashSet, we'd see ~6+ MiB growth
/// (32 bytes * 100K plus HashSet overhead). The SQL-only paths should add
/// negligible Rust-side memory.
///
/// Uses VmRSS delta (not VmHWM) so this test doesn't pollute the process-wide
/// peak for other tests sharing the same binary.
#[tokio::test]
#[cfg(target_os = "linux")]
async fn low_mem_large_trustset_budget() {
    let _env = EnvGuard::enable_low_mem_ios();

    let peer = Peer::new_with_identity("large_trust_lowmem");
    let fps = peer.seed_transport_keys(100_000);

    let db = open_connection(&peer.db_path).expect("open db");
    let cli_pins = AllowedPeers::from_fingerprints(vec![]);

    // Warm the SQLite page cache with a throwaway query so that DB I/O
    // overhead does not inflate the delta.
    let _: i64 = db.query_row(
        "SELECT COUNT(*) FROM transport_keys WHERE recorded_by = ?1",
        rusqlite::params![&peer.identity],
        |row| row.get(0),
    ).unwrap();

    // Measure RSS after cache is warm but before trust operations
    let rss_before = current_rss_mib().expect("VmRSS unavailable");

    // Exercise the non-materializing startup check (replaces is_empty)
    assert!(transport_trust::has_any_trust_combined(&db, &peer.identity, &cli_pins).unwrap());

    // Exercise point lookups (the hot path during handshakes)
    for &idx in &[0, 25_000, 50_000, 75_000, 99_999] {
        assert!(
            transport_trust::is_peer_allowed(&db, &peer.identity, &fps[idx], &cli_pins).unwrap(),
        );
    }
    let unknown: [u8; 32] = [0xFFu8; 32];
    assert!(!transport_trust::is_peer_allowed(&db, &peer.identity, &unknown, &cli_pins).unwrap());

    let rss_after = current_rss_mib().expect("VmRSS unavailable");
    // SQL EXISTS/point-lookup paths should add <2 MiB on top of warmed cache.
    // Full materialization would cost ~6+ MiB (32 * 100K + HashSet overhead).
    let delta = rss_after - rss_before;
    let max_delta_mib: f64 = 2.0;
    assert!(
        delta <= max_delta_mib,
        "large trustset low-mem RSS delta too high: before={:.2} MiB, after={:.2} MiB, delta={:.2} MiB (max {:.2} MiB), trust_keys=100000",
        rss_before,
        rss_after,
        delta,
        max_delta_mib,
    );
}
