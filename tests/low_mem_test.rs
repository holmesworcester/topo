//! Low-memory mode budget tests.
//!
//! These tests enforce bounded memory behavior under `LOW_MEM_IOS=1`.
//! The soak test is ignored by default because it is long-running.

use std::time::Duration;

use poc_7::db::{
    open_connection,
    schema::create_tables,
    transport_trust::{has_any_trusted_peer, is_peer_allowed, trusted_peer_count},
};
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

#[tokio::test]
#[cfg(target_os = "linux")]
async fn low_mem_large_trust_set_100k() {
    let _env = EnvGuard::enable_low_mem_ios();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let conn = open_connection(tmp.path()).unwrap();
    create_tables(&conn).unwrap();

    let recorded_by = "large_trust_test";
    let count = 100_000usize;

    // Seed 100K transport_keys rows in a single transaction
    conn.execute_batch("BEGIN").unwrap();
    {
        let mut stmt = conn
            .prepare(
                "INSERT INTO transport_keys (recorded_by, event_id, spki_fingerprint) VALUES (?1, ?2, ?3)",
            )
            .unwrap();
        for i in 0..count {
            let mut spki = [0u8; 32];
            // Spread i across the first 4 bytes (little-endian) for uniqueness
            spki[0] = (i & 0xFF) as u8;
            spki[1] = ((i >> 8) & 0xFF) as u8;
            spki[2] = ((i >> 16) & 0xFF) as u8;
            spki[3] = ((i >> 24) & 0xFF) as u8;
            let event_id = format!("evt_{}", i);
            stmt.execute(rusqlite::params![recorded_by, event_id, spki.as_slice()])
                .unwrap();
        }
    }
    conn.execute_batch("COMMIT").unwrap();

    // Verify has_any_trusted_peer returns true
    assert!(has_any_trusted_peer(&conn, recorded_by).unwrap());

    // Verify trusted_peer_count returns 100,000
    assert_eq!(trusted_peer_count(&conn, recorded_by).unwrap(), count as i64);

    // Verify is_peer_allowed returns true for a known fingerprint (index 42)
    let mut known_fp = [0u8; 32];
    known_fp[0] = 42;
    let empty_pins = AllowedPeers::from_fingerprints(vec![]);
    assert!(is_peer_allowed(&conn, recorded_by, &known_fp, &empty_pins).unwrap());

    // Verify is_peer_allowed returns false for a random fingerprint
    let random_fp = [0xFFu8; 32];
    assert!(!is_peer_allowed(&conn, recorded_by, &random_fp, &empty_pins).unwrap());

    // Verify RSS stays within budget
    let peak = peak_rss_mib().expect("VmHWM unavailable on this platform");
    let budget = rss_budget_mib_from_env("LOW_MEM_IOS_BUDGET_MIB", rss_budget_mib_default());
    assert!(
        peak <= budget,
        "large trust-set RSS budget exceeded: peak={:.2} MiB budget={:.2} MiB trust_rows={}",
        peak,
        budget,
        count
    );
}
