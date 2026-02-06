//! Low-memory mode budget tests.
//!
//! These tests enforce bounded memory behavior under `LOW_MEM_IOS=1`.
//! The soak test is ignored by default because it is long-running.

use std::time::Duration;

use poc_7::testutil::{Peer, sync_until_converged};

fn test_channel(tag: &[u8; 4]) -> [u8; 32] {
    let mut ch = [0u8; 32];
    ch[0..4].copy_from_slice(tag);
    ch
}

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

    let channel = test_channel(b"lm01");
    let alice = Peer::new("alice_lowmem_smoke", channel);
    let bob = Peer::new("bob_lowmem_smoke", channel);

    alice.batch_create_messages(5_000);
    bob.batch_create_messages(5_000);

    let _metrics = sync_until_converged(&alice, &bob, 10_000, Duration::from_secs(180)).await;

    assert_eq!(alice.store_count(), 10_000);
    assert_eq!(bob.store_count(), 10_000);

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

    let channel = test_channel(b"lm02");
    let alice = Peer::new("alice_lowmem_soak", channel);
    let bob = Peer::new("bob_lowmem_soak", channel);

    alice.batch_create_messages(events);
    let _metrics = sync_until_converged(&alice, &bob, events as i64, Duration::from_secs(3600)).await;

    assert_eq!(alice.store_count(), events as i64);
    assert_eq!(bob.store_count(), events as i64);

    let peak = peak_rss_mib().expect("VmHWM unavailable on this platform");
    assert!(
        peak <= budget,
        "low_mem_ios soak RSS budget exceeded: peak={:.2} MiB budget={:.2} MiB events={}",
        peak,
        budget,
        events
    );
}
