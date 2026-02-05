//! Performance benchmarks for sync system
//!
//! Run with: cargo test --release perf_ -- --nocapture --ignored

use std::process::Command;

/// Run the demo command and extract timing
fn run_demo(events: usize, env_vars: &[(&str, &str)]) -> Option<(f64, f64)> {
    let mut cmd = Command::new("cargo");
    cmd.args(["run", "--release", "--", "demo", "--events", &events.to_string(), "--timeout", "120"]);

    for (key, val) in env_vars {
        cmd.env(key, val);
    }

    let output = cmd.output().ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);

    // Parse reconciliation time
    let mut reconciliation_time: Option<f64> = None;
    let mut sync_complete_time: Option<f64> = None;

    for line in combined.lines() {
        if line.contains("Reconciliation complete") {
            // Extract timestamp from log line like [2026-02-03T10:17:07.021474Z]
            if let Some(ts) = extract_timestamp(line) {
                reconciliation_time = Some(ts);
            }
        }
        if line.contains("Sync stats:") && !line.contains("responder") {
            if let Some(ts) = extract_timestamp(line) {
                sync_complete_time = Some(ts);
            }
        }
    }

    match (reconciliation_time, sync_complete_time) {
        (Some(r), Some(s)) => Some((r, s)),
        _ => None,
    }
}

fn extract_timestamp(line: &str) -> Option<f64> {
    // Format: [2026-02-03T10:17:07.021474Z]
    let start = line.find('T')? + 1;
    let end = line.find('Z')?;
    let time_str = &line[start..end];

    let parts: Vec<&str> = time_str.split(':').collect();
    if parts.len() != 3 {
        return None;
    }

    let hours: f64 = parts[0].parse().ok()?;
    let mins: f64 = parts[1].parse().ok()?;
    let secs: f64 = parts[2].parse().ok()?;

    Some(hours * 3600.0 + mins * 60.0 + secs)
}

#[test]
#[ignore] // Run with: cargo test --release perf_sync -- --nocapture --ignored
fn perf_sync_50k() {
    println!("\n=== Performance Test: 50k events/peer ===\n");

    let events = 50000;

    // Baseline (no dependency reads)
    println!("Running NO_DEPS baseline...");
    let baseline = run_demo(events, &[("NO_DEPS", "1")]);

    // Naive (individual queries)
    println!("Running NAIVE (individual queries)...");
    let naive = run_demo(events, &[("NAIVE_DEPS", "1")]);

    // Batched (IN query)
    println!("Running BATCHED (IN query)...");
    let batched = run_demo(events, &[]);

    println!("\n=== Results ===\n");
    println!("| Mode | Transfer Time | vs Baseline |");
    println!("|------|---------------|-------------|");

    if let Some((recon, sync)) = baseline {
        let transfer = sync - recon;
        println!("| NO_DEPS (baseline) | {:.2}s | - |", transfer);

        if let Some((r2, s2)) = naive {
            let t2 = s2 - r2;
            let overhead = ((t2 / transfer) - 1.0) * 100.0;
            println!("| NAIVE | {:.2}s | +{:.0}% |", t2, overhead);
        }

        if let Some((r3, s3)) = batched {
            let t3 = s3 - r3;
            let overhead = ((t3 / transfer) - 1.0) * 100.0;
            println!("| BATCHED | {:.2}s | +{:.0}% |", t3, overhead);
        }
    }

    if let (Some((_, _)), Some((r2, s2)), Some((r3, s3))) = (baseline, naive, batched) {
        let naive_time = s2 - r2;
        let batched_time = s3 - r3;
        let speedup = ((naive_time / batched_time) - 1.0) * 100.0;
        println!("\nBATCHED is {:.0}% faster than NAIVE", speedup);
    }

    println!("\n=== Test Complete ===\n");
}

#[test]
#[ignore]
fn perf_sync_scaling() {
    println!("\n=== Scaling Test ===\n");
    println!("| Events/peer | Transfer Time |");
    println!("|-------------|---------------|");

    for events in [1000, 5000, 10000, 25000] {
        if let Some((recon, sync)) = run_demo(events, &[("NO_DEPS", "1")]) {
            let transfer = sync - recon;
            println!("| {} | {:.2}s |", events, transfer);
        }
    }

    println!("\n=== Test Complete ===\n");
}
