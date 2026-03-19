//! Linux `tc` (traffic control) based network shaper for validation tests.
//!
//! Uses kernel `htb` + `netem` qdiscs on the loopback interface to impose
//! real bandwidth limits, propagation delay, jitter, and packet loss on
//! traffic between two specific UDP ports.  This provides ground-truth
//! validation that the userspace `UdpTrafficShaper` produces comparable
//! results.
//!
//! **Requires**: Linux, `tc` binary in PATH, CAP_NET_ADMIN (typically root).
//! Tests using this module should be `#[ignore]` and gated on
//! `PERF_LINUX_TC=1`.

use std::net::SocketAddr;
use std::process::Command;

/// Check whether Linux tc-based shaping is available and requested.
///
/// Returns `true` when all of:
/// - `PERF_LINUX_TC=1` environment variable is set
/// - Running on Linux
/// - `tc` binary is in PATH and can query the loopback qdisc
pub fn tc_shaping_available() -> bool {
    if std::env::var("PERF_LINUX_TC").unwrap_or_default() != "1" {
        return false;
    }
    if !cfg!(target_os = "linux") {
        eprintln!("tc shaping requested but not on Linux");
        return false;
    }
    // Probe: can we actually modify lo qdiscs?  Try adding and immediately
    // removing a harmless pfifo_fast qdisc.  This catches the common case
    // where `tc` exists but we lack CAP_NET_ADMIN.
    let add = Command::new("tc")
        .args([
            "qdisc",
            "add",
            "dev",
            "lo",
            "root",
            "handle",
            "9999:",
            "pfifo_fast",
        ])
        .output();
    match add {
        Ok(out) if out.status.success() => {
            // Clean up the probe qdisc.
            let _ = Command::new("tc")
                .args(["qdisc", "del", "dev", "lo", "root", "handle", "9999:"])
                .output();
            true
        }
        Ok(out) => {
            eprintln!(
                "tc probe: no permission to modify lo qdiscs (exit {}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
            false
        }
        Err(e) => {
            eprintln!("tc binary not found: {e}");
            false
        }
    }
}

/// RAII guard that sets up `tc` qdiscs on loopback for two ports and tears
/// them down on drop.
pub struct TcLoopbackShaper {
    /// Whether we successfully installed rules (and therefore need to clean up).
    installed: bool,
}

impl TcLoopbackShaper {
    /// Set up HTB + netem shaping on lo for traffic between `addr_a` and `addr_b`.
    ///
    /// The shaping is symmetric: both A→B and B→A see the same bandwidth cap,
    /// delay, and loss.  Delay is configured as `rtt_ms / 2` per direction
    /// (each packet traverses the egress qdisc once on loopback).
    ///
    /// All other loopback traffic passes through an unlimited default class.
    pub fn new(
        addr_a: SocketAddr,
        addr_b: SocketAddr,
        bandwidth_mbps: f64,
        rtt_ms: u64,
        jitter_ms: u64,
        loss_percent: f64,
    ) -> Result<Self, String> {
        let port_a = addr_a.port();
        let port_b = addr_b.port();
        let half_delay_ms = rtt_ms / 2;
        let bw_kbit = (bandwidth_mbps * 1000.0) as u64;
        // Burst must be at least 1 MTU; use bandwidth * 10ms or 32kb minimum.
        let burst_bytes = ((bandwidth_mbps * 1_000_000.0 / 8.0) * 0.01) as u64;
        let burst_kb = burst_bytes.max(32 * 1024) / 1024;

        // Clean up any leftover rules from a prior crashed run.
        let _ = Command::new("tc")
            .args(["qdisc", "del", "dev", "lo", "root"])
            .output();

        // Root HTB qdisc with unlimited default class.
        tc_run(&[
            "qdisc", "add", "dev", "lo", "root", "handle", "1:", "htb", "default", "10",
        ])?;
        tc_run(&[
            "class", "add", "dev", "lo", "parent", "1:", "classid", "1:10", "htb", "rate", "10gbit",
        ])?;

        // Shaped class with bandwidth cap.
        let rate_str = format!("{bw_kbit}kbit");
        tc_run(&[
            "class",
            "add",
            "dev",
            "lo",
            "parent",
            "1:",
            "classid",
            "1:20",
            "htb",
            "rate",
            &rate_str,
            "ceil",
            &rate_str,
            "burst",
            &format!("{burst_kb}kb"),
        ])?;

        // Netem leaf under the shaped class for delay/jitter/loss.
        let mut netem_args: Vec<&str> = vec![
            "qdisc", "add", "dev", "lo", "parent", "1:20", "handle", "20:", "netem",
        ];
        let delay_str = format!("{half_delay_ms}ms");
        let jitter_str = format!("{jitter_ms}ms");
        let loss_str = format!("{loss_percent}%");
        if half_delay_ms > 0 || jitter_ms > 0 {
            netem_args.extend_from_slice(&["delay", &delay_str]);
            if jitter_ms > 0 {
                netem_args.push(&jitter_str);
            }
        }
        if loss_percent > 0.0 {
            netem_args.extend_from_slice(&["loss", &loss_str]);
        }
        // If no impairment at all, netem still needs to exist as a leaf.
        tc_run(&netem_args)?;

        // Filters: match traffic involving either port into the shaped class.
        let port_a_str = format!("{port_a}");
        let port_b_str = format!("{port_b}");
        for port_str in [&port_a_str, &port_b_str] {
            // Match dport
            tc_run(&[
                "filter", "add", "dev", "lo", "parent", "1:0", "protocol", "ip", "prio", "1",
                "u32", "match", "ip", "dport", port_str, "0xffff", "flowid", "1:20",
            ])?;
            // Match sport
            tc_run(&[
                "filter", "add", "dev", "lo", "parent", "1:0", "protocol", "ip", "prio", "1",
                "u32", "match", "ip", "sport", port_str, "0xffff", "flowid", "1:20",
            ])?;
        }

        eprintln!(
            "[tc-shaper] installed on lo: ports {port_a},{port_b} \
             bw={bandwidth_mbps}Mbps delay={half_delay_ms}ms jitter={jitter_ms}ms loss={loss_percent}%"
        );
        Ok(Self { installed: true })
    }
}

impl Drop for TcLoopbackShaper {
    fn drop(&mut self) {
        if self.installed {
            let _ = Command::new("tc")
                .args(["qdisc", "del", "dev", "lo", "root"])
                .output();
            eprintln!("[tc-shaper] cleaned up lo qdiscs");
        }
    }
}

fn tc_run(args: &[&str]) -> Result<(), String> {
    let out = Command::new("tc")
        .args(args)
        .output()
        .map_err(|e| format!("tc exec failed: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "tc {} failed (exit {}): {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}
