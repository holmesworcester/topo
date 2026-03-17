//! Daemon-based sync throughput benchmarks under realistic network shaping.
//!
//! The profiles here model peer-to-peer bottlenecks rather than headline
//! speedtest download numbers, because our sync path is constrained by the
//! slower full-duplex access side between two peers.

mod cli_harness;
mod daemon_perf_harness;
mod perf_network_shaper;

use std::net::SocketAddr;
use std::time::Duration;

use daemon_perf_harness::{
    run_bidirectional_sync, run_continuous_sync, run_one_way_sync, write_summary, BenchNetworkPath,
    PerfMeasurement, SharedWorkspaceBench,
};
use perf_network_shaper::{
    clear_realistic_network_env, repeat_count_from_env, selected_profiles_from_env, NetworkProfile,
    UdpTrafficShaper, REALISTIC_NETWORK_PROFILES,
};

struct MatrixMeasurement {
    profile: NetworkProfile,
    repeat: usize,
    measurement: PerfMeasurement,
}

fn shaped_network_path(
    profile: NetworkProfile,
    alice_direct_addr: String,
    bob_direct_addr: String,
) -> BenchNetworkPath {
    let alice_real_addr = alice_direct_addr
        .parse::<SocketAddr>()
        .unwrap_or_else(|_| panic!("parse daemon listen addr `{alice_direct_addr}`"));
    let bob_real_addr = bob_direct_addr
        .parse::<SocketAddr>()
        .unwrap_or_else(|_| panic!("parse daemon listen addr `{bob_direct_addr}`"));
    let shaper = UdpTrafficShaper::new(alice_real_addr, bob_real_addr, bootstrap_profile(profile));
    let controller = shaper.controller();
    BenchNetworkPath {
        bootstrap_addr: shaper.left_addr().to_string(),
        guard: Some(Box::new(shaper)),
        activate_after_ready: Some(Box::new(move || controller.set_profile(profile))),
        disable_alice_placeholder_autodial: false,
        disable_bob_placeholder_autodial: false,
        reseed_bob_bootstrap_after_activate: true,
    }
}

fn bootstrap_profile(profile: NetworkProfile) -> NetworkProfile {
    NetworkProfile {
        bandwidth_mbps_per_direction: 1_000.0,
        rtt_ms: 0,
        jitter_ms: 0,
        loss_percent: 0.0,
        ..profile
    }
}

fn run_profile_matrix<F>(summary_key: &str, title: &str, runner: F)
where
    F: Fn(NetworkProfile) -> PerfMeasurement,
{
    let profiles = selected_profiles_from_env();
    let repeats = repeat_count_from_env();
    clear_realistic_network_env();
    let mut measurements = Vec::new();

    for profile in profiles {
        for repeat in 1..=repeats {
            eprintln!(
                "\n=== realistic-network profile={} repeat={}/{} ===",
                profile.slug, repeat, repeats
            );
            measurements.push(MatrixMeasurement {
                profile,
                repeat,
                measurement: runner(profile),
            });
        }
    }

    let summary = format_matrix_summary(title, repeats, &measurements);
    eprintln!("\n{summary}");
    write_summary(summary_key, &summary);
}

fn format_matrix_summary(
    title: &str,
    repeats: usize,
    measurements: &[MatrixMeasurement],
) -> String {
    let mut summary = format!(
        "=== {title} ===\n  Profiles:     {}\n  Repeats/profile: {repeats}\n",
        measurements
            .iter()
            .map(|entry| entry.profile.slug)
            .collect::<Vec<_>>()
            .join(",")
    );

    for entry in measurements {
        summary.push_str(&format!(
            "\n  Profile:      {} ({})\n  Repeat:       {}/{}\n  Note:         {}\n  Bandwidth:    {:.1} Mbps/dir\n  RTT:          {} ms\n  Jitter:       +/- {} ms\n  Loss:         {:.2}%\n  Wall time:    {:.2}s\n  Generate:     {:.2}s\n  Sync wait:    {:.2}s\n  Messages:     {}\n  Msgs/s:       {:.0}\n  Peak RSS:     {:.1} MiB (max daemon VmHWM)\n  Alice peak RSS: {:.1} MiB\n  Bob peak RSS:   {:.1} MiB\n",
            entry.profile.title,
            entry.profile.slug,
            entry.repeat,
            repeats,
            entry.profile.note,
            entry.profile.bandwidth_mbps_per_direction,
            entry.profile.rtt_ms,
            entry.profile.jitter_ms,
            entry.profile.loss_percent,
            entry.measurement.wall_secs,
            entry.measurement.generate_secs,
            entry.measurement.sync_wait_secs,
            entry.measurement.messages,
            entry.measurement.msgs_per_sec,
            entry.measurement.max_rss,
            entry.measurement.alice_rss,
            entry.measurement.bob_rss,
        ));
    }

    summary
}

#[test]
#[ignore]
fn perf_sync_2k_realistic_profiles() {
    run_profile_matrix(
        "daemon_realistic_network_perf_test.perf_sync_2k_realistic_profiles",
        "2k bidirectional sync (daemon, warm, realistic network matrix)",
        |profile| {
            run_bidirectional_sync(
                1_000,
                Duration::from_secs(300),
                Duration::from_secs(300),
                move |alice_direct_addr, bob_direct_addr| {
                    shaped_network_path(profile, alice_direct_addr, bob_direct_addr)
                },
            )
        },
    );
}

#[test]
#[ignore]
fn perf_sync_10k_realistic_profiles() {
    run_profile_matrix(
        "daemon_realistic_network_perf_test.perf_sync_10k_realistic_profiles",
        "10k bidirectional sync (daemon, warm, realistic network matrix)",
        |profile| {
            run_bidirectional_sync(
                5_000,
                Duration::from_secs(300),
                Duration::from_secs(300),
                move |alice_direct_addr, bob_direct_addr| {
                    shaped_network_path(profile, alice_direct_addr, bob_direct_addr)
                },
            )
        },
    );
}

#[test]
#[ignore]
fn perf_continuous_10k_realistic_profiles() {
    run_profile_matrix(
        "daemon_realistic_network_perf_test.perf_continuous_10k_realistic_profiles",
        "10k continuous sync (daemon, warm, realistic network matrix)",
        |profile| {
            run_continuous_sync(
                5_000,
                Duration::from_secs(300),
                Duration::from_secs(600),
                move |alice_direct_addr, bob_direct_addr| {
                    shaped_network_path(profile, alice_direct_addr, bob_direct_addr)
                },
            )
        },
    );
}

#[test]
#[ignore]
fn perf_sync_50k_realistic_profiles() {
    run_profile_matrix(
        "daemon_realistic_network_perf_test.perf_sync_50k_realistic_profiles",
        "50k one-way sync (daemon, warm, realistic network matrix)",
        |profile| {
            run_one_way_sync(
                50_000,
                Duration::from_secs(300),
                Duration::from_secs(900),
                move |alice_direct_addr, bob_direct_addr| {
                    shaped_network_path(profile, alice_direct_addr, bob_direct_addr)
                },
            )
        },
    );
}

#[test]
#[ignore]
fn perf_sync_100k_realistic_profiles() {
    run_profile_matrix(
        "daemon_realistic_network_perf_test.perf_sync_100k_realistic_profiles",
        "100k one-way sync (daemon, warm, realistic network matrix)",
        |profile| {
            run_one_way_sync(
                100_000,
                Duration::from_secs(300),
                Duration::from_secs(1_800),
                move |alice_direct_addr, bob_direct_addr| {
                    shaped_network_path(profile, alice_direct_addr, bob_direct_addr)
                },
            )
        },
    );
}

#[test]
#[ignore]
fn perf_sync_200k_realistic_profiles() {
    run_profile_matrix(
        "daemon_realistic_network_perf_test.perf_sync_200k_realistic_profiles",
        "200k one-way sync (daemon, warm, realistic network matrix)",
        |profile| {
            run_one_way_sync(
                200_000,
                Duration::from_secs(300),
                Duration::from_secs(3_600),
                move |alice_direct_addr, bob_direct_addr| {
                    shaped_network_path(profile, alice_direct_addr, bob_direct_addr)
                },
            )
        },
    );
}

#[test]
#[ignore]
fn perf_sync_500k_realistic_profiles() {
    run_profile_matrix(
        "daemon_realistic_network_perf_test.perf_sync_500k_realistic_profiles",
        "500k one-way sync (daemon, warm, realistic network matrix)",
        |profile| {
            run_one_way_sync(
                500_000,
                Duration::from_secs(300),
                Duration::from_secs(7_200),
                move |alice_direct_addr, bob_direct_addr| {
                    shaped_network_path(profile, alice_direct_addr, bob_direct_addr)
                },
            )
        },
    );
}

#[test]
fn realistic_network_bench_construction_smoke() {
    clear_realistic_network_env();
    let _bench = SharedWorkspaceBench::new_with_network(|alice_direct_addr, bob_direct_addr| {
        shaped_network_path(
            NetworkProfile {
                slug: "smoke",
                title: "Smoke",
                note: "construction smoke",
                bandwidth_mbps_per_direction: 2.0,
                rtt_ms: 0,
                jitter_ms: 0,
                loss_percent: 0.0,
            },
            alice_direct_addr,
            bob_direct_addr,
        )
    });
}

#[test]
#[ignore]
fn realistic_cable_bidirectional_sync_smoke() {
    clear_realistic_network_env();
    let cable = REALISTIC_NETWORK_PROFILES
        .iter()
        .copied()
        .find(|profile| profile.slug == "cable")
        .expect("cable profile");
    let measurement = run_bidirectional_sync(
        50,
        Duration::from_secs(300),
        Duration::from_secs(300),
        move |alice_direct_addr, bob_direct_addr| {
            shaped_network_path(cable, alice_direct_addr, bob_direct_addr)
        },
    );
    assert_eq!(measurement.messages, 100);
}
