#![allow(dead_code)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use crate::cli_harness::{
    accept_invite_with_identity_on_running_daemon, active_tenant_peer_id, assert_eventually,
    create_invite_with_spki, daemon_listen_addr, daemon_transport_fingerprint, ensure_active_peer,
    generate_messages, message_count_sql, peak_rss_mib_for_pid, random_port, send_message,
    start_daemon_with_options, stop_daemon, topo_cmd, wait_for_active_tenant_ready,
    wait_for_daemon_stopped, wait_for_endpoint_observation, DaemonOptions, HarnessDaemon,
};
use crate::perf_metrics::{
    bandwidth_summary, delay_from, diff_new_ids, enable_projection_timeline, max_opt, min_opt,
    projection_window, recorded_message_event_ids, total_event_blob_bytes,
};

pub type BenchNetworkGuard = Box<dyn std::any::Any + Send>;
pub type BenchReadyHook = Box<dyn FnMut() + Send>;

pub struct BenchNetworkPath {
    pub bootstrap_addr: String,
    pub guard: Option<BenchNetworkGuard>,
    pub activate_after_ready: Option<BenchReadyHook>,
    pub disable_alice_placeholder_autodial: bool,
    pub disable_bob_placeholder_autodial: bool,
    pub reseed_bob_bootstrap_after_activate: bool,
}

struct BootstrapSeed {
    invite_event_id_b64: String,
    bootstrap_addr: String,
    bootstrap_spki_hex: String,
}

impl BenchNetworkPath {
    pub fn direct(bootstrap_addr: String, _bob_direct_addr: String) -> Self {
        Self {
            bootstrap_addr,
            guard: None,
            activate_after_ready: None,
            disable_alice_placeholder_autodial: false,
            disable_bob_placeholder_autodial: false,
            reseed_bob_bootstrap_after_activate: false,
        }
    }
}

pub struct SharedWorkspaceBench {
    tmpdir: Option<tempfile::TempDir>,
    tmpdir_path: PathBuf,
    keep_tmpdir: bool,
    pub alice_db: String,
    pub bob_db: String,
    alice_daemon: HarnessDaemon,
    alice_pid: u32,
    alice_bind_addr: SocketAddr,
    alice_transport_peer_id: String,
    bob_daemon: HarnessDaemon,
    bob_pid: u32,
    alice_disable_placeholder_autodial: bool,
    bob_disable_placeholder_autodial: bool,
    activate_after_warmup: Option<BenchReadyHook>,
    bob_bootstrap_seed_after_activate: Option<BootstrapSeed>,
    _network_guard: Option<BenchNetworkGuard>,
}

impl SharedWorkspaceBench {
    pub fn new() -> Self {
        Self::new_with_network(BenchNetworkPath::direct)
    }

    pub fn new_with_network<F>(configure_network: F) -> Self
    where
        F: FnOnce(String, String) -> BenchNetworkPath,
    {
        let keep_tmpdir = perf_debug_env("PERF_KEEP_TMPDIR");
        let (tmpdir, tmpdir_path) = if keep_tmpdir {
            let path = tempfile::tempdir().unwrap().keep();
            eprintln!(
                "PERF_KEEP_TMPDIR=1: preserving benchmark artifacts under {}",
                path.display()
            );
            (None, path)
        } else {
            let tmpdir = tempfile::tempdir().unwrap();
            let path = tmpdir.path().to_path_buf();
            (Some(tmpdir), path)
        };

        let alice_db = tmpdir_path.join("alice.db").to_str().unwrap().to_string();
        let bob_db = tmpdir_path.join("bob.db").to_str().unwrap().to_string();

        create_workspace_direct(&alice_db, "user", "device");
        let mut alice_daemon = start_perf_daemon(&alice_db, &tmpdir_path, "alice", false, None);
        let alice_pid = alice_daemon.child().id();
        let alice_direct_addr = daemon_listen_addr(&alice_db);
        let alice_transport_peer_id = daemon_transport_fingerprint(&alice_db);
        let alice_bind_addr = alice_direct_addr
            .parse::<SocketAddr>()
            .unwrap_or_else(|_| panic!("parse daemon listen addr `{alice_direct_addr}`"));
        let bob_bind_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, random_port()));
        let network_path = configure_network(alice_direct_addr.clone(), bob_bind_addr.to_string());
        let use_fixed_bob_bind = network_path.guard.is_some();
        if use_fixed_bob_bind {
            assert!(
                !network_path.disable_bob_placeholder_autodial,
                "disable_bob_placeholder_autodial is not supported when network shaping needs Bob's live listen addr"
            );
        }
        let invite_link = create_invite_with_spki(
            &alice_db,
            &network_path.bootstrap_addr,
            Some(&daemon_transport_fingerprint(&alice_db)),
        );
        let bob_bootstrap_seed_after_activate = if network_path.reseed_bob_bootstrap_after_activate
        {
            let parsed_invite =
                topo::event_modules::workspace::invite_link::parse_invite_link(&invite_link)
                    .expect("parse invite link for bootstrap reseed");
            Some(BootstrapSeed {
                invite_event_id_b64: topo::crypto::event_id_to_base64(
                    &parsed_invite.invite_event_id,
                ),
                bootstrap_addr: network_path.bootstrap_addr.clone(),
                bootstrap_spki_hex: hex::encode(parsed_invite.bootstrap_spki_fingerprint),
            })
        } else {
            None
        };
        let mut bob_daemon = if use_fixed_bob_bind {
            let mut bob_accept_daemon = start_perf_daemon(
                &bob_db,
                &tmpdir_path,
                "bob-accept",
                false,
                Some(bob_bind_addr),
            );
            accept_invite_with_identity_on_running_daemon(
                &bob_db,
                &invite_link,
                "bob",
                "laptop",
                Duration::from_secs(10),
            );
            stop_daemon(&bob_db, &mut bob_accept_daemon);
            wait_for_daemon_stopped(&bob_db, Duration::from_secs(10));
            start_perf_daemon(&bob_db, &tmpdir_path, "bob", false, Some(bob_bind_addr))
        } else {
            accept_invite_direct(&bob_db, &invite_link, "bob", "laptop");
            start_perf_daemon(&bob_db, &tmpdir_path, "bob", false, None)
        };
        let bob_pid = bob_daemon.child().id();

        ensure_active_peer(&alice_db, Duration::from_secs(10));
        ensure_active_peer(&bob_db, Duration::from_secs(10));
        let ready_timeout = perf_ready_timeout();
        wait_for_active_tenant_ready(&alice_db, ready_timeout);
        wait_for_active_tenant_ready(&bob_db, ready_timeout);
        maybe_enable_sync_logging(&alice_db);
        maybe_enable_sync_logging(&bob_db);

        Self {
            tmpdir,
            tmpdir_path,
            keep_tmpdir,
            alice_db,
            bob_db,
            alice_daemon,
            alice_pid,
            alice_bind_addr,
            alice_transport_peer_id,
            bob_daemon,
            bob_pid,
            alice_disable_placeholder_autodial: true,
            bob_disable_placeholder_autodial: network_path.disable_bob_placeholder_autodial,
            activate_after_warmup: network_path.activate_after_ready,
            bob_bootstrap_seed_after_activate,
            _network_guard: network_path.guard,
        }
    }

    pub fn warm_one_way(&self, timeout: Duration) -> i64 {
        let baseline = message_count_sql(&self.bob_db);
        let warm_eid = send_message(&self.alice_db, "warmup-alice");
        assert_eventually(
            &self.bob_db,
            &format!("has_event:{} >= 1", warm_eid),
            timeout.as_millis() as u64,
        );
        wait_for_message_count(&self.bob_db, baseline + 1, timeout);
        message_count_sql(&self.bob_db)
    }

    pub fn warm_bidirectional(&self, timeout: Duration) -> i64 {
        let alice_baseline = message_count_sql(&self.alice_db);
        let bob_baseline = message_count_sql(&self.bob_db);
        let alice_eid = send_message(&self.alice_db, "warmup-alice");
        let bob_eid = send_message(&self.bob_db, "warmup-bob");

        assert_eventually(
            &self.alice_db,
            &format!("has_event:{} >= 1", bob_eid),
            timeout.as_millis() as u64,
        );
        assert_eventually(
            &self.bob_db,
            &format!("has_event:{} >= 1", alice_eid),
            timeout.as_millis() as u64,
        );
        wait_for_message_count(&self.alice_db, alice_baseline + 2, timeout);
        wait_for_message_count(&self.bob_db, bob_baseline + 2, timeout);
        message_count_sql(&self.alice_db)
    }

    pub fn daemon_rss(&self) -> (f64, f64, f64) {
        let alice = peak_rss_mib_for_pid(self.alice_pid).expect("alice VmHWM unavailable");
        let bob = peak_rss_mib_for_pid(self.bob_pid).expect("bob VmHWM unavailable");
        (alice, bob, alice.max(bob))
    }

    pub fn stabilize_bootstrap_joiner(&self, timeout: Duration) {
        wait_for_endpoint_observation(&self.bob_db, &self.alice_transport_peer_id, timeout);
        self.warm_bidirectional(timeout);
    }

    pub fn has_pending_network_profile_activation(&self) -> bool {
        self.activate_after_warmup.is_some()
    }

    pub fn activate_network_profile(&mut self) {
        if let Some(mut activate_after_warmup) = self.activate_after_warmup.take() {
            activate_after_warmup();
            ensure_active_peer(&self.alice_db, Duration::from_secs(10));
            ensure_active_peer(&self.bob_db, Duration::from_secs(10));
        }
    }
}

impl Drop for SharedWorkspaceBench {
    fn drop(&mut self) {
        let _ = self.alice_daemon.child().try_wait();
        let _ = self.bob_daemon.child().try_wait();
        if self.keep_tmpdir {
            eprintln!(
                "preserved perf benchmark artifacts at {}",
                self.tmpdir_path.display()
            );
            return;
        }
        if let Some(tmpdir) = self.tmpdir.take() {
            drop(tmpdir);
        }
    }
}

pub struct PerfMeasurement {
    pub wall_secs: f64,
    pub generate_secs: f64,
    pub sync_wait_secs: f64,
    pub messages: i64,
    pub msgs_per_sec: f64,
    pub first_recorded_at_delay_ms: Option<i64>,
    pub last_recorded_at_delay_ms: Option<i64>,
    pub first_projected_at_delay_ms: Option<i64>,
    pub last_projected_at_delay_ms: Option<i64>,
    pub projected_tail_ms: Option<i64>,
    pub payload_bytes: u64,
    pub payload_mib_s: f64,
    pub payload_mbps: f64,
    pub perfect_payload_mbps: Option<f64>,
    pub estimated_quic_ceiling_mbps: Option<f64>,
    pub bandwidth_saturation_pct: Option<f64>,
    pub alice_rss: f64,
    pub bob_rss: f64,
    pub max_rss: f64,
}

struct BenchProjectionSnapshot {
    first_recorded_at_delay_ms: Option<i64>,
    last_recorded_at_delay_ms: Option<i64>,
    first_projected_at_delay_ms: Option<i64>,
    last_projected_at_delay_ms: Option<i64>,
    projected_tail_ms: Option<i64>,
    payload_bytes: u64,
}

fn daemon_perf_extra_env() -> Vec<(String, String)> {
    enable_projection_timeline();
    vec![
        ("TOPO_EVENT_TIMELINE".to_string(), "1".to_string()),
        (
            "TOPO_EVENT_TIMELINE_GROUPS".to_string(),
            "projection".to_string(),
        ),
    ]
}

fn active_peer_id_or_panic(db: &str) -> String {
    active_tenant_peer_id(db).unwrap_or_else(|| panic!("missing active tenant for db={db}"))
}

fn summarize_projection_windows(
    request_start_ms: i64,
    windows: &[crate::perf_metrics::ProjectionWindow],
    payload_bytes: u64,
) -> BenchProjectionSnapshot {
    let mut first_recorded_at = None;
    let mut last_recorded_at = None;
    let mut first_projected_at = None;
    let mut last_projected_at = None;

    for window in windows {
        first_recorded_at = min_opt(first_recorded_at, window.recorded_at.first_at_ms);
        last_recorded_at = max_opt(last_recorded_at, window.recorded_at.last_at_ms);
        first_projected_at = min_opt(first_projected_at, window.projected_at.first_at_ms);
        last_projected_at = max_opt(last_projected_at, window.projected_at.last_at_ms);
    }

    let first_recorded_at_delay_ms = delay_from(request_start_ms, first_recorded_at);
    let last_recorded_at_delay_ms = delay_from(request_start_ms, last_recorded_at);
    let first_projected_at_delay_ms = delay_from(request_start_ms, first_projected_at);
    let last_projected_at_delay_ms = delay_from(request_start_ms, last_projected_at);
    let projected_tail_ms = match (last_recorded_at, last_projected_at) {
        (Some(recorded), Some(projected)) => Some(projected.saturating_sub(recorded)),
        _ => None,
    };

    BenchProjectionSnapshot {
        first_recorded_at_delay_ms,
        last_recorded_at_delay_ms,
        first_projected_at_delay_ms,
        last_projected_at_delay_ms,
        projected_tail_ms,
        payload_bytes,
    }
}

pub fn run_one_way_sync<F>(
    message_count: i64,
    warm_timeout: Duration,
    sync_timeout: Duration,
    configure_network: F,
) -> PerfMeasurement
where
    F: FnOnce(String, String) -> BenchNetworkPath,
{
    let mut bench = SharedWorkspaceBench::new_with_network(configure_network);
    if bench.has_pending_network_profile_activation() {
        bench.stabilize_bootstrap_joiner(warm_timeout);
    }
    bench.activate_network_profile();
    let baseline = bench.warm_one_way(warm_timeout);
    let alice_peer_id = active_peer_id_or_panic(&bench.alice_db);
    let bob_peer_id = active_peer_id_or_panic(&bench.bob_db);
    let alice_baseline_ids = recorded_message_event_ids(&bench.alice_db, &alice_peer_id);

    let start = Instant::now();
    let request_start_ms = current_timestamp_ms();
    let generate_start = Instant::now();
    generate_messages(&bench.alice_db, message_count as usize);
    let generate_secs = generate_start.elapsed().as_secs_f64();
    let alice_target_ids = diff_new_ids(
        &alice_baseline_ids,
        &recorded_message_event_ids(&bench.alice_db, &alice_peer_id),
    );
    let wait_start = Instant::now();
    wait_for_message_count(&bench.bob_db, baseline + message_count, sync_timeout);
    let sync_wait_secs = wait_start.elapsed().as_secs_f64();
    let wall_secs = start.elapsed().as_secs_f64();
    let projection = summarize_projection_windows(
        request_start_ms,
        &[projection_window(
            &bench.bob_db,
            &bob_peer_id,
            &alice_target_ids,
        )],
        total_event_blob_bytes(&bench.alice_db, &alice_target_ids),
    );
    let bandwidth = bandwidth_summary(projection.payload_bytes, wall_secs, None);

    let (alice_rss, bob_rss, max_rss) = bench.daemon_rss();
    PerfMeasurement {
        wall_secs,
        generate_secs,
        sync_wait_secs,
        messages: message_count,
        msgs_per_sec: message_count as f64 / wall_secs,
        first_recorded_at_delay_ms: projection.first_recorded_at_delay_ms,
        last_recorded_at_delay_ms: projection.last_recorded_at_delay_ms,
        first_projected_at_delay_ms: projection.first_projected_at_delay_ms,
        last_projected_at_delay_ms: projection.last_projected_at_delay_ms,
        projected_tail_ms: projection.projected_tail_ms,
        payload_bytes: bandwidth.payload_bytes,
        payload_mib_s: bandwidth.payload_mib_s,
        payload_mbps: bandwidth.payload_mbps,
        perfect_payload_mbps: bandwidth.perfect_payload_mbps,
        estimated_quic_ceiling_mbps: bandwidth.estimated_quic_ceiling_mbps,
        bandwidth_saturation_pct: bandwidth.bandwidth_saturation_pct,
        alice_rss,
        bob_rss,
        max_rss,
    }
}

pub fn run_bidirectional_sync<F>(
    per_peer: i64,
    warm_timeout: Duration,
    sync_timeout: Duration,
    configure_network: F,
) -> PerfMeasurement
where
    F: FnOnce(String, String) -> BenchNetworkPath,
{
    let total = per_peer * 2;
    let mut bench = SharedWorkspaceBench::new_with_network(configure_network);
    if bench.has_pending_network_profile_activation() {
        bench.stabilize_bootstrap_joiner(warm_timeout);
    }
    bench.activate_network_profile();
    let baseline = bench.warm_bidirectional(warm_timeout);
    let alice_peer_id = active_peer_id_or_panic(&bench.alice_db);
    let bob_peer_id = active_peer_id_or_panic(&bench.bob_db);
    let alice_baseline_ids = recorded_message_event_ids(&bench.alice_db, &alice_peer_id);
    let bob_baseline_ids = recorded_message_event_ids(&bench.bob_db, &bob_peer_id);

    let start = Instant::now();
    let request_start_ms = current_timestamp_ms();
    let generate_start = Instant::now();
    generate_messages(&bench.alice_db, per_peer as usize);
    generate_messages(&bench.bob_db, per_peer as usize);
    let generate_secs = generate_start.elapsed().as_secs_f64();
    let alice_target_ids = diff_new_ids(
        &alice_baseline_ids,
        &recorded_message_event_ids(&bench.alice_db, &alice_peer_id),
    );
    let bob_target_ids = diff_new_ids(
        &bob_baseline_ids,
        &recorded_message_event_ids(&bench.bob_db, &bob_peer_id),
    );
    let wait_start = Instant::now();
    wait_for_message_count_pair(
        &bench.alice_db,
        &bench.bob_db,
        baseline + total,
        sync_timeout,
    );
    let sync_wait_secs = wait_start.elapsed().as_secs_f64();
    let wall_secs = start.elapsed().as_secs_f64();
    let projection = summarize_projection_windows(
        request_start_ms,
        &[
            projection_window(&bench.alice_db, &alice_peer_id, &bob_target_ids),
            projection_window(&bench.bob_db, &bob_peer_id, &alice_target_ids),
        ],
        total_event_blob_bytes(&bench.alice_db, &alice_target_ids)
            + total_event_blob_bytes(&bench.bob_db, &bob_target_ids),
    );
    let bandwidth = bandwidth_summary(projection.payload_bytes, wall_secs, None);

    let (alice_rss, bob_rss, max_rss) = bench.daemon_rss();
    PerfMeasurement {
        wall_secs,
        generate_secs,
        sync_wait_secs,
        messages: total,
        msgs_per_sec: total as f64 / wall_secs,
        first_recorded_at_delay_ms: projection.first_recorded_at_delay_ms,
        last_recorded_at_delay_ms: projection.last_recorded_at_delay_ms,
        first_projected_at_delay_ms: projection.first_projected_at_delay_ms,
        last_projected_at_delay_ms: projection.last_projected_at_delay_ms,
        projected_tail_ms: projection.projected_tail_ms,
        payload_bytes: bandwidth.payload_bytes,
        payload_mib_s: bandwidth.payload_mib_s,
        payload_mbps: bandwidth.payload_mbps,
        perfect_payload_mbps: bandwidth.perfect_payload_mbps,
        estimated_quic_ceiling_mbps: bandwidth.estimated_quic_ceiling_mbps,
        bandwidth_saturation_pct: bandwidth.bandwidth_saturation_pct,
        alice_rss,
        bob_rss,
        max_rss,
    }
}

pub fn run_continuous_sync<F>(
    per_peer: i64,
    warm_timeout: Duration,
    sync_timeout: Duration,
    configure_network: F,
) -> PerfMeasurement
where
    F: FnOnce(String, String) -> BenchNetworkPath,
{
    let total = per_peer * 2;
    let mut bench = SharedWorkspaceBench::new_with_network(configure_network);
    if bench.has_pending_network_profile_activation() {
        bench.stabilize_bootstrap_joiner(warm_timeout);
    }
    bench.activate_network_profile();
    let baseline = bench.warm_bidirectional(warm_timeout);
    let alice_peer_id = active_peer_id_or_panic(&bench.alice_db);
    let bob_peer_id = active_peer_id_or_panic(&bench.bob_db);
    let alice_baseline_ids = recorded_message_event_ids(&bench.alice_db, &alice_peer_id);
    let bob_baseline_ids = recorded_message_event_ids(&bench.bob_db, &bob_peer_id);

    let alice_db = bench.alice_db.clone();
    let bob_db = bench.bob_db.clone();
    let start = Instant::now();
    let request_start_ms = current_timestamp_ms();
    let generate_start = Instant::now();
    let alice_writer = thread::spawn(move || generate_messages(&alice_db, per_peer as usize));
    let bob_writer = thread::spawn(move || generate_messages(&bob_db, per_peer as usize));
    alice_writer.join().expect("alice generate thread panicked");
    bob_writer.join().expect("bob generate thread panicked");
    let generate_secs = generate_start.elapsed().as_secs_f64();
    let alice_target_ids = diff_new_ids(
        &alice_baseline_ids,
        &recorded_message_event_ids(&bench.alice_db, &alice_peer_id),
    );
    let bob_target_ids = diff_new_ids(
        &bob_baseline_ids,
        &recorded_message_event_ids(&bench.bob_db, &bob_peer_id),
    );
    let wait_start = Instant::now();
    wait_for_message_count_pair(
        &bench.alice_db,
        &bench.bob_db,
        baseline + total,
        sync_timeout,
    );
    let sync_wait_secs = wait_start.elapsed().as_secs_f64();
    let wall_secs = start.elapsed().as_secs_f64();
    let projection = summarize_projection_windows(
        request_start_ms,
        &[
            projection_window(&bench.alice_db, &alice_peer_id, &bob_target_ids),
            projection_window(&bench.bob_db, &bob_peer_id, &alice_target_ids),
        ],
        total_event_blob_bytes(&bench.alice_db, &alice_target_ids)
            + total_event_blob_bytes(&bench.bob_db, &bob_target_ids),
    );
    let bandwidth = bandwidth_summary(projection.payload_bytes, wall_secs, None);

    let (alice_rss, bob_rss, max_rss) = bench.daemon_rss();
    PerfMeasurement {
        wall_secs,
        generate_secs,
        sync_wait_secs,
        messages: total,
        msgs_per_sec: total as f64 / wall_secs,
        first_recorded_at_delay_ms: projection.first_recorded_at_delay_ms,
        last_recorded_at_delay_ms: projection.last_recorded_at_delay_ms,
        first_projected_at_delay_ms: projection.first_projected_at_delay_ms,
        last_projected_at_delay_ms: projection.last_projected_at_delay_ms,
        projected_tail_ms: projection.projected_tail_ms,
        payload_bytes: bandwidth.payload_bytes,
        payload_mib_s: bandwidth.payload_mib_s,
        payload_mbps: bandwidth.payload_mbps,
        perfect_payload_mbps: bandwidth.perfect_payload_mbps,
        estimated_quic_ceiling_mbps: bandwidth.estimated_quic_ceiling_mbps,
        bandwidth_saturation_pct: bandwidth.bandwidth_saturation_pct,
        alice_rss,
        bob_rss,
        max_rss,
    }
}

pub fn emit_summary(summary_key: &str, title: &str, measurement: &PerfMeasurement) {
    let bandwidth_saturation = measurement
        .bandwidth_saturation_pct
        .map(|pct| format!("{pct:.1}%"))
        .unwrap_or_else(|| "n/a (unshaped)".to_string());
    let summary = format!(
        "=== {title} ===\n  Full projected_count: {wall_secs:.2}s\n  First recorded_at:    {first_recorded_at}\n  Last recorded_at:     {last_recorded_at}\n  First projected_at:   {first_projected_at}\n  Last projected_at:    {last_projected_at}\n  Projected tail:       {projected_tail}\n  Generate:             {generate_secs:.2}s\n  Sync wait:            {sync_wait_secs:.2}s\n  Messages:             {messages}\n  Projected msgs/s:     {msgs_per_sec:.0}\n  Payload bytes:        {payload_bytes}\n  Payload MiB/s:        {payload_mib_s:.2}\n  Payload Mbps:         {payload_mbps:.2}\n  Bandwidth saturation: {bandwidth_saturation}\n  Peak RSS:             {max_rss:.1} MiB (max daemon VmHWM)\n  Alice peak RSS:       {alice_rss:.1} MiB\n  Bob peak RSS:         {bob_rss:.1} MiB\n",
        wall_secs = measurement.wall_secs,
        first_recorded_at = measurement
            .first_recorded_at_delay_ms
            .map(|ms| format!("{ms} ms after start"))
            .unwrap_or_else(|| "n/a".to_string()),
        last_recorded_at = measurement
            .last_recorded_at_delay_ms
            .map(|ms| format!("{ms} ms after start"))
            .unwrap_or_else(|| "n/a".to_string()),
        first_projected_at = measurement
            .first_projected_at_delay_ms
            .map(|ms| format!("{ms} ms after start"))
            .unwrap_or_else(|| "n/a".to_string()),
        last_projected_at = measurement
            .last_projected_at_delay_ms
            .map(|ms| format!("{ms} ms after start"))
            .unwrap_or_else(|| "n/a".to_string()),
        projected_tail = measurement
            .projected_tail_ms
            .map(|ms| format!("{ms} ms (last recorded_at -> last projected_at)"))
            .unwrap_or_else(|| "n/a".to_string()),
        generate_secs = measurement.generate_secs,
        sync_wait_secs = measurement.sync_wait_secs,
        messages = measurement.messages,
        msgs_per_sec = measurement.msgs_per_sec,
        payload_bytes = measurement.payload_bytes,
        payload_mib_s = measurement.payload_mib_s,
        payload_mbps = measurement.payload_mbps,
        bandwidth_saturation = bandwidth_saturation,
        max_rss = measurement.max_rss,
        alice_rss = measurement.alice_rss,
        bob_rss = measurement.bob_rss,
    );
    eprintln!("\n{summary}");
    write_summary(summary_key, &summary);
}

pub fn write_summary(summary_key: &str, summary: &str) {
    let summary_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/perf-results");
    std::fs::create_dir_all(&summary_dir).expect("create target/perf-results");
    std::fs::write(summary_dir.join(format!("{summary_key}.summary")), summary)
        .expect("write benchmark summary file");
}

fn perf_debug_env(name: &str) -> bool {
    std::env::var(name)
        .map(|v| v != "0" && v.to_lowercase() != "false")
        .unwrap_or(false)
}

fn perf_ready_timeout() -> Duration {
    match std::env::var("PERF_READY_TIMEOUT_SECS") {
        Ok(raw) => Duration::from_secs(
            raw.parse::<u64>()
                .unwrap_or_else(|_| panic!("invalid PERF_READY_TIMEOUT_SECS `{raw}`")),
        ),
        Err(_) => Duration::from_secs(120),
    }
}

fn current_timestamp_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_millis() as i64
}

fn start_perf_daemon(
    db: &str,
    tmpdir: &std::path::Path,
    label: &str,
    disable_placeholder_autodial: bool,
    bind_addr: Option<SocketAddr>,
) -> HarnessDaemon {
    let bind_ip = bind_addr.map(|addr| addr.ip().to_string());
    let bind_port = bind_addr.map(|addr| addr.port());
    let extra_env = daemon_perf_extra_env();
    if !perf_debug_env("PERF_DAEMON_LOGS") {
        return start_daemon_with_options(
            db,
            &DaemonOptions {
                bind_ip,
                bind_port,
                disable_placeholder_autodial,
                disable_discovery: true,
                extra_env,
                ..Default::default()
            },
        );
    }
    start_daemon_with_options(
        db,
        &DaemonOptions {
            bind_ip,
            bind_port,
            stdout_file: Some(tmpdir.join(format!("{label}.daemon.stdout.log"))),
            stderr_file: Some(tmpdir.join(format!("{label}.daemon.stderr.log"))),
            disable_placeholder_autodial,
            disable_discovery: true,
            extra_env,
            ..Default::default()
        },
    )
}

fn create_workspace_direct(db: &str, username: &str, device_name: &str) {
    topo::event_modules::workspace::commands::create_workspace_for_db(
        db,
        "workspace",
        username,
        device_name,
    )
    .expect("create_workspace_for_db");
}

fn accept_invite_direct(db: &str, invite_link: &str, username: &str, device_name: &str) {
    topo::event_modules::workspace::commands::accept_invite(db, invite_link, username, device_name)
        .expect("accept_invite");
}

fn wait_for_message_count(db: &str, expected: i64, timeout: Duration) {
    let start = Instant::now();
    loop {
        let count = message_count_sql(db);
        if count == expected {
            return;
        }
        assert!(
            start.elapsed() < timeout,
            "message_count timed out after {:?} for db={}: expected={}, actual={}\n{}",
            timeout,
            db,
            expected,
            count,
            format_bench_diagnostics(db)
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn wait_for_message_count_pair(left_db: &str, right_db: &str, expected: i64, timeout: Duration) {
    let start = Instant::now();
    loop {
        let left = message_count_sql(left_db);
        let right = message_count_sql(right_db);
        if left == expected && right == expected {
            return;
        }
        assert!(
            start.elapsed() < timeout,
            "paired message_count timed out after {:?}\nleft db={}: expected={}, actual={}\n{}\nright db={}: expected={}, actual={}\n{}",
            timeout,
            left_db,
            expected,
            left,
            format_bench_diagnostics(left_db),
            right_db,
            expected,
            right,
            format_bench_diagnostics(right_db),
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn maybe_enable_sync_logging(db: &str) {
    if !perf_debug_env("PERF_ENABLE_SYNC_LOG") {
        return;
    }
    let out = topo_cmd(db, &["sync-log", "enable", "--all-runs"]);
    assert!(
        out.status.success(),
        "sync-log enable failed for {}: {}",
        db,
        String::from_utf8_lossy(&out.stderr)
    );
}

fn query_count(conn: &rusqlite::Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |row| row.get::<_, i64>(0))
        .unwrap_or(-1)
}

fn format_bench_diagnostics(db: &str) -> String {
    let conn = match rusqlite::Connection::open(db) {
        Ok(conn) => conn,
        Err(err) => return format!("diagnostics unavailable: failed to open db: {err}"),
    };

    let recorded_events = query_count(&conn, "SELECT COUNT(*) FROM recorded_events");
    let wanted_events = query_count(&conn, "SELECT COUNT(*) FROM wanted_events");
    let blocked_events = query_count(&conn, "SELECT COUNT(*) FROM blocked_events");
    let project_queue = query_count(&conn, "SELECT COUNT(*) FROM project_queue");
    let sync_runs = query_count(&conn, "SELECT COUNT(*) FROM sync_runs");

    let mut out = String::new();
    out.push_str("bench diagnostics:\n");
    out.push_str(&format!(
        "  recorded_events={recorded_events} wanted_events={wanted_events} blocked_events={blocked_events} project_queue={project_queue} sync_runs={sync_runs}\n"
    ));

    if let Ok(mut stmt) = conn.prepare(
        "SELECT run_id, direction, role, rounds, events_sent, events_received, bytes_sent, bytes_received, outcome, COALESCE(error, '')
         FROM sync_runs
         ORDER BY run_id DESC
         LIMIT 6",
    ) {
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                ))
            })
            .ok();
        if let Some(rows) = rows {
            out.push_str("  recent_runs:\n");
            for row in rows.flatten() {
                let (run_id, direction, role, rounds, sent, recv, bytes_sent, bytes_recv, outcome, error) = row;
                out.push_str(&format!(
                    "    run_id={run_id} {direction}/{role} rounds={rounds} sent={sent} recv={recv} bytes_sent={bytes_sent} bytes_recv={bytes_recv} outcome={outcome}"
                ));
                if !error.is_empty() {
                    out.push_str(&format!(" error={error}"));
                }
                out.push('\n');
            }
        }
    }

    if let Ok(mut stmt) = conn.prepare(
        "SELECT peer_id, remote_addr, COUNT(*) AS active_runs
         FROM sync_runs
         WHERE outcome = 'in_progress'
         GROUP BY peer_id, remote_addr
         ORDER BY active_runs DESC, peer_id, remote_addr
         LIMIT 6",
    ) {
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .ok();
        if let Some(rows) = rows {
            let active_rows: Vec<_> = rows.flatten().collect();
            if !active_rows.is_empty() {
                out.push_str("  active_runs_by_peer:\n");
                for (peer_id, remote_addr, active_runs) in active_rows {
                    out.push_str(&format!(
                        "    peer={} remote_addr={} active_runs={}\n",
                        &peer_id[..16.min(peer_id.len())],
                        remote_addr,
                        active_runs
                    ));
                }
            }
        }
    }

    if let Ok(mut stmt) = conn.prepare(
        "SELECT run_id, seq, frame_type, detail_json
         FROM sync_run_events
         WHERE frame_type IN ('SendIdle', 'InitialControlTimeout')
         ORDER BY run_id DESC, seq DESC
         LIMIT 8",
    ) {
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            })
            .ok();
        if let Some(rows) = rows {
            let marker_rows: Vec<_> = rows.flatten().collect();
            if !marker_rows.is_empty() {
                out.push_str("  recent_sync_markers:\n");
                for (run_id, seq, frame_type, detail_json) in marker_rows {
                    out.push_str(&format!(
                        "    run_id={run_id} seq={seq} type={frame_type} detail={}\n",
                        detail_json.unwrap_or_default()
                    ));
                }
            }
        }
    }

    out
}
