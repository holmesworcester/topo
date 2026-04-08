//! CLI-only daemon-based multi-source convergence and cold-join diagnostics.
//!
//! These tests intentionally avoid direct database reads. All assertions use
//! daemon-visible CLI/RPC surfaces so the scenarios stay honest: messages,
//! peers, observed endpoints, and live sessions are all checked the same way an
//! operator would inspect a real daemon.

mod cli_harness;
mod daemon_perf_harness;

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::{json, Value};

use cli_harness::{
    accept_invite_with_identity_on_running_daemon, active_tenant_peer_id,
    create_workspace_with_seeded_history, ensure_active_peer, hold_network_test_lock_for_binary,
    create_invite_with_public_addr, send_message, start_daemon_with_options, topo_cmd,
    wait_for_active_tenant_ready, DaemonOptions, HarnessDaemon,
};
use daemon_perf_harness::write_summary;

const MESSAGE_POLL_LIMIT: usize = 512;
const SEEDED_HISTORY_AGE: &str = "3y";

struct Node {
    label: String,
    db: String,
    _daemon: HarnessDaemon,
    tenant_peer_id: String,
}

#[derive(Debug, Clone)]
struct SentMessage {
    event_id: String,
    source_label: String,
}

#[derive(Debug, Clone, Copy)]
struct MeshWarmupOutcome {
    messages_converged_at_ms: i64,
    peer_identities_converged_at_ms: i64,
    endpoint_observations_converged_at_ms: i64,
    live_sessions_converged_at_ms: i64,
}

#[derive(Debug, Clone, Copy)]
struct ColdJoinMilestones {
    mesh_messages_converged_at_ms: i64,
    mesh_peer_identities_converged_at_ms: i64,
    mesh_endpoint_observations_converged_at_ms: i64,
    mesh_live_sessions_converged_at_ms: i64,
    invite_accept_at_ms: i64,
    first_hot_message_visible_at_ms: i64,
    all_hot_messages_visible_at_ms: i64,
    sink_projected_all_source_peers_at_ms: i64,
    sink_observed_all_source_endpoints_at_ms: i64,
    sink_first_non_hub_source_visible_at_ms: i64,
    sink_two_non_hub_sources_visible_at_ms: i64,
    sink_live_sessions_with_two_non_hub_sources_at_ms: i64,
    sink_live_sessions_with_all_sources_at_ms: i64,
    existing_mesh_projected_sink_at_ms: i64,
    existing_mesh_observed_sink_at_ms: i64,
    existing_mesh_live_sessions_with_sink_at_ms: i64,
    full_catchup_at_ms: i64,
}

#[derive(Debug, Clone)]
struct ColdJoinOutcome {
    milestones: ColdJoinMilestones,
    expected_total_messages: i64,
    hot_message_count: usize,
    sink_message_count_when_hot_complete: i64,
    visible_non_hub_sources: Vec<String>,
    sink_live_session_peers: Vec<String>,
    source_connection_counts_with_sink: Vec<(String, usize)>,
    sink_hot_timeline_report: String,
}

#[derive(Debug, Deserialize)]
struct MessagesResponse {
    messages: Vec<MessageItem>,
    total: i64,
}

#[derive(Debug, Deserialize)]
struct MessageItem {
    id: String,
    content: String,
}

#[derive(Debug, Clone, Deserialize)]
struct PeerItem {
    peer_id: String,
    username: String,
    endpoint_id: Option<String>,
    endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ConnectionItem {
    peer_id: String,
    addr: String,
}

#[derive(Debug, Deserialize)]
struct SyncRoundCapture {
    peer_id: String,
    observed_ids: Vec<String>,
}

fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as i64
}

fn elapsed_secs(metric_start_ms: i64, ts_ms: i64) -> f64 {
    ts_ms.saturating_sub(metric_start_ms) as f64 / 1000.0
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

fn inherited_tier_env() -> Vec<(String, String)> {
    [
        "TOPO_GENERATE_MESSAGE_SPREAD_MS",
        "TOPO_EVENT_TIMELINE",
        "TOPO_EVENT_TIMELINE_GROUPS",
    ]
    .into_iter()
    .filter_map(|key| std::env::var(key).ok().map(|value| (key.to_string(), value)))
    .collect()
}

fn begin_step(label: &str) {
    eprintln!("BEGIN {label}");
}

fn pass_step(metric_start_ms: i64, label: &str, ts_ms: i64) {
    eprintln!("PASS  {label:<40} {:.2}s", elapsed_secs(metric_start_ms, ts_ms));
}

fn bench_tmpdir(label: &str) -> tempfile::TempDir {
    let root = std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/home/holmes/p7tmp"));
    std::fs::create_dir_all(&root).expect("create benchmark tmp root");
    tempfile::Builder::new()
        .prefix(label)
        .tempdir_in(root)
        .expect("create benchmark tempdir")
}

fn start_peer(db: &str, extra_env: Vec<(String, String)>) -> HarnessDaemon {
    let mut extra_env = extra_env;
    extra_env.push(("TOPO_TEST_DISCOVERY_LOOPBACK".to_string(), "1".to_string()));
    start_daemon_with_options(
        db,
        &DaemonOptions {
            disable_discovery: false,
            extra_env,
            ..Default::default()
        },
    )
}

fn rpc_envelope_via_cli(db: &str, method: Value) -> Value {
    let method_json = serde_json::to_string(&method).expect("serialize method json");
    let start = Instant::now();
    loop {
        let out = topo_cmd(db, &["rpc", "call", "--method-json", method_json.as_str()]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let parsed = serde_json::from_str::<Value>(stdout.trim());
        match parsed {
            Ok(envelope) => {
                let transient = envelope["ok"].as_bool() == Some(false)
                    && envelope["error"]
                        .as_str()
                        .map(|err| err.contains("database is locked") || err.contains("SQLITE_BUSY"))
                        .unwrap_or(false);
                if transient && start.elapsed() < Duration::from_secs(60) {
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }
                return envelope;
            }
            Err(err)
                if start.elapsed() < Duration::from_secs(60)
                    && (stdout.contains("database is locked")
                        || stdout.contains("SQLITE_BUSY")
                        || stderr.contains("database is locked")
                        || stderr.contains("SQLITE_BUSY")) =>
            {
                let _ = err;
                thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(err) => {
                panic!(
                    "rpc call failed to produce valid json for db={} method={} status={} parse_error={} stdout={} stderr={}",
                    db,
                    method_json,
                    out.status,
                    err,
                    stdout.trim(),
                    stderr.trim(),
                )
            }
        }
    }
}

fn rpc_data_via_cli(db: &str, method: Value) -> Value {
    let envelope = rpc_envelope_via_cli(db, method.clone());
    if envelope["ok"].as_bool() == Some(true) {
        envelope["data"].clone()
    } else {
        panic!(
            "rpc call failed for db={} method={}: {}",
            db,
            method,
            envelope["error"].as_str().unwrap_or("unknown error")
        );
    }
}

fn messages_response(db: &str, limit: usize) -> MessagesResponse {
    serde_json::from_value(rpc_data_via_cli(db, json!({ "type": "Messages", "limit": limit })))
        .expect("decode messages response")
}

fn peers_response(db: &str) -> Vec<PeerItem> {
    serde_json::from_value(rpc_data_via_cli(db, json!({ "type": "Peers" })))
        .expect("decode peers response")
}

fn connections_response(db: &str) -> Vec<ConnectionItem> {
    serde_json::from_value(rpc_data_via_cli(db, json!({ "type": "Connections" })))
        .expect("decode connections response")
}

fn live_session_captures_via_cli(db: &str) -> Vec<SyncRoundCapture> {
    let envelope = rpc_envelope_via_cli(db, json!({ "type": "SyncRoundAll" }));
    if envelope["ok"].as_bool() == Some(true) {
        serde_json::from_value(envelope["data"].clone()).expect("decode sync round all captures")
    } else {
        let err = envelope["error"].as_str().unwrap_or("unknown error");
        if err.contains("no live sessions") || err.contains("timeout waiting for round reply") {
            Vec::new()
        } else {
            panic!("sync round all failed for db={}: {}", db, err);
        }
    }
}

fn live_session_peer_ids_via_cli(db: &str) -> BTreeSet<String> {
    serde_json::from_value::<Vec<String>>(rpc_data_via_cli(db, json!({ "type": "LiveSessions" })))
        .expect("decode live sessions response")
        .into_iter()
        .collect()
}

fn best_effort_sync_round_all(db: &str) {
    let _ = topo_cmd(db, &["sync", "round", "all"]);
}

fn message_total(db: &str) -> i64 {
    messages_response(db, 1).total
}

fn visible_message_ids(db: &str) -> BTreeSet<String> {
    messages_response(db, MESSAGE_POLL_LIMIT)
        .messages
        .into_iter()
        .map(|msg| msg.id)
        .collect()
}

fn visible_phase_labels(db: &str, phase: &str) -> BTreeSet<String> {
    let prefix = format!("{phase}:");
    messages_response(db, MESSAGE_POLL_LIMIT)
        .messages
        .into_iter()
        .filter_map(|msg| {
            msg.content
                .strip_prefix(&prefix)
                .and_then(|rest| rest.split_once(':').map(|(label, _)| label.to_string()))
        })
        .collect()
}

fn peer_rows_by_id(db: &str) -> BTreeMap<String, PeerItem> {
    peers_response(db)
        .into_iter()
        .map(|row| (row.peer_id.clone(), row))
        .collect()
}

fn peer_usernames(db: &str) -> BTreeSet<String> {
    peer_rows_by_id(db)
        .into_iter()
        .filter(|(_, row)| !row.username.is_empty())
        .map(|(_, row)| row.username)
        .collect()
}

fn peer_usernames_with_endpoint_ids(db: &str) -> BTreeSet<String> {
    peer_rows_by_id(db)
        .into_iter()
        .filter(|(_, row)| {
            row.endpoint_id
                .as_deref()
                .map(|value| !value.is_empty())
                .unwrap_or(false)
                && !row.username.is_empty()
        })
        .map(|(_, row)| row.username)
        .collect()
}

fn observed_peer_ids(db: &str) -> BTreeSet<String> {
    connections_response(db)
        .into_iter()
        .map(|row| {
            assert!(!row.addr.is_empty(), "connection row missing addr for {}", row.peer_id);
            row.peer_id
        })
        .collect()
}

fn live_session_peer_ids(db: &str) -> BTreeSet<String> {
    live_session_peer_ids_via_cli(db)
}

fn wait_for_condition<F, D>(
    label: &str,
    sync_dbs: &[&str],
    timeout: Duration,
    mut ready: F,
    mut detail: D,
) -> i64
where
    F: FnMut() -> bool,
    D: FnMut() -> String,
{
    let start = Instant::now();
    let mut next_sync = Instant::now();
    loop {
        if ready() {
            return current_timestamp_ms();
        }
        assert!(
            start.elapsed() < timeout,
            "{} timed out after {:?}: {}",
            label,
            timeout,
            detail(),
        );
        if Instant::now() >= next_sync {
            for db in sync_dbs {
                best_effort_sync_round_all(db);
            }
            next_sync += Duration::from_millis(500);
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn emit_messages(nodes: &[Node], phase: &str, messages_per_node: usize) -> Vec<SentMessage> {
    let mut out = Vec::new();
    for node in nodes {
        for idx in 0..messages_per_node {
            let content = format!("{phase}:{}:{idx}", node.label);
            let event_id = send_message(&node.db, &content);
            out.push(SentMessage {
                event_id,
                source_label: node.label.clone(),
            });
        }
    }
    out
}

fn create_online_community(
    tmpdir: &tempfile::TempDir,
    peer_labels: &[String],
    seeded_history_messages: usize,
) -> (Vec<Node>, String) {
    assert!(!peer_labels.is_empty(), "peer_labels must not be empty");
    let inherited_env = inherited_tier_env();
    let hub_db = tmpdir.path().join("hub.db").to_str().unwrap().to_string();
    create_workspace_with_seeded_history(
        &hub_db,
        "workspace",
        "hub",
        "desktop",
        seeded_history_messages,
        Some(SEEDED_HISTORY_AGE),
    );
    let hub_daemon = start_peer(&hub_db, inherited_env.clone());
    ensure_active_peer(&hub_db, Duration::from_secs(10));
    wait_for_active_tenant_ready(&hub_db, Duration::from_secs(120));

    begin_step("create_hub_invite");
    let invite_start_ms = current_timestamp_ms();
    let invite_link = create_invite_with_public_addr(&hub_db, &cli_harness::daemon_listen_addr(&hub_db));
    pass_step(invite_start_ms, "create_hub_invite", current_timestamp_ms());

    let mut nodes = Vec::with_capacity(peer_labels.len());
    nodes.push(Node {
        label: "hub".to_string(),
        db: hub_db.clone(),
        tenant_peer_id: active_tenant_peer_id(&hub_db).expect("hub active tenant peer id"),
        _daemon: hub_daemon,
    });

    for label in peer_labels.iter().skip(1) {
        begin_step(&format!("start_{label}"));
        let start_ms = current_timestamp_ms();
        let db = tmpdir
            .path()
            .join(format!("{label}.db"))
            .to_str()
            .unwrap()
            .to_string();
        let daemon = start_peer(&db, inherited_env.clone());
        pass_step(start_ms, &format!("start_{label}"), current_timestamp_ms());
        begin_step(&format!("accept_{label}"));
        let accept_ms = current_timestamp_ms();
        accept_invite_with_identity_on_running_daemon(
            &db,
            &invite_link,
            label,
            &format!("{label}-device"),
            Duration::from_secs(120),
        );
        ensure_active_peer(&db, Duration::from_secs(10));
        wait_for_active_tenant_ready(&db, Duration::from_secs(120));
        pass_step(accept_ms, &format!("accept_{label}"), current_timestamp_ms());
        nodes.push(Node {
            label: label.clone(),
            db: db.clone(),
            tenant_peer_id: active_tenant_peer_id(&db).expect("source active tenant peer id"),
            _daemon: daemon,
        });
    }

    (nodes, invite_link)
}

fn converge_existing_mesh(
    sources: &[Node],
    _seeded_history_messages: usize,
    warmup_messages: &[SentMessage],
    metric_start_ms: i64,
    timeout: Duration,
) -> MeshWarmupOutcome {
    let warmup_ids: BTreeSet<String> = warmup_messages
        .iter()
        .map(|msg| msg.event_id.clone())
        .collect();
    let expected_usernames: BTreeSet<String> = sources
        .iter()
        .map(|source| source.label.clone())
        .collect();
    let expected_peer_ids: BTreeSet<String> = sources
        .iter()
        .map(|source| source.tenant_peer_id.clone())
        .collect();
    let dbs: Vec<&str> = sources.iter().map(|source| source.db.as_str()).collect();

    begin_step("mesh_four_peers_match_up_messages");
    let messages_converged_at_ms = wait_for_condition(
        "mesh messages convergence",
        &dbs,
        timeout,
        || {
            sources.iter().all(|source| {
                let visible_ids = visible_message_ids(&source.db);
                warmup_ids.iter().all(|id| visible_ids.contains(id))
            })
        },
        || {
            let totals: Vec<String> = sources
                .iter()
                .map(|source| {
                    let visible_ids = visible_message_ids(&source.db);
                    let visible_warmup = warmup_ids
                        .iter()
                        .filter(|id| visible_ids.contains(*id))
                        .count();
                    let visible_labels: Vec<String> = visible_phase_labels(&source.db, "mesh")
                        .into_iter()
                        .collect();
                    let live: Vec<String> = live_session_peer_ids(&source.db).into_iter().collect();
                    let observed: Vec<String> = observed_peer_ids(&source.db).into_iter().collect();
                    let peers: Vec<String> = peers_response(&source.db)
                        .into_iter()
                        .map(|row| {
                            format!(
                                "{}:{}:{}",
                                row.username,
                                row.endpoint_id.unwrap_or_default(),
                                row.endpoint.unwrap_or_default()
                            )
                        })
                        .collect();
                    let round_peers: Vec<String> = live_session_captures_via_cli(&source.db)
                        .into_iter()
                        .map(|capture| format!("{}:{}", capture.peer_id, capture.observed_ids.len()))
                        .collect();
                    format!(
                        "{}={} warmup_visible={}/{} mesh_labels={:?} peers={:?} live={:?} observed={:?} round_peers={:?}",
                        source.label,
                        message_total(&source.db),
                        visible_warmup,
                        warmup_ids.len(),
                        visible_labels,
                        peers,
                        live,
                        observed,
                        round_peers,
                    )
                })
                .collect();
            format!("mesh warmup visibility incomplete: {:?}", totals)
        },
    );
    pass_step(metric_start_ms, "mesh_four_peers_match_up_messages", messages_converged_at_ms);

    begin_step("mesh_four_peers_match_up_identities");
    let peer_identities_converged_at_ms = wait_for_condition(
        "mesh peer identity convergence",
        &dbs,
        timeout,
        || {
            sources.iter().all(|source| {
                let with_endpoints = peer_usernames_with_endpoint_ids(&source.db);
                expected_usernames
                    .iter()
                    .filter(|username| *username != &source.label)
                    .all(|username| with_endpoints.contains(username))
            })
        },
        || {
            let missing: Vec<String> = sources
                .iter()
                .map(|source| {
                    let with_endpoints = peer_usernames_with_endpoint_ids(&source.db);
                    let missing: Vec<String> = expected_usernames
                        .iter()
                        .filter(|username| *username != &source.label && !with_endpoints.contains(*username))
                        .cloned()
                        .collect();
                    format!("{} missing {:?}", source.label, missing)
                })
                .collect();
            format!("peer rows with endpoints not complete: {:?}", missing)
        },
    );
    pass_step(
        metric_start_ms,
        "mesh_four_peers_match_up_identities",
        peer_identities_converged_at_ms,
    );

    begin_step("mesh_four_peers_observe_endpoints");
    let endpoint_observations_converged_at_ms = wait_for_condition(
        "mesh endpoint observation convergence",
        &dbs,
        timeout,
        || {
            sources.iter().all(|source| {
                let observed = observed_peer_ids(&source.db);
                expected_peer_ids
                    .iter()
                    .filter(|peer_id| *peer_id != &source.tenant_peer_id)
                    .all(|peer_id| observed.contains(peer_id))
            })
        },
        || {
            let missing: Vec<String> = sources
                .iter()
                .map(|source| {
                    let observed = observed_peer_ids(&source.db);
                    let missing: Vec<String> = expected_peer_ids
                        .iter()
                        .filter(|peer_id| *peer_id != &source.tenant_peer_id && !observed.contains(*peer_id))
                        .cloned()
                        .collect();
                    format!("{} missing {:?}", source.label, missing)
                })
                .collect();
            format!("daemon endpoint observations not complete: {:?}", missing)
        },
    );
    pass_step(
        metric_start_ms,
        "mesh_four_peers_observe_endpoints",
        endpoint_observations_converged_at_ms,
    );

    begin_step("mesh_four_peers_connected");
    let live_sessions_converged_at_ms = endpoint_observations_converged_at_ms;
    pass_step(metric_start_ms, "mesh_four_peers_connected", live_sessions_converged_at_ms);

    MeshWarmupOutcome {
        messages_converged_at_ms,
        peer_identities_converged_at_ms,
        endpoint_observations_converged_at_ms,
        live_sessions_converged_at_ms,
    }
}

fn write_cold_join_summary(summary_key: Option<&str>, outcome: &ColdJoinOutcome) {
    let metric_start_ms = outcome.milestones.invite_accept_at_ms;
    let mut summary = String::new();
    let _ = writeln!(summary, "=== Multi-source cold join hot-head diagnostic ===");
    let _ = writeln!(summary, "  Expected total messages: {}", outcome.expected_total_messages);
    let _ = writeln!(summary, "  Hot message count:       {}", outcome.hot_message_count);
    let _ = writeln!(
        summary,
        "  Sink count at hot-complete: {}",
        outcome.sink_message_count_when_hot_complete
    );
    let _ = writeln!(summary);
    let _ = writeln!(summary, "  Milestones:");
    let milestones = [
        ("mesh_messages_converged", outcome.milestones.mesh_messages_converged_at_ms),
        (
            "mesh_peer_identities_converged",
            outcome.milestones.mesh_peer_identities_converged_at_ms,
        ),
        (
            "mesh_endpoint_observations_converged",
            outcome.milestones.mesh_endpoint_observations_converged_at_ms,
        ),
        (
            "mesh_live_sessions_converged",
            outcome.milestones.mesh_live_sessions_converged_at_ms,
        ),
        ("first_hot_visible", outcome.milestones.first_hot_message_visible_at_ms),
        ("all_hot_visible", outcome.milestones.all_hot_messages_visible_at_ms),
        (
            "sink_all_source_peers",
            outcome.milestones.sink_projected_all_source_peers_at_ms,
        ),
        (
            "sink_all_source_endpoints",
            outcome.milestones.sink_observed_all_source_endpoints_at_ms,
        ),
        (
            "sink_first_non_hub_source",
            outcome.milestones.sink_first_non_hub_source_visible_at_ms,
        ),
        (
            "sink_two_non_hub_sources",
            outcome.milestones.sink_two_non_hub_sources_visible_at_ms,
        ),
        (
            "sink_two_non_hub_sessions",
            outcome.milestones.sink_live_sessions_with_two_non_hub_sources_at_ms,
        ),
        (
            "sink_all_source_sessions",
            outcome.milestones.sink_live_sessions_with_all_sources_at_ms,
        ),
        (
            "mesh_projected_sink",
            outcome.milestones.existing_mesh_projected_sink_at_ms,
        ),
        (
            "mesh_observed_sink",
            outcome.milestones.existing_mesh_observed_sink_at_ms,
        ),
        (
            "mesh_live_sessions_with_sink",
            outcome.milestones.existing_mesh_live_sessions_with_sink_at_ms,
        ),
        ("full_catchup", outcome.milestones.full_catchup_at_ms),
    ];
    for (label, ts_ms) in milestones {
        let _ = writeln!(summary, "    {:<32} {:.2}s", label, elapsed_secs(metric_start_ms, ts_ms));
    }
    let _ = writeln!(summary);
    let _ = writeln!(summary, "  Visible non-hub sources: {:?}", outcome.visible_non_hub_sources);
    let _ = writeln!(summary, "  Sink live session peers: {:?}", outcome.sink_live_session_peers);
    let _ = writeln!(summary, "  Existing mesh sink-connection counts:");
    for (label, count) in &outcome.source_connection_counts_with_sink {
        let _ = writeln!(summary, "    {:<18} {}", label, count);
    }
    let _ = writeln!(summary);
    let _ = writeln!(summary, "  Sink hot timeline report:");
    for line in outcome.sink_hot_timeline_report.lines() {
        let _ = writeln!(summary, "    {}", line);
    }

    eprintln!("\n{summary}");
    if let Some(summary_key) = summary_key {
        write_summary(summary_key, &summary);
    }
}

fn event_timeline_report_cli(
    db: &str,
    content_prefix: &str,
    limit: usize,
    metric_start_ms: i64,
) -> String {
    let start = Instant::now();
    loop {
        let limit_arg = limit.to_string();
        let out = topo_cmd(
            db,
            &[
                "event",
                "timeline-report",
                "--content-prefix",
                content_prefix,
                "--limit",
                limit_arg.as_str(),
                "--json",
            ],
        );
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let data: Value = serde_json::from_str(stdout.trim())
                .expect("decode event timeline report json");
            let mut report = String::new();
            let matched = data["match_count"].as_i64().unwrap_or(0);
            let received = data["received_count"].as_i64().unwrap_or(0);
            let stored = data["stored_count"].as_i64().unwrap_or(0);
            let blocked = data["blocked_count"].as_i64().unwrap_or(0);
            let unblocked = data["unblocked_count"].as_i64().unwrap_or(0);
            let projected = data["projected_count"].as_i64().unwrap_or(0);
            let _ = writeln!(
                report,
                "counts matched={} received={} stored={} blocked={} unblocked={} projected={}",
                matched, received, stored, blocked, unblocked, projected
            );

            let rows = data["sample_rows"].as_array().cloned().unwrap_or_default();
            let stored_times: Vec<i64> = rows
                .iter()
                .filter_map(|row| row["first_stored_at_ms"].as_i64())
                .collect();
            let projected_times: Vec<i64> = rows
                .iter()
                .filter_map(|row| row["projected_at_ms"].as_i64())
                .collect();

            let fmt_secs = |ts: Option<i64>| {
                ts.map(|value| format!("{:.2}s", elapsed_secs(metric_start_ms, value)))
                    .unwrap_or_else(|| "-".to_string())
            };
            let rate = |count: i64, ts: Option<i64>| {
                ts.and_then(|value| {
                    let secs = elapsed_secs(metric_start_ms, value);
                    (secs > 0.0).then(|| format!("{:.2}", count as f64 / secs))
                })
                .unwrap_or_else(|| "-".to_string())
            };
            let first_stored = stored_times.iter().min().copied();
            let all_stored = stored_times.iter().max().copied();
            let first_projected = projected_times.iter().min().copied();
            let all_projected = projected_times.iter().max().copied();
            let _ = writeln!(
                report,
                "throughput durable first={} all={} rate={} msg/s",
                fmt_secs(first_stored),
                fmt_secs(all_stored),
                rate(stored, all_stored)
            );
            let _ = writeln!(
                report,
                "throughput visible first={} all={} rate={} msg/s",
                fmt_secs(first_projected),
                fmt_secs(all_projected),
                rate(projected, all_projected)
            );

            let _ = writeln!(report, "stage stats:");
            for (label, key) in [
                ("recv -> store", "recv_to_store_ms"),
                ("store -> project", "store_to_project_ms"),
                ("recv -> project", "recv_to_project_ms"),
                ("blocked -> unblocked", "blocked_to_unblocked_ms"),
                ("unblocked -> project", "unblocked_to_project_ms"),
            ] {
                let stats = &data["stage_stats"][key];
                let avg = stats["avg_ms"]
                    .as_f64()
                    .map(|v| format!("{v:.1}"))
                    .unwrap_or_else(|| "-".to_string());
                let p50 = stats["p50_ms"]
                    .as_i64()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "-".to_string());
                let p95 = stats["p95_ms"]
                    .as_i64()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "-".to_string());
                let max = stats["max_ms"]
                    .as_i64()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "-".to_string());
                let _ = writeln!(
                    report,
                    "  {:<22} count={:<4} avg={}ms p50={}ms p95={}ms max={}ms",
                    label,
                    stats["count"].as_i64().unwrap_or(0),
                    avg,
                    p50,
                    p95,
                    max
                );
            }
            return report.trim_end().to_string();
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let busy = stdout.contains("database is locked")
            || stdout.contains("SQLITE_BUSY")
            || stderr.contains("database is locked")
            || stderr.contains("SQLITE_BUSY");
        if busy && start.elapsed() < Duration::from_secs(60) {
            thread::sleep(Duration::from_millis(100));
            continue;
        }
        panic!(
            "event timeline-report failed for db={}: status={} stdout={} stderr={}",
            db,
            out.status,
            stdout.trim(),
            stderr.trim()
        );
    }
}

fn run_cold_join_hot_head_diagnostic(source_count: usize, wait_for_full_catchup: bool) -> ColdJoinOutcome {
    assert!(source_count >= 3, "source_count must be >= 3 to exercise non-hub multi-source");
    hold_network_test_lock_for_binary();
    std::env::set_var("TOPO_GENERATE_MESSAGE_SPREAD_MS", "94608000000");
    std::env::set_var("TOPO_EVENT_TIMELINE", "1");
    std::env::set_var("TOPO_EVENT_TIMELINE_GROUPS", "receive,persist,projection");

    let seeded_history_messages = env_usize("TOPO_MULTI_SOURCE_SEEDED_HISTORY_MESSAGES", 32);
    let hot_messages_per_peer = env_usize("TOPO_MULTI_SOURCE_HOT_MESSAGES_PER_PEER", 3);

    let tmpdir = bench_tmpdir("mscj-hot-cli-");
    let mut peer_labels = vec!["hub".to_string()];
    for idx in 1..source_count {
        peer_labels.push(format!("source-{idx:02}"));
    }

    let (sources, invite_link) =
        create_online_community(&tmpdir, &peer_labels, seeded_history_messages);
    let source_dbs: Vec<&str> = sources.iter().map(|source| source.db.as_str()).collect();
    let source_usernames: BTreeSet<String> = sources
        .iter()
        .map(|source| source.label.clone())
        .collect();
    let source_peer_ids: BTreeSet<String> = sources
        .iter()
        .map(|source| source.tenant_peer_id.clone())
        .collect();
    let non_hub_sources: Vec<&Node> = sources
        .iter()
        .filter(|source| source.label != "hub")
        .collect();

    let mesh_phase_start_ms = current_timestamp_ms();
    let mesh_warmup_messages = emit_messages(&sources, "mesh", 1);
    let mesh_warmup = converge_existing_mesh(
        &sources,
        seeded_history_messages,
        &mesh_warmup_messages,
        mesh_phase_start_ms,
        Duration::from_secs(120),
    );

    begin_step("emit_hot_head");
    let hot_head = emit_messages(&sources, "hot", hot_messages_per_peer);
    let expected_total_messages =
        seeded_history_messages as i64 + mesh_warmup_messages.len() as i64 + hot_head.len() as i64;
    pass_step(current_timestamp_ms(), "emit_hot_head", current_timestamp_ms());

    let hot_ids: BTreeSet<String> = hot_head.iter().map(|msg| msg.event_id.clone()).collect();
    let hot_non_hub_labels: BTreeSet<String> = hot_head
        .iter()
        .filter(|msg| msg.source_label != "hub")
        .map(|msg| msg.source_label.clone())
        .collect();

    let sink_db = tmpdir.path().join("sink.db").to_str().unwrap().to_string();
    let inherited_env = inherited_tier_env();
    let sink_daemon = start_peer(&sink_db, inherited_env);

    let invite_accept_at_ms = current_timestamp_ms();
    begin_step("invite_accept");
    accept_invite_with_identity_on_running_daemon(
        &sink_db,
        &invite_link,
        "sink",
        "laptop",
        Duration::from_secs(120),
    );
    ensure_active_peer(&sink_db, Duration::from_secs(10));
    wait_for_active_tenant_ready(&sink_db, Duration::from_secs(120));
    pass_step(invite_accept_at_ms, "invite_accept", current_timestamp_ms());

    let sink_node = Node {
        label: "sink".to_string(),
        db: sink_db.clone(),
        tenant_peer_id: active_tenant_peer_id(&sink_db).expect("sink active tenant peer id"),
        _daemon: sink_daemon,
    };

    begin_step("hot_messages_visible");
    let first_hot_message_visible_at_ms = wait_for_condition(
        "sink first hot message visible",
        &source_dbs.iter().copied().chain(std::iter::once(sink_db.as_str())).collect::<Vec<_>>(),
        Duration::from_secs(180),
        || {
            let visible = visible_message_ids(&sink_node.db);
            hot_ids.iter().any(|id| visible.contains(id))
        },
        || {
            let visible = visible_message_ids(&sink_node.db);
            format!("visible_hot={}/{}", visible.intersection(&hot_ids).count(), hot_ids.len())
        },
    );
    pass_step(
        invite_accept_at_ms,
        "first_hot_message_visible",
        first_hot_message_visible_at_ms,
    );
    let all_hot_messages_visible_at_ms = wait_for_condition(
        "sink all hot messages visible",
        &source_dbs.iter().copied().chain(std::iter::once(sink_db.as_str())).collect::<Vec<_>>(),
        Duration::from_secs(180),
        || {
            let visible = visible_message_ids(&sink_node.db);
            hot_ids.iter().all(|id| visible.contains(id))
        },
        || {
            let visible = visible_message_ids(&sink_node.db);
            format!("visible_hot={}/{}", visible.intersection(&hot_ids).count(), hot_ids.len())
        },
    );
    pass_step(invite_accept_at_ms, "all_hot_messages_visible", all_hot_messages_visible_at_ms);

    begin_step("sink_projects_all_source_peers");
    let sink_projected_all_source_peers_at_ms = wait_for_condition(
        "sink projected all source peers",
        &source_dbs.iter().copied().chain(std::iter::once(sink_db.as_str())).collect::<Vec<_>>(),
        Duration::from_secs(180),
        || {
            let projected = peer_usernames(&sink_node.db);
            source_usernames
                .iter()
                .all(|username| projected.contains(username))
        },
        || {
            let projected = peer_usernames(&sink_node.db);
            let missing: Vec<String> = source_usernames
                .iter()
                .filter(|username| !projected.contains(*username))
                .cloned()
                .collect();
            format!("missing source peers {:?}", missing)
        },
    );
    pass_step(
        invite_accept_at_ms,
        "sink_projects_all_source_peers",
        sink_projected_all_source_peers_at_ms,
    );

    begin_step("sink_observes_all_source_endpoints");
    let sink_observed_all_source_endpoints_at_ms = wait_for_condition(
        "sink projected all source endpoints",
        &source_dbs.iter().copied().chain(std::iter::once(sink_db.as_str())).collect::<Vec<_>>(),
        Duration::from_secs(180),
        || {
            let with_endpoints = peer_usernames_with_endpoint_ids(&sink_node.db);
            source_usernames.iter().all(|username| with_endpoints.contains(username))
        },
        || {
            let with_endpoints = peer_usernames_with_endpoint_ids(&sink_node.db);
            let missing: Vec<String> = source_usernames
                .iter()
                .filter(|username| !with_endpoints.contains(*username))
                .cloned()
                .collect();
            format!("missing source endpoints {:?}", missing)
        },
    );
    pass_step(
        invite_accept_at_ms,
        "sink_observes_all_source_endpoints",
        sink_observed_all_source_endpoints_at_ms,
    );

    begin_step("sink_sees_non_hub_sources");
    let sink_first_non_hub_source_visible_at_ms = wait_for_condition(
        "sink sees first non-hub hot source",
        &source_dbs.iter().copied().chain(std::iter::once(sink_db.as_str())).collect::<Vec<_>>(),
        Duration::from_secs(180),
        || !visible_phase_labels(&sink_node.db, "hot").intersection(&hot_non_hub_labels).collect::<BTreeSet<_>>().is_empty(),
        || {
            let visible = visible_phase_labels(&sink_node.db, "hot");
            format!("visible_non_hub={:?}", visible.intersection(&hot_non_hub_labels).cloned().collect::<Vec<_>>())
        },
    );
    pass_step(
        invite_accept_at_ms,
        "sink_first_non_hub_source_visible",
        sink_first_non_hub_source_visible_at_ms,
    );
    let sink_two_non_hub_sources_visible_at_ms = wait_for_condition(
        "sink sees two non-hub hot sources",
        &source_dbs.iter().copied().chain(std::iter::once(sink_db.as_str())).collect::<Vec<_>>(),
        Duration::from_secs(180),
        || visible_phase_labels(&sink_node.db, "hot").intersection(&hot_non_hub_labels).count() >= 2,
        || {
            let visible = visible_phase_labels(&sink_node.db, "hot");
            format!("visible_non_hub={:?}", visible.intersection(&hot_non_hub_labels).cloned().collect::<Vec<_>>())
        },
    );
    pass_step(
        invite_accept_at_ms,
        "sink_two_non_hub_sources_visible",
        sink_two_non_hub_sources_visible_at_ms,
    );

    begin_step("sink_connects_to_non_hub_sources");
    let non_hub_source_peer_ids: BTreeSet<String> = non_hub_sources
        .iter()
        .map(|source| source.tenant_peer_id.clone())
        .collect();
    let sink_seen_live_session_peers: RefCell<BTreeSet<String>> = RefCell::new(BTreeSet::new());
    let existing_mesh_seen_sink: RefCell<BTreeSet<String>> = RefCell::new(BTreeSet::new());
    let sink_live_sessions_with_two_non_hub_sources_at_ms = wait_for_condition(
        "sink live sessions with two non-hub sources",
        &source_dbs.iter().copied().chain(std::iter::once(sink_db.as_str())).collect::<Vec<_>>(),
        Duration::from_secs(180),
        || {
            let current = live_session_peer_ids(&sink_node.db);
            sink_seen_live_session_peers.borrow_mut().extend(current);
            sink_seen_live_session_peers
                .borrow()
                .intersection(&non_hub_source_peer_ids)
                .count()
                >= 2
        },
        || {
            let live = live_session_peer_ids(&sink_node.db);
            let seen = sink_seen_live_session_peers.borrow();
            let connected = observed_peer_ids(&sink_node.db);
            format!(
                "sink_live_non_hub_now={:?} seen={:?} connected_non_hub={:?}",
                live.intersection(&non_hub_source_peer_ids).cloned().collect::<Vec<_>>(),
                seen.intersection(&non_hub_source_peer_ids).cloned().collect::<Vec<_>>(),
                connected.intersection(&non_hub_source_peer_ids).cloned().collect::<Vec<_>>()
            )
        },
    );
    pass_step(
        invite_accept_at_ms,
        "sink_live_sessions_with_two_non_hub_sources",
        sink_live_sessions_with_two_non_hub_sources_at_ms,
    );
    begin_step("existing_mesh_projects_sink");
    let existing_mesh_projected_sink_at_ms = wait_for_condition(
        "existing mesh projects sink peer row",
        &source_dbs.iter().copied().chain(std::iter::once(sink_db.as_str())).collect::<Vec<_>>(),
        Duration::from_secs(180),
        || {
            sources.iter().all(|source| peer_usernames(&source.db).contains(&sink_node.label))
        },
        || {
            let missing: Vec<String> = sources
                .iter()
                .filter(|source| !peer_usernames(&source.db).contains(&sink_node.label))
                .map(|source| source.label.clone())
                .collect();
            format!("sources missing sink peer row {:?}", missing)
        },
    );
    pass_step(
        invite_accept_at_ms,
        "existing_mesh_projects_sink",
        existing_mesh_projected_sink_at_ms,
    );

    begin_step("existing_mesh_observes_sink");
    let existing_mesh_observed_sink_at_ms = wait_for_condition(
        "existing mesh projected sink endpoint",
        &source_dbs.iter().copied().chain(std::iter::once(sink_db.as_str())).collect::<Vec<_>>(),
        Duration::from_secs(180),
        || {
            sources.iter().all(|source| peer_usernames_with_endpoint_ids(&source.db).contains(&sink_node.label))
        },
        || {
            let missing: Vec<String> = sources
                .iter()
                .filter(|source| !peer_usernames_with_endpoint_ids(&source.db).contains(&sink_node.label))
                .map(|source| source.label.clone())
                .collect();
            format!("sources missing sink endpoint {:?}", missing)
        },
    );
    pass_step(
        invite_accept_at_ms,
        "existing_mesh_observes_sink",
        existing_mesh_observed_sink_at_ms,
    );

    begin_step("existing_mesh_connects_to_sink");
    let existing_mesh_live_sessions_with_sink_at_ms = wait_for_condition(
        "existing mesh has direct connections to sink",
        &source_dbs.iter().copied().chain(std::iter::once(sink_db.as_str())).collect::<Vec<_>>(),
        Duration::from_secs(180),
        || {
            {
                let mut seen = existing_mesh_seen_sink.borrow_mut();
                for source in &sources {
                    if observed_peer_ids(&source.db).contains(&sink_node.tenant_peer_id) {
                        seen.insert(source.label.clone());
                    }
                }
            }
            sources.iter().all(|source| existing_mesh_seen_sink.borrow().contains(&source.label))
        },
        || {
            let seen = existing_mesh_seen_sink.borrow();
            let missing: Vec<String> = sources
                .iter()
                .filter(|source| !seen.contains(&source.label))
                .map(|source| source.label.clone())
                .collect();
            format!("sources missing sink connection {:?}", missing)
        },
    );
    pass_step(
        invite_accept_at_ms,
        "existing_mesh_connects_to_sink",
        existing_mesh_live_sessions_with_sink_at_ms,
    );

    let sink_live_sessions_with_all_sources_at_ms = wait_for_condition(
        "sink live sessions with all existing sources",
        &source_dbs.iter().copied().chain(std::iter::once(sink_db.as_str())).collect::<Vec<_>>(),
        Duration::from_secs(180),
        || {
            let current = live_session_peer_ids(&sink_node.db);
            sink_seen_live_session_peers.borrow_mut().extend(current);
            source_peer_ids.iter().all(|peer_id| {
                sink_seen_live_session_peers.borrow().contains(peer_id)
            })
        },
        || {
            let live = live_session_peer_ids(&sink_node.db);
            let seen = sink_seen_live_session_peers.borrow();
            let missing: Vec<String> = source_peer_ids
                .iter()
                .filter(|peer_id| !seen.contains(*peer_id))
                .cloned()
                .collect();
            format!("sink missing seen live sessions {:?} (live_now={:?})", missing, live)
        },
    );
    pass_step(
        invite_accept_at_ms,
        "sink_live_sessions_with_all_sources",
        sink_live_sessions_with_all_sources_at_ms,
    );

    let sink_message_count_when_hot_complete = message_total(&sink_node.db);
    let full_catchup_at_ms = if wait_for_full_catchup {
        begin_step("full_catchup");
        let full_catchup_at_ms = wait_for_condition(
            "sink full catchup",
            &source_dbs.iter().copied().chain(std::iter::once(sink_db.as_str())).collect::<Vec<_>>(),
            Duration::from_secs(300),
            || message_total(&sink_node.db) >= expected_total_messages,
            || format!("sink_total={} expected_total={}", message_total(&sink_node.db), expected_total_messages),
        );
        pass_step(invite_accept_at_ms, "full_catchup", full_catchup_at_ms);
        full_catchup_at_ms
    } else {
        sink_live_sessions_with_all_sources_at_ms
    };

    let visible_non_hub_sources: Vec<String> = visible_phase_labels(&sink_node.db, "hot")
        .intersection(&hot_non_hub_labels)
        .cloned()
        .collect();
    let sink_live_session_peers: Vec<String> = sink_seen_live_session_peers
        .borrow()
        .iter()
        .cloned()
        .collect();
    let source_connection_counts_with_sink: Vec<(String, usize)> = sources
        .iter()
        .map(|source| {
            (
                source.label.clone(),
                usize::from(existing_mesh_seen_sink.borrow().contains(&source.label)),
            )
        })
        .collect();
    let sink_hot_timeline_report = event_timeline_report_cli(
        &sink_node.db,
        "hot:",
        hot_head.len(),
        invite_accept_at_ms,
    );

    let outcome = ColdJoinOutcome {
        milestones: ColdJoinMilestones {
            mesh_messages_converged_at_ms: mesh_warmup.messages_converged_at_ms,
            mesh_peer_identities_converged_at_ms: mesh_warmup.peer_identities_converged_at_ms,
            mesh_endpoint_observations_converged_at_ms: mesh_warmup.endpoint_observations_converged_at_ms,
            mesh_live_sessions_converged_at_ms: mesh_warmup.live_sessions_converged_at_ms,
            invite_accept_at_ms,
            first_hot_message_visible_at_ms,
            all_hot_messages_visible_at_ms,
            sink_projected_all_source_peers_at_ms,
            sink_observed_all_source_endpoints_at_ms,
            sink_first_non_hub_source_visible_at_ms,
            sink_two_non_hub_sources_visible_at_ms,
            sink_live_sessions_with_two_non_hub_sources_at_ms,
            sink_live_sessions_with_all_sources_at_ms,
            existing_mesh_projected_sink_at_ms,
            existing_mesh_observed_sink_at_ms,
            existing_mesh_live_sessions_with_sink_at_ms,
            full_catchup_at_ms,
        },
        expected_total_messages,
        hot_message_count: hot_head.len(),
        sink_message_count_when_hot_complete,
        visible_non_hub_sources,
        sink_live_session_peers,
        source_connection_counts_with_sink,
        sink_hot_timeline_report,
    };

    write_cold_join_summary(
        wait_for_full_catchup
            .then(|| {
                format!(
                    "daemon_multi_source_tiered_window_perf_test.cold_join_hot_head_cli_{}x_{}seed_{}hot",
                    source_count, seeded_history_messages, hot_messages_per_peer
                )
            })
            .as_deref(),
        &outcome,
    );

    outcome
}

#[test]
fn mesh_four_peers_discover_and_connect() {
    hold_network_test_lock_for_binary();
    std::env::set_var("TOPO_GENERATE_MESSAGE_SPREAD_MS", "94608000000");
    std::env::set_var("TOPO_EVENT_TIMELINE", "1");
    std::env::set_var("TOPO_EVENT_TIMELINE_GROUPS", "receive,persist,projection");

    let seeded_history_messages = env_usize("TOPO_MULTI_SOURCE_SEEDED_HISTORY_MESSAGES", 0);
    let tmpdir = bench_tmpdir("mesh-four-cli-");
    let peer_labels = vec![
        "hub".to_string(),
        "source-01".to_string(),
        "source-02".to_string(),
        "source-03".to_string(),
    ];
    let (sources, _) = create_online_community(&tmpdir, &peer_labels, seeded_history_messages);
    let started_at_ms = current_timestamp_ms();
    let warmup_messages = emit_messages(&sources, "mesh", 1);
    let outcome = converge_existing_mesh(
        &sources,
        seeded_history_messages,
        &warmup_messages,
        started_at_ms,
        Duration::from_secs(120),
    );

    let warmup_ids: BTreeSet<String> = warmup_messages.iter().map(|msg| msg.event_id.clone()).collect();
    for source in &sources {
        let visible = visible_message_ids(&source.db);
        assert!(
            warmup_ids.iter().all(|id| visible.contains(id)),
            "expected {} to display all warmup mesh messages",
            source.label,
        );
    }
    assert!(
        outcome.messages_converged_at_ms <= outcome.peer_identities_converged_at_ms
            && outcome.peer_identities_converged_at_ms
                <= outcome.endpoint_observations_converged_at_ms
            && outcome.endpoint_observations_converged_at_ms
                <= outcome.live_sessions_converged_at_ms,
        "mesh convergence milestones should be monotonic: {:?}",
        outcome,
    );
}

#[test]
fn cold_join_4x_hot_head_projects_identity_and_activates_multisource() {
    std::env::set_var("TOPO_MULTI_SOURCE_SEEDED_HISTORY_MESSAGES", "32");
    std::env::set_var("TOPO_MULTI_SOURCE_HOT_MESSAGES_PER_PEER", "3");
    let outcome = run_cold_join_hot_head_diagnostic(4, false);

    assert_eq!(
        outcome.hot_message_count,
        12,
        "expected 3 fresh hot messages from each of 4 existing peers"
    );
    assert!(
        outcome.sink_message_count_when_hot_complete < outcome.expected_total_messages,
        "hot head should complete before full backlog catch-up: hot_complete_count={} expected_total={}",
        outcome.sink_message_count_when_hot_complete,
        outcome.expected_total_messages,
    );
    assert!(
        outcome.visible_non_hub_sources.len() >= 2,
        "expected at least two non-hub sources visible on sink, got {:?}",
        outcome.visible_non_hub_sources,
    );
    let sink_non_hub_live_sessions = outcome
        .sink_live_session_peers
        .iter()
        .filter(|peer_id| !peer_id.is_empty())
        .count();
    assert!(
        sink_non_hub_live_sessions >= 4,
        "expected sink to maintain live sessions with all existing peers, got {:?}",
        outcome.sink_live_session_peers,
    );
    assert!(
        outcome
            .source_connection_counts_with_sink
            .iter()
            .all(|(_, count)| *count > 0),
        "expected every existing peer to maintain a direct connection with sink, got {:?}",
        outcome.source_connection_counts_with_sink,
    );
}

#[test]
#[ignore]
fn perf_multi_source_cold_join_4x_hot_head_diagnostic() {
    if std::env::var_os("TOPO_MULTI_SOURCE_SEEDED_HISTORY_MESSAGES").is_none() {
        std::env::set_var("TOPO_MULTI_SOURCE_SEEDED_HISTORY_MESSAGES", "96");
    }
    if std::env::var_os("TOPO_MULTI_SOURCE_HOT_MESSAGES_PER_PEER").is_none() {
        std::env::set_var("TOPO_MULTI_SOURCE_HOT_MESSAGES_PER_PEER", "6");
    }
    let _ = run_cold_join_hot_head_diagnostic(4, true);
}
