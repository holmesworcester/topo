//! Realistic two-peer join catchup benchmark focused on newest-message visibility.
//!
//! Run with:
//! `cargo test --release --test daemon_join_catchup_perf_test -- --ignored --nocapture --test-threads=1`

mod cli_harness;

use std::collections::{HashMap, HashSet};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cli_harness::{
    accept_invite_with_identity_on_running_daemon, active_tenant_peer_id, create_invite_with_spki,
    create_workspace_with_details, daemon_listen_addr, daemon_transport_fingerprint,
    ensure_active_peer, generate_messages, message_count_sql, send_message,
    start_daemon_with_options, stop_daemon, wait_for_daemon_stopped, DaemonOptions,
};
use topo::db::timeline::{EventTimeline, EventTimelineRow};
use topo::service::{self, EventListItem};

const NEWEST_MESSAGE_CONTENT: &str = "join-catchup-newest-message";
const DEP_GRAPH_DEPTH: usize = 6;

fn wait_for_message_count(db: &str, expected: i64, timeout: Duration) {
    let start = Instant::now();
    loop {
        let count = message_count_sql(db);
        if count >= expected {
            return;
        }
        assert!(
            start.elapsed() < timeout,
            "message_count timed out after {:?} for db={}: expected_at_least={} actual={}",
            timeout,
            db,
            expected,
            count
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn wait_for_event_projected_at(db: &str, event_id_b64: &str, timeout: Duration) -> i64 {
    let start = Instant::now();
    loop {
        if let Some(projected_at) =
            lookup_timeline_row(db, event_id_b64).and_then(|row| row.projected_at)
        {
            return projected_at;
        }
        assert!(
            start.elapsed() < timeout,
            "event {:?} did not reach projected_at in {:?} for db={}",
            event_id_b64,
            timeout,
            db
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn write_summary(summary_key: &str, summary: &str) {
    let summary_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/perf-results");
    std::fs::create_dir_all(&summary_dir).expect("create target/perf-results");
    std::fs::write(summary_dir.join(format!("{summary_key}.summary")), summary)
        .expect("write benchmark summary file");
}

fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as i64
}

fn env_i64(name: &str, default: i64) -> i64 {
    match std::env::var(name) {
        Ok(value) => value
            .parse::<i64>()
            .unwrap_or_else(|err| panic!("{name} must be a positive integer: {err}")),
        Err(_) => default,
    }
}

fn lookup_timeline_row(db: &str, event_id_b64: &str) -> Option<EventTimelineRow> {
    let conn = topo::db::open_connection(db).expect("open db for timeline lookup");
    EventTimeline::new(&conn)
        .load(event_id_b64)
        .expect("query event_timeline")
}

fn load_dep_events(
    db: &str,
    recorded_by: &str,
    event_id_b64: &str,
    depth: usize,
) -> Vec<EventListItem> {
    let conn = topo::db::open_connection(db).expect("open db for dependency walk");
    let response =
        service::svc_event_deps(&conn, recorded_by, event_id_b64, depth).expect("svc_event_deps");
    serde_json::from_value(response["events"].clone()).expect("deserialize dependency events")
}

fn load_dep_events_with_transport_provenance(
    db: &str,
    recorded_by: &str,
    event_id_b64: &str,
    depth: usize,
) -> Vec<EventListItem> {
    let mut dep_events = load_dep_events(db, recorded_by, event_id_b64, depth);
    let mut seen_ids: HashSet<String> = dep_events.iter().map(|item| item.id.clone()).collect();
    let key_secret_ids = dep_events
        .iter()
        .filter(|item| item.event_type == "key_secret")
        .map(|item| item.id.clone())
        .collect::<Vec<_>>();

    for key_secret_id in key_secret_ids {
        let Some(provenance) = lookup_key_secret_provenance(db, recorded_by, &key_secret_id) else {
            continue;
        };
        for item in load_dep_events(db, recorded_by, &provenance.wrapped_key_event_id, depth) {
            if seen_ids.insert(item.id.clone()) {
                dep_events.push(item);
            }
        }
    }

    dep_events
}

struct KeySecretProvenance {
    wrapped_key_event_id: String,
    wrapped_key_timeline: Option<EventTimelineRow>,
    unwrapped_recorded_at: Option<i64>,
    key_secret_projected_at: Option<i64>,
}

fn lookup_key_secret_provenance(
    db: &str,
    recorded_by: &str,
    key_secret_event_id_b64: &str,
) -> Option<KeySecretProvenance> {
    let conn = topo::db::open_connection(db).expect("open db for key_secret provenance");
    let unwrapped_recorded_at = conn
        .query_row(
            "SELECT recorded_at
             FROM recorded_events
             WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, key_secret_event_id_b64],
            |row| row.get::<_, i64>(0),
        )
        .ok();
    let key_secret_projected_at = EventTimeline::new(&conn)
        .load(key_secret_event_id_b64)
        .expect("query key_secret timeline")
        .and_then(|row| row.projected_at);
    let wrapped_key_event_ids: Vec<String> = {
        let mut stmt = conn
            .prepare(
                "SELECT event_id
                 FROM key_shared
                 WHERE recorded_by = ?1 AND key_event_id = ?2",
            )
            .expect("prepare key_shared provenance query");
        let rows = stmt
            .query_map(
                rusqlite::params![recorded_by, key_secret_event_id_b64],
                |row| row.get::<_, String>(0),
            )
            .expect("query key_shared provenance rows");
        rows.collect::<Result<Vec<_>, _>>()
            .expect("collect key_shared provenance rows")
    };

    let mut best_wrapped: Option<(String, Option<EventTimelineRow>, (i64, i64, i64, String))> =
        None;
    for wrapped_key_event_id in wrapped_key_event_ids {
        let wrapped_key_timeline = EventTimeline::new(&conn)
            .load(&wrapped_key_event_id)
            .expect("query key_shared timeline");
        let response_received_at = wrapped_key_timeline
            .as_ref()
            .and_then(|row| row.response_received_at)
            .unwrap_or(i64::MIN);
        let persisted_at = wrapped_key_timeline
            .as_ref()
            .and_then(|row| row.persisted_at)
            .unwrap_or(i64::MIN);
        let projected_at = wrapped_key_timeline
            .as_ref()
            .and_then(|row| row.projected_at)
            .unwrap_or(i64::MIN);
        let arrived_before_project = key_secret_projected_at
            .map(|projected| response_received_at <= projected || persisted_at <= projected)
            .unwrap_or(false);
        let rank = (
            if arrived_before_project { 1 } else { 0 },
            response_received_at,
            persisted_at.max(projected_at),
            wrapped_key_event_id.clone(),
        );

        match &best_wrapped {
            Some((_, _, best_rank)) if best_rank >= &rank => {}
            _ => {
                best_wrapped = Some((wrapped_key_event_id, wrapped_key_timeline, rank));
            }
        }
    }
    let (wrapped_key_event_id, wrapped_key_timeline, _) = best_wrapped?;

    Some(KeySecretProvenance {
        wrapped_key_event_id,
        wrapped_key_timeline,
        unwrapped_recorded_at,
        key_secret_projected_at,
    })
}

fn event_label(item: &EventListItem) -> String {
    match &item.decrypted_inner {
        Some(inner) => format!("{}({})", item.event_type, inner.inner_type),
        None => item.event_type.clone(),
    }
}

fn event_fields(item: &EventListItem) -> &[(String, String)] {
    match &item.decrypted_inner {
        Some(inner) => &inner.fields,
        None => &item.fields,
    }
}

fn short_id(event_id_b64: &str) -> &str {
    &event_id_b64[..event_id_b64.len().min(12)]
}

fn normalize_event_id_b64(event_id: &str) -> String {
    topo::crypto::event_id_from_hex(event_id)
        .map(|id| topo::crypto::event_id_to_base64(&id))
        .unwrap_or_else(|| event_id.to_string())
}

fn truncate(value: &str, max_len: usize) -> String {
    if value.len() <= max_len {
        value.to_string()
    } else {
        format!("{}...", &value[..max_len])
    }
}

fn summarize_fields(item: &EventListItem) -> String {
    let fields = event_fields(item);
    if fields.is_empty() {
        return String::new();
    }
    let mut parts = Vec::new();
    for (key, value) in fields.iter().take(2) {
        parts.push(format!("{key}={}", truncate(value, 36)));
    }
    format!(" [{}]", parts.join(", "))
}

fn fmt_rel_ts(ts: Option<i64>, start_ms: i64) -> String {
    match ts {
        Some(value) => format!("{value} ({:+}ms)", value - start_ms),
        None => "-".to_string(),
    }
}

fn fmt_rel_delta(from: Option<i64>, to: Option<i64>) -> String {
    match (from, to) {
        (Some(start), Some(end)) => format!("{}ms", end - start),
        _ => "-".to_string(),
    }
}

struct DiscoveryWindow {
    first_discovered_at: Option<i64>,
    last_discovered_at: Option<i64>,
}

fn load_discovery_window(db: &str) -> DiscoveryWindow {
    let conn = topo::db::open_connection(db).expect("open db for discovery window");
    let (first_discovered_at, last_discovered_at) = conn
        .query_row(
            "SELECT
                 MIN(wanted_discovered_at),
                 MAX(wanted_discovered_at)
             FROM event_timeline
             WHERE wanted_discovered_at IS NOT NULL",
            [],
            |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, Option<i64>>(1)?)),
        )
        .expect("query discovery window");
    DiscoveryWindow {
        first_discovered_at,
        last_discovered_at,
    }
}

fn append_dependency_timeline_summary(
    summary: &mut String,
    alice_db: &str,
    bob_db: &str,
    bob_peer_id: &str,
    newest_message_id: &str,
    metric_start_ms: i64,
) {
    let dep_events = load_dep_events_with_transport_provenance(
        bob_db,
        bob_peer_id,
        newest_message_id,
        DEP_GRAPH_DEPTH,
    );
    let dep_map: HashMap<String, &EventListItem> = dep_events
        .iter()
        .map(|item| (item.id.clone(), item))
        .collect();

    summary.push_str(
        "\nDependency graph for newest message (merged inner deps + wrapper deps + key transport provenance):\n",
    );
    for item in &dep_events {
        let mut dep_parts = item
            .deps
            .iter()
            .map(|(field, dep_id)| {
                let dep_label = dep_map
                    .get(dep_id)
                    .map(|dep| event_label(dep))
                    .unwrap_or_else(|| "missing".to_string());
                format!("{field}->{dep_label}[{}]", short_id(dep_id))
            })
            .collect::<Vec<_>>();
        if item.event_type == "key_secret" {
            if let Some(provenance) = lookup_key_secret_provenance(bob_db, bob_peer_id, &item.id) {
                let dep_label = dep_map
                    .get(&provenance.wrapped_key_event_id)
                    .map(|dep| event_label(dep))
                    .unwrap_or_else(|| "key_shared".to_string());
                dep_parts.push(format!(
                    "transport_key_shared->{dep_label}[{}]",
                    short_id(&provenance.wrapped_key_event_id)
                ));
            }
        }
        let deps = if dep_parts.is_empty() {
            "-".to_string()
        } else {
            dep_parts.join(", ")
        };
        summary.push_str(&format!(
            "  {} {} created_at={}{}\n",
            short_id(&item.id),
            event_label(item),
            item.created_at_ms,
            summarize_fields(item),
        ));
        summary.push_str(&format!("    deps: {deps}\n"));
        if item.event_type == "key_secret" {
            if let Some(provenance) = lookup_key_secret_provenance(bob_db, bob_peer_id, &item.id) {
                summary.push_str(&format!(
                    "    derived_from: key_shared[{}]; wrapped_key_arrived={}; unwrapped_recorded={}; key_secret_projected={}\n",
                    short_id(&provenance.wrapped_key_event_id),
                    fmt_rel_ts(
                        provenance
                            .wrapped_key_timeline
                            .as_ref()
                            .and_then(|row| row.response_received_at),
                        metric_start_ms,
                    ),
                    fmt_rel_ts(provenance.unwrapped_recorded_at, metric_start_ms),
                    fmt_rel_ts(provenance.key_secret_projected_at, metric_start_ms),
                ));
            }
        }
    }

    summary.push_str("\nEvent timeline timestamps (absolute ms and delta from invite accept):\n");
    summary.push_str("  columns: bob_discovered | bob_req_selected | bob_req_sent | alice_req_recv | alice_resp_sent | bob_resp_recv | bob_persisted | bob_projected\n");
    for item in &dep_events {
        let bob_row = lookup_timeline_row(bob_db, &item.id);
        let alice_row = lookup_timeline_row(alice_db, &item.id);
        summary.push_str(&format!(
            "  {} {}{} \n",
            short_id(&item.id),
            event_label(item),
            summarize_fields(item),
        ));
        summary.push_str(&format!(
            "    {} | {} | {} | {} | {} | {} | {} | {}\n",
            fmt_rel_ts(
                bob_row.as_ref().and_then(|row| row.wanted_discovered_at),
                metric_start_ms,
            ),
            fmt_rel_ts(
                bob_row.as_ref().and_then(|row| row.request_selected_at),
                metric_start_ms,
            ),
            fmt_rel_ts(
                bob_row.as_ref().and_then(|row| row.request_sent_at),
                metric_start_ms,
            ),
            fmt_rel_ts(
                alice_row.as_ref().and_then(|row| row.request_received_at),
                metric_start_ms,
            ),
            fmt_rel_ts(
                alice_row.as_ref().and_then(|row| row.response_sent_at),
                metric_start_ms,
            ),
            fmt_rel_ts(
                bob_row.as_ref().and_then(|row| row.response_received_at),
                metric_start_ms,
            ),
            fmt_rel_ts(
                bob_row.as_ref().and_then(|row| row.persisted_at),
                metric_start_ms,
            ),
            fmt_rel_ts(
                bob_row.as_ref().and_then(|row| row.projected_at),
                metric_start_ms,
            ),
        ));
        if bob_row
            .as_ref()
            .is_some_and(|row| row.blocked_at.is_some() || row.unblocked_at.is_some())
        {
            let unblocked_by = bob_row
                .as_ref()
                .and_then(|row| row.unblocked_by_event_id.as_deref())
                .map(short_id)
                .unwrap_or("-");
            summary.push_str(&format!(
                "    blocking: blocked={} | blocked_by_key={} | blocked_by_dep={} | unblocked={} | by={} | blocked->unblocked={} | unblocked->projected={}\n",
                fmt_rel_ts(bob_row.as_ref().and_then(|row| row.blocked_at), metric_start_ms),
                fmt_rel_ts(
                    bob_row.as_ref().and_then(|row| row.blocked_by_key_at),
                    metric_start_ms,
                ),
                fmt_rel_ts(
                    bob_row.as_ref().and_then(|row| row.blocked_by_dep_at),
                    metric_start_ms,
                ),
                fmt_rel_ts(bob_row.as_ref().and_then(|row| row.unblocked_at), metric_start_ms),
                unblocked_by,
                fmt_rel_delta(
                    bob_row.as_ref().and_then(|row| row.blocked_at),
                    bob_row.as_ref().and_then(|row| row.unblocked_at),
                ),
                fmt_rel_delta(
                    bob_row.as_ref().and_then(|row| row.unblocked_at),
                    bob_row.as_ref().and_then(|row| row.projected_at),
                ),
            ));
        }
        if item.event_type == "key_secret" {
            if let Some(provenance) = lookup_key_secret_provenance(bob_db, bob_peer_id, &item.id) {
                summary.push_str(&format!(
                    "    wrapped_from key_shared[{}]: discovered={} | requested={} | arrived={} | persisted={} | blocked_by_dep={} | unblocked={} | projected={}; key_secret_unwrapped_recorded={} | key_secret_projected={}\n",
                    short_id(&provenance.wrapped_key_event_id),
                    fmt_rel_ts(
                        provenance
                            .wrapped_key_timeline
                            .as_ref()
                            .and_then(|row| row.wanted_discovered_at),
                        metric_start_ms,
                    ),
                    fmt_rel_ts(
                        provenance
                            .wrapped_key_timeline
                            .as_ref()
                            .and_then(|row| row.request_sent_at),
                        metric_start_ms,
                    ),
                    fmt_rel_ts(
                        provenance
                            .wrapped_key_timeline
                            .as_ref()
                            .and_then(|row| row.response_received_at),
                        metric_start_ms,
                    ),
                    fmt_rel_ts(
                        provenance
                            .wrapped_key_timeline
                            .as_ref()
                            .and_then(|row| row.persisted_at),
                        metric_start_ms,
                    ),
                    fmt_rel_ts(
                        provenance
                            .wrapped_key_timeline
                            .as_ref()
                            .and_then(|row| row.blocked_by_dep_at),
                        metric_start_ms,
                    ),
                    fmt_rel_ts(
                        provenance
                            .wrapped_key_timeline
                            .as_ref()
                            .and_then(|row| row.unblocked_at),
                        metric_start_ms,
                    ),
                    fmt_rel_ts(
                        provenance
                            .wrapped_key_timeline
                            .as_ref()
                            .and_then(|row| row.projected_at),
                        metric_start_ms,
                    ),
                    fmt_rel_ts(provenance.unwrapped_recorded_at, metric_start_ms),
                    fmt_rel_ts(provenance.key_secret_projected_at, metric_start_ms),
                ));
            }
        }
    }
}

#[test]
#[ignore]
fn perf_join_catchup_10k_newest_message_visible() {
    std::env::set_var("TOPO_EVENT_TIMELINE", "1");
    let total_messages = env_i64("TOPO_JOIN_CATCHUP_TOTAL_MESSAGES", 10_000);
    assert!(
        total_messages >= 1,
        "TOPO_JOIN_CATCHUP_TOTAL_MESSAGES must be >= 1"
    );

    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();

    create_workspace_with_details(&alice_db, "workspace", "alice", "desktop");
    let mut alice_daemon = start_daemon_with_options(
        &alice_db,
        &DaemonOptions {
            disable_discovery: true,
            ..Default::default()
        },
    );
    ensure_active_peer(&alice_db, Duration::from_secs(10));

    generate_messages(&alice_db, (total_messages - 1) as usize);
    let newest_message_id_hex = send_message(&alice_db, NEWEST_MESSAGE_CONTENT)
        .trim()
        .to_string();
    let newest_message_id_b64 = normalize_event_id_b64(&newest_message_id_hex);
    wait_for_message_count(&alice_db, total_messages, Duration::from_secs(1200));
    eprintln!("preload complete: alice has {total_messages} messages");

    let invite_link = create_invite_with_spki(
        &alice_db,
        &daemon_listen_addr(&alice_db),
        Some(&daemon_transport_fingerprint(&alice_db)),
    );
    let mut bob_daemon = start_daemon_with_options(
        &bob_db,
        &DaemonOptions {
            disable_discovery: true,
            ..Default::default()
        },
    );

    let metric_start_ms = current_timestamp_ms();
    let start = Instant::now();
    accept_invite_with_identity_on_running_daemon(
        &bob_db,
        &invite_link,
        "bob",
        "laptop",
        Duration::from_secs(30),
    );
    eprintln!("invite accepted; waiting for newest message projection");

    let newest_projected_at =
        wait_for_event_projected_at(&bob_db, &newest_message_id_b64, Duration::from_secs(1200));
    let newest_projected_secs = (newest_projected_at - metric_start_ms) as f64 / 1000.0;
    eprintln!("newest message projected (visibility proxy) after {newest_projected_secs:.2}s");

    wait_for_message_count(&bob_db, total_messages, Duration::from_secs(1200));
    let full_catchup_secs = start.elapsed().as_secs_f64();
    eprintln!("full message catchup reached after {full_catchup_secs:.2}s");

    let bob_peer_id = active_tenant_peer_id(&bob_db).expect("bob active tenant peer id");
    let discovery_window = load_discovery_window(&bob_db);

    let mut summary = format!(
        "=== join catchup newest-message visibility ===\n  Messages preloaded on inviter: {total_messages}\n  Metric start: invite accept on running joiner daemon\n  Newest message id (hex): {newest_message_id_hex}\n  Newest message id (base64): {newest_message_id_b64}\n  Newest projected (visibility proxy): {newest_projected_secs:.2}s\n  Full catchup ready: {full_catchup_secs:.2}s\n  First discovered on joiner: {}\n  Last discovered on joiner: {}\n",
        fmt_rel_ts(discovery_window.first_discovered_at, metric_start_ms),
        fmt_rel_ts(discovery_window.last_discovered_at, metric_start_ms),
    );
    append_dependency_timeline_summary(
        &mut summary,
        &alice_db,
        &bob_db,
        &bob_peer_id,
        &newest_message_id_b64,
        metric_start_ms,
    );
    eprintln!("\n{summary}");
    let summary_key = format!(
        "daemon_join_catchup_perf_test.perf_join_catchup_newest_message_visible_{total_messages}"
    );
    write_summary(&summary_key, &summary);
    eprintln!("summary written; stopping daemons");

    stop_daemon(&bob_db, &mut bob_daemon);
    wait_for_daemon_stopped(&bob_db, Duration::from_secs(10));
    stop_daemon(&alice_db, &mut alice_daemon);
    wait_for_daemon_stopped(&alice_db, Duration::from_secs(10));
}
