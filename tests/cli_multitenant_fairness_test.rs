//! Black-box multitenant catch-up fairness benchmark.
//!
//! Models the real contention case:
//! - one shared-db daemon hosts 4 source tenants/workspaces
//! - one shared-db daemon hosts 4 sink tenants/workspaces
//! - each sink tenant catches up 50k projected messages from its source tenant
//!   at the same time over the real CLI/daemon path
//!
//! This is intentionally ignored by default because it is a heavy perf/fairness
//! run, not a merge-gate smoke test.

mod cli_harness;
mod daemon_perf_harness;

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use cli_harness::{
    accept_invite_with_identity, active_tenant_peer_id, create_invite,
    create_workspace_with_details, generate_messages, hold_network_test_lock_for_binary,
    peak_rss_mib_for_pid, random_port, start_daemon, start_daemon_with_options, use_tenant,
    DaemonOptions, HarnessDaemon,
};
use daemon_perf_harness::write_summary;
use topo::db::open_connection;

const MESSAGE_COUNT: i64 = 50_000;
const GENERATE_SPREAD_MS: i64 = 3 * 365 * 24 * 60 * 60 * 1000;

struct TenantSpec {
    workspace: &'static str,
    source_username: &'static str,
    source_device: &'static str,
    sink_username: &'static str,
    sink_device: &'static str,
}

const TENANTS: &[TenantSpec] = &[
    TenantSpec {
        workspace: "alpha-space",
        source_username: "alpha-src",
        source_device: "alpha-root",
        sink_username: "alpha-sink",
        sink_device: "alpha-phone",
    },
    TenantSpec {
        workspace: "beta-space",
        source_username: "beta-src",
        source_device: "beta-root",
        sink_username: "beta-sink",
        sink_device: "beta-phone",
    },
    TenantSpec {
        workspace: "gamma-space",
        source_username: "gamma-src",
        source_device: "gamma-root",
        sink_username: "gamma-sink",
        sink_device: "gamma-phone",
    },
    TenantSpec {
        workspace: "delta-space",
        source_username: "delta-src",
        source_device: "delta-root",
        sink_username: "delta-sink",
        sink_device: "delta-phone",
    },
];

fn tenant_peer_id_for_username(db_path: &str, username: &str) -> Option<String> {
    let conn = open_connection(db_path).expect("open db");
    let active_peer_id = active_tenant_peer_id(db_path).unwrap_or_default();
    topo::event_modules::workspace::queries::list_tenants_for_display(&conn, &active_peer_id)
        .ok()?
        .into_iter()
        .find(|tenant| tenant.username == username)
        .map(|tenant| tenant.peer_id)
}

fn wait_for_username_peer_id(db_path: &str, username: &str, timeout: Duration) -> String {
    let start = Instant::now();
    loop {
        if let Some(peer_id) = tenant_peer_id_for_username(db_path, username) {
            return peer_id;
        }
        assert!(
            start.elapsed() < timeout,
            "username {} did not materialize in {} within {:?}",
            username,
            db_path,
            timeout
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn tenant_index_for_peer_id(db_path: &str, peer_id: &str) -> usize {
    let conn = open_connection(db_path).expect("open db");
    let active_peer_id = active_tenant_peer_id(db_path).unwrap_or_default();
    topo::event_modules::workspace::queries::list_tenants_for_display(&conn, &active_peer_id)
        .expect("list tenants for display")
        .iter()
        .position(|tenant| tenant.peer_id == peer_id)
        .map(|idx| idx + 1)
        .expect("peer id should appear in tenant scopes")
}

fn use_tenant_for_username(db_path: &str, username: &str) {
    let peer_id = wait_for_username_peer_id(db_path, username, Duration::from_secs(90));
    let idx = tenant_index_for_peer_id(db_path, &peer_id);
    use_tenant(db_path, &idx.to_string());
}

fn projected_message_count_for_username(db_path: &str, username: &str) -> i64 {
    let peer_id = wait_for_username_peer_id(db_path, username, Duration::from_secs(90));
    let conn = open_connection(db_path).expect("open db");
    conn.query_row(
        "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
        rusqlite::params![peer_id],
        |row| row.get(0),
    )
    .expect("query messages by tenant")
}

fn setup_source_shared_db(db_path: &str) {
    for spec in TENANTS {
        create_workspace_with_details(
            db_path,
            spec.workspace,
            spec.source_username,
            spec.source_device,
        );
    }
}

fn accept_sink_tenants(source_db: &str, sink_db: &str, bootstrap_addr: &str) {
    for spec in TENANTS {
        use_tenant_for_username(source_db, spec.source_username);
        let invite = create_invite(source_db, bootstrap_addr);
        accept_invite_with_identity(sink_db, &invite, spec.sink_username, spec.sink_device);
    }
}

fn generate_source_history(source_db: &str) {
    std::env::set_var(
        "TOPO_GENERATE_MESSAGE_SPREAD_MS",
        GENERATE_SPREAD_MS.to_string(),
    );
    for spec in TENANTS {
        use_tenant_for_username(source_db, spec.source_username);
        generate_messages(source_db, MESSAGE_COUNT as usize);
    }
    std::env::remove_var("TOPO_GENERATE_MESSAGE_SPREAD_MS");
}

fn fairness_summary(
    completion_ms: &BTreeMap<&'static str, u128>,
    first_completion_counts: &BTreeMap<&'static str, i64>,
    source_rss_mib: f64,
    sink_rss_mib: f64,
) -> String {
    let fastest_ms = *completion_ms.values().min().unwrap_or(&0);
    let slowest_ms = *completion_ms.values().max().unwrap_or(&0);
    let spread_ms = slowest_ms.saturating_sub(fastest_ms);
    let min_progress = *first_completion_counts.values().min().unwrap_or(&0);
    let max_progress = *first_completion_counts.values().max().unwrap_or(&0);
    let progress_ratio = if max_progress == 0 {
        0.0
    } else {
        min_progress as f64 / max_progress as f64
    };

    let mut lines = String::new();
    lines.push_str("=== CLI multitenant fairness: 4x50k concurrent catch-up ===\n");
    lines.push_str(&format!(
        "  Source daemon peak RSS: {:.1} MiB\n  Sink daemon peak RSS:   {:.1} MiB\n",
        source_rss_mib, sink_rss_mib
    ));
    lines.push_str(&format!(
        "  Fastest completion: {:.2}s\n  Slowest completion: {:.2}s\n  Completion spread: {:.2}s\n",
        fastest_ms as f64 / 1000.0,
        slowest_ms as f64 / 1000.0,
        spread_ms as f64 / 1000.0
    ));
    lines.push_str(&format!(
        "  Counts when first tenant completed: min={} max={} ratio={:.3}\n",
        min_progress, max_progress, progress_ratio
    ));
    for spec in TENANTS {
        let complete_ms = completion_ms
            .get(spec.sink_username)
            .copied()
            .unwrap_or_default();
        let count_at_first = first_completion_counts
            .get(spec.sink_username)
            .copied()
            .unwrap_or_default();
        lines.push_str(&format!(
            "  {} -> complete {:.2}s, visible messages at first completion {}\n",
            spec.sink_username,
            complete_ms as f64 / 1000.0,
            count_at_first
        ));
    }
    lines
}

#[test]
#[ignore]
fn perf_cli_multitenant_shared_db_catchup_4x_50k_fairness() {
    hold_network_test_lock_for_binary();
    let tmpdir = tempfile::tempdir().expect("tempdir");
    let source_db = tmpdir
        .path()
        .join("source-shared.db")
        .to_str()
        .unwrap()
        .to_string();
    let sink_db = tmpdir
        .path()
        .join("sink-shared.db")
        .to_str()
        .unwrap()
        .to_string();

    setup_source_shared_db(&source_db);
    let source_port = random_port();
    let mut source_daemon: HarnessDaemon = start_daemon_with_options(
        &source_db,
        &DaemonOptions {
            bind_port: Some(source_port),
            ..Default::default()
        },
    );
    let source_bootstrap_addr = format!("127.0.0.1:{source_port}");
    accept_sink_tenants(&source_db, &sink_db, &source_bootstrap_addr);
    generate_source_history(&source_db);

    let mut sink_daemon: HarnessDaemon = start_daemon(&sink_db);
    for spec in TENANTS {
        wait_for_username_peer_id(&sink_db, spec.sink_username, Duration::from_secs(60));
    }

    let source_pid = source_daemon.child().id();
    let sink_pid = sink_daemon.child().id();
    let start = Instant::now();
    let timeout = Duration::from_secs(30 * 60);
    let mut completion_ms = BTreeMap::<&'static str, u128>::new();
    let mut first_completion_counts = None::<BTreeMap<&'static str, i64>>;

    loop {
        let counts: BTreeMap<&'static str, i64> = TENANTS
            .iter()
            .map(|spec| {
                (
                    spec.sink_username,
                    projected_message_count_for_username(&sink_db, spec.sink_username),
                )
            })
            .collect();

        for spec in TENANTS {
            if counts.get(spec.sink_username).copied().unwrap_or_default() >= MESSAGE_COUNT {
                completion_ms
                    .entry(spec.sink_username)
                    .or_insert_with(|| start.elapsed().as_millis());
            }
        }

        if first_completion_counts.is_none() && !completion_ms.is_empty() {
            first_completion_counts = Some(counts.clone());
        }

        if completion_ms.len() == TENANTS.len() {
            let source_rss_mib =
                peak_rss_mib_for_pid(source_pid).expect("source daemon VmHWM unavailable");
            let sink_rss_mib =
                peak_rss_mib_for_pid(sink_pid).expect("sink daemon VmHWM unavailable");
            let summary = fairness_summary(
                &completion_ms,
                &first_completion_counts.expect("first completion counts"),
                source_rss_mib,
                sink_rss_mib,
            );
            eprintln!("\n{summary}");
            write_summary(
                "cli_multitenant_fairness_test.perf_cli_multitenant_shared_db_catchup_4x_50k_fairness",
                &summary,
            );
            break;
        }

        assert!(
            start.elapsed() < timeout,
            "multitenant fairness benchmark timed out after {:?}: counts={:?} completed={:?}",
            timeout,
            counts,
            completion_ms
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}
